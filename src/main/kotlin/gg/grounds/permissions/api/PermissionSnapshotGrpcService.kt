package gg.grounds.permissions.api

import com.google.protobuf.Timestamp
import gg.grounds.grpc.permissions.GetPlayerSnapshotRequest
import gg.grounds.grpc.permissions.PermissionEffect
import gg.grounds.grpc.permissions.PermissionGrant
import gg.grounds.grpc.permissions.PermissionGrantOrigin
import gg.grounds.grpc.permissions.PermissionGrantOriginKind
import gg.grounds.grpc.permissions.PermissionGrantSource
import gg.grounds.grpc.permissions.PermissionScope
import gg.grounds.grpc.permissions.PermissionScopeKind
import gg.grounds.grpc.permissions.PermissionSnapshotService
import gg.grounds.grpc.permissions.PlayerPermissionSnapshot
import gg.grounds.grpc.permissions.RefreshOnlinePlayersReply
import gg.grounds.grpc.permissions.RefreshOnlinePlayersRequest
import gg.grounds.grpc.permissions.RoleMetadata
import gg.grounds.permissions.domain.EffectivePermissionSnapshot
import gg.grounds.permissions.policy.PolicyEngine
import io.grpc.Status
import io.grpc.StatusRuntimeException
import io.quarkus.grpc.GrpcService
import io.smallrye.common.annotation.Blocking
import io.smallrye.mutiny.Uni
import jakarta.inject.Inject
import java.time.Instant
import java.util.UUID
import org.jboss.logging.Logger

@GrpcService
@Blocking
class PermissionSnapshotGrpcService
@Inject
constructor(private val policyProvider: PermissionPolicyProvider) : PermissionSnapshotService {

    override fun getPlayerSnapshot(
        request: GetPlayerSnapshotRequest
    ): Uni<PlayerPermissionSnapshot> {
        return Uni.createFrom().item { handleGetPlayerSnapshot(request) }
    }

    override fun refreshOnlinePlayers(
        request: RefreshOnlinePlayersRequest
    ): Uni<RefreshOnlinePlayersReply> {
        return Uni.createFrom().item {
            val serverType = request.serverType.normalizedOptional("server_type")
            val serverId = request.serverId.normalizedOptional("server_id")

            LOG.infof(
                "Permission refresh accepted (serverType=%s, serverId=%s)",
                serverType,
                serverId,
            )
            RefreshOnlinePlayersReply.newBuilder()
                .setAccepted(true)
                .setMessage("refresh accepted")
                .build()
        }
    }

    private fun handleGetPlayerSnapshot(
        request: GetPlayerSnapshotRequest
    ): PlayerPermissionSnapshot {
        val playerId = request.playerId.toRequiredUuid("player_id")
        val serverType = request.serverType.normalizedOptional("server_type")
        val serverId = request.serverId.normalizedOptional("server_id")
        val input =
            policyProvider.policyFor(
                PermissionPolicyRequest(
                    playerId = playerId,
                    serverType = serverType,
                    serverId = serverId,
                )
            )
        val snapshot = PolicyEngine.createSnapshot(playerId = playerId, input = input)

        LOG.infof(
            "Permission snapshot computed (playerId=%s, serverType=%s, serverId=%s, policyVersion=%d, roleCount=%d)",
            playerId,
            serverType,
            serverId,
            snapshot.policyVersion,
            snapshot.roleKeys.size,
        )
        return snapshot.toGrpc()
    }

    private fun EffectivePermissionSnapshot.toGrpc(): PlayerPermissionSnapshot =
        PlayerPermissionSnapshot.newBuilder()
            .setPlayerId(playerId.toString())
            .setPolicyVersion(policyVersion)
            .setIssuedAt(issuedAt.toTimestamp())
            .setRefreshAfter(refreshAfter.toTimestamp())
            .setExpiresAt(expiresAt.toTimestamp())
            .addAllAllowPatterns(allowPatterns.map { it.toGrpc() })
            .addAllDenyPatterns(denyPatterns.map { it.toGrpc() })
            .addAllRoleKeys(roleKeys)
            .addAllRoleMetadata(roleMetadata.map { it.toGrpc() })
            .build()

    private fun gg.grounds.permissions.domain.PermissionGrant.toGrpc(): PermissionGrant =
        PermissionGrant.newBuilder()
            .setEffect(effect.toGrpc())
            .setPattern(pattern)
            .setScope(scope.toGrpc())
            .setSource(source.toGrpc())
            .setOrigin(origin.toGrpc())
            .also { builder -> expiresAt?.let { builder.setExpiresAt(it.toTimestamp()) } }
            .build()

    private fun gg.grounds.permissions.domain.PermissionGrantOrigin.toGrpc():
        PermissionGrantOrigin =
        PermissionGrantOrigin.newBuilder()
            .setKind(
                when (kind) {
                    gg.grounds.permissions.domain.PermissionGrantOriginKind.DEFAULT_ROLE ->
                        PermissionGrantOriginKind.PERMISSION_GRANT_ORIGIN_KIND_DEFAULT_ROLE
                    gg.grounds.permissions.domain.PermissionGrantOriginKind.DIRECT_ROLE ->
                        PermissionGrantOriginKind.PERMISSION_GRANT_ORIGIN_KIND_DIRECT_ROLE
                    gg.grounds.permissions.domain.PermissionGrantOriginKind.GROUP_MAPPING ->
                        PermissionGrantOriginKind.PERMISSION_GRANT_ORIGIN_KIND_GROUP_MAPPING
                    gg.grounds.permissions.domain.PermissionGrantOriginKind.DIRECT_PERMISSION ->
                        PermissionGrantOriginKind.PERMISSION_GRANT_ORIGIN_KIND_DIRECT_PERMISSION
                }
            )
            .also { builder ->
                roleKey?.let { builder.roleKey = it }
                mappingId?.let { builder.mappingId = it.toString() }
            }
            .addAllInheritedPath(inheritedPath)
            .build()

    private fun gg.grounds.permissions.domain.PermissionScope.toGrpc(): PermissionScope =
        PermissionScope.newBuilder()
            .setKind(
                when (kind) {
                    gg.grounds.permissions.domain.PermissionScopeKind.GLOBAL ->
                        PermissionScopeKind.PERMISSION_SCOPE_KIND_GLOBAL
                    gg.grounds.permissions.domain.PermissionScopeKind.SERVER_TYPE ->
                        PermissionScopeKind.PERMISSION_SCOPE_KIND_SERVER_TYPE
                    gg.grounds.permissions.domain.PermissionScopeKind.SERVER ->
                        PermissionScopeKind.PERMISSION_SCOPE_KIND_SERVER
                }
            )
            .also { builder -> value?.let { builder.value = it } }
            .build()

    private fun gg.grounds.permissions.domain.PermissionEffect.toGrpc(): PermissionEffect =
        when (this) {
            gg.grounds.permissions.domain.PermissionEffect.ALLOW ->
                PermissionEffect.PERMISSION_EFFECT_ALLOW
            gg.grounds.permissions.domain.PermissionEffect.DENY ->
                PermissionEffect.PERMISSION_EFFECT_DENY
        }

    private fun gg.grounds.permissions.domain.PermissionGrantSource.toGrpc():
        PermissionGrantSource =
        when (this) {
            gg.grounds.permissions.domain.PermissionGrantSource.ROLE ->
                PermissionGrantSource.PERMISSION_GRANT_SOURCE_ROLE
            gg.grounds.permissions.domain.PermissionGrantSource.PLAYER ->
                PermissionGrantSource.PERMISSION_GRANT_SOURCE_PLAYER
        }

    private fun gg.grounds.permissions.domain.RoleMetadata.toGrpc(): RoleMetadata =
        RoleMetadata.newBuilder()
            .setKey(key)
            .setName(name)
            .also { builder ->
                prefix?.let { builder.prefix = it }
                color?.let { builder.color = it }
            }
            .setSortOrder(sortOrder)
            .build()

    private fun Instant.toTimestamp(): Timestamp =
        Timestamp.newBuilder().setSeconds(epochSecond).setNanos(nano).build()

    private fun String.toRequiredUuid(fieldName: String): UUID {
        val trimmed = trim()
        if (trimmed.isEmpty()) {
            throw invalidArgument("$fieldName must be a nonblank UUID")
        }
        return runCatching { UUID.fromString(trimmed) }
            .getOrElse { throw invalidArgument("$fieldName must be a valid UUID") }
    }

    private fun String.normalizedOptional(fieldName: String): String {
        if (isEmpty()) {
            return ""
        }
        val trimmed = trim()
        if (trimmed.isEmpty()) {
            throw invalidArgument("$fieldName must not be blank")
        }
        return trimmed
    }

    companion object {
        private val LOG = Logger.getLogger(PermissionSnapshotGrpcService::class.java)

        private fun invalidArgument(description: String): StatusRuntimeException =
            Status.INVALID_ARGUMENT.withDescription(description).asRuntimeException()
    }
}
