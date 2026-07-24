package gg.grounds.permissions.api

import gg.grounds.grpc.permissions.PermissionCatalogService
import gg.grounds.grpc.permissions.PermissionScopeKind
import gg.grounds.grpc.permissions.RegisterPermissionManifestReply
import gg.grounds.grpc.permissions.RegisterPermissionManifestRequest
import gg.grounds.permissions.domain.PermissionScopeKind as DomainPermissionScopeKind
import gg.grounds.permissions.persistence.CatalogEntryRecord
import gg.grounds.permissions.persistence.PermissionRepository
import io.grpc.Status
import io.grpc.StatusRuntimeException
import io.quarkus.grpc.GrpcService
import io.smallrye.common.annotation.Blocking
import io.smallrye.mutiny.Uni
import java.time.Instant
import org.jboss.logging.Logger

@GrpcService
@Blocking
class PermissionCatalogGrpcService(private val repository: PermissionRepository) :
    PermissionCatalogService {
    override fun registerPermissionManifest(
        request: RegisterPermissionManifestRequest
    ): Uni<RegisterPermissionManifestReply> {
        return Uni.createFrom().item {
            val source = request.source.normalizedRequired("source")
            val sourceVersion = request.sourceVersion.normalizedRequired("source_version")
            val serverType = request.serverType.normalizedOptional("server_type")
            val serverId = request.serverId.normalizedOptional("server_id")
            if (request.permissionsList.isEmpty()) {
                throw invalidArgument("permissions must not be empty")
            }
            val permissionKeys = mutableSetOf<String>()
            val catalogEntries =
                request.permissionsList.mapIndexed { index, permission ->
                    val permissionKey = permission.key.normalizedRequired("permissions[$index].key")
                    if (!permissionKeys.add(permissionKey)) {
                        throw invalidArgument("permissions[$index].key must be unique")
                    }
                    val label = permission.label.normalizedRequired("permissions[$index].label")
                    if (permission.supportedScopesList.isEmpty()) {
                        throw invalidArgument(
                            "permissions[$index].supported_scopes must not be empty"
                        )
                    }
                    if (permission.supportedScopesValueList.any { it !in SUPPORTED_SCOPE_VALUES }) {
                        throw invalidArgument(
                            "permissions[$index].supported_scopes must contain only supported values"
                        )
                    }
                    CatalogEntryRecord(
                        key = permissionKey,
                        label = label,
                        description = permission.description,
                        source = source,
                        sourceVersion = sourceVersion,
                        supportedScopes =
                            permission.supportedScopesList.map { it.toDomainScopeKind() },
                        custom = false,
                        lastSeenAt = Instant.now(),
                    )
                }

            catalogEntries.forEach { entry ->
                repository.upsertCatalogEntry(RUNTIME_CATALOG_ACTOR, entry)
            }

            LOG.infof(
                "Permission manifest registration accepted (source=%s, sourceVersion=%s, serverType=%s, serverId=%s, permissionCount=%d)",
                source,
                sourceVersion,
                serverType,
                serverId,
                request.permissionsCount,
            )
            RegisterPermissionManifestReply.newBuilder()
                .setAccepted(true)
                .setMessage("manifest accepted")
                .build()
        }
    }

    private fun String.normalizedRequired(fieldName: String): String {
        val trimmed = trim()
        if (trimmed.isEmpty()) {
            throw invalidArgument("$fieldName must not be blank")
        }
        return trimmed
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

    private fun PermissionScopeKind.toDomainScopeKind(): DomainPermissionScopeKind =
        when (this) {
            PermissionScopeKind.PERMISSION_SCOPE_KIND_GLOBAL -> DomainPermissionScopeKind.GLOBAL
            PermissionScopeKind.PERMISSION_SCOPE_KIND_SERVER_TYPE ->
                DomainPermissionScopeKind.SERVER_TYPE
            PermissionScopeKind.PERMISSION_SCOPE_KIND_SERVER -> DomainPermissionScopeKind.SERVER
            PermissionScopeKind.PERMISSION_SCOPE_KIND_ENVIRONMENT ->
                DomainPermissionScopeKind.ENVIRONMENT
            else -> throw invalidArgument("supported scope must be recognized")
        }

    companion object {
        private const val RUNTIME_CATALOG_ACTOR = "runtime:catalog"
        private val LOG = Logger.getLogger(PermissionCatalogGrpcService::class.java)
        private val SUPPORTED_SCOPE_VALUES =
            setOf(
                PermissionScopeKind.PERMISSION_SCOPE_KIND_GLOBAL.number,
                PermissionScopeKind.PERMISSION_SCOPE_KIND_SERVER_TYPE.number,
                PermissionScopeKind.PERMISSION_SCOPE_KIND_SERVER.number,
                PermissionScopeKind.PERMISSION_SCOPE_KIND_ENVIRONMENT.number,
            )

        private fun invalidArgument(description: String): StatusRuntimeException =
            Status.INVALID_ARGUMENT.withDescription(description).asRuntimeException()
    }
}
