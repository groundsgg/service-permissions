package gg.grounds.permissions.rest

import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.auth.AdminAuthorizationService
import gg.grounds.permissions.domain.EffectivePermissionSnapshot
import gg.grounds.permissions.domain.PermissionGrant
import gg.grounds.permissions.domain.PermissionGrantOriginKind
import gg.grounds.permissions.identity.IdentitySyncReadinessCheck
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PlayerGrantRecord
import gg.grounds.permissions.persistence.PlayerIdentityRepository
import gg.grounds.permissions.persistence.PlayerRoleGrantRecord
import gg.grounds.permissions.policy.PermissionCheckScope
import gg.grounds.permissions.policy.PolicyEngine
import io.quarkus.security.Authenticated
import io.quarkus.security.identity.SecurityIdentity
import jakarta.inject.Inject
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.PUT
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import java.time.Duration
import java.time.Instant
import java.util.UUID
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.eclipse.microprofile.health.Readiness

@Path("/v1/permissions/players/{playerId}")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
class PermissionPlayerResource
@Inject
constructor(
    private val repository: PermissionRepository,
    private val identityRepository: PlayerIdentityRepository,
    @param:Readiness private val readinessCheck: IdentitySyncReadinessCheck,
    @param:ConfigProperty(name = "permissions.identity-sync.max-staleness")
    private val identityMaxStaleness: Duration,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {

    @GET
    @Path("/roles")
    fun listPlayerRoles(
        @PathParam("playerId") playerId: String,
        @Context headers: HttpHeaders,
    ): List<PlayerRoleGrantResponse> {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        return repository.listPlayerRoleGrantRecords(id).map { it.toResponse() }
    }

    @POST
    @Path("/roles")
    fun createPlayerRole(
        @PathParam("playerId") playerId: String,
        request: PlayerRoleGrantRequest,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val grant =
            PlayerRoleGrantRecord(
                id = UUID.randomUUID(),
                playerId = id,
                roleKey = PermissionValidation.roleKey(request.roleKey),
                expiresAt = request.expiresAt,
            )
        return Response.status(Response.Status.CREATED)
            .entity(repository.createPlayerRoleGrant(grant).toResponse())
            .build()
    }

    @PUT
    @Path("/roles/{grantId}")
    fun updatePlayerRole(
        @PathParam("playerId") playerId: String,
        @PathParam("grantId") grantId: String,
        request: PlayerRoleGrantRequest,
        @Context headers: HttpHeaders,
    ): PlayerRoleGrantResponse {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val parsedGrantId = PermissionValidation.uuid(grantId, "grantId")
        val grant =
            PlayerRoleGrantRecord(
                id = parsedGrantId,
                playerId = id,
                roleKey = PermissionValidation.roleKey(request.roleKey),
                expiresAt = request.expiresAt,
            )
        return repository.updatePlayerRoleGrant(id, parsedGrantId, grant).toResponse()
    }

    @DELETE
    @Path("/roles/{grantId}")
    fun deletePlayerRole(
        @PathParam("playerId") playerId: String,
        @PathParam("grantId") grantId: String,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        repository.deletePlayerRoleGrant(
            playerId = PermissionValidation.uuid(playerId, "playerId"),
            grantId = PermissionValidation.uuid(grantId, "grantId"),
        )
        return Response.noContent().build()
    }

    @GET
    @Path("/grants")
    fun listPlayerGrants(
        @PathParam("playerId") playerId: String,
        @Context headers: HttpHeaders,
    ): List<PlayerGrantResponse> {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        return repository.listPlayerGrantRecords(id).map { it.toResponse() }
    }

    @POST
    @Path("/grants")
    fun createPlayerGrant(
        @PathParam("playerId") playerId: String,
        request: GrantRequest,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val grant = request.toPlayerGrantRecord(playerId = id, grantId = UUID.randomUUID())
        return Response.status(Response.Status.CREATED)
            .entity(repository.createPlayerGrant(grant).toResponse())
            .build()
    }

    @PUT
    @Path("/grants/{grantId}")
    fun updatePlayerGrant(
        @PathParam("playerId") playerId: String,
        @PathParam("grantId") grantId: String,
        request: GrantRequest,
        @Context headers: HttpHeaders,
    ): PlayerGrantResponse {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val parsedGrantId = PermissionValidation.uuid(grantId, "grantId")
        return repository
            .updatePlayerGrant(id, parsedGrantId, request.toPlayerGrantRecord(id, parsedGrantId))
            .toResponse()
    }

    @DELETE
    @Path("/grants/{grantId}")
    fun deletePlayerGrant(
        @PathParam("playerId") playerId: String,
        @PathParam("grantId") grantId: String,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        repository.deletePlayerGrant(
            playerId = PermissionValidation.uuid(playerId, "playerId"),
            grantId = PermissionValidation.uuid(grantId, "grantId"),
        )
        return Response.noContent().build()
    }

    @GET
    @Path("/effective")
    fun effectivePermissions(
        @PathParam("playerId") playerId: String,
        @QueryParam("serverType") serverType: String?,
        @QueryParam("serverId") serverId: String?,
        @Context headers: HttpHeaders,
    ): EffectivePermissionResponse {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val snapshot = snapshotFor(id, serverType, serverId)
        return EffectivePermissionResponse(
            playerId = snapshot.playerId,
            policyVersion = snapshot.policyVersion,
            roleKeys = snapshot.roleKeys,
            allowPatterns = snapshot.allowPatterns.map { it.toResponse() },
            denyPatterns = snapshot.denyPatterns.map { it.toResponse() },
            roleAssignments =
                snapshot.roleAssignments.map { assignment ->
                    EffectiveRoleAssignmentResponse(
                        roleKey = assignment.roleKey,
                        source = assignment.origin.kind,
                        grantId = assignment.origin.grantId,
                        mappingId = assignment.origin.mappingId,
                        inheritedPath = assignment.origin.inheritedPath,
                        editable =
                            assignment.origin.kind == PermissionGrantOriginKind.DIRECT_ROLE &&
                                assignment.origin.inheritedPath.isEmpty(),
                    )
                },
            refreshAfter = snapshot.refreshAfter,
            expiresAt = snapshot.expiresAt,
        )
    }

    @GET
    @Path("/identity")
    fun identity(
        @PathParam("playerId") playerId: String,
        @Context headers: HttpHeaders,
    ): PlayerIdentityResponse {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val projectedIdentity = identityRepository.findByPlayerId(id)
        val fresh =
            projectedIdentity?.syncedAt?.isBefore(Instant.now().minus(identityMaxStaleness)) ==
                false
        val evaluationSafe =
            !repository.requiresIdentityProjection() || readinessCheck.isIdentityPolicyAvailable()
        return PlayerIdentityResponse(
            playerId = id,
            name = projectedIdentity?.minecraftUsername,
            linked = projectedIdentity != null,
            syncedAt = projectedIdentity?.syncedAt,
            sourceUpdatedAt = projectedIdentity?.sourceUpdatedAt,
            fresh = fresh,
            evaluationSafe = evaluationSafe,
        )
    }

    @GET
    @Path("/check")
    fun checkPermission(
        @PathParam("playerId") playerId: String,
        @QueryParam("permission") permission: String?,
        @QueryParam("serverType") serverType: String?,
        @QueryParam("serverId") serverId: String?,
        @Context headers: HttpHeaders,
    ): PermissionCheckResponse {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val normalizedPermission = PermissionValidation.permissionKey(permission)
        val snapshot = snapshotFor(id, serverType, serverId)
        val decision =
            PolicyEngine.checkPermission(
                snapshot = snapshot,
                permission = normalizedPermission,
                scope = checkScope(serverType, serverId),
            )
        return PermissionCheckResponse(
            playerId = id,
            permission = normalizedPermission,
            allowed = decision.allowed,
            winningGrant = decision.winningGrant?.toResponse(),
        )
    }

    private fun snapshotFor(
        playerId: UUID,
        serverType: String?,
        serverId: String?,
    ): EffectivePermissionSnapshot {
        val input =
            repository.policyFor(
                PermissionPolicyRequest(
                    playerId = playerId,
                    serverType = serverType?.trim().orEmpty(),
                    serverId = serverId?.trim().orEmpty(),
                )
            )
        return PolicyEngine.createSnapshot(playerId = playerId, input = input)
    }

    private fun checkScope(serverType: String?, serverId: String?): PermissionCheckScope {
        val normalizedServerType = serverType?.trim()?.takeIf(String::isNotEmpty)
        val normalizedServerId = serverId?.trim()?.takeIf(String::isNotEmpty)
        return when {
            normalizedServerId != null && normalizedServerType != null ->
                PermissionCheckScope.server(normalizedServerId, normalizedServerType)
            normalizedServerId != null -> PermissionCheckScope.serverOnly(normalizedServerId)
            normalizedServerType != null -> PermissionCheckScope.serverType(normalizedServerType)
            else -> PermissionCheckScope.global()
        }
    }

    private fun PermissionGrant.toResponse(): EffectiveGrantResponse =
        scope.toGrantResponse(effect, pattern, expiresAt, origin)

    private fun requireAdmin(headers: HttpHeaders): String =
        authorization.requireMinecraftPermissionsAdmin(identity, headers)

    private fun GrantRequest.toPlayerGrantRecord(playerId: UUID, grantId: UUID): PlayerGrantRecord =
        PlayerGrantRecord(
            id = grantId,
            playerId = playerId,
            effect = requireNotNull(effect) { "effect must not be null" },
            pattern = PermissionValidation.permissionPattern(permissionPattern),
            scope = PermissionValidation.scope(scopeKind, scopeValue),
            expiresAt = expiresAt,
        )
}

fun PlayerRoleGrantRecord.toResponse(): PlayerRoleGrantResponse =
    PlayerRoleGrantResponse(id = id, playerId = playerId, roleKey = roleKey, expiresAt = expiresAt)

fun PlayerGrantRecord.toResponse(): PlayerGrantResponse =
    PlayerGrantResponse(
        id = id,
        playerId = playerId,
        effect = effect,
        permissionPattern = pattern,
        scopeKind = scope.kind,
        scopeValue = scope.value,
        expiresAt = expiresAt,
    )
