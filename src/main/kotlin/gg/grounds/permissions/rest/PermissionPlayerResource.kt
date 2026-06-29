package gg.grounds.permissions.rest

import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PlayerGrantRecord
import gg.grounds.permissions.persistence.PlayerRoleGrantRecord
import gg.grounds.permissions.policy.PolicyEngine
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
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import java.util.UUID

@Path("/v1/permissions/players/{playerId}")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
class PermissionPlayerResource @Inject constructor(private val repository: PermissionRepository) {

    @GET
    @Path("/roles")
    fun listPlayerRoles(@PathParam("playerId") playerId: String): List<PlayerRoleGrantResponse> {
        val id = PermissionValidation.uuid(playerId, "playerId")
        return repository.listPlayerRoleGrantRecords(id).map { it.toResponse() }
    }

    @POST
    @Path("/roles")
    fun createPlayerRole(
        @PathParam("playerId") playerId: String,
        request: PlayerRoleGrantRequest,
    ): Response {
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
    ): PlayerRoleGrantResponse {
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
    ): Response {
        repository.deletePlayerRoleGrant(
            playerId = PermissionValidation.uuid(playerId, "playerId"),
            grantId = PermissionValidation.uuid(grantId, "grantId"),
        )
        return Response.noContent().build()
    }

    @GET
    @Path("/grants")
    fun listPlayerGrants(@PathParam("playerId") playerId: String): List<PlayerGrantResponse> {
        val id = PermissionValidation.uuid(playerId, "playerId")
        return repository.listPlayerGrantRecords(id).map { it.toResponse() }
    }

    @POST
    @Path("/grants")
    fun createPlayerGrant(
        @PathParam("playerId") playerId: String,
        request: GrantRequest,
    ): Response {
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
    ): PlayerGrantResponse {
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
    ): Response {
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
        @QueryParam("keycloakGroup") keycloakGroups: List<String>?,
        @QueryParam("serverType") serverType: String?,
        @QueryParam("serverId") serverId: String?,
    ): EffectivePermissionResponse {
        val id = PermissionValidation.uuid(playerId, "playerId")
        val input =
            repository.policyFor(
                PermissionPolicyRequest(
                    playerId = id,
                    keycloakGroups =
                        keycloakGroups
                            .orEmpty()
                            .mapNotNull { it.trim().takeIf(String::isNotEmpty) }
                            .toSet(),
                    serverType = serverType?.trim().orEmpty(),
                    serverId = serverId?.trim().orEmpty(),
                )
            )
        val snapshot = PolicyEngine.createSnapshot(playerId = id, input = input)
        return EffectivePermissionResponse(
            playerId = snapshot.playerId,
            policyVersion = snapshot.policyVersion,
            roleKeys = snapshot.roleKeys,
            allowPatterns =
                snapshot.allowPatterns.map {
                    it.scope.toGrantResponse(it.effect, it.pattern, it.expiresAt)
                },
            denyPatterns =
                snapshot.denyPatterns.map {
                    it.scope.toGrantResponse(it.effect, it.pattern, it.expiresAt)
                },
            refreshAfter = snapshot.refreshAfter,
            expiresAt = snapshot.expiresAt,
        )
    }

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
