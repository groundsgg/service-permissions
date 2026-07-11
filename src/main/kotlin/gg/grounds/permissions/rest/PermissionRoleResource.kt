package gg.grounds.permissions.rest

import gg.grounds.permissions.auth.AdminAuthorizationService
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.RoleAggregateCountsRecord
import gg.grounds.permissions.persistence.RoleGrantRecord
import gg.grounds.permissions.persistence.RoleRecord
import io.quarkus.security.Authenticated
import io.quarkus.security.identity.SecurityIdentity
import jakarta.inject.Inject
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.POST
import jakarta.ws.rs.PUT
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import java.util.UUID

@Path("/v1/permissions/roles")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
class PermissionRoleResource
@Inject
constructor(
    private val repository: PermissionRepository,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {

    @GET
    fun listRoles(@Context headers: HttpHeaders): List<RoleListResponse> {
        requireAdmin(headers)
        return repository.listRolesWithAggregateCounts().map { it.toListResponse() }
    }

    @POST
    fun createRole(request: RoleRequest, @Context headers: HttpHeaders): Response {
        requireAdmin(headers)
        val name = PermissionValidation.displayName(request.name)
        val role =
            RoleRecord(
                key = PermissionValidation.roleKeyFromName(name),
                name = name,
                description = request.description,
                prefix = request.prefix?.trim()?.takeIf { it.isNotEmpty() },
                color = request.color?.trim()?.takeIf { it.isNotEmpty() },
                sortOrder = request.sortOrder,
                metadata = request.metadata,
                isDefault = request.default,
            )
        return Response.status(Response.Status.CREATED)
            .entity(repository.createRole(role).toResponse())
            .build()
    }

    @GET
    @Path("/{roleKey}")
    fun getRole(
        @PathParam("roleKey") roleKey: String,
        @Context headers: HttpHeaders,
    ): RoleResponse {
        requireAdmin(headers)
        return repository.getRole(PermissionValidation.roleKey(roleKey))?.toResponse()
            ?: throw NotFoundException("Role not found (roleKey=$roleKey)")
    }

    @PUT
    @Path("/{roleKey}")
    fun updateRole(
        @PathParam("roleKey") roleKey: String,
        request: RoleRequest,
        @Context headers: HttpHeaders,
    ): RoleResponse {
        requireAdmin(headers)
        val key = PermissionValidation.roleKey(roleKey)
        val existing =
            repository.getRole(key) ?: throw NotFoundException("Role not found (roleKey=$key)")
        return repository
            .updateRole(
                key,
                RoleRecord(
                    key = key,
                    name = PermissionValidation.displayName(request.name),
                    description = request.description,
                    prefix = request.prefix?.trim()?.takeIf { it.isNotEmpty() },
                    color = request.color?.trim()?.takeIf { it.isNotEmpty() },
                    sortOrder = request.sortOrder,
                    metadata = request.metadata.ifEmpty { existing.metadata },
                    isDefault = request.default,
                ),
            )
            .toResponse()
    }

    @DELETE
    @Path("/{roleKey}")
    fun deleteRole(@PathParam("roleKey") roleKey: String, @Context headers: HttpHeaders): Response {
        requireAdmin(headers)
        repository.deleteRole(PermissionValidation.roleKey(roleKey))
        return Response.noContent().build()
    }

    @PUT
    @Path("/{roleKey}/inherits/{parentRoleKey}")
    fun addInheritance(
        @PathParam("roleKey") roleKey: String,
        @PathParam("parentRoleKey") parentRoleKey: String,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        repository.addRoleInheritance(
            childRoleKey = PermissionValidation.roleKey(roleKey),
            parentRoleKey = PermissionValidation.roleKey(parentRoleKey),
        )
        return Response.noContent().build()
    }

    @DELETE
    @Path("/{roleKey}/inherits/{parentRoleKey}")
    fun removeInheritance(
        @PathParam("roleKey") roleKey: String,
        @PathParam("parentRoleKey") parentRoleKey: String,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        repository.removeRoleInheritance(
            childRoleKey = PermissionValidation.roleKey(roleKey),
            parentRoleKey = PermissionValidation.roleKey(parentRoleKey),
        )
        return Response.noContent().build()
    }

    @GET
    @Path("/{roleKey}/grants")
    fun listRoleGrants(
        @PathParam("roleKey") roleKey: String,
        @Context headers: HttpHeaders,
    ): List<RoleGrantResponse> {
        requireAdmin(headers)
        return repository.listRoleGrantRecords(PermissionValidation.roleKey(roleKey)).map {
            it.toResponse()
        }
    }

    @POST
    @Path("/{roleKey}/grants")
    fun createRoleGrant(
        @PathParam("roleKey") roleKey: String,
        request: GrantRequest,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        val key = PermissionValidation.roleKey(roleKey)
        val grant = request.toRoleGrantRecord(roleKey = key, id = UUID.randomUUID())
        return Response.status(Response.Status.CREATED)
            .entity(repository.createRoleGrant(grant).toResponse())
            .build()
    }

    @PUT
    @Path("/{roleKey}/grants/{grantId}")
    fun updateRoleGrant(
        @PathParam("roleKey") roleKey: String,
        @PathParam("grantId") grantId: String,
        request: GrantRequest,
        @Context headers: HttpHeaders,
    ): RoleGrantResponse {
        requireAdmin(headers)
        val key = PermissionValidation.roleKey(roleKey)
        val id = PermissionValidation.uuid(grantId, "grantId")
        return repository.updateRoleGrant(key, id, request.toRoleGrantRecord(key, id)).toResponse()
    }

    @DELETE
    @Path("/{roleKey}/grants/{grantId}")
    fun deleteRoleGrant(
        @PathParam("roleKey") roleKey: String,
        @PathParam("grantId") grantId: String,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        repository.deleteRoleGrant(
            roleKey = PermissionValidation.roleKey(roleKey),
            grantId = PermissionValidation.uuid(grantId, "grantId"),
        )
        return Response.noContent().build()
    }

    private fun requireAdmin(headers: HttpHeaders): String =
        authorization.requireMinecraftPermissionsAdmin(identity, headers)

    private fun GrantRequest.toRoleGrantRecord(roleKey: String, id: UUID): RoleGrantRecord =
        RoleGrantRecord(
            id = id,
            roleKey = roleKey,
            effect = requireNotNull(effect) { "effect must not be null" },
            pattern = PermissionValidation.permissionPattern(permissionPattern),
            scope = PermissionValidation.scope(scopeKind, scopeValue),
            expiresAt = expiresAt,
        )
}

fun RoleRecord.toResponse(): RoleResponse =
    RoleResponse(
        key = key,
        name = name,
        description = description,
        prefix = prefix,
        color = color,
        sortOrder = sortOrder,
        metadata = metadata,
        default = isDefault,
    )

fun RoleAggregateCountsRecord.toListResponse(): RoleListResponse =
    with(role) {
        RoleListResponse(
            key = key,
            name = name,
            description = description,
            prefix = prefix,
            color = color,
            sortOrder = sortOrder,
            metadata = metadata,
            default = isDefault,
            grantCount = grantCount,
            inheritanceCount = inheritanceCount,
            parentRoleKeys = inheritedRoleKeys.toList(),
        )
    }

fun RoleGrantRecord.toResponse(): RoleGrantResponse =
    RoleGrantResponse(
        id = id,
        roleKey = roleKey,
        effect = effect,
        permissionPattern = pattern,
        scopeKind = scope.kind,
        scopeValue = scope.value,
        expiresAt = expiresAt,
    )

fun PermissionScope.toGrantResponse(
    effect: gg.grounds.permissions.domain.PermissionEffect,
    pattern: String,
    expiresAt: java.time.Instant?,
): EffectiveGrantResponse =
    EffectiveGrantResponse(
        effect = effect,
        permissionPattern = pattern,
        scopeKind = kind,
        scopeValue = value,
        expiresAt = expiresAt,
    )
