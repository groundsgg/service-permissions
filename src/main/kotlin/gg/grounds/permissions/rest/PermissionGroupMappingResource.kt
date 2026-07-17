package gg.grounds.permissions.rest

import gg.grounds.permissions.auth.AdminAuthorizationService
import gg.grounds.permissions.persistence.KeycloakGroupMappingRecord
import gg.grounds.permissions.persistence.PermissionRepository
import io.quarkus.security.Authenticated
import io.quarkus.security.identity.SecurityIdentity
import jakarta.inject.Inject
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.DefaultValue
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
import java.util.UUID

@Path("/v1/permissions/keycloak-groups")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
class PermissionGroupMappingResource
@Inject
constructor(
    private val repository: PermissionRepository,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {

    @GET
    fun listMappings(@Context headers: HttpHeaders): List<KeycloakGroupMappingResponse> {
        requireAdmin(headers)
        return repository.listKeycloakGroupMappings().map { it.toResponse() }
    }

    @GET
    @Path("/search")
    fun searchMappings(
        @QueryParam("query") query: String?,
        @QueryParam("page") @DefaultValue("1") page: Int,
        @QueryParam("perPage") @DefaultValue("20") perPage: Int,
        @QueryParam("sortBy") sortBy: String?,
        @QueryParam("sortDirection") sortDirection: String?,
        @Context headers: HttpHeaders,
    ): PagedResponse<KeycloakGroupMappingResponse> {
        requireAdmin(headers)
        val search =
            PermissionSearchPaging.validate(
                query = query,
                page = page,
                perPage = perPage,
                sortBy = sortBy,
                sortDirection = sortDirection,
                defaultSortBy = "group",
                allowedSortKeys = listOf("group", "role", "expiration"),
            )
        val result =
            repository.searchKeycloakGroupMappings(
                query = search.query,
                page = search.page,
                perPage = search.perPage,
                sortBy = search.sortBy,
                sortDirection = search.sortDirection,
            )
        return PagedResponse(
            items = result.items.map { it.toResponse() },
            page = search.page,
            perPage = search.perPage,
            total = result.total,
        )
    }

    @POST
    fun createMapping(
        request: KeycloakGroupMappingRequest,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        val mapping = request.toRecord(UUID.randomUUID())
        return Response.status(Response.Status.CREATED)
            .entity(repository.createKeycloakGroupMapping(mapping).toResponse())
            .build()
    }

    @PUT
    @Path("/{mappingId}")
    fun updateMapping(
        @PathParam("mappingId") mappingId: String,
        request: KeycloakGroupMappingRequest,
        @Context headers: HttpHeaders,
    ): KeycloakGroupMappingResponse {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(mappingId, "mappingId")
        return repository.updateKeycloakGroupMapping(id, request.toRecord(id)).toResponse()
    }

    @DELETE
    @Path("/{mappingId}")
    fun deleteMapping(
        @PathParam("mappingId") mappingId: String,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        repository.deleteKeycloakGroupMapping(PermissionValidation.uuid(mappingId, "mappingId"))
        return Response.noContent().build()
    }

    private fun requireAdmin(headers: HttpHeaders): String =
        authorization.requireMinecraftPermissionsAdmin(identity, headers)

    private fun KeycloakGroupMappingRequest.toRecord(id: UUID): KeycloakGroupMappingRecord =
        KeycloakGroupMappingRecord(
            id = id,
            keycloakGroup = PermissionValidation.keycloakGroup(keycloakGroup),
            roleKey = PermissionValidation.roleKey(roleKey),
            expiresAt = expiresAt,
        )
}

fun KeycloakGroupMappingRecord.toResponse(): KeycloakGroupMappingResponse =
    KeycloakGroupMappingResponse(
        id = id,
        keycloakGroup = keycloakGroup,
        roleKey = roleKey,
        expiresAt = expiresAt,
    )
