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
import org.eclipse.microprofile.openapi.annotations.Operation
import org.eclipse.microprofile.openapi.annotations.media.Content
import org.eclipse.microprofile.openapi.annotations.media.Schema
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement
import org.eclipse.microprofile.openapi.annotations.tags.Tag

@Path("/v1/permissions/keycloak-groups")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
@Tag(name = "Administration")
@SecurityRequirement(name = "portalBearer")
class PermissionGroupMappingResource
@Inject
constructor(
    private val repository: PermissionRepository,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {

    @GET
    @Operation(operationId = "listKeycloakGroupMappings", summary = "List Keycloak group mappings")
    fun listMappings(@Context headers: HttpHeaders): List<KeycloakGroupMappingResponse> {
        requireView(headers)
        return repository.listKeycloakGroupMappings().map { it.toResponse() }
    }

    @GET
    @Path("/search")
    @Operation(
        operationId = "searchKeycloakGroupMappings",
        summary = "Search Keycloak group mappings",
    )
    fun searchMappings(
        @QueryParam("query") query: String?,
        @QueryParam("page") @DefaultValue("1") page: Int,
        @QueryParam("perPage") @DefaultValue("20") perPage: Int,
        @QueryParam("sortBy") sortBy: String?,
        @QueryParam("sortDirection") sortDirection: String?,
        @Context headers: HttpHeaders,
    ): PagedResponse<KeycloakGroupMappingResponse> {
        requireView(headers)
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
    @Operation(
        operationId = "createKeycloakGroupMapping",
        summary = "Create a Keycloak group mapping",
    )
    @APIResponse(
        responseCode = "201",
        description = "Keycloak group mapping created.",
        content =
            [
                Content(
                    mediaType = MediaType.APPLICATION_JSON,
                    schema = Schema(implementation = KeycloakGroupMappingResponse::class),
                )
            ],
    )
    fun createMapping(
        request: KeycloakGroupMappingRequest,
        @Context headers: HttpHeaders,
    ): Response {
        val actor = requireManage(headers)
        val mapping = request.toRecord(UUID.randomUUID())
        return Response.status(Response.Status.CREATED)
            .entity(repository.createKeycloakGroupMapping(actor, mapping).toResponse())
            .build()
    }

    @PUT
    @Path("/{mappingId}")
    @Operation(
        operationId = "updateKeycloakGroupMapping",
        summary = "Update a Keycloak group mapping",
    )
    fun updateMapping(
        @PathParam("mappingId") mappingId: String,
        request: KeycloakGroupMappingRequest,
        @Context headers: HttpHeaders,
    ): KeycloakGroupMappingResponse {
        val actor = requireManage(headers)
        val id = PermissionValidation.uuid(mappingId, "mappingId")
        return repository.updateKeycloakGroupMapping(actor, id, request.toRecord(id)).toResponse()
    }

    @DELETE
    @Path("/{mappingId}")
    @Operation(
        operationId = "deleteKeycloakGroupMapping",
        summary = "Delete a Keycloak group mapping",
    )
    @APIResponse(responseCode = "204", description = "Keycloak group mapping deleted.")
    fun deleteMapping(
        @PathParam("mappingId") mappingId: String,
        @Context headers: HttpHeaders,
    ): Response {
        val actor = requireManage(headers)
        repository.deleteKeycloakGroupMapping(
            actor,
            PermissionValidation.uuid(mappingId, "mappingId"),
        )
        return Response.noContent().build()
    }

    private fun requireView(headers: HttpHeaders): String =
        authorization.requireMinecraftPermissionsView(identity, headers)

    private fun requireManage(headers: HttpHeaders): String =
        authorization.requireMinecraftPermissionsManage(identity, headers)

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
