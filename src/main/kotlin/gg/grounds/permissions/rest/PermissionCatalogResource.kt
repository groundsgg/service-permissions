package gg.grounds.permissions.rest

import gg.grounds.permissions.auth.AdminAuthorizationService
import gg.grounds.permissions.persistence.CatalogEntryRecord
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
import org.eclipse.microprofile.openapi.annotations.Operation
import org.eclipse.microprofile.openapi.annotations.media.Content
import org.eclipse.microprofile.openapi.annotations.media.Schema
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement
import org.eclipse.microprofile.openapi.annotations.tags.Tag

@Path("/v1/permissions/catalog")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
@Tag(name = "Administration")
@SecurityRequirement(name = "portalBearer")
class PermissionCatalogResource
@Inject
constructor(
    private val repository: PermissionRepository,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {

    @GET
    @Operation(operationId = "listPermissionCatalog", summary = "List permission catalog entries")
    fun listCatalog(@Context headers: HttpHeaders): List<CatalogEntryResponse> {
        requireView(headers)
        return repository.listCatalogEntries().map { it.toResponse() }
    }

    @GET
    @Path("/search")
    @Operation(
        operationId = "searchPermissionCatalog",
        summary = "Search permission catalog entries",
    )
    fun searchCatalog(
        @QueryParam("query") query: String?,
        @QueryParam("page") @DefaultValue("1") page: Int,
        @QueryParam("perPage") @DefaultValue("20") perPage: Int,
        @QueryParam("sortBy") sortBy: String?,
        @QueryParam("sortDirection") sortDirection: String?,
        @Context headers: HttpHeaders,
    ): PagedResponse<CatalogEntryResponse> {
        requireView(headers)
        val search =
            PermissionSearchPaging.validate(
                query = query,
                page = page,
                perPage = perPage,
                sortBy = sortBy,
                sortDirection = sortDirection,
                defaultSortBy = "permission",
                allowedSortKeys = listOf("permission", "label", "source", "lastseen"),
            )
        val result =
            repository.searchCatalogEntries(
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
    @Path("/custom")
    @Operation(operationId = "createCustomCatalogEntry", summary = "Create a custom catalog entry")
    @APIResponse(
        responseCode = "201",
        description = "Custom catalog entry created.",
        content =
            [
                Content(
                    mediaType = MediaType.APPLICATION_JSON,
                    schema = Schema(implementation = CatalogEntryResponse::class),
                )
            ],
    )
    fun createCustomEntry(request: CatalogEntryRequest, @Context headers: HttpHeaders): Response {
        val actor = requireManage(headers)
        val entry = request.toRecord(custom = true)
        return Response.status(Response.Status.CREATED)
            .entity(repository.upsertCatalogEntry(actor, entry).toResponse())
            .build()
    }

    @PUT
    @Path("/custom/{permissionKey}")
    @Operation(operationId = "updateCustomCatalogEntry", summary = "Update a custom catalog entry")
    fun updateCustomEntry(
        @PathParam("permissionKey") permissionKey: String,
        request: CatalogEntryRequest,
        @Context headers: HttpHeaders,
    ): CatalogEntryResponse {
        val actor = requireManage(headers)
        return repository
            .upsertCatalogEntry(actor, request.copy(key = permissionKey).toRecord(custom = true))
            .toResponse()
    }

    @DELETE
    @Path("/custom/{permissionKey}")
    @Operation(operationId = "deleteCustomCatalogEntry", summary = "Delete a custom catalog entry")
    @APIResponse(responseCode = "204", description = "Custom catalog entry deleted.")
    fun deleteCustomEntry(
        @PathParam("permissionKey") permissionKey: String,
        @Context headers: HttpHeaders,
    ): Response {
        val actor = requireManage(headers)
        repository.deleteCustomCatalogEntry(
            actor,
            PermissionValidation.permissionKey(permissionKey),
        )
        return Response.noContent().build()
    }

    private fun requireView(headers: HttpHeaders): String =
        authorization.requireMinecraftPermissionsView(identity, headers)

    private fun requireManage(headers: HttpHeaders): String =
        authorization.requireMinecraftPermissionsManage(identity, headers)

    private fun CatalogEntryRequest.toRecord(custom: Boolean): CatalogEntryRecord =
        CatalogEntryRecord(
            key = PermissionValidation.permissionKey(key),
            label = PermissionValidation.label(label),
            description = description,
            source = source.trim().ifEmpty { "portal" },
            sourceVersion = sourceVersion.trim().ifEmpty { "custom" },
            supportedScopes =
                supportedScopes.ifEmpty {
                    throw IllegalArgumentException("supportedScopes must not be empty")
                },
            custom = custom,
        )
}

fun CatalogEntryRecord.toResponse(): CatalogEntryResponse =
    CatalogEntryResponse(
        key = key,
        label = label,
        description = description,
        source = source,
        sourceVersion = sourceVersion,
        supportedScopes = supportedScopes,
        custom = custom,
        lastSeenAt = lastSeenAt,
    )
