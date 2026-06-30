package gg.grounds.permissions.rest

import gg.grounds.permissions.persistence.CatalogEntryRecord
import gg.grounds.permissions.persistence.PermissionRepository
import jakarta.inject.Inject
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.PUT
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response

@Path("/v1/permissions/catalog")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
class PermissionCatalogResource @Inject constructor(private val repository: PermissionRepository) {

    @GET
    fun listCatalog(): List<CatalogEntryResponse> =
        repository.listCatalogEntries().map { it.toResponse() }

    @POST
    @Path("/custom")
    fun createCustomEntry(request: CatalogEntryRequest): Response {
        val entry = request.toRecord(custom = true)
        return Response.status(Response.Status.CREATED)
            .entity(repository.upsertCatalogEntry(entry).toResponse())
            .build()
    }

    @PUT
    @Path("/custom/{permissionKey}")
    fun updateCustomEntry(
        @PathParam("permissionKey") permissionKey: String,
        request: CatalogEntryRequest,
    ): CatalogEntryResponse =
        repository
            .upsertCatalogEntry(request.copy(key = permissionKey).toRecord(custom = true))
            .toResponse()

    @DELETE
    @Path("/custom/{permissionKey}")
    fun deleteCustomEntry(@PathParam("permissionKey") permissionKey: String): Response {
        repository.deleteCustomCatalogEntry(PermissionValidation.permissionKey(permissionKey))
        return Response.noContent().build()
    }

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
