package gg.grounds.permissions.rest

import gg.grounds.permissions.auth.AdminAuthorizationService
import gg.grounds.permissions.persistence.PermissionSyncMetadataRecord
import gg.grounds.permissions.sync.GlobalPermissionSnapshot
import gg.grounds.permissions.sync.PermissionSyncImportRequest
import gg.grounds.permissions.sync.PermissionSyncPreviewResponse
import gg.grounds.permissions.sync.PermissionSyncService
import io.quarkus.security.Authenticated
import io.quarkus.security.identity.SecurityIdentity
import jakarta.inject.Inject
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
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

@Path("/v1/permissions/sync")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
@Tag(name = "Environment sync")
@SecurityRequirement(name = "portalBearer")
class PermissionSyncResource
@Inject
constructor(
    private val sync: PermissionSyncService,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {
    @GET
    @Path("/snapshot")
    @Operation(operationId = "getPermissionSyncSnapshot", summary = "Export a permission snapshot")
    fun snapshot(@Context headers: HttpHeaders): GlobalPermissionSnapshot {
        authorization.requireMinecraftPermissionsSnapshotRead(identity, headers)
        return sync.snapshot()
    }

    @POST
    @Path("/preview")
    @Operation(
        operationId = "previewPermissionSync",
        summary = "Preview a permission snapshot import",
    )
    fun preview(
        snapshot: GlobalPermissionSnapshot,
        @Context headers: HttpHeaders,
    ): PermissionSyncPreviewResponse {
        authorization.requireMinecraftPermissionsView(identity, headers)
        return sync.preview(snapshot)
    }

    @POST
    @Path("/import")
    @Operation(operationId = "importPermissionSync", summary = "Import a permission snapshot")
    @APIResponse(
        responseCode = "200",
        description = "Permission snapshot imported.",
        content =
            [
                Content(
                    mediaType = MediaType.APPLICATION_JSON,
                    schema = Schema(implementation = PermissionSyncMetadataRecord::class),
                )
            ],
    )
    fun import(request: PermissionSyncImportRequest, @Context headers: HttpHeaders): Response {
        val actor = authorization.requireMinecraftPermissionsManage(identity, headers)
        val metadata = sync.import(request, actor)
        return Response.ok(metadata).build()
    }
}
