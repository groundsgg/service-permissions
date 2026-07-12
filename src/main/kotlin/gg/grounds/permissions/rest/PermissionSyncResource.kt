package gg.grounds.permissions.rest

import gg.grounds.permissions.auth.AdminAuthorizationService
import gg.grounds.permissions.sync.GlobalPermissionSnapshot
import gg.grounds.permissions.sync.PermissionSyncImportRequest
import gg.grounds.permissions.sync.PermissionSyncPreviewResponse
import gg.grounds.permissions.sync.PermissionSyncService
import io.quarkus.security.Authenticated
import io.quarkus.security.identity.SecurityIdentity
import jakarta.inject.Inject
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response

@Path("/v1/permissions/sync")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
class PermissionSyncResource
@Inject
constructor(
    private val sync: PermissionSyncService,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {
    @POST
    @Path("/preview")
    fun preview(
        snapshot: GlobalPermissionSnapshot,
        @Context headers: HttpHeaders,
    ): PermissionSyncPreviewResponse {
        authorization.requireMinecraftPermissionsAdmin(identity, headers)
        val diff = sync.preview(snapshot)
        return PermissionSyncPreviewResponse(
            snapshot.snapshotId,
            diff.changes,
            diff.conflicts,
            diff.projectOnlyEntries,
        )
    }

    @POST
    @Path("/import")
    fun import(request: PermissionSyncImportRequest, @Context headers: HttpHeaders): Response {
        val actor = authorization.requireMinecraftPermissionsAdmin(identity, headers)
        val metadata = sync.import(request, actor)
        return Response.ok(metadata).build()
    }
}
