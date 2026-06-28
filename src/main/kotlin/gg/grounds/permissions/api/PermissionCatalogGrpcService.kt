package gg.grounds.permissions.api

import gg.grounds.grpc.permissions.PermissionCatalogService
import gg.grounds.grpc.permissions.RegisterPermissionManifestReply
import gg.grounds.grpc.permissions.RegisterPermissionManifestRequest
import io.quarkus.grpc.GrpcService
import io.smallrye.common.annotation.Blocking
import io.smallrye.mutiny.Uni
import org.jboss.logging.Logger

@GrpcService
@Blocking
class PermissionCatalogGrpcService : PermissionCatalogService {
    override fun registerPermissionManifest(
        request: RegisterPermissionManifestRequest
    ): Uni<RegisterPermissionManifestReply> {
        return Uni.createFrom().item {
            LOG.infof(
                "Permission manifest registration accepted (serverType=%s, serverId=%s, permissionCount=%d)",
                request.serverType,
                request.serverId,
                request.permissionsCount,
            )
            RegisterPermissionManifestReply.newBuilder()
                .setAccepted(true)
                .setMessage("manifest accepted")
                .build()
        }
    }

    companion object {
        private val LOG = Logger.getLogger(PermissionCatalogGrpcService::class.java)
    }
}
