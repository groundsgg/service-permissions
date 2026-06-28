package gg.grounds.permissions.api

import gg.grounds.grpc.permissions.PermissionCatalogService
import gg.grounds.grpc.permissions.PermissionScopeKind
import gg.grounds.grpc.permissions.RegisterPermissionManifestReply
import gg.grounds.grpc.permissions.RegisterPermissionManifestRequest
import io.grpc.Status
import io.grpc.StatusRuntimeException
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
            val source = request.source.normalizedRequired("source")
            val sourceVersion = request.sourceVersion.normalizedRequired("source_version")
            val serverType = request.serverType.normalizedOptional("server_type")
            val serverId = request.serverId.normalizedOptional("server_id")
            if (request.permissionsList.isEmpty()) {
                throw invalidArgument("permissions must not be empty")
            }
            request.permissionsList.forEachIndexed { index, permission ->
                permission.key.normalizedRequired("permissions[$index].key")
                permission.label.normalizedRequired("permissions[$index].label")
                if (permission.supportedScopesList.isEmpty()) {
                    throw invalidArgument("permissions[$index].supported_scopes must not be empty")
                }
                if (
                    permission.supportedScopesList.any {
                        it == PermissionScopeKind.PERMISSION_SCOPE_KIND_UNSPECIFIED
                    }
                ) {
                    throw invalidArgument(
                        "permissions[$index].supported_scopes must not contain unspecified values"
                    )
                }
            }

            LOG.infof(
                "Permission manifest registration accepted (source=%s, sourceVersion=%s, serverType=%s, serverId=%s, permissionCount=%d)",
                source,
                sourceVersion,
                serverType,
                serverId,
                request.permissionsCount,
            )
            RegisterPermissionManifestReply.newBuilder()
                .setAccepted(true)
                .setMessage("manifest accepted")
                .build()
        }
    }

    private fun String.normalizedRequired(fieldName: String): String {
        val trimmed = trim()
        if (trimmed.isEmpty()) {
            throw invalidArgument("$fieldName must not be blank")
        }
        return trimmed
    }

    private fun String.normalizedOptional(fieldName: String): String {
        if (isEmpty()) {
            return ""
        }
        val trimmed = trim()
        if (trimmed.isEmpty()) {
            throw invalidArgument("$fieldName must not be blank")
        }
        return trimmed
    }

    companion object {
        private val LOG = Logger.getLogger(PermissionCatalogGrpcService::class.java)

        private fun invalidArgument(description: String): StatusRuntimeException =
            Status.INVALID_ARGUMENT.withDescription(description).asRuntimeException()
    }
}
