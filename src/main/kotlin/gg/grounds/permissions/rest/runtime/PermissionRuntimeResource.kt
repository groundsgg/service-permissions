package gg.grounds.permissions.rest.runtime

import gg.grounds.permissions.api.PermissionPolicyProvider
import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.domain.EffectivePermissionSnapshot
import gg.grounds.permissions.domain.PermissionGrant
import gg.grounds.permissions.domain.RoleMetadata
import gg.grounds.permissions.metrics.RuntimePermissionMetrics
import gg.grounds.permissions.persistence.CatalogEntryRecord
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.RuntimeManifestRegistration
import gg.grounds.permissions.policy.PolicyEngine
import gg.grounds.permissions.rest.PermissionValidation
import io.quarkus.security.Authenticated
import jakarta.inject.Inject
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.GET
import jakarta.ws.rs.PUT
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import java.time.Instant
import org.eclipse.microprofile.openapi.annotations.Operation
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement
import org.eclipse.microprofile.openapi.annotations.tags.Tag
import org.jboss.logging.Logger

@Path("/v1/permissions/runtime")
@Authenticated
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "Runtime")
@SecurityRequirement(name = "workloadBearer")
class PermissionRuntimeResource
@Inject
constructor(
    private val policyProvider: PermissionPolicyProvider,
    private val repository: PermissionRepository,
    private val metrics: RuntimePermissionMetrics,
) {
    @GET
    @Path("/players/{playerId}/snapshot")
    @Operation(
        operationId = "getRuntimePermissionSnapshot",
        summary = "Get a runtime player permission snapshot",
    )
    fun snapshot(
        @PathParam("playerId") playerId: String,
        @QueryParam("serverType") serverType: String?,
        @QueryParam("serverId") serverId: String?,
        @Context headers: HttpHeaders,
    ): RuntimePermissionSnapshotResponse {
        val id = PermissionValidation.uuid(playerId, "playerId")
        val normalizedServerType = normalizedOptional(serverType, "serverType")
        val normalizedServerId = normalizedOptional(serverId, "serverId")
        val computationStartedAt = System.nanoTime()
        val snapshot =
            PolicyEngine.createSnapshot(
                playerId = id,
                input =
                    policyProvider.policyFor(
                        PermissionPolicyRequest(
                            playerId = id,
                            serverType = normalizedServerType,
                            serverId = normalizedServerId,
                        )
                    ),
            )
        metrics.recordSnapshotComputation(
            java.time.Duration.ofNanos(System.nanoTime() - computationStartedAt)
        )
        LOG.infof(
            "Permission runtime snapshot computed successfully (requestId=%s, playerId=%s, serverType=%s, serverId=%s, policyVersion=%d, roleCount=%d)",
            gg.grounds.permissions.rest.RequestIdResolver.resolve(headers),
            id,
            normalizedServerType,
            normalizedServerId,
            snapshot.policyVersion,
            snapshot.roleKeys.size,
        )
        return snapshot.toResponse()
    }

    @PUT
    @Path("/catalog/manifests/{source}")
    @Operation(
        operationId = "replaceRuntimePermissionManifest",
        summary = "Replace a runtime permission manifest",
    )
    @APIResponse(responseCode = "204", description = "Runtime permission manifest replaced.")
    fun replaceManifest(
        @PathParam("source") source: String,
        request: RuntimeManifestRequest,
    ): Response {
        val registration = request.toRegistration(source)
        repository.replaceRuntimeManifest(registration)
        return Response.noContent().build()
    }

    private fun RuntimeManifestRequest.toRegistration(
        pathSource: String
    ): RuntimeManifestRegistration {
        require(!containsBodySource()) { "source must not be provided in the request body" }
        val normalizedSource = required(pathSource, "source")
        val normalizedSourceVersion = required(sourceVersion, "sourceVersion")
        val catalogEntries =
            requireNotNull(permissions) { "permissions must not be null" }
                .mapIndexed { index, permission ->
                    permission.toCatalogEntry(normalizedSource, normalizedSourceVersion, index)
                }
        require(
            catalogEntries.map(CatalogEntryRecord::key).distinct().size == catalogEntries.size
        ) {
            "permissions keys must be unique"
        }
        return RuntimeManifestRegistration(
            source = normalizedSource,
            sourceVersion = normalizedSourceVersion,
            serverType = normalizedOptional(serverType, "serverType"),
            serverId = normalizedOptional(serverId, "serverId"),
            permissions = catalogEntries,
            registeredAt = Instant.now(),
        )
    }

    private fun RuntimeManifestPermissionRequest.toCatalogEntry(
        source: String,
        sourceVersion: String,
        index: Int,
    ): CatalogEntryRecord {
        val scopes =
            requireNotNull(supportedScopes) {
                "permissions[$index].supportedScopes must not be null"
            }
        require(scopes.isNotEmpty()) { "permissions[$index].supportedScopes must not be empty" }
        return CatalogEntryRecord(
            key = PermissionValidation.permissionKey(key),
            label = PermissionValidation.label(label),
            description = description?.trim().orEmpty(),
            source = source,
            sourceVersion = sourceVersion,
            supportedScopes = scopes,
            custom = false,
            lastSeenAt = Instant.now(),
        )
    }

    private fun EffectivePermissionSnapshot.toResponse() =
        RuntimePermissionSnapshotResponse(
            playerId = playerId,
            policyVersion = policyVersion,
            issuedAt = issuedAt,
            refreshAfter = refreshAfter,
            expiresAt = expiresAt,
            allowPatterns = allowPatterns.map { it.toResponse() },
            denyPatterns = denyPatterns.map { it.toResponse() },
            roleKeys = roleKeys,
            roleMetadata = roleMetadata.map { it.toResponse() },
        )

    private fun PermissionGrant.toResponse() =
        RuntimePermissionGrantDto(
            effect = effect,
            pattern = pattern,
            scope = PermissionScopeDto(scope.kind, scope.value),
            source = source,
            expiresAt = expiresAt,
        )

    private fun RoleMetadata.toResponse() =
        RuntimeRoleMetadataDto(
            key = key,
            name = name,
            prefix = prefix,
            color = color,
            sortOrder = sortOrder,
        )

    private fun normalizedOptional(value: String?, fieldName: String): String {
        if (value == null) return ""
        return value.trim().also { require(it.isNotEmpty()) { "$fieldName must not be blank" } }
    }

    private fun required(value: String?, fieldName: String): String =
        value?.trim().takeIf { !it.isNullOrEmpty() }
            ?: throw IllegalArgumentException("$fieldName must not be blank")

    private companion object {
        val LOG = Logger.getLogger(PermissionRuntimeResource::class.java)
    }
}
