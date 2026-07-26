package gg.grounds.permissions.rest.runtime

import gg.grounds.permissions.api.PermissionPolicyProvider
import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.domain.EffectivePermissionSnapshot
import gg.grounds.permissions.domain.PermissionGrant
import gg.grounds.permissions.domain.RoleMetadata
import gg.grounds.permissions.metrics.RuntimeManifestOutcome
import gg.grounds.permissions.metrics.RuntimeOperation
import gg.grounds.permissions.metrics.RuntimePermissionMetrics
import gg.grounds.permissions.metrics.RuntimeRequestStatus
import gg.grounds.permissions.persistence.CatalogEntryRecord
import gg.grounds.permissions.persistence.CatalogSourceConflictException
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
import java.time.Duration
import java.time.Instant
import org.jboss.logging.Logger

@Path("/v1/permissions/runtime")
@Authenticated
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
class PermissionRuntimeResource
@Inject
constructor(
    private val policyProvider: PermissionPolicyProvider,
    private val repository: PermissionRepository,
    private val metrics: RuntimePermissionMetrics,
) {
    @GET
    @Path("/players/{playerId}/snapshot")
    fun snapshot(
        @PathParam("playerId") playerId: String,
        @QueryParam("serverType") serverType: String?,
        @QueryParam("serverId") serverId: String?,
        @Context headers: HttpHeaders,
    ): RuntimePermissionSnapshotResponse {
        val startedAt = System.nanoTime()
        try {
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
            metrics.recordSnapshotComputation(elapsed(computationStartedAt))
            metrics.recordRuntimeRequest(
                RuntimeOperation.SNAPSHOT,
                RuntimeRequestStatus.SUCCESS,
                elapsed(startedAt),
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
        } catch (exception: IllegalArgumentException) {
            metrics.recordRuntimeRequest(
                RuntimeOperation.SNAPSHOT,
                RuntimeRequestStatus.INVALID,
                elapsed(startedAt),
            )
            throw exception
        } catch (exception: RuntimeException) {
            metrics.recordRuntimeRequest(
                RuntimeOperation.SNAPSHOT,
                RuntimeRequestStatus.FAILURE,
                elapsed(startedAt),
            )
            throw exception
        }
    }

    @PUT
    @Path("/catalog/manifests/{source}")
    fun replaceManifest(
        @PathParam("source") source: String,
        request: RuntimeManifestRequest,
    ): Response {
        val startedAt = System.nanoTime()
        try {
            val registration = request.toRegistration(source)
            repository.replaceRuntimeManifest(registration)
            metrics.recordManifest(RuntimeManifestOutcome.SUCCESS)
            metrics.recordRuntimeRequest(
                RuntimeOperation.MANIFEST,
                RuntimeRequestStatus.SUCCESS,
                elapsed(startedAt),
            )
            return Response.noContent().build()
        } catch (exception: CatalogSourceConflictException) {
            metrics.recordManifest(RuntimeManifestOutcome.CONFLICT)
            metrics.recordRuntimeRequest(
                RuntimeOperation.MANIFEST,
                RuntimeRequestStatus.CONFLICT,
                elapsed(startedAt),
            )
            throw exception
        } catch (exception: IllegalArgumentException) {
            metrics.recordManifest(RuntimeManifestOutcome.FAILURE)
            metrics.recordRuntimeRequest(
                RuntimeOperation.MANIFEST,
                RuntimeRequestStatus.INVALID,
                elapsed(startedAt),
            )
            throw exception
        } catch (exception: RuntimeException) {
            metrics.recordManifest(RuntimeManifestOutcome.FAILURE)
            metrics.recordRuntimeRequest(
                RuntimeOperation.MANIFEST,
                RuntimeRequestStatus.FAILURE,
                elapsed(startedAt),
            )
            throw exception
        }
    }

    private fun RuntimeManifestRequest.toRegistration(
        pathSource: String
    ): RuntimeManifestRegistration {
        val normalizedSource = required(pathSource, "source")
        val normalizedSourceVersion = required(sourceVersion, "sourceVersion")
        val catalogEntries =
            requireNotNull(permissions) { "permissions must not be null" }
                .also { require(it.isNotEmpty()) { "permissions must not be empty" } }
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

    private fun elapsed(startedAt: Long): Duration = Duration.ofNanos(System.nanoTime() - startedAt)

    private companion object {
        val LOG = Logger.getLogger(PermissionRuntimeResource::class.java)
    }
}
