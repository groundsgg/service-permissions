package gg.grounds.permissions.rest.runtime

import gg.grounds.permissions.metrics.RuntimeManifestOutcome
import gg.grounds.permissions.metrics.RuntimeOperation
import gg.grounds.permissions.metrics.RuntimePermissionMetrics
import gg.grounds.permissions.metrics.RuntimeRequestStatus
import jakarta.annotation.Priority
import jakarta.inject.Inject
import jakarta.ws.rs.HttpMethod
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerRequestFilter
import jakarta.ws.rs.container.ContainerResponseContext
import jakarta.ws.rs.container.ContainerResponseFilter
import jakarta.ws.rs.container.PreMatching
import jakarta.ws.rs.ext.Provider
import java.time.Duration

@Provider
@PreMatching
@Priority(Priorities.USER)
class RuntimePermissionMetricsFilter
@Inject
constructor(private val metrics: RuntimePermissionMetrics) :
    ContainerRequestFilter, ContainerResponseFilter {
    override fun filter(requestContext: ContainerRequestContext) {
        operationFor(requestContext)?.let { operation ->
            requestContext.setProperty(
                REQUEST_CONTEXT_PROPERTY,
                RequestMetricsContext(operation, System.nanoTime()),
            )
        }
    }

    override fun filter(
        requestContext: ContainerRequestContext,
        responseContext: ContainerResponseContext,
    ) {
        val requestMetrics =
            requestContext.getProperty(REQUEST_CONTEXT_PROPERTY) as? RequestMetricsContext ?: return
        val status = requestStatus(responseContext.status)
        metrics.recordRuntimeRequest(
            requestMetrics.operation,
            status,
            Duration.ofNanos(System.nanoTime() - requestMetrics.startedAtNanos),
        )
        if (requestMetrics.operation == RuntimeOperation.MANIFEST) {
            metrics.recordManifest(manifestOutcome(status))
        }
    }

    private fun operationFor(requestContext: ContainerRequestContext): RuntimeOperation? {
        val path = "/${requestContext.uriInfo.path.trimStart('/')}"
        return when {
            requestContext.method == HttpMethod.GET && SNAPSHOT_PATH.matches(path) ->
                RuntimeOperation.SNAPSHOT
            requestContext.method == HttpMethod.PUT && MANIFEST_PATH.matches(path) ->
                RuntimeOperation.MANIFEST
            else -> null
        }
    }

    private fun requestStatus(statusCode: Int): RuntimeRequestStatus =
        when (statusCode) {
            in 200..299 -> RuntimeRequestStatus.SUCCESS
            400 -> RuntimeRequestStatus.INVALID
            401 -> RuntimeRequestStatus.UNAUTHORIZED
            403 -> RuntimeRequestStatus.FORBIDDEN
            409 -> RuntimeRequestStatus.CONFLICT
            503 -> RuntimeRequestStatus.UNAVAILABLE
            else -> RuntimeRequestStatus.FAILURE
        }

    private fun manifestOutcome(status: RuntimeRequestStatus): RuntimeManifestOutcome =
        when (status) {
            RuntimeRequestStatus.SUCCESS -> RuntimeManifestOutcome.SUCCESS
            RuntimeRequestStatus.CONFLICT -> RuntimeManifestOutcome.CONFLICT
            else -> RuntimeManifestOutcome.FAILURE
        }

    private data class RequestMetricsContext(
        val operation: RuntimeOperation,
        val startedAtNanos: Long,
    )

    private companion object {
        const val REQUEST_CONTEXT_PROPERTY =
            "gg.grounds.permissions.runtime.metrics.request-context"
        val SNAPSHOT_PATH = Regex("^/v1/permissions/runtime/players/[^/]+/snapshot$")
        val MANIFEST_PATH = Regex("^/v1/permissions/runtime/catalog/manifests/[^/]+$")
    }
}
