package gg.grounds.permissions.auth

import gg.grounds.permissions.metrics.RuntimeOperation
import gg.grounds.permissions.metrics.RuntimePermissionMetrics
import gg.grounds.permissions.metrics.RuntimeRequestStatus
import io.fabric8.kubernetes.client.KubernetesClientException
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.time.Duration
import java.util.Locale

interface RuntimeAccessAuthorizer {
    fun requireAccess(
        authorizationHeader: String?,
        verb: String,
        path: String,
    ): RuntimeWorkloadIdentity
}

sealed class RuntimeAccessException(
    val statusCode: Int,
    val error: String,
    val publicDetail: String,
) : RuntimeException(error)

class RuntimeAuthenticationException :
    RuntimeAccessException(
        statusCode = 401,
        error = "runtime_authentication_failed",
        publicDetail = "Runtime workload authentication failed.",
    )

class RuntimeAuthorizationException :
    RuntimeAccessException(
        statusCode = 403,
        error = "runtime_access_denied",
        publicDetail = "Runtime workload access is denied.",
    )

class RuntimeAccessUnavailableException :
    RuntimeAccessException(
        statusCode = 503,
        error = "runtime_authorization_unavailable",
        publicDetail = "Runtime workload authorization is unavailable.",
    )

@ApplicationScoped
class DefaultRuntimeAccessAuthorizer
@Inject
constructor(
    private val client: KubernetesWorkloadAccessClient,
    private val metrics: RuntimePermissionMetrics,
) : RuntimeAccessAuthorizer {
    internal constructor(
        client: KubernetesWorkloadAccessClient
    ) : this(client, RuntimePermissionMetrics.noOp())

    override fun requireAccess(
        authorizationHeader: String?,
        verb: String,
        path: String,
    ): RuntimeWorkloadIdentity {
        val startedAt = System.nanoTime()
        try {
            val token = bearerToken(authorizationHeader) ?: throw RuntimeAuthenticationException()
            val identity =
                try {
                    client.authenticate(token, RUNTIME_AUDIENCE)
                } catch (_: RuntimeInvalidWorkloadCredentialException) {
                    throw RuntimeAuthenticationException()
                } catch (_: RuntimeWorkloadReviewUnavailableException) {
                    throw RuntimeAccessUnavailableException()
                } catch (_: KubernetesClientException) {
                    throw RuntimeAccessUnavailableException()
                }
            if (!identity.isConsistentServiceAccount()) throw RuntimeAuthenticationException()

            val normalizedVerb = verb.lowercase(Locale.ROOT)
            val queryFreePath = path.substringBefore('?')
            val allowed =
                try {
                    client.isAllowed(identity, normalizedVerb, queryFreePath)
                } catch (_: RuntimeWorkloadReviewUnavailableException) {
                    throw RuntimeAccessUnavailableException()
                } catch (_: KubernetesClientException) {
                    throw RuntimeAccessUnavailableException()
                }
            if (!allowed) throw RuntimeAuthorizationException()
            return identity
        } catch (exception: RuntimeAccessException) {
            metrics.recordRuntimeRequest(
                operationFor(path),
                requestStatusFor(exception.statusCode),
                Duration.ofNanos(System.nanoTime() - startedAt),
            )
            throw exception
        }
    }

    private fun bearerToken(authorizationHeader: String?): String? {
        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX))
            return null
        return authorizationHeader.removePrefix(BEARER_PREFIX).takeIf {
            it.isNotEmpty() && it.none(Char::isWhitespace)
        }
    }

    private fun RuntimeWorkloadIdentity.isConsistentServiceAccount(): Boolean =
        username == "system:serviceaccount:$namespace:$serviceAccount" &&
            namespace.isNotEmpty() &&
            serviceAccount.isNotEmpty() &&
            ':' !in namespace &&
            ':' !in serviceAccount

    private fun operationFor(path: String): RuntimeOperation =
        if (path.substringBefore('?').startsWith("$RUNTIME_ROOT/catalog/"))
            RuntimeOperation.MANIFEST
        else RuntimeOperation.SNAPSHOT

    private fun requestStatusFor(statusCode: Int): RuntimeRequestStatus =
        when (statusCode) {
            401 -> RuntimeRequestStatus.UNAUTHORIZED
            403 -> RuntimeRequestStatus.FORBIDDEN
            503 -> RuntimeRequestStatus.UNAVAILABLE
            else -> RuntimeRequestStatus.FAILURE
        }

    private companion object {
        const val BEARER_PREFIX = "Bearer "
        const val RUNTIME_AUDIENCE = "service-permissions"
        const val RUNTIME_ROOT = "/v1/permissions/runtime"
    }
}
