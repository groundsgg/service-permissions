package gg.grounds.permissions.auth

import gg.grounds.permissions.metrics.RuntimePermissionMetrics
import gg.grounds.permissions.metrics.RuntimeReviewOutcome
import gg.grounds.permissions.metrics.RuntimeReviewType
import io.fabric8.kubernetes.api.model.authentication.TokenReviewBuilder
import io.fabric8.kubernetes.api.model.authorization.v1.NonResourceAttributesBuilder
import io.fabric8.kubernetes.api.model.authorization.v1.SubjectAccessReviewBuilder
import io.fabric8.kubernetes.client.KubernetesClient
import io.fabric8.kubernetes.client.KubernetesClientException
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.util.Locale

interface KubernetesWorkloadAccessClient {
    fun authenticate(token: String, audience: String): RuntimeWorkloadIdentity

    fun isAllowed(identity: RuntimeWorkloadIdentity, verb: String, path: String): Boolean
}

class RuntimeInvalidWorkloadCredentialException :
    RuntimeException("runtime_workload_credential_invalid")

class RuntimeWorkloadReviewUnavailableException :
    RuntimeException("runtime_workload_review_unavailable")

@ApplicationScoped
class Fabric8KubernetesWorkloadAccessClient
@Inject
constructor(
    private val kubernetesClient: KubernetesClient,
    private val cache: RuntimeReviewCache,
    private val metrics: RuntimePermissionMetrics,
) : KubernetesWorkloadAccessClient {
    internal constructor(
        kubernetesClient: KubernetesClient,
        cache: RuntimeReviewCache,
    ) : this(kubernetesClient, cache, RuntimePermissionMetrics.noOp())

    override fun authenticate(token: String, audience: String): RuntimeWorkloadIdentity {
        if (audience != RUNTIME_AUDIENCE) throw RuntimeInvalidWorkloadCredentialException()
        cache.authenticatedIdentity(token)?.let {
            metrics.recordAuthCacheHit(RuntimeReviewType.TOKEN)
            return it
        }
        val startedAt = System.nanoTime()
        var outcome = RuntimeReviewOutcome.UNAVAILABLE
        try {
            val review =
                TokenReviewBuilder()
                    .withNewSpec()
                    .withToken(token)
                    .withAudiences(audience)
                    .endSpec()
                    .build()
            val result =
                try {
                    kubernetesClient.authentication().v1().tokenReviews().create(review)
                } catch (_: KubernetesClientException) {
                    throw RuntimeWorkloadReviewUnavailableException()
                }
            val status = result.status ?: throw RuntimeWorkloadReviewUnavailableException()
            if (status.authenticated != true || status.audiences?.toSet() != setOf(audience)) {
                outcome = RuntimeReviewOutcome.INVALID
                throw RuntimeInvalidWorkloadCredentialException()
            }
            val username =
                status.user?.username
                    ?: run {
                        outcome = RuntimeReviewOutcome.INVALID
                        throw RuntimeInvalidWorkloadCredentialException()
                    }
            val match =
                SERVICE_ACCOUNT_USERNAME.matchEntire(username)
                    ?: run {
                        outcome = RuntimeReviewOutcome.INVALID
                        throw RuntimeInvalidWorkloadCredentialException()
                    }
            val identity =
                RuntimeWorkloadIdentity(
                    username = username,
                    namespace = match.groupValues[1],
                    serviceAccount = match.groupValues[2],
                    groups = status.user?.groups.orEmpty().toSet(),
                )
            cache.cacheAuthenticatedIdentity(token, identity)
            outcome = RuntimeReviewOutcome.SUCCESS
            return identity
        } finally {
            metrics.recordTokenReview(outcome, elapsed(startedAt))
        }
    }

    override fun isAllowed(identity: RuntimeWorkloadIdentity, verb: String, path: String): Boolean {
        val normalizedVerb = verb.lowercase(Locale.ROOT)
        val queryFreePath = path.substringBefore('?')
        cache.allowed(identity, normalizedVerb, queryFreePath)?.let {
            metrics.recordAuthCacheHit(RuntimeReviewType.SUBJECT_ACCESS)
            return it
        }
        val startedAt = System.nanoTime()
        var outcome = RuntimeReviewOutcome.UNAVAILABLE
        try {
            val nonResourceAttributes =
                NonResourceAttributesBuilder()
                    .withVerb(normalizedVerb)
                    .withPath(queryFreePath)
                    .build()
            val review =
                SubjectAccessReviewBuilder()
                    .withNewSpec()
                    .withUser(identity.username)
                    .withGroups(identity.groups.toList())
                    .withNonResourceAttributes(nonResourceAttributes)
                    .endSpec()
                    .build()
            val result =
                try {
                    kubernetesClient.authorization().v1().subjectAccessReview().create(review)
                } catch (_: KubernetesClientException) {
                    throw RuntimeWorkloadReviewUnavailableException()
                }
            val status = result.status ?: throw RuntimeWorkloadReviewUnavailableException()
            if (!status.evaluationError.isNullOrBlank()) {
                throw RuntimeWorkloadReviewUnavailableException()
            }
            val allowed = status.allowed ?: throw RuntimeWorkloadReviewUnavailableException()
            outcome = if (allowed) RuntimeReviewOutcome.SUCCESS else RuntimeReviewOutcome.DENIED
            if (allowed) cache.cacheAllowed(identity, normalizedVerb, queryFreePath)
            return allowed
        } finally {
            metrics.recordSubjectAccessReview(outcome, elapsed(startedAt))
        }
    }

    private companion object {
        const val RUNTIME_AUDIENCE = "service-permissions"
        val SERVICE_ACCOUNT_USERNAME = Regex("^system:serviceaccount:([^:]+):([^:]+)$")

        fun elapsed(startedAt: Long) = java.time.Duration.ofNanos(System.nanoTime() - startedAt)
    }
}
