package gg.grounds.permissions.auth

import io.fabric8.kubernetes.api.model.authentication.TokenReviewBuilder
import io.fabric8.kubernetes.api.model.authorization.v1.NonResourceAttributesBuilder
import io.fabric8.kubernetes.api.model.authorization.v1.SubjectAccessReviewBuilder
import io.fabric8.kubernetes.client.KubernetesClient
import io.fabric8.kubernetes.client.KubernetesClientException
import jakarta.enterprise.context.ApplicationScoped
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
class Fabric8KubernetesWorkloadAccessClient(
    private val kubernetesClient: KubernetesClient,
    private val cache: RuntimeReviewCache,
) : KubernetesWorkloadAccessClient {
    override fun authenticate(token: String, audience: String): RuntimeWorkloadIdentity {
        if (audience != RUNTIME_AUDIENCE) throw RuntimeInvalidWorkloadCredentialException()
        cache.authenticatedIdentity(token)?.let {
            return it
        }

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
            throw RuntimeInvalidWorkloadCredentialException()
        }
        val username = status.user?.username ?: throw RuntimeInvalidWorkloadCredentialException()
        val match =
            SERVICE_ACCOUNT_USERNAME.matchEntire(username)
                ?: throw RuntimeInvalidWorkloadCredentialException()
        val identity =
            RuntimeWorkloadIdentity(
                username = username,
                namespace = match.groupValues[1],
                serviceAccount = match.groupValues[2],
                groups = status.user?.groups.orEmpty().toSet(),
            )
        cache.cacheAuthenticatedIdentity(token, identity)
        return identity
    }

    override fun isAllowed(identity: RuntimeWorkloadIdentity, verb: String, path: String): Boolean {
        val normalizedVerb = verb.lowercase(Locale.ROOT)
        val queryFreePath = path.substringBefore('?')
        cache.allowed(identity, normalizedVerb, queryFreePath)?.let {
            return it
        }

        val nonResourceAttributes =
            NonResourceAttributesBuilder().withVerb(normalizedVerb).withPath(queryFreePath).build()
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
        val allowed = status.allowed == true
        if (allowed) cache.cacheAllowed(identity, normalizedVerb, queryFreePath)
        return allowed
    }

    private companion object {
        const val RUNTIME_AUDIENCE = "service-permissions"
        val SERVICE_ACCOUNT_USERNAME = Regex("^system:serviceaccount:([^:]+):([^:]+)$")
    }
}
