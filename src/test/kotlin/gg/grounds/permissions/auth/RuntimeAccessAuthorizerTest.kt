package gg.grounds.permissions.auth

import io.fabric8.kubernetes.api.model.authentication.TokenReview
import io.fabric8.kubernetes.api.model.authentication.TokenReviewBuilder
import io.fabric8.kubernetes.api.model.authorization.v1.SubjectAccessReview
import io.fabric8.kubernetes.api.model.authorization.v1.SubjectAccessReviewBuilder
import io.fabric8.kubernetes.client.KubernetesClient
import io.fabric8.kubernetes.client.KubernetesClientException
import io.fabric8.kubernetes.client.V1AuthenticationAPIGroupDSL
import io.fabric8.kubernetes.client.V1AuthorizationAPIGroupDSL
import io.fabric8.kubernetes.client.dsl.AuthenticationAPIGroupDSL
import io.fabric8.kubernetes.client.dsl.AuthorizationAPIGroupDSL
import io.fabric8.kubernetes.client.dsl.InOutCreateable
import java.nio.charset.StandardCharsets.UTF_8
import java.time.Duration
import java.time.Instant
import java.util.Base64
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.NullAndEmptySource
import org.junit.jupiter.params.provider.ValueSource
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class RuntimeAccessAuthorizerTest {
    private val client = mock<KubernetesWorkloadAccessClient>()
    private val authorizer = DefaultRuntimeAccessAuthorizer(client)

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = ["Basic opaque", "Bearer", "Bearer ", "bearer runtime-token"])
    fun rejectsMissingOrMalformedBearerCredentials(header: String?) {
        val failure =
            assertThrows(RuntimeAuthenticationException::class.java) {
                authorizer.requireAccess(header, "GET", RUNTIME_PATH)
            }

        assertEquals(401, failure.statusCode)
        verify(client, never()).authenticate(any(), any())
    }

    @Test
    fun mapsRejectedTokenReviewToSafeUnauthorizedFailure() {
        val token = "sensitive-runtime-token"
        whenever(client.authenticate(token, RUNTIME_AUDIENCE))
            .thenThrow(RuntimeInvalidWorkloadCredentialException())

        val failure =
            assertThrows(RuntimeAuthenticationException::class.java) {
                authorizer.requireAccess("Bearer $token", "GET", RUNTIME_PATH)
            }

        assertEquals(401, failure.statusCode)
        assertFalse(failure.message.orEmpty().contains(token))
    }

    @Test
    fun rejectsMalformedServiceAccountIdentity() {
        whenever(client.authenticate("runtime-token", RUNTIME_AUDIENCE))
            .thenReturn(
                RuntimeWorkloadIdentity(
                    username = "workload-a",
                    namespace = "runtime",
                    serviceAccount = "workload-a",
                    groups = emptySet(),
                )
            )

        val failure =
            assertThrows(RuntimeAuthenticationException::class.java) {
                authorizer.requireAccess("Bearer runtime-token", "GET", RUNTIME_PATH)
            }

        assertEquals(401, failure.statusCode)
        verify(client, never()).isAllowed(any(), any(), any())
    }

    @Test
    fun mapsExplicitSubjectAccessReviewDenialToForbidden() {
        val identity = workloadIdentity()
        whenever(client.authenticate("runtime-token", RUNTIME_AUDIENCE)).thenReturn(identity)
        whenever(client.isAllowed(identity, "post", RUNTIME_PATH)).thenReturn(false)

        val failure =
            assertThrows(RuntimeAuthorizationException::class.java) {
                authorizer.requireAccess("Bearer runtime-token", "POST", RUNTIME_PATH)
            }

        assertEquals(403, failure.statusCode)
    }

    @Test
    fun mapsTokenReviewFailureToServiceUnavailableWithoutLeakingToken() {
        val token = "sensitive-runtime-token"
        whenever(client.authenticate(token, RUNTIME_AUDIENCE))
            .thenThrow(KubernetesClientException("review endpoint unavailable"))

        val failure =
            assertThrows(RuntimeAccessUnavailableException::class.java) {
                authorizer.requireAccess("Bearer $token", "GET", RUNTIME_PATH)
            }

        assertEquals(503, failure.statusCode)
        assertFalse(failure.message.orEmpty().contains(token))
    }

    @Test
    fun mapsSubjectAccessReviewFailureToServiceUnavailable() {
        val identity = workloadIdentity()
        whenever(client.authenticate("runtime-token", RUNTIME_AUDIENCE)).thenReturn(identity)
        whenever(client.isAllowed(identity, "get", RUNTIME_PATH))
            .thenThrow(KubernetesClientException("review endpoint unavailable"))

        val failure =
            assertThrows(RuntimeAccessUnavailableException::class.java) {
                authorizer.requireAccess("Bearer runtime-token", "GET", RUNTIME_PATH)
            }

        assertEquals(503, failure.statusCode)
    }

    @Test
    fun authorizesWithLowercaseVerbAndQueryFreeExactPath() {
        val identity = workloadIdentity()
        whenever(client.authenticate("runtime-token", RUNTIME_AUDIENCE)).thenReturn(identity)
        whenever(client.isAllowed(identity, "put", RUNTIME_PATH)).thenReturn(true)

        val result =
            authorizer.requireAccess(
                "Bearer runtime-token",
                "PUT",
                "$RUNTIME_PATH?submitted=secret",
            )

        assertEquals(identity, result)
        verify(client).isAllowed(identity, "put", RUNTIME_PATH)
    }

    private fun workloadIdentity() =
        RuntimeWorkloadIdentity(
            username = "system:serviceaccount:runtime:workload-a",
            namespace = "runtime",
            serviceAccount = "workload-a",
            groups = setOf("system:serviceaccounts", "system:serviceaccounts:runtime"),
        )

    private companion object {
        const val RUNTIME_AUDIENCE = "service-permissions"
        const val RUNTIME_PATH = "/v1/permissions/runtime/manifests"
    }
}

class KubernetesWorkloadRuntimeAccessAuthorizerTest {
    private val kubernetesClient = mock<KubernetesClient>()
    private val authenticationApi = mock<AuthenticationAPIGroupDSL>()
    private val authenticationV1 = mock<V1AuthenticationAPIGroupDSL>()
    private val tokenReviews = mock<InOutCreateable<TokenReview, TokenReview>>()
    private val authorizationApi = mock<AuthorizationAPIGroupDSL>()
    private val authorizationV1 = mock<V1AuthorizationAPIGroupDSL>()
    private val subjectAccessReviews =
        mock<InOutCreateable<SubjectAccessReview, SubjectAccessReview>>()
    private var nowNanos = 0L
    private val cache =
        RuntimeReviewCache(
            positiveTtl = Duration.ofSeconds(60),
            maximumEntries = 32,
            ticker = { nowNanos },
        )
    private val client = Fabric8KubernetesWorkloadAccessClient(kubernetesClient, cache)

    init {
        whenever(kubernetesClient.authentication()).thenReturn(authenticationApi)
        whenever(authenticationApi.v1()).thenReturn(authenticationV1)
        whenever(authenticationV1.tokenReviews()).thenReturn(tokenReviews)
        whenever(kubernetesClient.authorization()).thenReturn(authorizationApi)
        whenever(authorizationApi.v1()).thenReturn(authorizationV1)
        whenever(authorizationV1.subjectAccessReview()).thenReturn(subjectAccessReviews)
    }

    @Test
    fun tokenReviewUsesOnlyRequiredAudienceAndParsesServiceAccountIdentity() {
        whenever(tokenReviews.create(any<TokenReview>())).thenReturn(authenticatedReview())

        val identity = client.authenticate("runtime-token", RUNTIME_AUDIENCE)

        val review = argumentCaptor<TokenReview>()
        verify(tokenReviews).create(review.capture())
        assertEquals("runtime-token", review.firstValue.spec.token)
        assertEquals(listOf(RUNTIME_AUDIENCE), review.firstValue.spec.audiences)
        assertEquals("system:serviceaccount:runtime:workload-a", identity.username)
        assertEquals("runtime", identity.namespace)
        assertEquals("workload-a", identity.serviceAccount)
        assertEquals(
            setOf("system:serviceaccounts", "system:serviceaccounts:runtime"),
            identity.groups,
        )
    }

    @Test
    fun rejectsTokenReviewWithoutExactReturnedAudience() {
        whenever(tokenReviews.create(any<TokenReview>()))
            .thenReturn(authenticatedReview(audiences = listOf("another-service")))

        assertThrows(RuntimeInvalidWorkloadCredentialException::class.java) {
            client.authenticate("runtime-token", RUNTIME_AUDIENCE)
        }
    }

    @Test
    fun rejectsAnyRequestedAudienceOtherThanServicePermissionsBeforeReview() {
        whenever(tokenReviews.create(any<TokenReview>()))
            .thenReturn(authenticatedReview(audiences = listOf("another-service")))

        assertThrows(RuntimeInvalidWorkloadCredentialException::class.java) {
            client.authenticate("runtime-token", "another-service")
        }
        verify(tokenReviews, never()).create(any<TokenReview>())
    }

    @Test
    fun rejectsMalformedServiceAccountUsernameReturnedByTokenReview() {
        whenever(tokenReviews.create(any<TokenReview>()))
            .thenReturn(authenticatedReview(username = "workload-a"))

        assertThrows(RuntimeInvalidWorkloadCredentialException::class.java) {
            client.authenticate("runtime-token", RUNTIME_AUDIENCE)
        }
    }

    @Test
    fun tokenReviewReportedErrorFailsClosedAsSafeServiceUnavailable() {
        val upstreamError = "sensitive review backend diagnostic"
        whenever(tokenReviews.create(any<TokenReview>()))
            .thenReturn(authenticatedReview(error = upstreamError))
        val authorizer = DefaultRuntimeAccessAuthorizer(client)

        val failure =
            assertThrows(RuntimeAccessUnavailableException::class.java) {
                authorizer.requireAccess("Bearer runtime-token", "GET", RUNTIME_PATH)
            }

        assertEquals(503, failure.statusCode)
        assertFalse(failure.message.orEmpty().contains(upstreamError))
        verify(subjectAccessReviews, never()).create(any<SubjectAccessReview>())
    }

    @Test
    fun subjectAccessReviewUsesReviewedIdentityLowercaseVerbAndExactPath() {
        whenever(subjectAccessReviews.create(any<SubjectAccessReview>()))
            .thenReturn(
                SubjectAccessReviewBuilder().withNewStatus().withAllowed(true).endStatus().build()
            )
        val identity = workloadIdentity()

        val allowed = client.isAllowed(identity, "PATCH", RUNTIME_PATH)

        assertTrue(allowed)
        val review = argumentCaptor<SubjectAccessReview>()
        verify(subjectAccessReviews).create(review.capture())
        assertEquals(identity.username, review.firstValue.spec.user)
        assertEquals(identity.groups.toList(), review.firstValue.spec.groups)
        assertEquals("patch", review.firstValue.spec.nonResourceAttributes.verb)
        assertEquals(RUNTIME_PATH, review.firstValue.spec.nonResourceAttributes.path)
        assertEquals(null, review.firstValue.spec.resourceAttributes)
    }

    @Test
    fun subjectAccessReviewEvaluationErrorFailsClosedAsUnavailable() {
        whenever(subjectAccessReviews.create(any<SubjectAccessReview>()))
            .thenReturn(
                SubjectAccessReviewBuilder()
                    .withNewStatus()
                    .withAllowed(false)
                    .withEvaluationError("authorizer unavailable")
                    .endStatus()
                    .build()
            )

        assertThrows(RuntimeWorkloadReviewUnavailableException::class.java) {
            client.isAllowed(workloadIdentity(), "get", RUNTIME_PATH)
        }
    }

    @Test
    fun subjectAccessReviewWithoutAllowedFailsClosedAsSafeServiceUnavailable() {
        whenever(tokenReviews.create(any<TokenReview>())).thenReturn(authenticatedReview())
        whenever(subjectAccessReviews.create(any<SubjectAccessReview>()))
            .thenReturn(SubjectAccessReviewBuilder().withNewStatus().endStatus().build())
        val authorizer = DefaultRuntimeAccessAuthorizer(client)

        val failure =
            assertThrows(RuntimeAccessUnavailableException::class.java) {
                authorizer.requireAccess("Bearer runtime-token", "GET", RUNTIME_PATH)
            }

        assertEquals(503, failure.statusCode)
    }

    @Test
    fun cachesPositiveTokenAndAccessReviewsWithoutCachingDenials() {
        whenever(tokenReviews.create(any<TokenReview>())).thenReturn(authenticatedReview())
        whenever(subjectAccessReviews.create(any<SubjectAccessReview>()))
            .thenReturn(
                SubjectAccessReviewBuilder().withNewStatus().withAllowed(true).endStatus().build(),
                SubjectAccessReviewBuilder().withNewStatus().withAllowed(false).endStatus().build(),
                SubjectAccessReviewBuilder().withNewStatus().withAllowed(false).endStatus().build(),
            )

        val token = projectedToken(Instant.now().plusSeconds(3_600))
        val firstIdentity = client.authenticate(token, RUNTIME_AUDIENCE)
        val secondIdentity = client.authenticate(token, RUNTIME_AUDIENCE)
        assertEquals(firstIdentity, secondIdentity)
        assertTrue(client.isAllowed(firstIdentity, "get", RUNTIME_PATH))
        assertTrue(client.isAllowed(firstIdentity, "get", RUNTIME_PATH))
        assertFalse(client.isAllowed(firstIdentity, "post", RUNTIME_PATH))
        assertFalse(client.isAllowed(firstIdentity, "post", RUNTIME_PATH))

        verify(tokenReviews, times(1)).create(any<TokenReview>())
        verify(subjectAccessReviews, times(3)).create(any<SubjectAccessReview>())
    }

    @Test
    fun positiveReviewCacheExpiresAtConfiguredTtl() {
        whenever(tokenReviews.create(any<TokenReview>())).thenReturn(authenticatedReview())
        val token = projectedToken(Instant.now().plusSeconds(3_600))

        client.authenticate(token, RUNTIME_AUDIENCE)
        nowNanos = Duration.ofSeconds(61).toNanos()
        client.authenticate(token, RUNTIME_AUDIENCE)

        verify(tokenReviews, times(2)).create(any<TokenReview>())
    }

    @Test
    fun tokenReviewCacheExpiresAtJwtExpiryBeforeConfiguredTtl() {
        whenever(tokenReviews.create(any<TokenReview>())).thenReturn(authenticatedReview())
        val token = projectedToken(Instant.now().plusSeconds(10))

        client.authenticate(token, RUNTIME_AUDIENCE)
        nowNanos = Duration.ofSeconds(5).toNanos()
        client.authenticate(token, RUNTIME_AUDIENCE)
        verify(tokenReviews, times(1)).create(any<TokenReview>())

        nowNanos = Duration.ofSeconds(11).toNanos()
        client.authenticate(token, RUNTIME_AUDIENCE)
        verify(tokenReviews, times(2)).create(any<TokenReview>())
    }

    @Test
    fun authenticatedExpiredJwtIsNeverCached() {
        whenever(tokenReviews.create(any<TokenReview>())).thenReturn(authenticatedReview())
        val token = projectedToken(Instant.now().minusSeconds(1))

        client.authenticate(token, RUNTIME_AUDIENCE)
        client.authenticate(token, RUNTIME_AUDIENCE)

        verify(tokenReviews, times(2)).create(any<TokenReview>())
    }

    @Test
    fun authenticatedJwtWithoutUsableExpiryIsNeverCached() {
        whenever(tokenReviews.create(any<TokenReview>())).thenReturn(authenticatedReview())

        listOf(projectedTokenPayload("{}"), projectedTokenPayload("{\"exp\":\"invalid\"}"))
            .forEach { token ->
                client.authenticate(token, RUNTIME_AUDIENCE)
                client.authenticate(token, RUNTIME_AUDIENCE)
            }

        verify(tokenReviews, times(4)).create(any<TokenReview>())
    }

    private fun authenticatedReview(
        audiences: List<String> = listOf(RUNTIME_AUDIENCE),
        username: String = "system:serviceaccount:runtime:workload-a",
        error: String? = null,
    ): TokenReview =
        TokenReviewBuilder()
            .withNewStatus()
            .withAuthenticated(true)
            .withAudiences(audiences)
            .withError(error)
            .withNewUser()
            .withUsername(username)
            .withGroups("system:serviceaccounts", "system:serviceaccounts:runtime")
            .endUser()
            .endStatus()
            .build()

    private fun workloadIdentity() =
        RuntimeWorkloadIdentity(
            username = "system:serviceaccount:runtime:workload-a",
            namespace = "runtime",
            serviceAccount = "workload-a",
            groups = setOf("system:serviceaccounts", "system:serviceaccounts:runtime"),
        )

    private fun projectedToken(expiresAt: Instant): String =
        projectedTokenPayload("{\"exp\":${expiresAt.epochSecond}}")

    private fun projectedTokenPayload(payload: String): String {
        val encoder = Base64.getUrlEncoder().withoutPadding()
        return "${encoder.encodeToString("{}".toByteArray(UTF_8))}." +
            "${encoder.encodeToString(payload.toByteArray(UTF_8))}.signature"
    }

    private companion object {
        const val RUNTIME_AUDIENCE = "service-permissions"
        const val RUNTIME_PATH = "/v1/permissions/runtime/manifests"
    }
}

class RuntimeReviewCacheTest {
    private var nowNanos = 0L
    private val cache =
        RuntimeReviewCache(
            positiveTtl = Duration.ofSeconds(60),
            maximumEntries = 2,
            ticker = { nowNanos },
        )

    @Test
    fun positiveAccessCacheStaysBoundedAndEvictsBeforeInsertion() {
        val identity = workloadIdentity(setOf("group-a"))

        cache.cacheAllowed(identity, "get", "/first")
        cache.cacheAllowed(identity, "get", "/second")
        cache.cacheAllowed(identity, "get", "/third")

        assertEquals(
            1,
            listOf("/first", "/second").count { cache.allowed(identity, "get", it) == true },
        )
        assertEquals(true, cache.allowed(identity, "get", "/third"))
    }

    @Test
    fun accessCacheSeparatesSameUsernameWithDifferentReviewedGroups() {
        val firstIdentity = workloadIdentity(setOf("group-a"))
        val secondIdentity = workloadIdentity(setOf("group-b"))

        cache.cacheAllowed(firstIdentity, "get", "/v1/permissions/runtime/players/*")

        assertEquals(true, cache.allowed(firstIdentity, "get", "/v1/permissions/runtime/players/*"))
        assertNull(cache.allowed(secondIdentity, "get", "/v1/permissions/runtime/players/*"))
    }

    @Test
    fun accessCacheSeparatesVerbAndExactPath() {
        val identity = workloadIdentity(setOf("group-a"))

        cache.cacheAllowed(identity, "get", "/v1/permissions/runtime/players/one/snapshot")

        assertEquals(
            true,
            cache.allowed(identity, "get", "/v1/permissions/runtime/players/one/snapshot"),
        )
        assertNull(cache.allowed(identity, "put", "/v1/permissions/runtime/players/one/snapshot"))
        assertNull(cache.allowed(identity, "get", "/v1/permissions/runtime/players/two/snapshot"))
    }

    private fun workloadIdentity(groups: Set<String>) =
        RuntimeWorkloadIdentity(
            username = "system:serviceaccount:runtime:workload-a",
            namespace = "runtime",
            serviceAccount = "workload-a",
            groups = groups,
        )
}
