package gg.grounds.permissions.auth

import io.quarkus.security.Authenticated
import io.quarkus.security.identity.SecurityIdentity
import io.quarkus.test.InjectMock
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.junit.QuarkusTestProfile
import io.quarkus.test.junit.TestProfile
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism
import io.restassured.RestAssured.given
import io.vertx.core.http.HttpHeaders
import io.vertx.core.http.HttpMethod
import io.vertx.core.http.HttpServerRequest
import io.vertx.ext.web.RoutingContext
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import org.eclipse.microprofile.openapi.annotations.Operation
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class RuntimeBearerAuthenticationTest {
    private val authorizer = mock<RuntimeAccessAuthorizer>()
    private val mechanism = RuntimeBearerAuthenticationMechanism(authorizer)

    @Test
    fun ignoresCredentialsOutsideRuntimePaths() {
        val context = routingContext("/v1/permissions/roles", "Bearer runtime-token")

        val identity = mechanism.authenticate(context, mock()).await().indefinitely()

        assertNull(identity)
        verify(authorizer, never())
            .requireAccess("Bearer runtime-token", "GET", "/v1/permissions/roles")
    }

    @Test
    fun createsSecurityIdentityFromReviewedServiceAccount() {
        val path = "/v1/permissions/runtime/manifests"
        val reviewed =
            RuntimeWorkloadIdentity(
                username = "system:serviceaccount:runtime:workload-a",
                namespace = "runtime",
                serviceAccount = "workload-a",
                groups = setOf("system:serviceaccounts"),
            )
        whenever(authorizer.requireAccess("Bearer runtime-token", "POST", path))
            .thenReturn(reviewed)

        val identity =
            mechanism
                .authenticate(routingContext(path, "Bearer runtime-token", HttpMethod.POST), mock())
                .await()
                .indefinitely()

        assertEquals(reviewed.username, identity.principal.name)
        assertTrue(identity.roles.isEmpty())
    }

    @Test
    fun runsBeforeSmallRyeJwtSoRuntimeBearerTokensCannotCrossMechanisms() {
        assertTrue(mechanism.priority > HttpAuthenticationMechanism.DEFAULT_PRIORITY)
    }

    private fun routingContext(
        path: String,
        authorization: String?,
        method: HttpMethod = HttpMethod.GET,
    ): RoutingContext {
        val request = mock<HttpServerRequest>()
        whenever(request.path()).thenReturn(path)
        whenever(request.method()).thenReturn(method)
        whenever(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authorization)
        return mock { whenever(it.request()).thenReturn(request) }
    }
}

@QuarkusTest
@TestProfile(RuntimeBearerAuthenticationTestProfile::class)
class RuntimeBearerAuthenticationIntegrationTest {
    @InjectMock lateinit var authorizer: RuntimeAccessAuthorizer

    @BeforeEach
    fun configureRuntimeAuthorization() {
        whenever(authorizer.requireAccess("Bearer runtime-token", "GET", PROBE_PATH))
            .thenReturn(
                RuntimeWorkloadIdentity(
                    username = "system:serviceaccount:runtime:workload-a",
                    namespace = "runtime",
                    serviceAccount = "workload-a",
                    groups = setOf("system:serviceaccounts"),
                )
            )
        whenever(authorizer.requireAccess(null, "GET", PROBE_PATH))
            .thenThrow(RuntimeAuthenticationException())
        whenever(authorizer.requireAccess("Bearer portal.jwt.token", "GET", PROBE_PATH))
            .thenThrow(RuntimeAuthenticationException())
        whenever(authorizer.requireAccess("Bearer denied-runtime-token", "GET", PROBE_PATH))
            .thenThrow(RuntimeAuthorizationException())
        whenever(authorizer.requireAccess("Bearer unavailable-runtime-token", "GET", PROBE_PATH))
            .thenThrow(RuntimeAccessUnavailableException())
    }

    @Test
    fun authenticatesRuntimeWorkloadOnRuntimePath() {
        given()
            .header("Authorization", "Bearer runtime-token")
            .get(PROBE_PATH)
            .then()
            .statusCode(200)
            .body(org.hamcrest.Matchers.equalTo("system:serviceaccount:runtime:workload-a"))
    }

    @Test
    fun rejectsPortalJwtOnRuntimePathWithSafeProblem() {
        val response = given().header("Authorization", "Bearer portal.jwt.token").get(PROBE_PATH)

        response.then().statusCode(401).contentType("application/problem+json")
        assertEquals("runtime_authentication_failed", response.jsonPath().getString("error"))
        assertFalse(response.body.asString().contains("portal.jwt.token"))
    }

    @Test
    fun rejectsMissingRuntimeTokenWithSafeProblem() {
        val response = given().get(PROBE_PATH)

        response.then().statusCode(401).contentType("application/problem+json")
        assertEquals("runtime_authentication_failed", response.jsonPath().getString("error"))
    }

    @Test
    fun mapsExplicitKubernetesDenialToSafeForbiddenProblem() {
        val response =
            given().header("Authorization", "Bearer denied-runtime-token").get(PROBE_PATH)

        response.then().statusCode(403).contentType("application/problem+json")
        assertEquals("runtime_access_denied", response.jsonPath().getString("error"))
        assertFalse(response.body.asString().contains("denied-runtime-token"))
    }

    @Test
    fun mapsKubernetesReviewFailureToSafeUnavailableProblem() {
        val response =
            given().header("Authorization", "Bearer unavailable-runtime-token").get(PROBE_PATH)

        response.then().statusCode(503).contentType("application/problem+json")
        assertEquals("runtime_authorization_unavailable", response.jsonPath().getString("error"))
        assertFalse(response.body.asString().contains("unavailable-runtime-token"))
    }

    @Test
    fun rejectsServiceAccountTokenOnAdministrationPath() {
        given()
            .header("Authorization", "Bearer runtime-token")
            .get("/v1/permissions/roles")
            .then()
            .statusCode(401)

        verify(authorizer, never())
            .requireAccess("Bearer runtime-token", "GET", "/v1/permissions/roles")
    }

    private companion object {
        const val PROBE_PATH = "/v1/permissions/runtime/auth-probe"
    }
}

@Path("/v1/permissions/runtime/auth-probe")
@Authenticated
class RuntimeAuthenticationProbeResource(private val securityIdentity: SecurityIdentity) {
    @GET
    @Operation(hidden = true)
    @Produces(MediaType.TEXT_PLAIN)
    fun identity(): String = securityIdentity.principal.name
}

class RuntimeBearerAuthenticationTestProfile : QuarkusTestProfile {
    override fun getConfigOverrides(): Map<String, String> =
        mapOf(
            "quarkus.flyway.migrate-at-start" to "false",
            "quarkus.datasource.devservices.enabled" to "false",
            "permissions.instance-environment" to "stage",
        )
}
