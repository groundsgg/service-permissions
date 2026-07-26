package gg.grounds.permissions.rest.runtime

import gg.grounds.permissions.auth.RuntimeAccessAuthorizer
import gg.grounds.permissions.auth.RuntimeAccessUnavailableException
import gg.grounds.permissions.auth.RuntimeAuthorizationException
import gg.grounds.permissions.auth.RuntimeWorkloadIdentity
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import io.micrometer.core.instrument.MeterRegistry
import io.quarkus.test.InjectMock
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.junit.QuarkusTestProfile
import io.quarkus.test.junit.TestProfile
import io.restassured.RestAssured.given
import java.util.UUID
import org.hamcrest.Matchers.empty
import org.hamcrest.Matchers.equalTo
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.whenever

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
@TestProfile(PermissionRuntimeResourceTestProfile::class)
class PermissionRuntimeResourceTest {
    @InjectMock lateinit var authorizer: RuntimeAccessAuthorizer
    @jakarta.inject.Inject lateinit var repository: PermissionRepository
    @jakarta.inject.Inject lateinit var meterRegistry: MeterRegistry

    @BeforeEach
    fun resetRuntimeState() {
        repository.deleteAllPermissionData()
        whenever(authorizer.requireAccess(anyOrNull(), any(), any())).thenAnswer { invocation ->
            when (invocation.getArgument<String?>(0)) {
                null -> throw gg.grounds.permissions.auth.RuntimeAuthenticationException()
                "Bearer denied-runtime-token" -> throw RuntimeAuthorizationException()
                "Bearer unavailable-runtime-token" -> throw RuntimeAccessUnavailableException()
                else ->
                    if (invocation.getArgument<String>(2) == FORBIDDEN_MANIFEST_PATH) {
                        throw RuntimeAuthorizationException()
                    } else {
                        WORKLOAD
                    }
            }
        }
    }

    @Test
    fun `returns an empty runtime snapshot for a valid player without assignments`() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000101")

        given()
            .header("Authorization", "Bearer runtime-token")
            .queryParam("serverType", " velocity ")
            .queryParam("serverId", " velocity-1 ")
            .get("$SNAPSHOT_PATH_TEMPLATE/$playerId/snapshot")
            .then()
            .statusCode(200)
            .body("playerId", equalTo(playerId.toString()))
            .body("policyVersion", equalTo(1))
            .body("issuedAt", org.hamcrest.Matchers.notNullValue())
            .body("refreshAfter", org.hamcrest.Matchers.notNullValue())
            .body("expiresAt", org.hamcrest.Matchers.notNullValue())
            .body("allowPatterns", empty<Any>())
            .body("denyPatterns", empty<Any>())
            .body("roleKeys", empty<Any>())
            .body("roleMetadata", empty<Any>())
    }

    @Test
    fun `rejects an invalid runtime snapshot player id with a problem response`() {
        given()
            .header("Authorization", "Bearer runtime-token")
            .get("$SNAPSHOT_PATH_TEMPLATE/not-a-uuid/snapshot")
            .then()
            .statusCode(400)
            .contentType("application/problem+json")
            .body("requestId", org.hamcrest.Matchers.notNullValue())
    }

    @Test
    fun `rejects blank runtime context parameters`() {
        given()
            .header("Authorization", "Bearer runtime-token")
            .queryParam("serverType", "   ")
            .get("$SNAPSHOT_PATH_TEMPLATE/${UUID.randomUUID()}/snapshot")
            .then()
            .statusCode(400)
            .contentType("application/problem+json")
    }

    @Test
    fun `requires a runtime workload token for snapshots`() {
        given()
            .get("$SNAPSHOT_PATH_TEMPLATE/${UUID.randomUUID()}/snapshot")
            .then()
            .statusCode(401)
            .contentType("application/problem+json")
    }

    @Test
    fun `returns forbidden when the runtime workload is denied snapshot access`() {
        given()
            .header("Authorization", "Bearer denied-runtime-token")
            .get("$SNAPSHOT_PATH_TEMPLATE/${UUID.randomUUID()}/snapshot")
            .then()
            .statusCode(403)
            .contentType("application/problem+json")
    }

    @Test
    fun `returns unavailable when runtime authorization dependencies fail`() {
        given()
            .header("Authorization", "Bearer unavailable-runtime-token")
            .get("$SNAPSHOT_PATH_TEMPLATE/${UUID.randomUUID()}/snapshot")
            .then()
            .statusCode(503)
            .contentType("application/problem+json")
    }

    @Test
    fun `replaces a runtime manifest for the authorized source`() {
        val requestCountBefore = runtimeRequestCount("success")
        val manifestCountBefore = manifestCount("success")

        given()
            .header("Authorization", "Bearer runtime-token")
            .contentType("application/json")
            .body(VALID_MANIFEST)
            .put(MANIFEST_PATH)
            .then()
            .statusCode(204)

        assertEquals(requestCountBefore + 1, runtimeRequestCount("success"))
        assertEquals(manifestCountBefore + 1, manifestCount("success"))
    }

    @Test
    fun `rejects duplicate permission keys before replacing a runtime manifest`() {
        given()
            .header("Authorization", "Bearer runtime-token")
            .contentType("application/json")
            .body(DUPLICATE_KEYS_MANIFEST)
            .put(MANIFEST_PATH)
            .then()
            .statusCode(400)
            .contentType("application/problem+json")
    }

    @Test
    fun `rejects a workload that cannot replace the requested manifest source`() {
        given()
            .header("Authorization", "Bearer runtime-token")
            .contentType("application/json")
            .body(VALID_MANIFEST)
            .put(FORBIDDEN_MANIFEST_PATH)
            .then()
            .statusCode(403)
            .contentType("application/problem+json")
    }

    @Test
    fun `rejects a manifest source duplicated in the request body`() {
        val requestCountBefore = runtimeRequestCount("invalid")
        val manifestCountBefore = manifestCount("failure")

        given()
            .header("Authorization", "Bearer runtime-token")
            .contentType("application/json")
            .body("""{"source":"plugin-chat",${VALID_MANIFEST.removePrefix("{")}""")
            .put(MANIFEST_PATH)
            .then()
            .statusCode(400)
            .contentType("application/problem+json")

        assertEquals(requestCountBefore + 1, runtimeRequestCount("invalid"))
        assertEquals(manifestCountBefore + 1, manifestCount("failure"))
    }

    @Test
    fun `returns a safe problem response for a malformed manifest binding failure`() {
        val requestCountBefore = runtimeRequestCount("invalid")
        val manifestCountBefore = manifestCount("failure")
        val requestId = "runtime-binding-request-123"
        val malformedManifest = """{"sourceVersion":"secret-like-token","""

        val response =
            given()
                .header("Authorization", "Bearer runtime-token")
                .header("X-Request-ID", requestId)
                .contentType("application/json")
                .body(malformedManifest)
                .put(MANIFEST_PATH)
                .then()
                .statusCode(400)
                .contentType("application/problem+json")
                .body("type", equalTo("about:blank"))
                .body("title", equalTo("Bad Request"))
                .body("status", equalTo(400))
                .body("detail", equalTo("The request is invalid."))
                .body("instance", equalTo(MANIFEST_PATH))
                .body("requestId", equalTo(requestId))
                .body("error", equalTo("invalid_request"))
                .extract()
                .response()

        assertFalse(response.asString().contains("secret-like-token"))
        assertFalse(response.asString().contains("runtime-token"))
        assertEquals(requestCountBefore + 1, runtimeRequestCount("invalid"))
        assertEquals(manifestCountBefore + 1, manifestCount("failure"))
    }

    private fun runtimeRequestCount(status: String): Double =
        meterRegistry
            .find("permissions.runtime.request.count")
            .tags("operation", "manifest", "status", status)
            .counter()
            ?.count() ?: 0.0

    private fun manifestCount(outcome: String): Double =
        meterRegistry
            .find("permissions.runtime.manifest")
            .tag("outcome", outcome)
            .counter()
            ?.count() ?: 0.0

    private companion object {
        const val SNAPSHOT_PATH_TEMPLATE = "/v1/permissions/runtime/players"
        const val SNAPSHOT_PATH =
            "$SNAPSHOT_PATH_TEMPLATE/00000000-0000-0000-0000-000000000101/snapshot"
        const val MANIFEST_PATH = "/v1/permissions/runtime/catalog/manifests/plugin-chat"
        const val FORBIDDEN_MANIFEST_PATH = "/v1/permissions/runtime/catalog/manifests/forbidden"
        val WORKLOAD =
            RuntimeWorkloadIdentity(
                username = "system:serviceaccount:runtime:plugin-chat",
                namespace = "runtime",
                serviceAccount = "plugin-chat",
                groups = setOf("system:serviceaccounts", "system:serviceaccounts:runtime"),
            )
        const val VALID_MANIFEST =
            """{"sourceVersion":"1.4.0","serverType":"velocity","serverId":"velocity-1","permissions":[{"key":"grounds.chat.staff","label":"Staff chat","description":"Allows access to staff chat.","supportedScopes":["GLOBAL","SERVER_TYPE","SERVER"]}]}"""
        const val DUPLICATE_KEYS_MANIFEST =
            """{"sourceVersion":"1.4.0","permissions":[{"key":"grounds.chat.staff","label":"Staff chat","description":"Allows access to staff chat.","supportedScopes":["GLOBAL"]},{"key":"grounds.chat.staff","label":"Staff chat again","description":"Duplicate.","supportedScopes":["GLOBAL"]}]}"""
    }
}

class PermissionRuntimeResourceTestProfile : QuarkusTestProfile {
    override fun getConfigOverrides(): Map<String, String> =
        mapOf(
            "permissions.identity-sync.enabled" to "false",
            "permissions.identity-events.enabled" to "false",
            "permissions.instance-environment" to "stage",
        )
}
