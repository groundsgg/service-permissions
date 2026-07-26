package gg.grounds.permissions.rest

import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import io.quarkus.security.Authenticated
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.junit.TestProfile
import io.quarkus.test.security.TestSecurity
import io.restassured.RestAssured.given
import io.restassured.http.ContentType
import io.restassured.response.Response
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import org.eclipse.microprofile.openapi.annotations.Operation
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.matchesPattern
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
@TestProfile(PermissionRestResourceTestProfile::class)
@TestSecurity(
    user = "admin-user",
    roles = ["GAME_AREA_ACCESS", "MINECRAFT_PERMISSIONS_STAGE_MANAGE"],
)
class ProblemDetailsTest {
    @Test
    fun `invalid request uses RFC 9457`() {
        given()
            .header("X-Request-ID", "request-123")
            .contentType(ContentType.JSON)
            .body("""{"name":"!!!"}""")
            .post("/v1/permissions/roles")
            .then()
            .statusCode(400)
            .contentType("application/problem+json")
            .body("type", equalTo("about:blank"))
            .body("title", equalTo("Bad Request"))
            .body("status", equalTo(400))
            .body("detail", equalTo("The role name is invalid."))
            .body("instance", equalTo("/v1/permissions/roles"))
            .body("requestId", equalTo("request-123"))
            .body("error", equalTo("role_name_invalid"))
    }

    @Test
    fun `unknown REST route uses RFC 9457`() {
        val response =
            given()
                .header("X-Request-ID", "not-found-request-123")
                .get("/v1/permissions/not-a-route")

        assertProblem(
            response,
            status = 404,
            title = "Not Found",
            detail = "The requested resource was not found.",
            instance = "/v1/permissions/not-a-route",
            requestId = "not-found-request-123",
            error = "not_found",
        )
    }

    @Test
    fun `unsupported REST method uses RFC 9457`() {
        val response =
            given().header("X-Request-ID", "method-request-123").post("/v1/permissions/audit")

        assertProblem(
            response,
            status = 405,
            title = "Method Not Allowed",
            detail = "The HTTP method is not supported for this resource.",
            instance = "/v1/permissions/audit",
            requestId = "method-request-123",
            error = "method_not_allowed",
        )
    }

    @Test
    fun `unsupported REST media type uses RFC 9457`() {
        val response =
            given()
                .header("X-Request-ID", "media-type-request-123")
                .contentType(ContentType.TEXT)
                .body("secret-like-request-body")
                .post("/v1/permissions/roles")

        assertProblem(
            response,
            status = 415,
            title = "Unsupported Media Type",
            detail = "The request media type is not supported.",
            instance = "/v1/permissions/roles",
            requestId = "media-type-request-123",
            error = "unsupported_media_type",
        )
        assertFalse(response.asString().contains("secret-like-request-body"))
    }

    @Test
    fun `unexpected REST failure uses safe RFC 9457`() {
        val response =
            given()
                .header("X-Request-ID", "failure-request-123")
                .get("/v1/permissions/problem-probe/unexpected")

        assertProblem(
            response,
            status = 500,
            title = "Internal Server Error",
            detail = "The request failed because of an internal service error.",
            instance = "/v1/permissions/problem-probe/unexpected",
            requestId = "failure-request-123",
            error = "internal_server_error",
        )
        assertFalse(response.asString().contains("secret-like-exception-message"))
    }

    @Test
    fun `blank request ID is replaced with a generated UUID`() {
        given()
            .header("X-Request-ID", " ")
            .contentType(ContentType.JSON)
            .body("""{"name":"!!!"}""")
            .post("/v1/permissions/roles")
            .then()
            .statusCode(400)
            .contentType("application/problem+json")
            .body(
                "requestId",
                matchesPattern("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
            )
    }

    @Test
    fun `invalid audit timestamp omits secret query values from problem response`() {
        val secret = "secret-like-token-123"
        val response =
            given()
                .queryParam("to", secret)
                .get("/v1/permissions/audit")
                .then()
                .statusCode(400)
                .contentType("application/problem+json")
                .extract()
                .response()

        assertFalse(response.asString().contains(secret))
        assertEquals("invalid_request", response.jsonPath().getString("error"))
        assertEquals("The request is invalid.", response.jsonPath().getString("detail"))
        assertEquals("/v1/permissions/audit", response.jsonPath().getString("instance"))
    }

    @Test
    fun `invalid encoded path uses a valid query-free problem instance`() {
        given()
            .urlEncodingEnabled(false)
            .get("/v1/permissions/roles/bad%20key")
            .then()
            .statusCode(400)
            .contentType("application/problem+json")
            .body("instance", equalTo("/v1/permissions/roles/bad%20key"))
    }

    private fun assertProblem(
        response: Response,
        status: Int,
        title: String,
        detail: String,
        instance: String,
        requestId: String,
        error: String,
    ) {
        response
            .then()
            .statusCode(status)
            .contentType("application/problem+json")
            .body("type", equalTo("about:blank"))
            .body("title", equalTo(title))
            .body("status", equalTo(status))
            .body("detail", equalTo(detail))
            .body("instance", equalTo(instance))
            .body("requestId", equalTo(requestId))
            .body("error", equalTo(error))
    }
}

@Path("/v1/permissions/problem-probe")
@Authenticated
class ProblemDetailsProbeResource {
    @GET
    @Path("/unexpected")
    @Operation(hidden = true)
    fun unexpected(): Nothing = throw RuntimeException("secret-like-exception-message")
}
