package gg.grounds.permissions.rest

import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.junit.TestProfile
import io.quarkus.test.security.TestSecurity
import io.restassured.RestAssured.given
import io.restassured.http.ContentType
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
            .body("status", equalTo(400))
            .body("requestId", equalTo("request-123"))
            .body("error", equalTo("role_name_invalid"))
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
}
