package gg.grounds.permissions.rest

import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.security.TestSecurity
import io.restassured.RestAssured.given
import jakarta.inject.Inject
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID
import javax.sql.DataSource
import org.hamcrest.Matchers.contains
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.hasSize
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
class PermissionAuditResourceTest {

    @Inject lateinit var repository: PermissionRepository

    @Inject lateinit var dataSource: DataSource

    @BeforeEach
    fun resetDatabase() {
        repository.deleteAllPermissionData()
    }

    @Test
    @TestSecurity(user = "admin-user", roles = ["MINECRAFT_PERMISSIONS_MANAGE"])
    fun auditListsEmptyPage() {
        given()
            .get("/v1/permissions/audit")
            .then()
            .statusCode(200)
            .body("items", hasSize<Any>(0))
            .body("page", equalTo(1))
            .body("perPage", equalTo(25))
            .body("total", equalTo(0))
    }

    @Test
    @TestSecurity(user = "admin-user", roles = ["MINECRAFT_PERMISSIONS_MANAGE"])
    fun auditListsNewestEventsWithActorAndMetadata() {
        insertAuditEvent(
            id = UUID.fromString("00000000-0000-0000-0000-000000000001"),
            actorUserId = "admin-user",
            action = "role.created",
            target = "role:moderator",
            metadata = """{"roleKey":"moderator"}""",
            createdAt = Instant.parse("2030-01-02T00:00:00Z"),
        )

        given()
            .queryParam("action", "role.created")
            .queryParam("page", 1)
            .queryParam("perPage", 25)
            .get("/v1/permissions/audit")
            .then()
            .statusCode(200)
            .body("items", hasSize<Any>(1))
            .body("items[0].actorUserId", equalTo("admin-user"))
            .body("items[0].action", equalTo("role.created"))
            .body("items[0].target", equalTo("role:moderator"))
            .body("items[0].metadata.roleKey", equalTo("moderator"))
            .body("page", equalTo(1))
            .body("perPage", equalTo(25))
            .body("total", equalTo(1))
    }

    @Test
    @TestSecurity(user = "admin-user", roles = ["MINECRAFT_PERMISSIONS_MANAGE"])
    fun auditFiltersByActionQueryAndTimeRange() {
        insertAuditEvent(
            id = UUID.fromString("00000000-0000-0000-0000-000000000010"),
            actorUserId = "admin-user",
            action = "role.created",
            target = "role:moderator",
            metadata = "{}",
            createdAt = Instant.parse("2030-01-02T00:00:00Z"),
        )
        insertAuditEvent(
            id = UUID.fromString("00000000-0000-0000-0000-000000000011"),
            actorUserId = "editor-user",
            action = "role.updated",
            target = "role:moderator",
            metadata = "{}",
            createdAt = Instant.parse("2030-01-03T00:00:00Z"),
        )
        insertAuditEvent(
            id = UUID.fromString("00000000-0000-0000-0000-000000000012"),
            actorUserId = "admin-user",
            action = "role.created",
            target = "role:builder",
            metadata = "{}",
            createdAt = Instant.parse("2030-01-04T00:00:00Z"),
        )

        given()
            .queryParam("action", "role.created")
            .queryParam("q", "MODERATOR")
            .queryParam("from", "2030-01-02T00:00:00Z")
            .queryParam("to", "2030-01-03T00:00:00Z")
            .get("/v1/permissions/audit")
            .then()
            .statusCode(200)
            .body("items", hasSize<Any>(1))
            .body("items[0].id", equalTo("00000000-0000-0000-0000-000000000010"))
            .body("total", equalTo(1))
    }

    @Test
    @TestSecurity(user = "admin-user", roles = ["MINECRAFT_PERMISSIONS_MANAGE"])
    fun auditPaginatesWithStableUuidTieBreaker() {
        val createdAt = Instant.parse("2030-01-02T00:00:00Z")
        insertAuditEvent(
            id = UUID.fromString("00000000-0000-0000-0000-000000000001"),
            actorUserId = "admin-user",
            action = "role.created",
            target = "role:first",
            metadata = "{}",
            createdAt = createdAt,
        )
        insertAuditEvent(
            id = UUID.fromString("00000000-0000-0000-0000-000000000002"),
            actorUserId = "admin-user",
            action = "role.created",
            target = "role:second",
            metadata = "{}",
            createdAt = createdAt,
        )

        given()
            .queryParam("page", 1)
            .queryParam("perPage", 1)
            .get("/v1/permissions/audit")
            .then()
            .statusCode(200)
            .body("items.id", contains("00000000-0000-0000-0000-000000000002"))
            .body("page", equalTo(1))
            .body("perPage", equalTo(1))
            .body("total", equalTo(2))

        given()
            .queryParam("page", 2)
            .queryParam("perPage", 1)
            .get("/v1/permissions/audit")
            .then()
            .statusCode(200)
            .body("items.id", contains("00000000-0000-0000-0000-000000000001"))
            .body("total", equalTo(2))
    }

    @Test
    @TestSecurity(user = "admin-user", roles = ["MINECRAFT_PERMISSIONS_MANAGE"])
    fun auditRejectsInvalidPerPage() {
        given().queryParam("perPage", 101).get("/v1/permissions/audit").then().statusCode(400)
    }

    @Test
    @TestSecurity(user = "admin-user", roles = ["MINECRAFT_PERMISSIONS_MANAGE"])
    fun auditRejectsInvalidPageAndTimeRange() {
        given().queryParam("page", 0).get("/v1/permissions/audit").then().statusCode(400)

        given()
            .queryParam("from", "2030-01-03T00:00:00Z")
            .queryParam("to", "2030-01-02T00:00:00Z")
            .get("/v1/permissions/audit")
            .then()
            .statusCode(400)
    }

    @Test
    fun auditRejectsUnauthenticatedReads() {
        given().auth().none().get("/v1/permissions/audit").then().statusCode(401)
    }

    @Test
    @TestSecurity(user = "reader-user", roles = ["MINECRAFT_PERMISSIONS_READ"])
    fun auditRejectsAuthenticatedUsersWithoutPermissionManagementAccess() {
        given().get("/v1/permissions/audit").then().statusCode(403)
    }

    private fun insertAuditEvent(
        id: UUID,
        actorUserId: String?,
        action: String,
        target: String,
        metadata: String,
        createdAt: Instant,
    ) {
        dataSource.connection.use { connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_audit_events (
                        id, actor_user_id, action, target, metadata, created_at
                    )
                    VALUES (?, ?, ?, ?, ?::jsonb, ?)
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setObject(1, id)
                    statement.setString(2, actorUserId)
                    statement.setString(3, action)
                    statement.setString(4, target)
                    statement.setString(5, metadata)
                    statement.setTimestamp(6, Timestamp.from(createdAt))
                    statement.executeUpdate()
                }
        }
    }
}
