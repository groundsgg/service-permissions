package gg.grounds.permissions.rest

import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.sync.PermissionProjectSnapshot
import io.quarkus.test.InjectMock
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.junit.QuarkusTestProfile
import io.quarkus.test.junit.TestProfile
import io.quarkus.test.security.TestSecurity
import io.restassured.RestAssured.given
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.whenever

@QuarkusTest
@TestProfile(PermissionRestAuthorizationTestProfile::class)
class PermissionRestAuthorizationTest {

    @InjectMock lateinit var repository: PermissionRepository

    @BeforeEach
    fun mockRepository() {
        whenever(repository.listRolesWithAggregateCounts()).thenReturn(emptyList())
        whenever(repository.permissionProjectSnapshot())
            .thenReturn(
                PermissionProjectSnapshot(
                    emptyList(),
                    emptyList(),
                    emptyList(),
                    emptyList(),
                    emptyList(),
                )
            )
    }

    @Test
    fun rejectsAnonymousRoleRequests() {
        given().get("/v1/permissions/roles").then().statusCode(401)
    }

    @Test
    @TestSecurity(user = "user-alpha")
    fun rejectsAuthenticatedUsersWithoutMinecraftPermissionManagementAccess() {
        given().get("/v1/permissions/roles").then().statusCode(403)
    }

    @Test
    @TestSecurity(user = "admin-user", roles = ["MINECRAFT_PERMISSIONS_MANAGE"])
    fun allowsUsersWithMinecraftPermissionManagementAccess() {
        given().get("/v1/permissions/roles").then().statusCode(200)
    }

    @Test
    fun rejectsUnauthorisedSyncPreview() {
        given()
            .contentType("application/json")
            .body(
                """{"snapshotId":"snapshot-1","roles":[],"roleGrants":[],"inheritance":[],"catalogEntries":[]}"""
            )
            .post("/v1/permissions/sync/preview")
            .then()
            .statusCode(401)
    }

    @Test
    @TestSecurity(user = "admin-user", roles = ["MINECRAFT_PERMISSIONS_MANAGE"])
    fun allowsAuthorisedSyncPreview() {
        given()
            .contentType("application/json")
            .body(
                """{"snapshotId":"snapshot-1","roles":[],"roleGrants":[],"inheritance":[],"catalogEntries":[]}"""
            )
            .post("/v1/permissions/sync/preview")
            .then()
            .statusCode(200)
            .body("snapshotId", org.hamcrest.Matchers.equalTo("snapshot-1"))
    }
}

class PermissionRestAuthorizationTestProfile : QuarkusTestProfile {
    override fun getConfigOverrides(): Map<String, String> =
        mapOf(
            "quarkus.flyway.migrate-at-start" to "false",
            "quarkus.datasource.devservices.enabled" to "false",
            "permissions.auth.allow-test-security-principal" to "true",
        )
}
