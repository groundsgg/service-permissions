package gg.grounds.permissions.rest

import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.security.TestSecurity
import io.restassured.RestAssured.given
import jakarta.inject.Inject
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.hasItem
import org.hamcrest.Matchers.hasSize
import org.hamcrest.Matchers.nullValue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
@TestSecurity(user = "admin-user", roles = ["MINECRAFT_PERMISSIONS_MANAGE"])
class PermissionRestResourceTest {

    @Inject lateinit var repository: PermissionRepository

    @BeforeEach
    fun resetDatabase() {
        repository.deleteAllPermissionData()
    }

    @Test
    fun roleCreationGeneratesKeyAndIgnoresIncomingKey() {
        given()
            .contentType("application/json")
            .body("""{"key":"client-selected","name":"Über Admin"}""")
            .post("/v1/permissions/roles")
            .then()
            .statusCode(201)
            .body("key", equalTo("uber-admin"))
            .body("name", equalTo("Über Admin"))
    }

    @Test
    fun duplicateGeneratedRoleKeyReturnsConflict() {
        createRole("ignored", "Senior Moderator")

        given()
            .contentType("application/json")
            .body("""{"name":"Senior Moderator"}""")
            .post("/v1/permissions/roles")
            .then()
            .statusCode(409)
            .body("error", equalTo("role_key_conflict"))
    }

    @Test
    fun invalidGeneratedRoleKeyReturnsBadRequest() {
        given()
            .contentType("application/json")
            .body("""{"name":"!!!"}""")
            .post("/v1/permissions/roles")
            .then()
            .statusCode(400)
            .body("error", equalTo("role_name_invalid"))
    }

    @Test
    fun renamingRoleKeepsGeneratedKey() {
        createRole("ignored", "Event Staff")

        given()
            .contentType("application/json")
            .body("""{"name":"Tournament Staff"}""")
            .put("/v1/permissions/roles/event-staff")
            .then()
            .statusCode(200)
            .body("key", equalTo("event-staff"))
            .body("name", equalTo("Tournament Staff"))
    }

    @Test
    fun roleInheritanceAndRoleGrantCrud() {
        createRole("default", "Default", default = true)
        createRole("moderator", "Moderator")

        given().put("/v1/permissions/roles/moderator/inherits/default").then().statusCode(204)
        given().put("/v1/permissions/roles/moderator/inherits/default").then().statusCode(204)

        given()
            .contentType("application/json")
            .body(
                """
                {
                  "effect": "ALLOW",
                  "permissionPattern": "grounds.command.moderate",
                  "scopeKind": "SERVER_TYPE",
                  "scopeValue": "paper",
                  "expiresAt": "2030-01-01T00:00:00Z"
                }
                """
                    .trimIndent()
            )
            .post("/v1/permissions/roles/moderator/grants")
            .then()
            .statusCode(201)
            .body("roleKey", equalTo("moderator"))
            .body("permissionPattern", equalTo("grounds.command.moderate"))
            .body("scopeKind", equalTo("SERVER_TYPE"))

        given()
            .get("/v1/permissions/roles")
            .then()
            .statusCode(200)
            .body("key", hasItem("default"))
            .body("key", hasItem("moderator"))

        given()
            .contentType("application/json")
            .body("""{"name":"Moderator","description":"Updated","sortOrder":40}""")
            .put("/v1/permissions/roles/moderator")
            .then()
            .statusCode(200)
            .body("description", equalTo("Updated"))
            .body("sortOrder", equalTo(40))

        given().delete("/v1/permissions/roles/moderator/inherits/default").then().statusCode(204)
    }

    @Test
    fun roleListIncludesAccurateAggregateCountsWithoutOvercounting() {
        createRole("member", "Member")
        createRole("guardian", "Guardian")
        createRole("moderator", "Moderator")
        createRole("observer", "Observer")

        createRoleGrant("moderator", "grounds.command.moderate")
        createRoleGrant("moderator", "grounds.command.warn")
        given().put("/v1/permissions/roles/moderator/inherits/member").then().statusCode(204)
        given().put("/v1/permissions/roles/moderator/inherits/guardian").then().statusCode(204)

        given()
            .get("/v1/permissions/roles")
            .then()
            .statusCode(200)
            .body("find { it.key == 'moderator' }.grantCount", equalTo(2))
            .body("find { it.key == 'moderator' }.inheritanceCount", equalTo(2))
            .body("find { it.key == 'moderator' }.parentRoleKeys", hasItem("guardian"))
            .body("find { it.key == 'moderator' }.parentRoleKeys", hasItem("member"))
            .body("find { it.key == 'observer' }.grantCount", equalTo(0))
            .body("find { it.key == 'observer' }.inheritanceCount", equalTo(0))

        given()
            .get("/v1/permissions/roles/moderator")
            .then()
            .statusCode(200)
            .body("grantCount", nullValue())
            .body("inheritanceCount", nullValue())

        given()
            .contentType("application/json")
            .body("""{"name":"Moderator","description":"Updated"}""")
            .put("/v1/permissions/roles/moderator")
            .then()
            .statusCode(200)
            .body("grantCount", nullValue())
            .body("inheritanceCount", nullValue())
    }

    @Test
    fun catalogCustomPermissionCrud() {
        given()
            .contentType("application/json")
            .body(
                """
                {
                  "key": "grounds.command.fly",
                  "label": "Fly command",
                  "description": "Allows flight",
                  "supportedScopes": ["GLOBAL", "SERVER_TYPE"]
                }
                """
                    .trimIndent()
            )
            .post("/v1/permissions/catalog/custom")
            .then()
            .statusCode(201)
            .body("key", equalTo("grounds.command.fly"))
            .body("custom", equalTo(true))

        given()
            .get("/v1/permissions/catalog")
            .then()
            .statusCode(200)
            .body("", hasSize<Any>(1))
            .body("[0].label", equalTo("Fly command"))

        given().delete("/v1/permissions/catalog/custom/grounds.command.fly").then().statusCode(204)
    }

    @Test
    fun playerGroupAndEffectivePermissionCrud() {
        createRole("default", "Default", default = true)
        createRole("moderator", "Moderator")

        val playerRoleGrantId =
            given()
                .contentType("application/json")
                .body("""{"roleKey":"moderator","expiresAt":"2030-01-01T00:00:00Z"}""")
                .post("/v1/permissions/players/00000000-0000-0000-0000-000000000123/roles")
                .then()
                .statusCode(201)
                .body("roleKey", equalTo("moderator"))
                .extract()
                .path<String>("id")

        given()
            .contentType("application/json")
            .body("""{"roleKey":"default"}""")
            .put(
                "/v1/permissions/players/00000000-0000-0000-0000-000000000123/roles/$playerRoleGrantId"
            )
            .then()
            .statusCode(200)
            .body("roleKey", equalTo("default"))

        given()
            .contentType("application/json")
            .body(
                """
                {
                  "effect": "DENY",
                  "permissionPattern": "grounds.command.op",
                  "scopeKind": "GLOBAL"
                }
                """
                    .trimIndent()
            )
            .post("/v1/permissions/players/00000000-0000-0000-0000-000000000123/grants")
            .then()
            .statusCode(201)
            .body("permissionPattern", equalTo("grounds.command.op"))

        given()
            .contentType("application/json")
            .body("""{"keycloakGroup":"/staff","roleKey":"moderator"}""")
            .post("/v1/permissions/keycloak-groups")
            .then()
            .statusCode(201)
            .body("keycloakGroup", equalTo("/staff"))

        given()
            .get(
                "/v1/permissions/players/00000000-0000-0000-0000-000000000123/effective?keycloakGroup=/staff"
            )
            .then()
            .statusCode(200)
            .body("roleKeys", hasItem("default"))
            .body("roleKeys", hasItem("moderator"))
            .body("denyPatterns.permissionPattern", hasItem("grounds.command.op"))
    }

    private fun createRole(key: String, name: String, default: Boolean = false) {
        given()
            .contentType("application/json")
            .body("""{"key":"$key","name":"$name","default":$default}""")
            .post("/v1/permissions/roles")
            .then()
            .statusCode(201)
    }

    private fun createRoleGrant(roleKey: String, permissionPattern: String) {
        given()
            .contentType("application/json")
            .body(
                """
                {
                  "effect": "ALLOW",
                  "permissionPattern": "$permissionPattern",
                  "scopeKind": "GLOBAL"
                }
                """
                    .trimIndent()
            )
            .post("/v1/permissions/roles/$roleKey/grants")
            .then()
            .statusCode(201)
    }
}
