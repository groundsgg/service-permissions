package gg.grounds.permissions.rest

import gg.grounds.permissions.identity.ProjectedPlayerIdentity
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import gg.grounds.permissions.persistence.PlayerIdentityRepository
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.security.TestSecurity
import io.restassured.RestAssured.given
import jakarta.inject.Inject
import java.time.Instant
import java.util.UUID
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
    @Inject lateinit var identityRepository: PlayerIdentityRepository

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
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000123")
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

        val playerGrantId =
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
                .extract()
                .path<String>("id")

        given()
            .contentType("application/json")
            .body("""{"keycloakGroup":"/staff","roleKey":"moderator"}""")
            .post("/v1/permissions/keycloak-groups")
            .then()
            .statusCode(201)
            .body("keycloakGroup", equalTo("/staff"))
        given().put("/v1/permissions/roles/moderator/inherits/default").then().statusCode(204)

        val syncedAt = Instant.now()
        identityRepository.markSyncRunning(syncedAt)
        identityRepository.replaceAll(
            identities =
                listOf(
                    ProjectedPlayerIdentity(
                        playerId = playerId,
                        keycloakUserId = "keycloak-user-123",
                        minecraftUsername = "TestPlayer",
                        normalizedUsername = "testplayer",
                        groupPaths = setOf("/staff"),
                        syncedAt = syncedAt,
                        sourceUpdatedAt = null,
                    )
                ),
            completedAt = syncedAt,
        )

        given()
            .queryParam("keycloakGroup", "/spoofed")
            .get("/v1/permissions/players/$playerId/effective")
            .then()
            .statusCode(200)
            .body("roleKeys", hasItem("default"))
            .body("roleKeys", hasItem("moderator"))
            .body("denyPatterns.permissionPattern", hasItem("grounds.command.op"))
            .body(
                "denyPatterns.find { it.permissionPattern == 'grounds.command.op' }.source",
                equalTo("DIRECT_PERMISSION"),
            )
            .body(
                "denyPatterns.find { it.permissionPattern == 'grounds.command.op' }.editable",
                equalTo(true),
            )
            .body(
                "denyPatterns.find { it.permissionPattern == 'grounds.command.op' }.grantId",
                equalTo(playerGrantId),
            )
            .body(
                "roleAssignments.find { it.roleKey == 'default' && it.source == 'DEFAULT_ROLE' }.editable",
                equalTo(false),
            )
            .body(
                "roleAssignments.find { it.roleKey == 'default' && it.source == 'DIRECT_ROLE' }.editable",
                equalTo(true),
            )
            .body(
                "roleAssignments.find { it.roleKey == 'default' && it.source == 'DIRECT_ROLE' }.grantId",
                equalTo(playerRoleGrantId),
            )
            .body(
                "roleAssignments.find { it.roleKey == 'moderator' && it.source == 'GROUP_MAPPING' }.editable",
                equalTo(false),
            )
            .body(
                "roleAssignments.find { it.inheritedPath == ['moderator', 'default'] }.editable",
                equalTo(false),
            )

        given()
            .queryParam("permission", "grounds.command.op")
            .get("/v1/permissions/players/$playerId/check")
            .then()
            .statusCode(200)
            .body("allowed", equalTo(false))
            .body("winningGrant.permissionPattern", equalTo("grounds.command.op"))
            .body("winningGrant.source", equalTo("DIRECT_PERMISSION"))
            .body("winningGrant.grantId", equalTo(playerGrantId))

        given()
            .get("/v1/permissions/players/$playerId/identity")
            .then()
            .statusCode(200)
            .body("linked", equalTo(true))
            .body("name", equalTo("TestPlayer"))
            .body("fresh", equalTo(true))
            .body("evaluationSafe", equalTo(true))
    }

    @Test
    fun reportsUnavailableIdentityProjectionWithoutLeakingItsFailure() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000124")
        createRole("moderator", "Moderator")
        given()
            .contentType("application/json")
            .body("""{"keycloakGroup":"/staff","roleKey":"moderator"}""")
            .post("/v1/permissions/keycloak-groups")
            .then()
            .statusCode(201)

        given()
            .get("/v1/permissions/players/$playerId/identity")
            .then()
            .statusCode(200)
            .body("linked", equalTo(false))
            .body("fresh", equalTo(false))
            .body("evaluationSafe", equalTo(false))

        given()
            .get("/v1/permissions/players/$playerId/effective")
            .then()
            .statusCode(503)
            .body("error", equalTo("identity_projection_unavailable"))
    }

    @Test
    fun reportsFreshTargetedIdentityAsUnsafeWhenTheGlobalProjectionIsStale() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000125")
        createRole("moderator", "Moderator")
        given()
            .contentType("application/json")
            .body("""{"keycloakGroup":"/staff","roleKey":"moderator"}""")
            .post("/v1/permissions/keycloak-groups")
            .then()
            .statusCode(201)
        identityRepository.replacePlayer(
            ProjectedPlayerIdentity(
                playerId = playerId,
                keycloakUserId = "keycloak-user-125",
                minecraftUsername = "FreshPlayer",
                normalizedUsername = "freshplayer",
                groupPaths = setOf("/staff"),
                syncedAt = Instant.now(),
                sourceUpdatedAt = null,
            )
        )

        given()
            .get("/v1/permissions/players/$playerId/identity")
            .then()
            .statusCode(200)
            .body("linked", equalTo(true))
            .body("fresh", equalTo(true))
            .body("evaluationSafe", equalTo(false))

        given()
            .get("/v1/permissions/players/$playerId/effective")
            .then()
            .statusCode(503)
            .body("error", equalTo("identity_projection_unavailable"))
    }

    @Test
    fun reportsAnAbsentPlayerAsEvaluationSafeAfterAFreshFullProjection() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000126")
        createRole("moderator", "Moderator")
        given()
            .contentType("application/json")
            .body("""{"keycloakGroup":"/staff","roleKey":"moderator"}""")
            .post("/v1/permissions/keycloak-groups")
            .then()
            .statusCode(201)
        val syncedAt = Instant.now()
        identityRepository.markSyncRunning(syncedAt)
        identityRepository.replaceAll(emptyList(), syncedAt)

        given()
            .get("/v1/permissions/players/$playerId/identity")
            .then()
            .statusCode(200)
            .body("linked", equalTo(false))
            .body("fresh", equalTo(false))
            .body("evaluationSafe", equalTo(true))

        given().get("/v1/permissions/players/$playerId/effective").then().statusCode(200)
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
