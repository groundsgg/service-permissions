package gg.grounds.permissions.rest

import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.identity.ProjectedPlayerIdentity
import gg.grounds.permissions.persistence.CatalogEntryRecord
import gg.grounds.permissions.persistence.KeycloakGroupMappingRecord
import gg.grounds.permissions.persistence.PermissionAuditEventQuery
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import gg.grounds.permissions.persistence.PlayerGrantRecord
import gg.grounds.permissions.persistence.PlayerIdentityRepository
import gg.grounds.permissions.persistence.PlayerRoleGrantRecord
import gg.grounds.permissions.persistence.RoleGrantRecord
import gg.grounds.permissions.persistence.RoleRecord
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
import org.junit.jupiter.api.Assertions.assertEquals
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
    fun roleGrantSearchUsesDefaultsAndNormalizesQueryWhitespace() {
        repository.createRole(RoleRecord(key = "moderator", name = "Moderator"))
        repository.createRoleGrant(
            RoleGrantRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000321"),
                "moderator",
                PermissionEffect.ALLOW,
                "grounds.command.fly",
                PermissionScope(PermissionScopeKind.SERVER_TYPE, "paper network"),
            )
        )

        given()
            .queryParam("query", "  PAPER   network  ")
            .get("/v1/permissions/roles/moderator/grants/search")
            .then()
            .statusCode(200)
            .body("page", equalTo(1))
            .body("perPage", equalTo(20))
            .body("total", equalTo(1))
            .body("items[0].permissionPattern", equalTo("grounds.command.fly"))
    }

    @Test
    fun groupMappingSearchSupportsDescendingSecondPages() {
        repository.createRole(RoleRecord(key = "builder", name = "Builder"))
        repository.createRole(RoleRecord(key = "moderator", name = "Moderator"))
        repository.createKeycloakGroupMapping(
            KeycloakGroupMappingRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000331"),
                "/staff/builders",
                "builder",
            )
        )
        repository.createKeycloakGroupMapping(
            KeycloakGroupMappingRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000332"),
                "/staff/moderators",
                "moderator",
            )
        )

        given()
            .queryParam("page", 2)
            .queryParam("perPage", 1)
            .queryParam("sortBy", "group")
            .queryParam("sortDirection", "desc")
            .get("/v1/permissions/keycloak-groups/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(2))
            .body("items", hasSize<Any>(1))
            .body("items[0].keycloakGroup", equalTo("/staff/builders"))
    }

    @Test
    fun catalogSearchUsesDefaultPagingAndSorting() {
        repository.upsertCatalogEntry(
            CatalogEntryRecord(
                key = "grounds.command.warn",
                label = "Warn",
                source = "plugin-runtime",
                sourceVersion = "1.0.0",
                supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                custom = false,
            )
        )
        repository.upsertCatalogEntry(
            CatalogEntryRecord(
                key = "grounds.command.fly",
                label = "Fly",
                source = "portal",
                sourceVersion = "custom",
                supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                custom = true,
            )
        )

        given()
            .get("/v1/permissions/catalog/search")
            .then()
            .statusCode(200)
            .body("page", equalTo(1))
            .body("perPage", equalTo(20))
            .body("total", equalTo(2))
            .body(
                "items.key",
                org.hamcrest.Matchers.contains("grounds.command.fly", "grounds.command.warn"),
            )

        given()
            .queryParam("sortBy", "lastSeen")
            .queryParam("sortDirection", "desc")
            .get("/v1/permissions/catalog/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(2))
    }

    @Test
    fun searchesRejectInvalidPagingAndSortingParameters() {
        given()
            .queryParam("page", 0)
            .get("/v1/permissions/catalog/search")
            .then()
            .statusCode(400)
            .body("error", equalTo("page must be at least 1"))

        given()
            .queryParam("perPage", 101)
            .get("/v1/permissions/catalog/search")
            .then()
            .statusCode(400)
            .body("error", equalTo("perPage must be between 1 and 100"))

        given()
            .queryParam("sortBy", "createdAt")
            .get("/v1/permissions/catalog/search")
            .then()
            .statusCode(400)
            .body("error", equalTo("sortBy must be one of: permission, label, source, lastseen"))

        given()
            .queryParam("sortDirection", "sideways")
            .get("/v1/permissions/catalog/search")
            .then()
            .statusCode(400)
            .body("error", equalTo("sortDirection must be one of: asc, desc"))
    }

    @Test
    fun playerAccessSearchesReturnDirectAndDerivedRowsWithFilteringAndPagination() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000127")
        val directRoleGrantId = UUID.fromString("00000000-0000-0000-0000-000000000401")
        val directPermissionGrantId = UUID.fromString("00000000-0000-0000-0000-000000000402")
        val mappingId = UUID.fromString("00000000-0000-0000-0000-000000000403")
        createRole("default", "Default", default = true)
        createRole("moderator", "Moderator")
        createRole("builder", "Builder")
        repository.addRoleInheritance(childRoleKey = "moderator", parentRoleKey = "default")
        repository.createPlayerRoleGrant(
            PlayerRoleGrantRecord(
                directRoleGrantId,
                playerId,
                "moderator",
                Instant.parse("2030-01-02T00:00:00Z"),
            )
        )
        repository.createKeycloakGroupMapping(
            KeycloakGroupMappingRecord(mappingId, "/builders", "builder")
        )
        repository.createPlayerGrant(
            PlayerGrantRecord(
                directPermissionGrantId,
                playerId,
                PermissionEffect.DENY,
                "grounds.command.op",
                PermissionScope(PermissionScopeKind.SERVER, "lobby-1"),
                Instant.parse("2030-01-03T00:00:00Z"),
            )
        )
        repository.createRoleGrant(
            RoleGrantRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000404"),
                "moderator",
                PermissionEffect.ALLOW,
                "grounds.command.kick",
                PermissionScope(PermissionScopeKind.GLOBAL),
            )
        )
        val syncedAt = Instant.now()
        identityRepository.markSyncRunning(syncedAt.minusSeconds(1))
        identityRepository.replaceAll(
            listOf(
                ProjectedPlayerIdentity(
                    playerId,
                    "keycloak-player-127",
                    "SearchPlayer",
                    "searchplayer",
                    setOf("/builders"),
                    syncedAt,
                    null,
                )
            ),
            syncedAt,
        )

        given()
            .queryParam("query", "DIRECT_ROLE")
            .queryParam("sortBy", "source")
            .get("/v1/permissions/players/$playerId/roles/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(2))
            .body("items", hasSize<Any>(2))
            .body(
                "items.find { it.roleKey == 'moderator' }.id",
                equalTo(directRoleGrantId.toString()),
            )
            .body("items.find { it.roleKey == 'moderator' }.roleName", equalTo("Moderator"))
            .body("items.find { it.roleKey == 'moderator' }.source", equalTo("DIRECT_ROLE"))
            .body("items.find { it.roleKey == 'moderator' }.editable", equalTo(true))
            .body(
                "items.find { it.roleKey == 'moderator' }.directGrant.id",
                equalTo(directRoleGrantId.toString()),
            )
            .body("items.find { it.roleKey == 'default' }.inherited", equalTo(true))
            .body("items.find { it.roleKey == 'default' }.directGrant", nullValue())

        given()
            .queryParam("query", "GROUP_MAPPING")
            .queryParam("sortBy", "role")
            .get("/v1/permissions/players/$playerId/roles/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(1))
            .body("items[0].roleKey", equalTo("builder"))
            .body("items[0].source", equalTo("GROUP_MAPPING"))

        given()
            .queryParam("sortBy", "expiration")
            .get("/v1/permissions/players/$playerId/roles/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(4))

        given()
            .queryParam("query", "lobby")
            .queryParam("sortBy", "expiration")
            .get("/v1/permissions/players/$playerId/grants/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(1))
            .body("items[0].id", equalTo(directPermissionGrantId.toString()))
            .body("items[0].effect", equalTo("DENY"))

        given()
            .queryParam("effect", "ALLOW")
            .queryParam("query", "moderator")
            .queryParam("perPage", 1)
            .queryParam("sortBy", "source")
            .get("/v1/permissions/players/$playerId/effective/search")
            .then()
            .statusCode(200)
            .body("page", equalTo(1))
            .body("perPage", equalTo(1))
            .body("total", equalTo(1))
            .body("items[0].permissionPattern", equalTo("grounds.command.kick"))
            .body("items[0].source", equalTo("DIRECT_ROLE"))

        given()
            .queryParam("effect", "MAYBE")
            .get("/v1/permissions/players/$playerId/effective/search")
            .then()
            .statusCode(400)
            .body("error", equalTo("effect must be one of: ALL, ALLOW, DENY"))
    }

    @Test
    fun playerRoleSearchReturnsAnEmptyPageWhenTheOffsetExceedsTheResultSize() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000128")

        given()
            .queryParam("page", Int.MAX_VALUE)
            .queryParam("perPage", 100)
            .get("/v1/permissions/players/$playerId/roles/search")
            .then()
            .statusCode(200)
            .body("page", equalTo(Int.MAX_VALUE))
            .body("perPage", equalTo(100))
            .body("total", equalTo(0))
            .body("items", hasSize<Any>(0))
    }

    @Test
    fun effectiveSearchUsesExpirationToOrderOtherwiseEqualGrantsAcrossPages() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000129")
        repository.createRole(RoleRecord(key = "operator", name = "Operator"))
        repository.createPlayerRoleGrant(
            PlayerRoleGrantRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000411"),
                playerId,
                "operator",
            )
        )
        repository.createRoleGrant(
            RoleGrantRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000412"),
                "operator",
                PermissionEffect.ALLOW,
                "grounds.command.teleport",
                PermissionScope(PermissionScopeKind.GLOBAL),
                Instant.parse("2031-01-01T00:00:00Z"),
            )
        )
        repository.createRoleGrant(
            RoleGrantRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000413"),
                "operator",
                PermissionEffect.ALLOW,
                "grounds.command.teleport",
                PermissionScope(PermissionScopeKind.GLOBAL),
                Instant.parse("2030-01-01T00:00:00Z"),
            )
        )

        given()
            .queryParam("sortBy", "permission")
            .queryParam("page", 1)
            .queryParam("perPage", 1)
            .get("/v1/permissions/players/$playerId/effective/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(2))
            .body("items[0].expiresAt", equalTo("2030-01-01T00:00:00Z"))

        given()
            .queryParam("sortBy", "permission")
            .queryParam("page", 2)
            .queryParam("perPage", 1)
            .get("/v1/permissions/players/$playerId/effective/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(2))
            .body("items[0].expiresAt", equalTo("2031-01-01T00:00:00Z"))
    }

    @Test
    fun playerGrantSearchReturnsTheSecondPageInPermissionOrder() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000130")
        listOf(
                PlayerGrantRecord(
                    UUID.fromString("00000000-0000-0000-0000-000000000421"),
                    playerId,
                    PermissionEffect.ALLOW,
                    "grounds.command.warn",
                    PermissionScope(PermissionScopeKind.GLOBAL),
                ),
                PlayerGrantRecord(
                    UUID.fromString("00000000-0000-0000-0000-000000000422"),
                    playerId,
                    PermissionEffect.ALLOW,
                    "grounds.command.kick",
                    PermissionScope(PermissionScopeKind.GLOBAL),
                ),
            )
            .forEach(repository::createPlayerGrant)

        given()
            .queryParam("sortBy", "permission")
            .queryParam("sortDirection", "asc")
            .queryParam("page", 2)
            .queryParam("perPage", 1)
            .get("/v1/permissions/players/$playerId/grants/search")
            .then()
            .statusCode(200)
            .body("page", equalTo(2))
            .body("total", equalTo(2))
            .body("items[0].permissionPattern", equalTo("grounds.command.warn"))
    }

    @Test
    fun playerRoleSearchReturnsOrderedRowsForEverySortAndDirection() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000131")
        repository.createRole(RoleRecord(key = "default", name = "Zulu", isDefault = true))
        repository.createRole(RoleRecord(key = "direct", name = "Mike"))
        repository.createRole(RoleRecord(key = "mapped", name = "Alpha"))
        repository.createPlayerRoleGrant(
            PlayerRoleGrantRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000431"),
                playerId,
                "direct",
                Instant.parse("2031-01-01T00:00:00Z"),
            )
        )
        repository.createKeycloakGroupMapping(
            KeycloakGroupMappingRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000432"),
                "/mapped",
                "mapped",
                Instant.parse("2030-01-01T00:00:00Z"),
            )
        )
        val syncedAt = Instant.now()
        identityRepository.markSyncRunning(syncedAt.minusSeconds(1))
        identityRepository.replaceAll(
            listOf(
                ProjectedPlayerIdentity(
                    playerId,
                    "keycloak-player-131",
                    "OrderedRoles",
                    "orderedroles",
                    setOf("/mapped"),
                    syncedAt,
                    null,
                )
            ),
            syncedAt,
        )

        val endpoint = "/v1/permissions/players/$playerId/roles/search"
        assertSearchDefaults(endpoint, "items.roleKey", listOf("mapped", "direct", "default"))
        assertSearchQuery(endpoint, "Alpha", "items.roleKey", listOf("mapped"))
        assertSearchQuery(endpoint, "direct", "items.roleKey", listOf("direct"))
        assertSearchQuery(endpoint, "GROUP_MAPPING", "items.roleKey", listOf("mapped"))
        assertSearchOrder(
            endpoint,
            "role",
            "asc",
            "items.roleKey",
            listOf("mapped", "direct", "default"),
        )
        assertSearchOrder(
            endpoint,
            "role",
            "desc",
            "items.roleKey",
            listOf("default", "direct", "mapped"),
        )
        assertSearchOrder(
            endpoint,
            "source",
            "asc",
            "items.roleKey",
            listOf("default", "direct", "mapped"),
        )
        assertSearchOrder(
            endpoint,
            "source",
            "desc",
            "items.roleKey",
            listOf("mapped", "direct", "default"),
        )
        assertSearchOrder(
            endpoint,
            "expiration",
            "asc",
            "items.roleKey",
            listOf("mapped", "direct", "default"),
        )
        assertSearchOrder(
            endpoint,
            "expiration",
            "desc",
            "items.roleKey",
            listOf("direct", "mapped", "default"),
        )
    }

    @Test
    fun playerGrantSearchReturnsOrderedRowsForEverySortAndDirection() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000132")
        listOf(
                PlayerGrantRecord(
                    UUID.fromString("00000000-0000-0000-0000-000000000441"),
                    playerId,
                    PermissionEffect.ALLOW,
                    "grounds.command.zeta",
                    PermissionScope(PermissionScopeKind.GLOBAL),
                    Instant.parse("2031-01-01T00:00:00Z"),
                ),
                PlayerGrantRecord(
                    UUID.fromString("00000000-0000-0000-0000-000000000442"),
                    playerId,
                    PermissionEffect.DENY,
                    "grounds.command.alpha",
                    PermissionScope(PermissionScopeKind.SERVER_TYPE, "paper"),
                ),
                PlayerGrantRecord(
                    UUID.fromString("00000000-0000-0000-0000-000000000443"),
                    playerId,
                    PermissionEffect.ALLOW,
                    "grounds.command.middle",
                    PermissionScope(PermissionScopeKind.SERVER, "lobby"),
                    Instant.parse("2030-01-01T00:00:00Z"),
                ),
            )
            .forEach(repository::createPlayerGrant)

        val endpoint = "/v1/permissions/players/$playerId/grants/search"
        val itemPath = "items.permissionPattern"
        assertSearchDefaults(
            endpoint,
            itemPath,
            listOf("grounds.command.alpha", "grounds.command.middle", "grounds.command.zeta"),
        )
        assertSearchQuery(endpoint, "alpha", itemPath, listOf("grounds.command.alpha"))
        assertSearchQuery(endpoint, "deny", itemPath, listOf("grounds.command.alpha"))
        assertSearchQuery(endpoint, "server_type", itemPath, listOf("grounds.command.alpha"))
        assertSearchQuery(endpoint, "lobby", itemPath, listOf("grounds.command.middle"))
        assertSearchOrder(
            endpoint,
            "permission",
            "asc",
            itemPath,
            listOf("grounds.command.alpha", "grounds.command.middle", "grounds.command.zeta"),
        )
        assertSearchOrder(
            endpoint,
            "permission",
            "desc",
            itemPath,
            listOf("grounds.command.zeta", "grounds.command.middle", "grounds.command.alpha"),
        )
        assertSearchOrder(
            endpoint,
            "effect",
            "asc",
            itemPath,
            listOf("grounds.command.zeta", "grounds.command.middle", "grounds.command.alpha"),
        )
        assertSearchOrder(
            endpoint,
            "effect",
            "desc",
            itemPath,
            listOf("grounds.command.alpha", "grounds.command.zeta", "grounds.command.middle"),
        )
        assertSearchOrder(
            endpoint,
            "scope",
            "asc",
            itemPath,
            listOf("grounds.command.zeta", "grounds.command.middle", "grounds.command.alpha"),
        )
        assertSearchOrder(
            endpoint,
            "scope",
            "desc",
            itemPath,
            listOf("grounds.command.alpha", "grounds.command.middle", "grounds.command.zeta"),
        )
        assertSearchOrder(
            endpoint,
            "expiration",
            "asc",
            itemPath,
            listOf("grounds.command.middle", "grounds.command.zeta", "grounds.command.alpha"),
        )
        assertSearchOrder(
            endpoint,
            "expiration",
            "desc",
            itemPath,
            listOf("grounds.command.zeta", "grounds.command.middle", "grounds.command.alpha"),
        )
    }

    @Test
    fun effectiveSearchReturnsOrderedRowsForEverySortAndDirection() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000133")
        repository.createRole(RoleRecord(key = "default", name = "Default", isDefault = true))
        repository.createRole(RoleRecord(key = "operator", name = "Operator"))
        repository.createPlayerRoleGrant(
            PlayerRoleGrantRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000451"),
                playerId,
                "operator",
            )
        )
        repository.createRoleGrant(
            RoleGrantRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000452"),
                "operator",
                PermissionEffect.ALLOW,
                "grounds.command.alpha",
                PermissionScope(PermissionScopeKind.GLOBAL),
            )
        )
        repository.createRoleGrant(
            RoleGrantRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000453"),
                "default",
                PermissionEffect.DENY,
                "grounds.command.middle",
                PermissionScope(PermissionScopeKind.SERVER, "lobby"),
                Instant.parse("2030-01-01T00:00:00Z"),
            )
        )
        repository.createPlayerGrant(
            PlayerGrantRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000454"),
                playerId,
                PermissionEffect.DENY,
                "grounds.command.zeta",
                PermissionScope(PermissionScopeKind.SERVER_TYPE, "paper"),
                Instant.parse("2032-01-01T00:00:00Z"),
            )
        )

        val endpoint = "/v1/permissions/players/$playerId/effective/search"
        val itemPath = "items.permissionPattern"
        assertSearchDefaults(
            endpoint,
            itemPath,
            listOf("grounds.command.alpha", "grounds.command.middle", "grounds.command.zeta"),
        )
        assertSearchQuery(endpoint, "alpha", itemPath, listOf("grounds.command.alpha"))
        assertSearchQuery(endpoint, "DEFAULT_ROLE", itemPath, listOf("grounds.command.middle"))
        assertSearchQuery(endpoint, "operator", itemPath, listOf("grounds.command.alpha"))
        assertSearchQuery(endpoint, "server_type", itemPath, listOf("grounds.command.zeta"))
        assertSearchQuery(endpoint, "lobby", itemPath, listOf("grounds.command.middle"))
        assertSearchOrder(
            endpoint,
            "permission",
            "asc",
            itemPath,
            listOf("grounds.command.alpha", "grounds.command.middle", "grounds.command.zeta"),
        )
        assertSearchOrder(
            endpoint,
            "permission",
            "desc",
            itemPath,
            listOf("grounds.command.zeta", "grounds.command.middle", "grounds.command.alpha"),
        )
        assertSearchOrder(
            endpoint,
            "effect",
            "asc",
            itemPath,
            listOf("grounds.command.alpha", "grounds.command.middle", "grounds.command.zeta"),
        )
        assertSearchOrder(
            endpoint,
            "effect",
            "desc",
            itemPath,
            listOf("grounds.command.middle", "grounds.command.zeta", "grounds.command.alpha"),
        )
        assertSearchOrder(
            endpoint,
            "scope",
            "asc",
            itemPath,
            listOf("grounds.command.alpha", "grounds.command.middle", "grounds.command.zeta"),
        )
        assertSearchOrder(
            endpoint,
            "scope",
            "desc",
            itemPath,
            listOf("grounds.command.zeta", "grounds.command.middle", "grounds.command.alpha"),
        )
        assertSearchOrder(
            endpoint,
            "source",
            "asc",
            itemPath,
            listOf("grounds.command.middle", "grounds.command.zeta", "grounds.command.alpha"),
        )
        assertSearchOrder(
            endpoint,
            "source",
            "desc",
            itemPath,
            listOf("grounds.command.alpha", "grounds.command.zeta", "grounds.command.middle"),
        )
        assertSearchOrder(
            endpoint,
            "expiration",
            "asc",
            itemPath,
            listOf("grounds.command.middle", "grounds.command.zeta", "grounds.command.alpha"),
        )
        assertSearchOrder(
            endpoint,
            "expiration",
            "desc",
            itemPath,
            listOf("grounds.command.zeta", "grounds.command.middle", "grounds.command.alpha"),
        )
    }

    @Test
    fun playerAccessSearchesRejectEveryInvalidParameterForEveryEndpoint() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000134")
        assertSearchValidation(
            "/v1/permissions/players/$playerId/roles/search",
            "sortBy must be one of: role, source, expiration",
        )
        assertSearchValidation(
            "/v1/permissions/players/$playerId/grants/search",
            "sortBy must be one of: permission, effect, scope, expiration",
        )
        assertSearchValidation(
            "/v1/permissions/players/$playerId/effective/search",
            "sortBy must be one of: permission, effect, scope, source, expiration",
        )
    }

    @Test
    fun effectiveSearchPagesCollidingRoleGrantsConsistentlyAcrossRepeatedCalls() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000136")
        repository.createRole(RoleRecord(key = "operator", name = "Operator"))
        repository.createPlayerRoleGrant(
            PlayerRoleGrantRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000471"),
                playerId,
                "operator",
            )
        )
        listOf(
                UUID.fromString("00000000-0000-0000-0000-000000000472"),
                UUID.fromString("00000000-0000-0000-0000-000000000473"),
            )
            .forEach { roleGrantId ->
                repository.createRoleGrant(
                    RoleGrantRecord(
                        roleGrantId,
                        "operator",
                        PermissionEffect.ALLOW,
                        "grounds.command.teleport",
                        PermissionScope(PermissionScopeKind.GLOBAL),
                        Instant.parse("2030-01-01T00:00:00Z"),
                    )
                )
            }

        repeat(3) {
            listOf(1, 2).forEach { page ->
                given()
                    .queryParam("page", page)
                    .queryParam("perPage", 1)
                    .get("/v1/permissions/players/$playerId/effective/search")
                    .then()
                    .statusCode(200)
                    .body("page", equalTo(page))
                    .body("total", equalTo(2))
                    .body("items", hasSize<Any>(1))
                    .body("items[0].permissionPattern", equalTo("grounds.command.teleport"))
                    .body("items[0].expiresAt", equalTo("2030-01-01T00:00:00Z"))
            }
        }
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
    fun directPlayerGrantRecordsTheAuthenticatedActor() {
        val playerId = "00000000-0000-0000-0000-000000000123"
        given()
            .contentType("application/json")
            .body(
                """{"effect":"ALLOW","permissionPattern":"grounds.command.fly","scopeKind":"GLOBAL"}"""
            )
            .post("/v1/permissions/players/$playerId/grants")
            .then()
            .statusCode(201)

        given()
            .queryParam("action", "player.grant.created")
            .get("/v1/permissions/audit")
            .then()
            .statusCode(200)
            .body("items[0].actorUserId", equalTo("admin-user"))
            .body("items[0].action", equalTo("player.grant.created"))
            .body("items[0].metadata.playerId", equalTo(playerId))
            .body("items[0].metadata.permissionPattern", equalTo("grounds.command.fly"))
    }

    @Test
    fun roleInheritanceRecordsTheAuthenticatedActor() {
        createRole("parent", "Parent")
        createRole("child", "Child")

        given().put("/v1/permissions/roles/child/inherits/parent").then().statusCode(204)

        given()
            .queryParam("action", "role.inheritance.created")
            .get("/v1/permissions/audit")
            .then()
            .statusCode(200)
            .body("items[0].actorUserId", equalTo("admin-user"))
            .body("items[0].metadata.roleKey", equalTo("child"))
            .body("items[0].metadata.parentRoleKey", equalTo("parent"))
    }

    @Test
    fun idempotentInheritanceMutationsDoNotAdvancePolicyVersionOrCreateAuditEvents() {
        createRole("parent", "Parent")
        createRole("child", "Child")

        given().put("/v1/permissions/roles/child/inherits/parent").then().statusCode(204)
        val versionAfterCreate = repository.currentPolicyVersion()
        val createdAuditEvents =
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("role.inheritance.created"))
                )
                .total

        given().put("/v1/permissions/roles/child/inherits/parent").then().statusCode(204)

        assertEquals(versionAfterCreate, repository.currentPolicyVersion())
        assertEquals(
            createdAuditEvents,
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("role.inheritance.created"))
                )
                .total,
        )

        given().delete("/v1/permissions/roles/child/inherits/parent").then().statusCode(204)
        val versionAfterDelete = repository.currentPolicyVersion()
        val deletedAuditEvents =
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("role.inheritance.deleted"))
                )
                .total

        given().delete("/v1/permissions/roles/child/inherits/parent").then().statusCode(204)

        assertEquals(versionAfterDelete, repository.currentPolicyVersion())
        assertEquals(
            deletedAuditEvents,
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("role.inheritance.deleted"))
                )
                .total,
        )
    }

    @Test
    fun identicalRoleUpdateDoesNotAdvancePolicyVersionOrCreateAuditEvent() {
        createRole("moderator", "Moderator")
        val versionBeforeUpdate = repository.currentPolicyVersion()
        val updatedAuditEvents =
            repository
                .listAuditEvents(PermissionAuditEventQuery(actions = setOf("role.updated")))
                .total

        given()
            .contentType("application/json")
            .body("""{"name":"Moderator"}""")
            .put("/v1/permissions/roles/moderator")
            .then()
            .statusCode(200)
            .body("key", equalTo("moderator"))

        assertEquals(versionBeforeUpdate, repository.currentPolicyVersion())
        assertEquals(
            updatedAuditEvents,
            repository
                .listAuditEvents(PermissionAuditEventQuery(actions = setOf("role.updated")))
                .total,
        )
    }

    @Test
    fun identicalCustomCatalogUpsertDoesNotAdvancePolicyVersionOrCreateAuditEvent() {
        val request =
            """
            {
              "key": "grounds.command.fly",
              "label": "Fly command",
              "description": "Allows flight",
              "supportedScopes": ["GLOBAL", "SERVER_TYPE"]
            }
            """
                .trimIndent()
        given()
            .contentType("application/json")
            .body(request)
            .post("/v1/permissions/catalog/custom")
            .then()
            .statusCode(201)
        val versionBeforeUpsert = repository.currentPolicyVersion()
        val upsertAuditEvents =
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("catalog.entry.upserted"))
                )
                .total

        given()
            .contentType("application/json")
            .body(request)
            .post("/v1/permissions/catalog/custom")
            .then()
            .statusCode(201)

        assertEquals(versionBeforeUpsert, repository.currentPolicyVersion())
        assertEquals(
            upsertAuditEvents,
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("catalog.entry.upserted"))
                )
                .total,
        )
    }

    @Test
    fun keycloakMappingRecordsTheAuthenticatedActor() {
        createRole("moderator", "Moderator")

        given()
            .contentType("application/json")
            .body("""{"keycloakGroup":"/staff","roleKey":"moderator"}""")
            .post("/v1/permissions/keycloak-groups")
            .then()
            .statusCode(201)

        given()
            .queryParam("action", "keycloak_group.mapping.created")
            .get("/v1/permissions/audit")
            .then()
            .statusCode(200)
            .body("items[0].actorUserId", equalTo("admin-user"))
            .body("items[0].metadata.keycloakGroup", equalTo("/staff"))
            .body("items[0].metadata.roleKey", equalTo("moderator"))
    }

    @Test
    fun customCatalogUpsertRecordsTheAuthenticatedActor() {
        given()
            .contentType("application/json")
            .body(
                """
                {
                  "key": "grounds.command.fly",
                  "label": "Fly command",
                  "supportedScopes": ["GLOBAL"]
                }
                """
                    .trimIndent()
            )
            .post("/v1/permissions/catalog/custom")
            .then()
            .statusCode(201)

        given()
            .queryParam("action", "catalog.entry.upserted")
            .get("/v1/permissions/audit")
            .then()
            .statusCode(200)
            .body("items[0].actorUserId", equalTo("admin-user"))
            .body("items[0].metadata.catalogKey", equalTo("grounds.command.fly"))
    }

    @Test
    fun deletionRecordsTheAuthenticatedActorAndTarget() {
        given()
            .contentType("application/json")
            .body(
                """
                {
                  "key": "grounds.command.fly",
                  "label": "Fly command",
                  "supportedScopes": ["GLOBAL"]
                }
                """
                    .trimIndent()
            )
            .post("/v1/permissions/catalog/custom")
            .then()
            .statusCode(201)

        given().delete("/v1/permissions/catalog/custom/grounds.command.fly").then().statusCode(204)

        given()
            .queryParam("action", "catalog.entry.deleted")
            .get("/v1/permissions/audit")
            .then()
            .statusCode(200)
            .body("items[0].actorUserId", equalTo("admin-user"))
            .body("items[0].action", equalTo("catalog.entry.deleted"))
            .body("items[0].target", equalTo("permission:grounds.command.fly"))
            .body("items[0].metadata.catalogKey", equalTo("grounds.command.fly"))
    }

    @Test
    fun syncImportRecordsTheAuthenticatedActor() {
        given()
            .contentType("application/json")
            .body(
                """
                {
                  "snapshot": {
                    "snapshotId": "actor-attributed-import",
                    "roles": [],
                    "roleGrants": [],
                    "inheritance": [],
                    "catalogEntries": [],
                    "keycloakMappings": []
                  },
                  "actions": []
                }
                """
                    .trimIndent()
            )
            .post("/v1/permissions/sync/import")
            .then()
            .statusCode(200)

        given()
            .queryParam("action", "permission.sync.imported")
            .get("/v1/permissions/audit")
            .then()
            .statusCode(200)
            .body("items[0].actorUserId", equalTo("admin-user"))
            .body("items[0].target", equalTo("snapshot:actor-attributed-import"))
            .body("items[0].metadata.snapshotId", equalTo("actor-attributed-import"))
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

    private fun assertSearchOrder(
        endpoint: String,
        sortBy: String,
        sortDirection: String,
        itemPath: String,
        expected: List<String>,
    ) {
        given()
            .queryParam("sortBy", sortBy)
            .queryParam("sortDirection", sortDirection)
            .get(endpoint)
            .then()
            .statusCode(200)
            .body("total", equalTo(expected.size))
            .body(itemPath, equalTo(expected))
    }

    private fun assertSearchDefaults(endpoint: String, itemPath: String, expected: List<String>) {
        given()
            .get(endpoint)
            .then()
            .statusCode(200)
            .body("page", equalTo(1))
            .body("perPage", equalTo(20))
            .body("total", equalTo(expected.size))
            .body(itemPath, equalTo(expected))
    }

    private fun assertSearchQuery(
        endpoint: String,
        query: String,
        itemPath: String,
        expected: List<String>,
    ) {
        given()
            .queryParam("query", query)
            .get(endpoint)
            .then()
            .statusCode(200)
            .body("total", equalTo(expected.size))
            .body(itemPath, equalTo(expected))
    }

    private fun assertSearchValidation(endpoint: String, sortByError: String) {
        given()
            .queryParam("page", 0)
            .get(endpoint)
            .then()
            .statusCode(400)
            .body("error", equalTo("page must be at least 1"))

        given()
            .queryParam("perPage", 101)
            .get(endpoint)
            .then()
            .statusCode(400)
            .body("error", equalTo("perPage must be between 1 and 100"))

        given()
            .queryParam("perPage", 0)
            .get(endpoint)
            .then()
            .statusCode(400)
            .body("error", equalTo("perPage must be between 1 and 100"))

        given()
            .queryParam("sortBy", "unknown")
            .get(endpoint)
            .then()
            .statusCode(400)
            .body("error", equalTo(sortByError))

        given()
            .queryParam("sortDirection", "sideways")
            .get(endpoint)
            .then()
            .statusCode(400)
            .body("error", equalTo("sortDirection must be one of: asc, desc"))
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
