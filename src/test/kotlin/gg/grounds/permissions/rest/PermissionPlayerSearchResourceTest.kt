package gg.grounds.permissions.rest

import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.identity.MojangLookupResult
import gg.grounds.permissions.identity.MojangProfile
import gg.grounds.permissions.identity.MojangProfileClient
import gg.grounds.permissions.identity.ProjectedPlayerIdentity
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import gg.grounds.permissions.persistence.PlayerGrantRecord
import gg.grounds.permissions.persistence.PlayerIdentityRepository
import gg.grounds.permissions.persistence.PlayerRoleGrantRecord
import gg.grounds.permissions.persistence.RoleRecord
import io.quarkus.test.InjectMock
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.security.TestSecurity
import io.restassured.RestAssured.given
import jakarta.inject.Inject
import java.time.Instant
import java.util.UUID
import org.hamcrest.Matchers.contains
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.hasSize
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.reset
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
@TestSecurity(user = "admin-user", roles = ["MINECRAFT_PERMISSIONS_MANAGE"])
class PermissionPlayerSearchResourceTest {

    @Inject lateinit var permissionRepository: PermissionRepository
    @Inject lateinit var identityRepository: PlayerIdentityRepository
    @InjectMock lateinit var mojangProfileClient: MojangProfileClient

    @BeforeEach
    fun resetDatabase() {
        permissionRepository.deleteAllPermissionData()
        reset(mojangProfileClient)
    }

    @Test
    fun rejectsShortQueriesButAcceptsCompleteUuids() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000401")
        identityRepository.replacePlayer(identity(playerId, "UuidPlayer"))

        given()
            .queryParam("query", "u")
            .get("/v1/permissions/players/search")
            .then()
            .statusCode(400)
            .body("error", equalTo("query must contain at least 2 characters"))

        given()
            .queryParam("query", playerId.toString())
            .get("/v1/permissions/players/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(1))
            .body("items[0].playerId", equalTo(playerId.toString()))
            .body("items[0].linked", equalTo(true))
    }

    @Test
    fun validatesPaginationAndReturnsDeterministicallyOrderedLocalResults() {
        val alpha = UUID.fromString("00000000-0000-0000-0000-000000000402")
        val beta = UUID.fromString("00000000-0000-0000-0000-000000000403")
        identityRepository.replacePlayer(identity(beta, "BetaPlayer"))
        identityRepository.replacePlayer(identity(alpha, "AlphaPlayer"))
        permissionRepository.createRole(RoleRecord(key = "moderator", name = "Moderator"))
        permissionRepository.createPlayerRoleGrant(
            PlayerRoleGrantRecord(UUID.randomUUID(), alpha, "moderator")
        )
        permissionRepository.createPlayerGrant(
            PlayerGrantRecord(
                UUID.randomUUID(),
                alpha,
                PermissionEffect.ALLOW,
                "grounds.command.moderate",
                PermissionScope(PermissionScopeKind.GLOBAL),
            )
        )

        given()
            .queryParam("query", "player")
            .queryParam("page", 0)
            .get("/v1/permissions/players/search")
            .then()
            .statusCode(400)
            .body("error", equalTo("page must be at least 1"))

        given()
            .queryParam("query", "player")
            .queryParam("perPage", 0)
            .get("/v1/permissions/players/search")
            .then()
            .statusCode(400)
            .body("error", equalTo("perPage must be between 1 and 100"))

        given()
            .queryParam("query", "player")
            .queryParam("page", 1)
            .queryParam("perPage", 1)
            .get("/v1/permissions/players/search")
            .then()
            .statusCode(200)
            .body("page", equalTo(1))
            .body("perPage", equalTo(1))
            .body("total", equalTo(2))
            .body("items", hasSize<Any>(1))
            .body("items[0].name", equalTo("AlphaPlayer"))
            .body("items[0].directRoleGrantCount", equalTo(1))
            .body("items[0].directPermissionGrantCount", equalTo(1))

        given()
            .queryParam("query", "player")
            .queryParam("page", 1)
            .queryParam("perPage", 10)
            .get("/v1/permissions/players/search")
            .then()
            .statusCode(200)
            .body("items.name", contains("AlphaPlayer", "BetaPlayer"))
    }

    @Test
    fun returnsExactLocalUsernameWithoutCallingMojang() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000404")
        identityRepository.replacePlayer(identity(playerId, "ExactPlayer"))

        given()
            .queryParam("query", "exactplayer")
            .get("/v1/permissions/players/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(1))
            .body("items[0].playerId", equalTo(playerId.toString()))
            .body("items[0].linked", equalTo(true))

        verifyNoInteractions(mojangProfileClient)
    }

    @Test
    fun keepsLocalSearchIndependentFromMojangForMissingUsernames() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000405")
        whenever(mojangProfileClient.lookupExactUsername("MissingPlayer"))
            .thenReturn(MojangLookupResult.Found(MojangProfile(playerId, "MissingPlayer")))

        given()
            .queryParam("query", "MissingPlayer")
            .get("/v1/permissions/players/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(0))
            .body("items", hasSize<Any>(0))

        verifyNoInteractions(mojangProfileClient)
    }

    @Test
    fun returnsAnUnlinkedMojangProfileFromTheExplicitExternalLookupWithoutPersistingIt() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000405")
        whenever(mojangProfileClient.lookupExactUsername("MissingPlayer"))
            .thenReturn(MojangLookupResult.Found(MojangProfile(playerId, "MissingPlayer")))

        given()
            .queryParam("query", "MissingPlayer")
            .get("/v1/permissions/players/external-search")
            .then()
            .statusCode(200)
            .body("playerId", equalTo(playerId.toString()))
            .body("name", equalTo("MissingPlayer"))
            .body("linked", equalTo(false))
            .body("directRoleGrantCount", equalTo(0))
            .body("directPermissionGrantCount", equalTo(0))

        org.junit.jupiter.api.Assertions.assertNull(identityRepository.findByPlayerId(playerId))
    }

    @Test
    fun doesNotCallMojangForExternalLookupWhenAnExactLocalUsernameExists() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000406")
        identityRepository.replacePlayer(identity(playerId, "ExactPlayer"))

        given()
            .queryParam("query", "exactplayer")
            .get("/v1/permissions/players/external-search")
            .then()
            .statusCode(404)
            .body("error", equalTo("player_already_known"))

        verifyNoInteractions(mojangProfileClient)
    }

    @Test
    fun returnsNotFoundWhenTheExternalPlayerDoesNotExist() {
        whenever(mojangProfileClient.lookupExactUsername("MissingPlayer"))
            .thenReturn(MojangLookupResult.NotFound)

        given()
            .queryParam("query", "MissingPlayer")
            .get("/v1/permissions/players/external-search")
            .then()
            .statusCode(404)
            .body("error", equalTo("player_not_found"))
    }

    @Test
    fun returnsServiceUnavailableWhenTheExternalLookupIsUnavailable() {
        whenever(mojangProfileClient.lookupExactUsername("UnavailableUser"))
            .thenReturn(MojangLookupResult.Unavailable)

        given()
            .queryParam("query", "UnavailableUser")
            .get("/v1/permissions/players/external-search")
            .then()
            .statusCode(503)
            .body("error", equalTo("external_player_lookup_unavailable"))
    }

    @Test
    fun keepsUnavailableMojangResponsesOutOfTheLocalSearch() {
        whenever(mojangProfileClient.lookupExactUsername("UnavailablePlayer"))
            .thenReturn(MojangLookupResult.Unavailable)

        given()
            .queryParam("query", "UnavailablePlayer")
            .get("/v1/permissions/players/search")
            .then()
            .statusCode(200)
            .body("total", equalTo(0))
            .body("items", hasSize<Any>(0))

        verifyNoInteractions(mojangProfileClient)
    }

    private fun identity(playerId: UUID, username: String) =
        ProjectedPlayerIdentity(
            playerId = playerId,
            keycloakUserId = "keycloak-$playerId",
            minecraftUsername = username,
            normalizedUsername = username.lowercase(),
            groupPaths = emptySet(),
            syncedAt = Instant.parse("2030-01-01T00:00:00Z"),
            sourceUpdatedAt = null,
        )
}
