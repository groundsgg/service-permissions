package gg.grounds.permissions.rest

import gg.grounds.permissions.identity.IdentityRefreshOutcome
import gg.grounds.permissions.identity.IdentitySyncCoordinator
import gg.grounds.permissions.identity.IdentitySyncOutcome
import gg.grounds.permissions.identity.ProjectedPlayerIdentity
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import gg.grounds.permissions.persistence.PlayerIdentityRepository
import io.quarkus.test.InjectMock
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.security.TestSecurity
import io.restassured.RestAssured.given
import jakarta.inject.Inject
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.hamcrest.Matchers.equalTo
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.reset
import org.mockito.kotlin.timeout
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
@TestSecurity(user = "admin-user", roles = ["MINECRAFT_PERMISSIONS_MANAGE"])
class PermissionIdentitySyncResourceTest {

    @Inject lateinit var permissionRepository: PermissionRepository
    @Inject lateinit var identityRepository: PlayerIdentityRepository
    @InjectMock lateinit var coordinator: IdentitySyncCoordinator

    private var releaseSync: CountDownLatch? = null

    @BeforeEach
    fun resetDatabase() {
        permissionRepository.deleteAllPermissionData()
        reset(coordinator)
    }

    @AfterEach
    fun releaseRunningSync() {
        releaseSync?.countDown()
    }

    @Test
    fun reportsCurrentStatusAndAcceptsOnlyOneRunningFullSyncDispatch() {
        val started = CountDownLatch(1)
        releaseSync = CountDownLatch(1)
        doAnswer {
                started.countDown()
                check(releaseSync!!.await(5, TimeUnit.SECONDS))
                IdentitySyncOutcome.COMPLETED
            }
            .whenever(coordinator)
            .synchronizeAll()

        given()
            .post("/v1/permissions/identity-sync")
            .then()
            .statusCode(202)
            .body("status", equalTo("RUNNING"))

        check(started.await(5, TimeUnit.SECONDS))

        given()
            .post("/v1/permissions/identity-sync")
            .then()
            .statusCode(202)
            .body("status", equalTo("RUNNING"))

        verify(coordinator, timeout(1_000).times(1)).synchronizeAll()
    }

    @Test
    fun returnsPersistedIdentitySyncStatus() {
        val startedAt = Instant.parse("2030-01-01T00:00:00Z")
        identityRepository.markSyncRunning(startedAt)

        given()
            .get("/v1/permissions/identity-sync/status")
            .then()
            .statusCode(200)
            .body("status", equalTo("RUNNING"))
            .body("startedAt", equalTo("2030-01-01T00:00:00Z"))
            .body("stale", equalTo(true))
    }

    @Test
    fun refreshesAPlayerThroughItsLocalKeycloakProjection() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000406")
        identityRepository.replacePlayer(
            ProjectedPlayerIdentity(
                playerId = playerId,
                keycloakUserId = "keycloak-player-406",
                minecraftUsername = "SyncPlayer",
                normalizedUsername = "syncplayer",
                groupPaths = emptySet(),
                syncedAt = Instant.parse("2030-01-01T00:00:00Z"),
                sourceUpdatedAt = null,
            )
        )
        whenever(coordinator.refreshPlayer(any())).thenReturn(IdentityRefreshOutcome.UPDATED)

        given()
            .post("/v1/permissions/players/$playerId/identity-sync")
            .then()
            .statusCode(202)
            .body("status", equalTo("RUNNING"))

        verify(coordinator, timeout(1_000)).refreshPlayer("keycloak-player-406")
    }

    @Test
    fun rejectsTargetedSyncWhenThePlayerHasNoLocalIdentityProjection() {
        given()
            .post("/v1/permissions/players/00000000-0000-0000-0000-000000000407/identity-sync")
            .then()
            .statusCode(404)
            .body("error", equalTo("player_identity_not_linked"))
    }
}
