package gg.grounds.permissions.persistence

import gg.grounds.permissions.identity.IdentitySyncStatus
import gg.grounds.permissions.identity.ProjectedPlayerIdentity
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import java.time.Instant
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
class PlayerIdentityRepositoryTest {

    @Inject lateinit var identityRepository: PlayerIdentityRepository

    @Inject lateinit var permissionRepository: PermissionRepository

    @BeforeEach
    fun resetDatabase() {
        permissionRepository.deleteAllPermissionData()
    }

    @Test
    fun searchesNormalizedUsernamesWithPaginationAndDirectAssignmentCounts() {
        val skywalker =
            identity("00000000-0000-0000-0000-000000000101", "keycloak-sky", "SkyWalker")
        val alex = identity("00000000-0000-0000-0000-000000000102", "keycloak-alex", "Alex")
        identityRepository.replacePlayer(skywalker)
        identityRepository.replacePlayer(alex)
        permissionRepository.createRole(RoleRecord(key = "moderator", name = "Moderator"))
        permissionRepository.createPlayerRoleGrant(
            PlayerRoleGrantRecord(UUID.randomUUID(), skywalker.playerId, "moderator")
        )
        permissionRepository.createPlayerGrant(
            PlayerGrantRecord(
                UUID.randomUUID(),
                skywalker.playerId,
                gg.grounds.permissions.domain.PermissionEffect.ALLOW,
                "grounds.command.moderate",
                gg.grounds.permissions.domain.PermissionScope(
                    gg.grounds.permissions.domain.PermissionScopeKind.GLOBAL
                ),
            )
        )
        permissionRepository.createPlayerGrant(
            PlayerGrantRecord(
                UUID.randomUUID(),
                skywalker.playerId,
                gg.grounds.permissions.domain.PermissionEffect.DENY,
                "grounds.command.op",
                gg.grounds.permissions.domain.PermissionScope(
                    gg.grounds.permissions.domain.PermissionScopeKind.GLOBAL
                ),
            )
        )

        val prefix = identityRepository.search("sky", page = 1, perPage = 10)
        val substring = identityRepository.search("walk", page = 1, perPage = 10)
        val secondPage = identityRepository.search("", page = 2, perPage = 1)

        assertEquals(1, prefix.total)
        assertEquals("SkyWalker", prefix.items.single().minecraftUsername)
        assertEquals(1, prefix.items.single().directRoleGrantCount)
        assertEquals(2, prefix.items.single().directPermissionGrantCount)
        assertEquals(listOf("SkyWalker"), substring.items.map { it.minecraftUsername })
        assertEquals(2, secondPage.total)
        assertEquals(listOf("SkyWalker"), secondPage.items.map { it.minecraftUsername })
    }

    @Test
    fun findsProjectedIdentitiesByPlayerAndKeycloakIds() {
        val expected =
            identity("00000000-0000-0000-0000-000000000103", "keycloak-id", "IdentityPlayer")
        identityRepository.replacePlayer(expected)

        assertEquals(expected, identityRepository.findByPlayerId(expected.playerId))
        assertEquals(expected, identityRepository.findByKeycloakUserId(expected.keycloakUserId))
    }

    @Test
    fun replacesOnePlayersCompleteGroupSet() {
        val original =
            identity(
                "00000000-0000-0000-0000-000000000104",
                "keycloak-groups",
                "GroupedPlayer",
                setOf("/staff", "/staff/moderators"),
            )
        identityRepository.replacePlayer(original)
        val replacement = original.copy(groupPaths = setOf("/builders"))

        identityRepository.replacePlayer(replacement)

        assertEquals(replacement, identityRepository.findByPlayerId(original.playerId))
    }

    @Test
    fun reconcilesAllIdentitiesDeletesMissingRowsAndCompletesSync() {
        val retained =
            identity("00000000-0000-0000-0000-000000000105", "keycloak-retained", "Retained")
        val removed =
            identity("00000000-0000-0000-0000-000000000106", "keycloak-removed", "Removed")
        val added = identity("00000000-0000-0000-0000-000000000107", "keycloak-added", "Added")
        identityRepository.replacePlayer(retained)
        identityRepository.replacePlayer(removed)
        val startedAt = Instant.parse("2030-01-01T00:00:00Z")
        val completedAt = Instant.parse("2030-01-01T00:00:03Z")

        assertEquals(IdentitySyncStatus.IDLE, identityRepository.currentSyncState().status)
        identityRepository.markSyncRunning(startedAt)
        assertEquals(IdentitySyncStatus.RUNNING, identityRepository.currentSyncState().status)
        identityRepository.replaceAll(
            listOf(retained.copy(groupPaths = setOf("/updated")), added),
            completedAt,
        )

        assertEquals(
            setOf("/updated"),
            identityRepository.findByPlayerId(retained.playerId)?.groupPaths,
        )
        assertNull(identityRepository.findByKeycloakUserId(removed.keycloakUserId))
        assertEquals(added, identityRepository.findByPlayerId(added.playerId))
        assertEquals(IdentitySyncStatus.IDLE, identityRepository.currentSyncState().status)
        assertEquals(completedAt, identityRepository.currentSyncState().lastSuccessAt)
        assertEquals(3_000, identityRepository.currentSyncState().durationMs)
        assertEquals(2, identityRepository.currentSyncState().playerCount)
    }

    @Test
    fun marksSyncFailureAfterRunning() {
        val startedAt = Instant.parse("2030-01-01T00:00:00Z")
        val failedAt = Instant.parse("2030-01-01T00:00:02Z")

        identityRepository.markSyncRunning(startedAt)
        identityRepository.markSyncFailed(failedAt, "keycloak_unavailable")

        val state = identityRepository.currentSyncState()
        assertEquals(IdentitySyncStatus.FAILED, state.status)
        assertEquals(failedAt, state.completedAt)
        assertEquals(2_000, state.durationMs)
        assertEquals("keycloak_unavailable", state.failureReason)
    }

    @Test
    fun rollsBackReconciliationWhenAnIdentityConflicts() {
        val existing =
            identity(
                "00000000-0000-0000-0000-000000000108",
                "keycloak-existing",
                "Existing",
                setOf("/existing"),
            )
        identityRepository.replacePlayer(existing)
        identityRepository.markSyncRunning(Instant.parse("2030-01-01T00:00:00Z"))

        org.junit.jupiter.api.Assertions.assertThrows(Exception::class.java) {
            identityRepository.replaceAll(
                listOf(
                    existing.copy(minecraftUsername = "Changed", normalizedUsername = "changed"),
                    identity(
                        "00000000-0000-0000-0000-000000000109",
                        existing.keycloakUserId,
                        "Conflicting",
                    ),
                ),
                Instant.parse("2030-01-01T00:00:01Z"),
            )
        }

        assertEquals(existing, identityRepository.findByPlayerId(existing.playerId))
        assertEquals(IdentitySyncStatus.RUNNING, identityRepository.currentSyncState().status)
    }

    private fun identity(
        playerId: String,
        keycloakUserId: String,
        minecraftUsername: String,
        groupPaths: Set<String> = setOf("/players"),
    ) =
        ProjectedPlayerIdentity(
            playerId = UUID.fromString(playerId),
            keycloakUserId = keycloakUserId,
            minecraftUsername = minecraftUsername,
            normalizedUsername = minecraftUsername.lowercase(),
            groupPaths = groupPaths,
            syncedAt = Instant.parse("2030-01-01T00:00:00Z"),
            sourceUpdatedAt = Instant.parse("2029-12-31T23:00:00Z"),
        )
}
