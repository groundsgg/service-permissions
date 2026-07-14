package gg.grounds.permissions.persistence

import gg.grounds.permissions.identity.IdentitySyncStatus
import gg.grounds.permissions.identity.ProjectedPlayerIdentity
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import java.time.Instant
import java.util.Locale
import java.util.UUID
import javax.sql.DataSource
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
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

    @Inject lateinit var dataSource: DataSource

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
    fun preservesTotalForOutOfRangeSearchPage() {
        identityRepository.replacePlayer(
            identity("00000000-0000-0000-0000-000000000111", "keycloak-first", "First")
        )
        identityRepository.replacePlayer(
            identity("00000000-0000-0000-0000-000000000112", "keycloak-second", "Second")
        )

        val page = identityRepository.search("", page = 3, perPage = 1)

        assertEquals(emptyList<Any>(), page.items)
        assertEquals(2, page.total)
    }

    @Test
    fun trimsAndLowercasesSearchQueryUsingRootLocale() {
        identityRepository.replacePlayer(
            identity("00000000-0000-0000-0000-000000000114", "keycloak-normalized", "Iris")
        )

        val previousDefault = Locale.getDefault()
        Locale.setDefault(Locale.forLanguageTag("tr-TR"))
        val result =
            try {
                identityRepository.search("  IR  ", page = 1, perPage = 10)
            } finally {
                Locale.setDefault(previousDefault)
            }

        assertEquals(listOf("Iris"), result.items.map { it.minecraftUsername })
    }

    @Test
    fun treatsLikeMetacharactersAsLiteralSearchText() {
        listOf(
                identity(
                    "00000000-0000-0000-0000-000000000115",
                    "keycloak-percent",
                    "Percent%Player",
                ),
                identity(
                    "00000000-0000-0000-0000-000000000116",
                    "keycloak-percent-control",
                    "PercentXPlayer",
                ),
                identity(
                    "00000000-0000-0000-0000-000000000117",
                    "keycloak-underscore",
                    "Under_Score",
                ),
                identity(
                    "00000000-0000-0000-0000-000000000118",
                    "keycloak-underscore-control",
                    "UnderXScore",
                ),
                identity(
                    "00000000-0000-0000-0000-000000000119",
                    "keycloak-backslash",
                    "Back\\Slash",
                ),
                identity(
                    "00000000-0000-0000-0000-000000000120",
                    "keycloak-backslash-control",
                    "BackXSlash",
                ),
            )
            .forEach(identityRepository::replacePlayer)

        val percent = identityRepository.search("%", page = 1, perPage = 10)
        val underscore = identityRepository.search("_", page = 1, perPage = 10)
        val backslash = identityRepository.search("\\", page = 1, perPage = 10)

        assertEquals(listOf("Percent%Player"), percent.items.map { it.minecraftUsername })
        assertEquals(listOf("Under_Score"), underscore.items.map { it.minecraftUsername })
        assertEquals(listOf("Back\\Slash"), backslash.items.map { it.minecraftUsername })
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
    fun relinksKeycloakUserToNewPlayerDuringTargetedReplacement() {
        val oldIdentity =
            identity(
                "00000000-0000-0000-0000-000000000123",
                "keycloak-relinked-targeted",
                "OldPlayer",
                setOf("/old-group"),
            )
        val newIdentity =
            identity(
                "00000000-0000-0000-0000-000000000124",
                oldIdentity.keycloakUserId,
                "NewPlayer",
                setOf("/new-group"),
            )
        identityRepository.replacePlayer(oldIdentity)

        identityRepository.replacePlayer(newIdentity)

        assertNull(identityRepository.findByPlayerId(oldIdentity.playerId))
        assertEquals(newIdentity, identityRepository.findByPlayerId(newIdentity.playerId))
        assertEquals(0, groupCount(oldIdentity.playerId))
    }

    @Test
    fun rollsBackPlayerAndGroupsWhenGroupReplacementFails() {
        val original =
            identity(
                "00000000-0000-0000-0000-000000000121",
                "keycloak-player-rollback",
                "OriginalPlayer",
                setOf("/original"),
            )
        identityRepository.replacePlayer(original)
        dataSource.connection.use { connection ->
            connection
                .prepareStatement(
                    """
                    ALTER TABLE permission_player_keycloak_groups
                    ADD CONSTRAINT permission_player_groups_force_failure
                    CHECK (keycloak_group_path <> '/force-failure')
                    """
                        .trimIndent()
                )
                .use { it.executeUpdate() }
        }

        try {
            org.junit.jupiter.api.Assertions.assertThrows(Exception::class.java) {
                identityRepository.replacePlayer(
                    original.copy(
                        minecraftUsername = "ChangedPlayer",
                        normalizedUsername = "changedplayer",
                        groupPaths = setOf("/force-failure"),
                    )
                )
            }

            assertEquals(original, identityRepository.findByPlayerId(original.playerId))
        } finally {
            dataSource.connection.use { connection ->
                connection
                    .prepareStatement(
                        """
                        ALTER TABLE permission_player_keycloak_groups
                        DROP CONSTRAINT permission_player_groups_force_failure
                        """
                            .trimIndent()
                    )
                    .use { it.executeUpdate() }
            }
        }
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
        startSync(startedAt)
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
    fun relinksKeycloakUserToNewPlayerDuringFullReconciliation() {
        val oldIdentity =
            identity(
                "00000000-0000-0000-0000-000000000125",
                "keycloak-relinked-full",
                "OldPlayer",
                setOf("/old-group"),
            )
        val newIdentity =
            identity(
                "00000000-0000-0000-0000-000000000126",
                oldIdentity.keycloakUserId,
                "NewPlayer",
                setOf("/new-group"),
            )
        identityRepository.replacePlayer(oldIdentity)
        startSync(Instant.parse("2030-01-01T00:00:01Z"))

        identityRepository.replaceAll(listOf(newIdentity), Instant.parse("2030-01-01T00:00:02Z"))

        assertNull(identityRepository.findByPlayerId(oldIdentity.playerId))
        assertEquals(newIdentity, identityRepository.findByPlayerId(newIdentity.playerId))
        assertEquals(0, groupCount(oldIdentity.playerId))
        assertEquals(IdentitySyncStatus.IDLE, identityRepository.currentSyncState().status)
        assertEquals(1, identityRepository.currentSyncState().playerCount)
    }

    @Test
    fun preservesNewerTargetedProjectionWhenOlderFullSnapshotCompletesLater() {
        val staleSnapshot =
            identity(
                "00000000-0000-0000-0000-000000000127",
                "keycloak-newer-targeted",
                "OldPlayer",
                setOf("/old-group"),
            )
        val newerTargeted =
            staleSnapshot.copy(
                minecraftUsername = "NewPlayer",
                normalizedUsername = "newplayer",
                groupPaths = setOf("/new-group"),
                syncedAt = Instant.parse("2030-01-01T00:00:02Z"),
            )
        startSync(Instant.parse("2030-01-01T00:00:01Z"))
        identityRepository.replacePlayer(newerTargeted)

        identityRepository.replaceAll(listOf(staleSnapshot), Instant.parse("2030-01-01T00:00:03Z"))

        assertEquals(newerTargeted, identityRepository.findByPlayerId(newerTargeted.playerId))
        assertEquals(IdentitySyncStatus.IDLE, identityRepository.currentSyncState().status)
        assertEquals(1, identityRepository.currentSyncState().playerCount)
    }

    @Test
    fun preservesTargetedIdentityCreatedAfterOlderFullSnapshotStarted() {
        val newerTargeted =
            identity(
                    "00000000-0000-0000-0000-000000000128",
                    "keycloak-created-during-full",
                    "NewPlayer",
                    setOf("/new-group"),
                )
                .copy(syncedAt = Instant.parse("2030-01-01T00:00:02Z"))
        startSync(Instant.parse("2030-01-01T00:00:01Z"))
        identityRepository.replacePlayer(newerTargeted)

        identityRepository.replaceAll(emptyList(), Instant.parse("2030-01-01T00:00:03Z"))

        assertEquals(newerTargeted, identityRepository.findByPlayerId(newerTargeted.playerId))
        assertEquals(IdentitySyncStatus.IDLE, identityRepository.currentSyncState().status)
        assertEquals(1, identityRepository.currentSyncState().playerCount)
    }

    @Test
    fun marksSyncFailureAfterRunning() {
        val startedAt = Instant.parse("2030-01-01T00:00:00Z")
        val failedAt = Instant.parse("2030-01-01T00:00:02Z")

        startSync(startedAt)
        identityRepository.markSyncFailed(failedAt, "keycloak_unavailable")

        val state = identityRepository.currentSyncState()
        assertEquals(IdentitySyncStatus.FAILED, state.status)
        assertEquals(failedAt, state.completedAt)
        assertEquals(2_000, state.durationMs)
        assertEquals("keycloak_unavailable", state.failureReason)
    }

    @Test
    fun rejectsOverlappingSyncStartAndPreservesRunningSyncForCompletion() {
        val existing =
            identity(
                "00000000-0000-0000-0000-000000000122",
                "keycloak-overlapping-completion",
                "CurrentPlayer",
            )
        val firstStartedAt = Instant.parse("2030-01-01T00:00:00Z")
        identityRepository.replacePlayer(existing)
        startSync(firstStartedAt)

        assertFalse(
            identityRepository.tryMarkSyncRunning(
                Instant.parse("2030-01-01T00:00:04Z"),
                Instant.parse("2029-12-31T18:00:04Z"),
            )
        )

        assertEquals(firstStartedAt, identityRepository.currentSyncState().startedAt)
        identityRepository.replaceAll(listOf(existing), Instant.parse("2030-01-01T00:00:05Z"))
        assertEquals(5_000, identityRepository.currentSyncState().durationMs)
    }

    @Test
    fun rejectsOverlappingSyncStartAndPreservesRunningSyncForFailure() {
        val firstStartedAt = Instant.parse("2030-01-01T00:00:00Z")
        startSync(firstStartedAt)

        assertFalse(
            identityRepository.tryMarkSyncRunning(
                Instant.parse("2030-01-01T00:00:04Z"),
                Instant.parse("2029-12-31T18:00:04Z"),
            )
        )

        assertEquals(firstStartedAt, identityRepository.currentSyncState().startedAt)
        identityRepository.markSyncFailed(
            Instant.parse("2030-01-01T00:00:05Z"),
            "keycloak_unavailable",
        )
        assertEquals(5_000, identityRepository.currentSyncState().durationMs)
    }

    @Test
    fun preservesRunningSyncAtTheStalenessThreshold() {
        val firstStartedAt = Instant.parse("2030-01-01T00:00:00Z")
        val secondStartedAt = Instant.parse("2030-01-01T06:00:00Z")
        startSync(firstStartedAt)

        val started =
            identityRepository.tryMarkSyncRunning(secondStartedAt, staleBefore = firstStartedAt)

        assertEquals(false, started)
        assertEquals(firstStartedAt, identityRepository.currentSyncState().startedAt)
    }

    @Test
    fun atomicallyReplacesRunningSyncOlderThanTheStalenessThreshold() {
        val firstStartedAt = Instant.parse("2030-01-01T00:00:00Z")
        val secondStartedAt = Instant.parse("2030-01-01T06:00:00.001Z")
        startSync(firstStartedAt)

        val started =
            identityRepository.tryMarkSyncRunning(
                secondStartedAt,
                staleBefore = secondStartedAt.minusSeconds(6 * 60 * 60),
            )

        assertEquals(true, started)
        assertEquals(IdentitySyncStatus.RUNNING, identityRepository.currentSyncState().status)
        assertEquals(secondStartedAt, identityRepository.currentSyncState().startedAt)
    }

    @Test
    fun rejectsStaleCompletionAfterNewerSyncFailure() {
        val existing =
            identity(
                "00000000-0000-0000-0000-000000000113",
                "keycloak-stale-completion",
                "CurrentPlayer",
            )
        identityRepository.replacePlayer(existing)
        startSync(Instant.parse("2030-01-01T00:00:00Z"))
        identityRepository.markSyncFailed(Instant.parse("2030-01-01T00:00:01Z"), "newer_failure")
        val newerState = identityRepository.currentSyncState()

        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException::class.java) {
            identityRepository.replaceAll(
                listOf(existing.copy(minecraftUsername = "StalePlayer")),
                Instant.parse("2030-01-01T00:00:02Z"),
            )
        }

        assertEquals(existing, identityRepository.findByPlayerId(existing.playerId))
        assertEquals(newerState, identityRepository.currentSyncState())
    }

    @Test
    fun rejectsSyncFailureWhileIdle() {
        val idleState = identityRepository.currentSyncState()

        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException::class.java) {
            identityRepository.markSyncFailed(
                Instant.parse("2030-01-01T00:00:01Z"),
                "invalid_failure",
            )
        }

        assertEquals(idleState, identityRepository.currentSyncState())
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
        startSync(Instant.parse("2030-01-01T00:00:00Z"))

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

    private fun startSync(startedAt: Instant) {
        assertTrue(identityRepository.tryMarkSyncRunning(startedAt, staleBefore = startedAt))
    }

    private fun groupCount(playerId: UUID): Int =
        dataSource.connection.use { connection ->
            connection
                .prepareStatement(
                    "SELECT COUNT(*) FROM permission_player_keycloak_groups WHERE player_id = ?"
                )
                .use { statement ->
                    statement.setObject(1, playerId)
                    statement.executeQuery().use { rows ->
                        check(rows.next())
                        rows.getInt(1)
                    }
                }
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
