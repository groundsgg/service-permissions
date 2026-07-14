package gg.grounds.permissions.persistence

import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionRoleAssignmentSource
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.identity.IdentityProjectionUnavailableException
import gg.grounds.permissions.identity.IdentitySyncStatus
import gg.grounds.permissions.identity.ProjectedPlayerIdentity
import gg.grounds.permissions.sync.GlobalPermissionSnapshot
import gg.grounds.permissions.sync.PermissionSyncAction
import gg.grounds.permissions.sync.SyncAction
import gg.grounds.permissions.sync.SyncEntityType
import gg.grounds.permissions.sync.SyncInheritance
import gg.grounds.permissions.sync.SyncKeycloakMapping
import gg.grounds.permissions.sync.SyncRole
import gg.grounds.permissions.sync.SyncRoleGrant
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import java.time.Instant
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
class PermissionRepositoryTest {

    @Inject lateinit var repository: PermissionRepository

    @Inject lateinit var identityRepository: PlayerIdentityRepository

    @BeforeEach
    fun resetDatabase() {
        repository.deleteAllPermissionData()
    }

    @Test
    fun deletesProjectedIdentitiesAndResetsIdentitySyncState() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000110")
        identityRepository.replacePlayer(
            ProjectedPlayerIdentity(
                playerId = playerId,
                keycloakUserId = "keycloak-cleanup",
                minecraftUsername = "CleanupPlayer",
                normalizedUsername = "cleanupplayer",
                groupPaths = setOf("/staff"),
                syncedAt = Instant.parse("2030-01-01T00:00:00Z"),
                sourceUpdatedAt = null,
            )
        )
        identityRepository.markSyncRunning(Instant.parse("2030-01-01T00:00:00Z"))
        identityRepository.replaceAll(
            listOf(identityRepository.findByPlayerId(playerId)!!),
            Instant.parse("2030-01-01T00:00:01Z"),
        )
        identityRepository.markSyncRunning(Instant.parse("2030-01-01T00:00:02Z"))
        identityRepository.markSyncFailed(Instant.parse("2030-01-01T00:00:03Z"), "cleanup_failure")
        val populatedState = identityRepository.currentSyncState()
        assertEquals(IdentitySyncStatus.FAILED, populatedState.status)
        assertEquals(Instant.parse("2030-01-01T00:00:02Z"), populatedState.startedAt)
        assertEquals(Instant.parse("2030-01-01T00:00:03Z"), populatedState.completedAt)
        assertEquals(Instant.parse("2030-01-01T00:00:01Z"), populatedState.lastSuccessAt)
        assertEquals(1_000, populatedState.durationMs)
        assertEquals(1, populatedState.playerCount)
        assertEquals("cleanup_failure", populatedState.failureReason)

        repository.deleteAllPermissionData()

        assertEquals(null, identityRepository.findByPlayerId(playerId))
        val state = identityRepository.currentSyncState()
        assertEquals(IdentitySyncStatus.IDLE, state.status)
        assertNull(state.startedAt)
        assertNull(state.completedAt)
        assertNull(state.lastSuccessAt)
        assertNull(state.durationMs)
        assertEquals(0, state.playerCount)
        assertNull(state.failureReason)
    }

    @Test
    fun writesPermissionPolicyAndLoadsEffectiveInput() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000123")
        val directPlayerGrantId = UUID.fromString("00000000-0000-0000-0000-000000000201")
        val playerRoleGrantId = UUID.fromString("00000000-0000-0000-0000-000000000202")
        val groupMappingId = UUID.fromString("00000000-0000-0000-0000-000000000203")
        val roleGrantId = UUID.fromString("00000000-0000-0000-0000-000000000204")
        val expiresAt = Instant.parse("2030-01-01T00:00:00Z")

        repository.createRole(
            RoleRecord(
                key = "default",
                name = "Default",
                description = "Default player role",
                prefix = "[D]",
                color = "green",
                sortOrder = 100,
                metadata = mapOf("source" to "test"),
                isDefault = true,
            )
        )
        repository.createRole(RoleRecord(key = "moderator", name = "Moderator", sortOrder = 50))
        repository.addRoleInheritance(childRoleKey = "moderator", parentRoleKey = "default")
        repository.createRoleGrant(
            RoleGrantRecord(
                id = roleGrantId,
                roleKey = "moderator",
                effect = PermissionEffect.ALLOW,
                pattern = "grounds.command.moderate",
                scope = PermissionScope(PermissionScopeKind.SERVER_TYPE, "paper"),
                expiresAt = expiresAt,
            )
        )
        repository.createPlayerRoleGrant(
            PlayerRoleGrantRecord(
                id = playerRoleGrantId,
                playerId = playerId,
                roleKey = "moderator",
                expiresAt = expiresAt,
            )
        )
        repository.createPlayerGrant(
            PlayerGrantRecord(
                id = directPlayerGrantId,
                playerId = playerId,
                effect = PermissionEffect.DENY,
                pattern = "grounds.command.op",
                scope = PermissionScope(PermissionScopeKind.GLOBAL),
                expiresAt = expiresAt,
            )
        )
        repository.createKeycloakGroupMapping(
            KeycloakGroupMappingRecord(
                id = groupMappingId,
                keycloakGroup = "/staff",
                roleKey = "moderator",
                expiresAt = expiresAt,
            )
        )
        val syncedAt = Instant.now()
        identityRepository.markSyncRunning(syncedAt.minusSeconds(1))
        identityRepository.replaceAll(
            listOf(
                ProjectedPlayerIdentity(
                    playerId = playerId,
                    keycloakUserId = "keycloak-policy-player",
                    minecraftUsername = "PolicyPlayer",
                    normalizedUsername = "policyplayer",
                    groupPaths = setOf("/staff"),
                    syncedAt = syncedAt,
                    sourceUpdatedAt = null,
                )
            ),
            syncedAt,
        )
        repository.upsertCatalogEntry(
            CatalogEntryRecord(
                key = "grounds.command.moderate",
                label = "Moderate",
                description = "Moderation command",
                source = "plugin-test",
                sourceVersion = "1.0.0",
                supportedScopes =
                    listOf(PermissionScopeKind.GLOBAL, PermissionScopeKind.SERVER_TYPE),
                custom = false,
                lastSeenAt = expiresAt,
            )
        )

        val versionAfterWrites = repository.currentPolicyVersion()
        val input =
            repository.policyFor(
                PermissionPolicyRequest(
                    playerId = playerId,
                    serverType = "paper",
                    serverId = "survival-1",
                )
            )

        assertTrue(versionAfterWrites > 1)
        assertEquals(versionAfterWrites, input.policyVersion)
        assertEquals(setOf("default", "moderator"), input.roles.mapTo(linkedSetOf()) { it.key })
        assertEquals(
            setOf("default"),
            input.roles.single { it.key == "moderator" }.inheritedRoleKeys,
        )
        assertEquals(1, input.roles.single { it.key == "moderator" }.grants.size)
        assertEquals(
            2,
            input.playerRoles.count { it.playerId == playerId && it.roleKey == "moderator" },
        )
        assertTrue(
            input.playerRoles.any {
                it.roleKey == "moderator" &&
                    it.assignmentSource == PermissionRoleAssignmentSource.GROUP_MAPPING &&
                    it.mappingId == groupMappingId
            }
        )
        assertEquals(1, input.playerGrants.count { it.playerId == playerId })
        assertEquals(1, repository.listCatalogEntries().size)
    }

    @Test
    fun freshProjectionWithoutAPlayerStillAllowsDefaultAndDirectRoles() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000124")
        repository.createRole(RoleRecord(key = "default", name = "Default", isDefault = true))
        repository.createRole(RoleRecord(key = "builder", name = "Builder"))
        repository.createPlayerRoleGrant(
            PlayerRoleGrantRecord(UUID.randomUUID(), playerId, "builder")
        )
        repository.createKeycloakGroupMapping(
            KeycloakGroupMappingRecord(UUID.randomUUID(), "/staff", "builder")
        )
        val syncedAt = Instant.now()
        identityRepository.markSyncRunning(syncedAt.minusSeconds(1))
        identityRepository.replaceAll(emptyList(), syncedAt)

        val input =
            repository.policyFor(
                PermissionPolicyRequest(playerId, serverType = "paper", serverId = "server-1")
            )

        assertEquals(setOf("default", "builder"), input.roles.mapTo(linkedSetOf()) { it.key })
        assertEquals(listOf("builder"), input.playerRoles.map { it.roleKey })
    }

    @Test
    fun staleProjectionRejectsPolicyEvaluationWhenGroupMappingsExist() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000125")
        repository.createRole(RoleRecord(key = "member", name = "Member"))
        repository.createKeycloakGroupMapping(
            KeycloakGroupMappingRecord(UUID.randomUUID(), "/players", "member")
        )

        assertThrows(IdentityProjectionUnavailableException::class.java) {
            repository.policyFor(
                PermissionPolicyRequest(playerId, serverType = "paper", serverId = "server-1")
            )
        }
    }

    @Test
    fun rejectsRoleInheritanceCycles() {
        repository.createRole(RoleRecord(key = "alpha", name = "Alpha"))
        repository.createRole(RoleRecord(key = "beta", name = "Beta"))

        repository.addRoleInheritance(childRoleKey = "beta", parentRoleKey = "alpha")

        val error =
            assertThrows(IllegalArgumentException::class.java) {
                repository.addRoleInheritance(childRoleKey = "alpha", parentRoleKey = "beta")
            }

        assertEquals(
            "Role inheritance would create a cycle (childRoleKey=alpha, parentRoleKey=beta)",
            error.message,
        )
    }

    @Test
    fun rejectsCustomCatalogUpsertOverRuntimeOwnedEntry() {
        repository.upsertCatalogEntry(
            CatalogEntryRecord(
                key = "grounds.command.fly",
                label = "Fly",
                source = "plugin-runtime",
                sourceVersion = "1.0.0",
                supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                custom = false,
            )
        )

        val error =
            assertThrows(IllegalArgumentException::class.java) {
                repository.upsertCatalogEntry(
                    CatalogEntryRecord(
                        key = "grounds.command.fly",
                        label = "Custom fly",
                        source = "custom",
                        sourceVersion = "admin",
                        supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                        custom = true,
                    )
                )
            }

        assertEquals(
            "Catalog entry is owned by runtime registration (permissionKey=grounds.command.fly)",
            error.message,
        )
        assertEquals(false, repository.listCatalogEntries().single().custom)
    }

    @Test
    fun rollsBackAllSnapshotChangesWhenOneEntityFails() {
        val snapshot =
            GlobalPermissionSnapshot(
                snapshotId = "rollback-test",
                roles = listOf(SyncRole("imported", "Imported")),
                roleGrants =
                    listOf(
                        SyncRoleGrant(
                            id = UUID.randomUUID(),
                            roleKey = "missing-role",
                            effect = PermissionEffect.ALLOW,
                            permissionPattern = "grounds.test",
                            scopeKind = PermissionScopeKind.GLOBAL,
                        )
                    ),
                inheritance = emptyList(),
                catalogEntries = emptyList(),
                keycloakMappings = emptyList(),
            )

        assertThrows(Exception::class.java) {
            repository.importPermissionSnapshot(
                snapshot,
                actions =
                    listOf(
                        PermissionSyncAction(SyncEntityType.ROLE, "imported", SyncAction.IMPORT)
                    ),
                actorUserId = "test-user",
            )
        }

        assertEquals(null, repository.getRole("imported"))
    }

    @Test
    fun removesNaturalKeyConflictsBeforeImportingReplacementMappings() {
        repository.createRole(RoleRecord(key = "moderator", name = "Moderator"))
        val projectMappingId = UUID.randomUUID()
        repository.createKeycloakGroupMapping(
            KeycloakGroupMappingRecord(projectMappingId, "/staff", "moderator")
        )
        val globalMappingId = UUID.randomUUID()
        val snapshot =
            GlobalPermissionSnapshot(
                snapshotId = "mapping-replacement",
                roles = emptyList(),
                roleGrants = emptyList(),
                inheritance = emptyList(),
                catalogEntries = emptyList(),
                keycloakMappings =
                    listOf(SyncKeycloakMapping(globalMappingId, "/staff", "moderator")),
            )

        repository.importPermissionSnapshot(
            snapshot,
            actions =
                listOf(
                    PermissionSyncAction(
                        SyncEntityType.KEYCLOAK_MAPPING,
                        projectMappingId.toString(),
                        SyncAction.REMOVE_PROJECT_ENTRY,
                    )
                ),
            actorUserId = "test-user",
        )

        assertEquals(globalMappingId, repository.listKeycloakGroupMappings().single().id)
    }

    @Test
    fun rejectsCyclicInheritanceInImportedSnapshot() {
        repository.createRole(RoleRecord(key = "alpha", name = "Alpha"))
        repository.createRole(RoleRecord(key = "beta", name = "Beta"))
        val snapshot =
            GlobalPermissionSnapshot(
                snapshotId = "cycle-test",
                roles = emptyList(),
                roleGrants = emptyList(),
                inheritance =
                    listOf(
                        SyncInheritance(parentRoleKey = "alpha", childRoleKey = "beta"),
                        SyncInheritance(parentRoleKey = "beta", childRoleKey = "alpha"),
                    ),
                catalogEntries = emptyList(),
            )

        assertThrows(IllegalArgumentException::class.java) {
            repository.importPermissionSnapshot(snapshot, emptyList(), "test-user")
        }
        assertTrue(repository.listRoleInheritances().isEmpty())
    }
}
