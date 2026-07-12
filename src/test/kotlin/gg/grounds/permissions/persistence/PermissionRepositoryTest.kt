package gg.grounds.permissions.persistence

import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.sync.GlobalPermissionSnapshot
import gg.grounds.permissions.sync.PermissionSyncAction
import gg.grounds.permissions.sync.SyncAction
import gg.grounds.permissions.sync.SyncEntityType
import gg.grounds.permissions.sync.SyncRole
import gg.grounds.permissions.sync.SyncRoleGrant
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import java.time.Instant
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
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

    @BeforeEach
    fun resetDatabase() {
        repository.deleteAllPermissionData()
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
                    keycloakGroups = setOf("/staff"),
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
        assertEquals(1, input.playerGrants.count { it.playerId == playerId })
        assertEquals(1, repository.listCatalogEntries().size)
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
}
