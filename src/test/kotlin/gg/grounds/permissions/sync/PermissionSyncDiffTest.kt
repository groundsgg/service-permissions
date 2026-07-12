package gg.grounds.permissions.sync

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionScopeKind
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class PermissionSyncDiffTest {
    @Test
    fun rejectsPlayerGrantsInGlobalSnapshots() {
        val error =
            assertThrows(IllegalArgumentException::class.java) {
                GlobalPermissionSnapshot(
                    snapshotId = "snapshot-1",
                    roles = emptyList(),
                    roleGrants = emptyList(),
                    inheritance = emptyList(),
                    catalogEntries = emptyList(),
                    keycloakMappings = emptyList(),
                    playerGrants = listOf(SyncPlayerGrant("must-never-be-accepted")),
                )
            }

        assertEquals("playerGrants must not be provided", error.message)
    }

    @Test
    fun preservesDefaultRoleWireNameDuringSnapshotRoundTrip() {
        val mapper = ObjectMapper().registerModule(KotlinModule.Builder().build())
        val json =
            """
            {
              "snapshotId": "snapshot-1",
              "roles": [{"key":"admin","name":"Admin","default":true}],
              "roleGrants": [],
              "inheritance": [],
              "catalogEntries": []
            }
            """
                .trimIndent()

        val snapshot = mapper.readValue(json, GlobalPermissionSnapshot::class.java)

        assertEquals(true, snapshot.roles.single().isDefault)
        assertEquals(true, mapper.writeValueAsString(snapshot).contains("\"default\":true"))
    }

    @Test
    fun reportsGlobalOnlyConflictAndProjectOnlyEntries() {
        val project =
            PermissionProjectSnapshot(
                roles = listOf(SyncRole("staff", "Old staff")),
                roleGrants = emptyList(),
                inheritance = emptyList(),
                catalogEntries = emptyList(),
                keycloakMappings = emptyList(),
            )
        val global =
            GlobalPermissionSnapshot(
                snapshotId = "snapshot-1",
                roles = listOf(SyncRole("staff", "New staff"), SyncRole("new", "New")),
                roleGrants = emptyList(),
                inheritance = emptyList(),
                catalogEntries = emptyList(),
                keycloakMappings = emptyList(),
            )

        val diff = PermissionSyncDiff.calculate(project, global)

        assertEquals(
            setOf(
                SyncChange(SyncEntityType.ROLE, "staff", SyncChangeKind.CONFLICT),
                SyncChange(SyncEntityType.ROLE, "new", SyncChangeKind.IMPORT),
            ),
            diff.changes.toSet(),
        )
        assertEquals(emptySet<SyncChange>(), diff.projectOnlyEntries)
    }

    @Test
    fun preservesProjectOnlyEntriesUnlessExplicitlyRemoved() {
        val project =
            PermissionProjectSnapshot(
                roles = listOf(SyncRole("project-only", "Project")),
                roleGrants = emptyList(),
                inheritance = emptyList(),
                catalogEntries = emptyList(),
                keycloakMappings = emptyList(),
            )
        val global =
            GlobalPermissionSnapshot(
                snapshotId = "snapshot-1",
                roles = emptyList(),
                roleGrants = emptyList(),
                inheritance = emptyList(),
                catalogEntries = emptyList(),
                keycloakMappings = emptyList(),
            )

        val diff = PermissionSyncDiff.calculate(project, global)

        assertEquals(
            setOf(SyncChange(SyncEntityType.ROLE, "project-only", SyncChangeKind.PROJECT_ONLY)),
            diff.projectOnlyEntries,
        )
    }

    @Test
    fun rejectsImportWithoutExplicitConflictActions() {
        val conflict = SyncChange(SyncEntityType.ROLE, "staff", SyncChangeKind.CONFLICT)
        val error =
            assertThrows(IllegalArgumentException::class.java) {
                PermissionSyncImportRequest(snapshot = sampleSnapshot(), actions = emptyList())
                    .validatedAgainst(PermissionSyncDiff(listOf(conflict), setOf(conflict)))
            }

        assertEquals(
            "Explicit action required (entityType=ROLE, technicalKey=staff)",
            error.message,
        )
    }

    private fun sampleSnapshot() =
        GlobalPermissionSnapshot(
            snapshotId = "snapshot-1",
            roles = emptyList(),
            roleGrants =
                listOf(
                    SyncRoleGrant(
                        id = UUID.randomUUID(),
                        roleKey = "staff",
                        effect = PermissionEffect.ALLOW,
                        permissionPattern = "grounds.test",
                        scopeKind = PermissionScopeKind.GLOBAL,
                    )
                ),
            inheritance = emptyList(),
            catalogEntries = emptyList(),
            keycloakMappings = emptyList(),
        )
}
