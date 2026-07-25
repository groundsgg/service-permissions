package gg.grounds.permissions.sync

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.persistence.PermissionRepository
import java.util.Optional
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

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
    fun rejectsPlayerRoleGrantsInGlobalSnapshots() {
        val error =
            assertThrows(IllegalArgumentException::class.java) {
                GlobalPermissionSnapshot(
                    snapshotId = "snapshot-1",
                    roles = emptyList(),
                    roleGrants = emptyList(),
                    inheritance = emptyList(),
                    catalogEntries = emptyList(),
                    keycloakMappings = emptyList(),
                    playerRoleGrants = listOf(SyncPlayerGrant("must-never-be-accepted")),
                )
            }

        assertEquals("playerRoleGrants must not be provided", error.message)
    }

    @Test
    fun preservesDefaultRoleWireNameDuringSnapshotRoundTrip() {
        val mapper = ObjectMapper().registerModule(KotlinModule.Builder().build())
        val json =
            """
            {
              "schemaVersion": 1,
              "sourceEnvironment": "prod",
              "sourceServiceVersion": "1.2.3",
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
        val serialized = mapper.writeValueAsString(snapshot)
        assertEquals(true, serialized.contains("\"default\":true"))
        assertEquals(true, serialized.contains("\"schemaVersion\":1"))
        assertEquals(true, serialized.contains("\"sourceEnvironment\":\"prod\""))
        assertEquals(true, serialized.contains("\"sourceServiceVersion\":\"1.2.3\""))
        assertEquals(true, serialized.contains("\"snapshotId\":\"snapshot-1\""))
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

    @Test
    fun projectSnapshotsAlwaysDeclareProjectSourceEnvironment() {
        val repository = mock<PermissionRepository>()
        whenever(repository.permissionProjectSnapshot())
            .thenReturn(
                PermissionProjectSnapshot(
                    roles = emptyList(),
                    roleGrants = emptyList(),
                    inheritance = emptyList(),
                    catalogEntries = emptyList(),
                    keycloakMappings = emptyList(),
                )
            )

        val snapshot =
            PermissionSyncService(
                    repository = repository,
                    instanceEnvironmentConfig = Optional.of(" "),
                    serviceVersion = "test-version",
                )
                .snapshot()

        assertEquals(1, snapshot.schemaVersion)
        assertEquals("project", snapshot.sourceEnvironment)
        assertEquals("test-version", snapshot.sourceServiceVersion)
    }

    @Test
    fun productionTargetsAcceptStageSnapshots() {
        assertEquals(
            emptyList<SyncChange>(),
            serviceFor("prod").preview(compatibleSnapshot("stage")).changes,
        )
    }

    @Test
    fun projectTargetsAcceptProductionSnapshots() {
        assertEquals(
            emptyList<SyncChange>(),
            serviceFor(" ").preview(compatibleSnapshot("prod")).changes,
        )
    }

    @Test
    fun legacySnapshotsWithoutMetadataReportUnsupportedSchema() {
        val error =
            assertThrows(PermissionSyncConflictException::class.java) {
                serviceFor("stage")
                    .preview(
                        compatibleSnapshot(sourceEnvironment = "prod")
                            .copy(schemaVersion = 0, sourceEnvironment = "")
                    )
            }

        assertEquals(PermissionSyncConflictReason.UNSUPPORTED_SCHEMA, error.reason)
    }

    private fun serviceFor(instanceEnvironment: String): PermissionSyncService {
        val repository = mock<PermissionRepository>()
        whenever(repository.permissionProjectSnapshot()).thenReturn(emptyProjectSnapshot())
        return PermissionSyncService(repository, Optional.of(instanceEnvironment), "test-version")
    }

    private fun compatibleSnapshot(sourceEnvironment: String) =
        GlobalPermissionSnapshot(
            schemaVersion = 1,
            sourceEnvironment = sourceEnvironment,
            sourceServiceVersion = "test-version",
            snapshotId = "snapshot-1",
            roles = emptyList(),
            roleGrants = emptyList(),
            inheritance = emptyList(),
            catalogEntries = emptyList(),
        )

    private fun emptyProjectSnapshot() =
        PermissionProjectSnapshot(
            roles = emptyList(),
            roleGrants = emptyList(),
            inheritance = emptyList(),
            catalogEntries = emptyList(),
            keycloakMappings = emptyList(),
        )

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
