package gg.grounds.permissions.sync

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.persistence.PermissionRepository
import java.time.Instant
import java.util.Optional
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class PermissionSyncDiffTest {
    private val mapper = ObjectMapper().registerModule(KotlinModule.Builder().build())

    @Test
    fun fingerprintsEmptyPolicyWithCanonicalSha256() {
        assertEquals(
            "b0da458196945c34afe51284df3923283663aa945bef30a167d76cd627b64a6f",
            PermissionSnapshotFingerprint(mapper).calculate(emptyProjectSnapshot()),
        )
    }

    @Test
    fun fingerprintsPolicyIndependentlyOfCollectionMapAndScopeOrdering() {
        val first = fingerprintProjectSnapshot()
        val reordered =
            first.copy(
                roles =
                    first.roles.reversed().map { role ->
                        role.copy(
                            metadata = role.metadata.entries.reversed().associate { it.toPair() }
                        )
                    },
                roleGrants = first.roleGrants.reversed(),
                inheritance = first.inheritance.reversed(),
                catalogEntries =
                    first.catalogEntries.reversed().map { entry ->
                        entry.copy(
                            supportedScopes = entry.supportedScopes.reversed(),
                            lastSeenAt = entry.lastSeenAt?.plusSeconds(3600),
                        )
                    },
                keycloakMappings = first.keycloakMappings.reversed(),
            )

        val fingerprint = PermissionSnapshotFingerprint(mapper)

        assertEquals(fingerprint.calculate(first), fingerprint.calculate(reordered))
    }

    @Test
    fun fingerprintChangesForEverySyncablePolicyEntityAndSemanticExpiry() {
        val original = fingerprintProjectSnapshot()
        val changedSnapshots =
            listOf(
                original.copy(roles = original.roles.map { it.copy(name = "Changed ${it.name}") }),
                original.copy(
                    roleGrants =
                        original.roleGrants.map {
                            it.copy(expiresAt = Instant.parse("2031-01-01T00:00:00Z"))
                        }
                ),
                original.copy(
                    roleGrants =
                        original.roleGrants.map {
                            it.copy(startsAt = Instant.parse("2029-01-01T00:00:00Z"))
                        }
                ),
                original.copy(
                    inheritance =
                        listOf(SyncInheritance(parentRoleKey = "admin", childRoleKey = "guest"))
                ),
                original.copy(
                    catalogEntries = original.catalogEntries.map { it.copy(label = "Changed") }
                ),
                original.copy(
                    keycloakMappings =
                        original.keycloakMappings.map {
                            it.copy(expiresAt = Instant.parse("2031-01-01T00:00:00Z"))
                        }
                ),
                original.copy(
                    keycloakMappings =
                        original.keycloakMappings.map {
                            it.copy(startsAt = Instant.parse("2029-01-01T00:00:00Z"))
                        }
                ),
            )
        val fingerprint = PermissionSnapshotFingerprint(mapper)
        val originalFingerprint = fingerprint.calculate(original)

        changedSnapshots.forEach { changed ->
            assertNotEquals(originalFingerprint, fingerprint.calculate(changed))
        }
    }

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
    fun ignoresCatalogHeartbeatAndSupportedScopeOrderingWhenCalculatingDiff() {
        val project =
            emptyProjectSnapshot()
                .copy(
                    catalogEntries =
                        listOf(
                            SyncCatalogEntry(
                                permissionKey = "grounds.command.fly",
                                label = "Fly",
                                source = "runtime",
                                sourceVersion = "1.0.0",
                                supportedScopes =
                                    listOf(
                                        PermissionScopeKind.SERVER_TYPE,
                                        PermissionScopeKind.GLOBAL,
                                    ),
                                lastSeenAt = Instant.parse("2030-01-01T00:00:00Z"),
                            )
                        )
                )
        val global =
            compatibleSnapshot("stage")
                .copy(
                    catalogEntries =
                        listOf(
                            project.catalogEntries
                                .single()
                                .copy(
                                    supportedScopes =
                                        listOf(
                                            PermissionScopeKind.GLOBAL,
                                            PermissionScopeKind.SERVER_TYPE,
                                        ),
                                    lastSeenAt = Instant.parse("2030-01-02T00:00:00Z"),
                                )
                        )
                )

        assertEquals(emptyList<SyncChange>(), PermissionSyncDiff.calculate(project, global).changes)
    }

    @Test
    fun rejectsImportWithoutExplicitConflictActions() {
        val conflict = SyncChange(SyncEntityType.ROLE, "staff", SyncChangeKind.CONFLICT)
        val error =
            assertThrows(IllegalArgumentException::class.java) {
                PermissionSyncImportRequest(
                        snapshot = sampleSnapshot(),
                        expectedTargetFingerprint = "reviewed-target",
                        actions = emptyList(),
                    )
                    .validatedAgainst(PermissionSyncDiff(listOf(conflict), setOf(conflict)))
            }

        assertEquals(
            "Explicit action required (entityType=ROLE, technicalKey=staff)",
            error.message,
        )
    }

    @Test
    fun rejectsDuplicateSyncActionsDeterministically() {
        val conflict = SyncChange(SyncEntityType.ROLE, "staff", SyncChangeKind.CONFLICT)
        val error =
            assertThrows(IllegalArgumentException::class.java) {
                PermissionSyncImportRequest(
                        snapshot = sampleSnapshot(),
                        expectedTargetFingerprint = "reviewed-target",
                        actions =
                            listOf(
                                PermissionSyncAction(
                                    SyncEntityType.ROLE,
                                    "staff",
                                    SyncAction.IMPORT,
                                ),
                                PermissionSyncAction(
                                    SyncEntityType.ROLE,
                                    "staff",
                                    SyncAction.KEEP_PROJECT,
                                ),
                            ),
                    )
                    .validatedAgainst(PermissionSyncDiff(listOf(conflict), setOf(conflict)))
            }

        assertEquals("Duplicate sync action (entityType=ROLE, technicalKey=staff)", error.message)
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
                    fingerprint = PermissionSnapshotFingerprint(mapper),
                )
                .snapshot()

        assertEquals(1, snapshot.schemaVersion)
        assertEquals("project", snapshot.sourceEnvironment)
        assertEquals("test-version", snapshot.sourceServiceVersion)
    }

    @Test
    fun previewReturnsTheCurrentTargetFingerprint() {
        val repository = mock<PermissionRepository>()
        val target = fingerprintProjectSnapshot()
        whenever(repository.permissionProjectSnapshot()).thenReturn(target)
        val fingerprint = PermissionSnapshotFingerprint(mapper)

        val preview =
            PermissionSyncService(
                    repository = repository,
                    instanceEnvironmentConfig = Optional.of("prod"),
                    serviceVersion = "test-version",
                    fingerprint = fingerprint,
                )
                .preview(compatibleSnapshot("stage"))

        assertEquals(fingerprint.calculate(target), preview.targetFingerprint)
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
        return PermissionSyncService(
            repository,
            Optional.of(instanceEnvironment),
            "test-version",
            PermissionSnapshotFingerprint(mapper),
        )
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

    private fun fingerprintProjectSnapshot() =
        PermissionProjectSnapshot(
            roles =
                listOf(
                    SyncRole(
                        key = "guest",
                        name = "Guest",
                        metadata = linkedMapOf("z" to "last", "a" to "first"),
                    ),
                    SyncRole(key = "admin", name = "Admin"),
                ),
            roleGrants =
                listOf(
                    SyncRoleGrant(
                        id = UUID.fromString("00000000-0000-0000-0000-000000000002"),
                        roleKey = "guest",
                        effect = PermissionEffect.ALLOW,
                        permissionPattern = "grounds.chat",
                        scopeKind = PermissionScopeKind.SERVER_TYPE,
                        scopeValue = "paper",
                    ),
                    SyncRoleGrant(
                        id = UUID.fromString("00000000-0000-0000-0000-000000000001"),
                        roleKey = "admin",
                        effect = PermissionEffect.ALLOW,
                        permissionPattern = "grounds.*",
                        scopeKind = PermissionScopeKind.GLOBAL,
                        expiresAt = Instant.parse("2030-01-01T00:00:00Z"),
                    ),
                ),
            inheritance =
                listOf(
                    SyncInheritance(parentRoleKey = "admin", childRoleKey = "guest"),
                    SyncInheritance(parentRoleKey = "guest", childRoleKey = "visitor"),
                ),
            catalogEntries =
                listOf(
                    SyncCatalogEntry(
                        permissionKey = "grounds.chat",
                        label = "Chat",
                        source = "runtime",
                        sourceVersion = "1.0.0",
                        supportedScopes =
                            listOf(PermissionScopeKind.SERVER_TYPE, PermissionScopeKind.GLOBAL),
                        lastSeenAt = Instant.parse("2030-01-01T00:00:00Z"),
                    ),
                    SyncCatalogEntry(
                        permissionKey = "grounds.admin",
                        label = "Admin",
                        source = "custom",
                        sourceVersion = "admin",
                        supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                        custom = true,
                    ),
                ),
            keycloakMappings =
                listOf(
                    SyncKeycloakMapping(
                        id = UUID.fromString("00000000-0000-0000-0000-000000000004"),
                        keycloakGroup = "/guest",
                        roleKey = "guest",
                    ),
                    SyncKeycloakMapping(
                        id = UUID.fromString("00000000-0000-0000-0000-000000000003"),
                        keycloakGroup = "/admin",
                        roleKey = "admin",
                        expiresAt = Instant.parse("2030-01-01T00:00:00Z"),
                    ),
                ),
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
