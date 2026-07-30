package gg.grounds.permissions.persistence

import com.fasterxml.jackson.databind.ObjectMapper
import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionRoleAssignmentSource
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.identity.IdentityProjectionUnavailableException
import gg.grounds.permissions.identity.IdentitySyncStatus
import gg.grounds.permissions.identity.ProjectedPlayerIdentity
import gg.grounds.permissions.policy.PolicyEngine
import gg.grounds.permissions.sync.GlobalPermissionSnapshot
import gg.grounds.permissions.sync.PermissionSnapshotFingerprint
import gg.grounds.permissions.sync.PermissionSyncAction
import gg.grounds.permissions.sync.PermissionSyncConflictException
import gg.grounds.permissions.sync.PermissionSyncConflictReason
import gg.grounds.permissions.sync.SyncAction
import gg.grounds.permissions.sync.SyncEntityType
import gg.grounds.permissions.sync.SyncInheritance
import gg.grounds.permissions.sync.SyncKeycloakMapping
import gg.grounds.permissions.sync.SyncRole
import gg.grounds.permissions.sync.SyncRoleGrant
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Proxy
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
class PermissionRepositoryTest {

    private val testActor = "test-user"

    @Inject lateinit var repository: PermissionRepository

    @Inject lateinit var identityRepository: PlayerIdentityRepository

    @Inject lateinit var dataSource: DataSource

    @Inject lateinit var objectMapper: ObjectMapper

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
    fun deletesPlayerIdentityTombstones() {
        val deletedAt = Instant.parse("2030-01-01T00:00:05Z")
        val staleIdentity =
            ProjectedPlayerIdentity(
                playerId = UUID.fromString("00000000-0000-0000-0000-000000000111"),
                keycloakUserId = "keycloak-tombstone-cleanup",
                minecraftUsername = "CleanupPlayer",
                normalizedUsername = "cleanupplayer",
                groupPaths = emptySet(),
                syncedAt = deletedAt.minusSeconds(1),
                sourceUpdatedAt = null,
            )
        identityRepository.deleteByKeycloakUserId(staleIdentity.keycloakUserId, deletedAt)

        repository.deleteAllPermissionData()
        identityRepository.replacePlayer(staleIdentity)

        assertEquals(staleIdentity, identityRepository.findByPlayerId(staleIdentity.playerId))
    }

    @Test
    fun searchesRoleGrantsAcrossColumnsAndPaginatesAfterCounting() {
        repository.createRole(RoleRecord(key = "moderator", name = "Moderator"))
        listOf(
                RoleGrantRecord(
                    id = UUID.fromString("00000000-0000-0000-0000-000000000301"),
                    roleKey = "moderator",
                    effect = PermissionEffect.ALLOW,
                    pattern = "grounds.command.fly",
                    scope = PermissionScope(PermissionScopeKind.GLOBAL),
                ),
                RoleGrantRecord(
                    id = UUID.fromString("00000000-0000-0000-0000-000000000302"),
                    roleKey = "moderator",
                    effect = PermissionEffect.DENY,
                    pattern = "grounds.command.kick",
                    scope = PermissionScope(PermissionScopeKind.SERVER_TYPE, "Paper"),
                ),
                RoleGrantRecord(
                    id = UUID.fromString("00000000-0000-0000-0000-000000000303"),
                    roleKey = "moderator",
                    effect = PermissionEffect.ALLOW,
                    pattern = "grounds.command.warn",
                    scope = PermissionScope(PermissionScopeKind.SERVER, "Lobby-1"),
                ),
            )
            .forEach(repository::createRoleGrant)

        val page =
            repository.searchRoleGrantRecords(
                roleKey = "moderator",
                query = "GrOuNdS.CoMmAnD",
                page = 2,
                perPage = 1,
                sortBy = "permission",
                sortDirection = "desc",
            )

        assertEquals(3, page.total)
        assertEquals(listOf("grounds.command.kick"), page.items.map { it.pattern })
        assertEquals(
            listOf("grounds.command.kick"),
            repository
                .searchRoleGrantRecords("moderator", "paper", 1, 20, "permission", "asc")
                .items
                .map { it.pattern },
        )
        assertEquals(
            listOf("grounds.command.kick"),
            repository
                .searchRoleGrantRecords("moderator", "deny", 1, 20, "permission", "asc")
                .items
                .map { it.pattern },
        )
    }

    @Test
    fun searchesPlayerGrantsAcrossColumnsWithCountingSortingAndPaging() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000126")
        listOf(
                PlayerGrantRecord(
                    UUID.fromString("00000000-0000-0000-0000-000000000381"),
                    playerId,
                    PermissionEffect.ALLOW,
                    "grounds.command.fly",
                    PermissionScope(PermissionScopeKind.GLOBAL),
                ),
                PlayerGrantRecord(
                    UUID.fromString("00000000-0000-0000-0000-000000000382"),
                    playerId,
                    PermissionEffect.DENY,
                    "grounds.command.kick",
                    PermissionScope(PermissionScopeKind.SERVER_TYPE, "paper"),
                    Instant.parse("2030-01-01T00:00:00Z"),
                ),
                PlayerGrantRecord(
                    UUID.fromString("00000000-0000-0000-0000-000000000383"),
                    UUID.fromString("00000000-0000-0000-0000-000000000127"),
                    PermissionEffect.DENY,
                    "grounds.command.kick",
                    PermissionScope(PermissionScopeKind.SERVER, "lobby"),
                ),
            )
            .forEach(repository::createPlayerGrant)

        val page =
            repository.searchPlayerGrantRecords(
                playerId = playerId,
                query = "PAPER",
                page = 1,
                perPage = 1,
                sortBy = "expiration",
                sortDirection = "desc",
            )

        assertEquals(1, page.total)
        assertEquals(listOf("grounds.command.kick"), page.items.map { it.pattern })
        assertEquals(
            listOf("grounds.command.kick"),
            repository
                .searchPlayerGrantRecords(playerId, "deny", 1, 20, "effect", "asc")
                .items
                .map { it.pattern },
        )
        assertEquals(
            listOf("grounds.command.fly", "grounds.command.kick"),
            repository
                .searchPlayerGrantRecords(playerId, "", 1, 20, "permission", "asc")
                .items
                .map { it.pattern },
        )
        assertEquals(
            listOf("grounds.command.fly", "grounds.command.kick"),
            repository.searchPlayerGrantRecords(playerId, "", 1, 20, "scope", "asc").items.map {
                it.pattern
            },
        )
    }

    @Test
    fun searchesGroupMappingsAcrossColumnsWithDeterministicSorting() {
        repository.createRole(RoleRecord(key = "builder", name = "Builder"))
        repository.createRole(RoleRecord(key = "moderator", name = "Moderator"))
        listOf(
                KeycloakGroupMappingRecord(
                    UUID.fromString("00000000-0000-0000-0000-000000000311"),
                    "/Staff/Builders",
                    "builder",
                ),
                KeycloakGroupMappingRecord(
                    UUID.fromString("00000000-0000-0000-0000-000000000312"),
                    "/staff/moderators",
                    "moderator",
                ),
                KeycloakGroupMappingRecord(
                    UUID.fromString("00000000-0000-0000-0000-000000000313"),
                    "/events/builders",
                    "builder",
                ),
            )
            .forEach(repository::createKeycloakGroupMapping)

        val descending =
            repository.searchKeycloakGroupMappings(
                query = "STAFF",
                page = 1,
                perPage = 20,
                sortBy = "group",
                sortDirection = "desc",
            )
        val roleMatch =
            repository.searchKeycloakGroupMappings(
                query = "builder",
                page = 2,
                perPage = 1,
                sortBy = "role",
                sortDirection = "asc",
            )

        assertEquals(
            listOf("/staff/moderators", "/Staff/Builders"),
            descending.items.map { it.keycloakGroup },
        )
        assertEquals(2, roleMatch.total)
        assertEquals(listOf("/events/builders"), roleMatch.items.map { it.keycloakGroup })
    }

    @Test
    fun searchesCatalogAcrossColumnsWithDeterministicSorting() {
        listOf(
                CatalogEntryRecord(
                    key = "grounds.command.fly",
                    label = "Flight",
                    description = "Allows creative movement",
                    source = "portal",
                    sourceVersion = "custom",
                    supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                    custom = true,
                ),
                CatalogEntryRecord(
                    key = "grounds.command.kick",
                    label = "Moderation",
                    description = "Removes a player",
                    source = "plugin-runtime",
                    sourceVersion = "2.0.0",
                    supportedScopes = listOf(PermissionScopeKind.SERVER_TYPE),
                    custom = false,
                    lastSeenAt = Instant.parse("2026-07-16T00:00:00Z"),
                ),
                CatalogEntryRecord(
                    key = "grounds.command.warn",
                    label = "Moderation",
                    description = "Warns a player",
                    source = "plugin-runtime",
                    sourceVersion = "2.0.0",
                    supportedScopes = listOf(PermissionScopeKind.SERVER),
                    custom = false,
                    lastSeenAt = Instant.parse("2026-07-17T00:00:00Z"),
                ),
            )
            .forEach(repository::upsertCatalogEntry)

        val page =
            repository.searchCatalogEntries(
                query = "PLAYER",
                page = 2,
                perPage = 1,
                sortBy = "label",
                sortDirection = "asc",
            )

        assertEquals(2, page.total)
        assertEquals(listOf("grounds.command.warn"), page.items.map { it.key })
        assertEquals(
            listOf("grounds.command.kick", "grounds.command.warn"),
            repository
                .searchCatalogEntries("PLUGIN-RUNTIME", 1, 20, "permission", "asc")
                .items
                .map { it.key },
        )
        assertEquals(
            listOf("grounds.command.warn", "grounds.command.kick", "grounds.command.fly"),
            repository.searchCatalogEntries("", 1, 20, "lastseen", "desc").items.map { it.key },
        )
    }

    @Test
    fun preservesUniqueRolePermissionGrantIdsInPolicySnapshots() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000135")
        val playerRoleGrantId = UUID.fromString("00000000-0000-0000-0000-000000000461")
        val firstRoleGrantId = UUID.fromString("00000000-0000-0000-0000-000000000462")
        val secondRoleGrantId = UUID.fromString("00000000-0000-0000-0000-000000000463")
        repository.createRole(RoleRecord(key = "operator", name = "Operator"))
        repository.createPlayerRoleGrant(
            PlayerRoleGrantRecord(playerRoleGrantId, playerId, "operator")
        )
        listOf(firstRoleGrantId, secondRoleGrantId).forEach { roleGrantId ->
            repository.createRoleGrant(
                RoleGrantRecord(
                    roleGrantId,
                    "operator",
                    PermissionEffect.ALLOW,
                    "grounds.command.teleport",
                    PermissionScope(PermissionScopeKind.GLOBAL),
                )
            )
        }

        val snapshot =
            PolicyEngine.createSnapshot(
                playerId,
                repository.policyFor(PermissionPolicyRequest(playerId, "", "")),
            )
        assertEquals(
            setOf(firstRoleGrantId, secondRoleGrantId),
            snapshot.allowPatterns.mapTo(linkedSetOf()) { it.origin.permissionGrantId },
        )
    }

    @Test
    fun writesPermissionPolicyAndLoadsEffectiveInput() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000123")
        val directPlayerGrantId = UUID.fromString("00000000-0000-0000-0000-000000000201")
        val playerRoleGrantId = UUID.fromString("00000000-0000-0000-0000-000000000202")
        val groupMappingId = UUID.fromString("00000000-0000-0000-0000-000000000203")
        val roleGrantId = UUID.fromString("00000000-0000-0000-0000-000000000204")
        val startsAt = Instant.parse("2029-01-01T00:00:00Z")
        val expiresAt = Instant.parse("2030-01-01T00:00:00Z")

        repository.createRole(
            testActor,
            RoleRecord(
                key = "default",
                name = "Default",
                description = "Default player role",
                prefix = "[D]",
                color = "green",
                sortOrder = 100,
                metadata = mapOf("source" to "test"),
                isDefault = true,
            ),
        )
        repository.createRole(
            testActor,
            RoleRecord(key = "moderator", name = "Moderator", sortOrder = 50),
        )
        repository.addRoleInheritance(
            actorUserId = testActor,
            childRoleKey = "moderator",
            parentRoleKey = "default",
        )
        repository.createRoleGrant(
            testActor,
            RoleGrantRecord(
                id = roleGrantId,
                roleKey = "moderator",
                effect = PermissionEffect.ALLOW,
                pattern = "grounds.command.moderate",
                scope = PermissionScope(PermissionScopeKind.SERVER_TYPE, "paper"),
                startsAt = startsAt,
                expiresAt = expiresAt,
            ),
        )
        repository.createPlayerRoleGrant(
            testActor,
            PlayerRoleGrantRecord(
                id = playerRoleGrantId,
                playerId = playerId,
                roleKey = "moderator",
                startsAt = startsAt,
                expiresAt = expiresAt,
            ),
        )
        repository.createPlayerGrant(
            testActor,
            PlayerGrantRecord(
                id = directPlayerGrantId,
                playerId = playerId,
                effect = PermissionEffect.DENY,
                pattern = "grounds.command.op",
                scope = PermissionScope(PermissionScopeKind.GLOBAL),
                startsAt = startsAt,
                expiresAt = expiresAt,
            ),
        )
        repository.createKeycloakGroupMapping(
            testActor,
            KeycloakGroupMappingRecord(
                id = groupMappingId,
                keycloakGroup = "/staff",
                roleKey = "moderator",
                startsAt = startsAt,
                expiresAt = expiresAt,
            ),
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
            testActor,
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
            ),
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
            startsAt,
            input.roles.single { it.key == "moderator" }.grants.single().startsAt,
        )
        assertEquals(
            2,
            input.playerRoles.count { it.playerId == playerId && it.roleKey == "moderator" },
        )
        assertTrue(
            input.playerRoles.any {
                it.roleKey == "moderator" &&
                    it.assignmentSource == PermissionRoleAssignmentSource.GROUP_MAPPING &&
                    it.mappingId == groupMappingId &&
                    it.startsAt == startsAt
            }
        )
        assertTrue(
            input.playerRoles.any {
                it.roleKey == "moderator" &&
                    it.assignmentSource == PermissionRoleAssignmentSource.DIRECT &&
                    it.startsAt == startsAt
            }
        )
        assertEquals(1, input.playerGrants.count { it.playerId == playerId })
        assertEquals(startsAt, input.playerGrants.single().assignmentStartsAt)
        assertEquals(startsAt, input.playerGrants.single().grant.startsAt)
        val projectSnapshot = repository.permissionProjectSnapshot()
        assertEquals(startsAt, projectSnapshot.roleGrants.single().startsAt)
        assertEquals(startsAt, projectSnapshot.keycloakMappings.single().startsAt)
        assertEquals(1, repository.listCatalogEntries().size)
    }

    @Test
    fun freshProjectionWithoutAPlayerStillAllowsDefaultAndDirectRoles() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000124")
        repository.createRole(
            testActor,
            RoleRecord(key = "default", name = "Default", isDefault = true),
        )
        repository.createRole(testActor, RoleRecord(key = "builder", name = "Builder"))
        repository.createPlayerRoleGrant(
            testActor,
            PlayerRoleGrantRecord(UUID.randomUUID(), playerId, "builder"),
        )
        repository.createKeycloakGroupMapping(
            testActor,
            KeycloakGroupMappingRecord(UUID.randomUUID(), "/staff", "builder"),
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
        repository.createRole(testActor, RoleRecord(key = "member", name = "Member"))
        repository.createKeycloakGroupMapping(
            testActor,
            KeycloakGroupMappingRecord(UUID.randomUUID(), "/players", "member"),
        )

        assertThrows(IdentityProjectionUnavailableException::class.java) {
            repository.policyFor(
                PermissionPolicyRequest(playerId, serverType = "paper", serverId = "server-1")
            )
        }
    }

    @Test
    fun rejectsRoleInheritanceCycles() {
        repository.createRole(testActor, RoleRecord(key = "alpha", name = "Alpha"))
        repository.createRole(testActor, RoleRecord(key = "beta", name = "Beta"))

        repository.addRoleInheritance(
            actorUserId = testActor,
            childRoleKey = "beta",
            parentRoleKey = "alpha",
        )

        val error =
            assertThrows(IllegalArgumentException::class.java) {
                repository.addRoleInheritance(
                    actorUserId = testActor,
                    childRoleKey = "alpha",
                    parentRoleKey = "beta",
                )
            }

        assertEquals(
            "Role inheritance would create a cycle (childRoleKey=alpha, parentRoleKey=beta)",
            error.message,
        )
    }

    @Test
    fun rejectsCustomCatalogUpsertOverRuntimeOwnedEntry() {
        repository.upsertCatalogEntry(
            testActor,
            CatalogEntryRecord(
                key = "grounds.command.fly",
                label = "Fly",
                source = "plugin-runtime",
                sourceVersion = "1.0.0",
                supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                custom = false,
            ),
        )

        val error =
            assertThrows(IllegalArgumentException::class.java) {
                repository.upsertCatalogEntry(
                    testActor,
                    CatalogEntryRecord(
                        key = "grounds.command.fly",
                        label = "Custom fly",
                        source = "custom",
                        sourceVersion = "admin",
                        supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                        custom = true,
                    ),
                )
            }

        assertEquals(
            "Catalog entry is owned by runtime registration (permissionKey=grounds.command.fly)",
            error.message,
        )
        assertEquals(false, repository.listCatalogEntries().single().custom)
    }

    @Test
    fun `runtime manifest replacement removes stale entries from the same source`() {
        repository.replaceRuntimeManifest(
            runtimeManifest(
                source = "plugin-runtime",
                registeredAt = Instant.parse("2030-01-01T00:00:00Z"),
                permissions =
                    listOf(
                        runtimeCatalogEntry("grounds.command.fly", "Fly"),
                        runtimeCatalogEntry("grounds.command.kick", "Kick"),
                    ),
            )
        )

        repository.replaceRuntimeManifest(
            runtimeManifest(
                source = "plugin-runtime",
                registeredAt = Instant.parse("2030-01-02T00:00:00Z"),
                permissions = listOf(runtimeCatalogEntry("grounds.command.fly", "Flight")),
            )
        )

        assertEquals(
            listOf(
                CatalogEntryRecord(
                    key = "grounds.command.fly",
                    label = "Flight",
                    source = "plugin-runtime",
                    sourceVersion = "1.0.0",
                    supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                    custom = false,
                    lastSeenAt = Instant.parse("2030-01-02T00:00:00Z"),
                )
            ),
            repository.listCatalogEntries(),
        )
    }

    @Test
    fun `runtime manifest replacement removes all stale entries for an empty list`() {
        repository.replaceRuntimeManifest(
            runtimeManifest(
                source = "plugin-runtime",
                permissions = listOf(runtimeCatalogEntry("grounds.command.fly", "Fly")),
            )
        )

        repository.replaceRuntimeManifest(
            runtimeManifest(source = "plugin-runtime", permissions = emptyList())
        )

        assertEquals(emptyList<CatalogEntryRecord>(), repository.listCatalogEntries())
    }

    @Test
    fun `runtime manifest replacement rejects a key owned by another source without partial writes`() {
        repository.replaceRuntimeManifest(
            runtimeManifest(
                source = "first-plugin",
                permissions = listOf(runtimeCatalogEntry("grounds.command.fly", "Fly")),
            )
        )

        val error =
            assertThrows(CatalogSourceConflictException::class.java) {
                repository.replaceRuntimeManifest(
                    runtimeManifest(
                        source = "second-plugin",
                        permissions =
                            listOf(
                                runtimeCatalogEntry("grounds.command.kick", "Kick"),
                                runtimeCatalogEntry("grounds.command.fly", "Flight"),
                            ),
                    )
                )
            }

        assertEquals("grounds.command.fly", error.permissionKey)
        assertEquals("first-plugin", error.existingSource)
        assertEquals("second-plugin", error.requestedSource)
        assertEquals(
            listOf(
                CatalogEntryRecord(
                    key = "grounds.command.fly",
                    label = "Fly",
                    source = "first-plugin",
                    sourceVersion = "1.0.0",
                    supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                    custom = false,
                    lastSeenAt = Instant.parse("2030-01-01T00:00:00Z"),
                )
            ),
            repository.listCatalogEntries(),
        )
    }

    @Test
    fun `runtime manifest replacement preserves custom entries`() {
        repository.upsertCatalogEntry(
            CatalogEntryRecord(
                key = "grounds.command.fly",
                label = "Custom fly",
                source = "portal",
                sourceVersion = "custom",
                supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                custom = true,
            )
        )

        assertThrows(CatalogSourceConflictException::class.java) {
            repository.replaceRuntimeManifest(
                runtimeManifest(
                    source = "plugin-runtime",
                    permissions = listOf(runtimeCatalogEntry("grounds.command.fly", "Fly")),
                )
            )
        }

        assertEquals("Custom fly", repository.listCatalogEntries().single().label)
        assertTrue(repository.listCatalogEntries().single().custom)
    }

    @Test
    fun `repeating the same runtime manifest is idempotent`() {
        val registration =
            runtimeManifest(
                source = "plugin-runtime",
                registeredAt = Instant.parse("2030-01-01T00:00:00Z"),
                permissions = listOf(runtimeCatalogEntry("grounds.command.fly", "Fly")),
            )

        repository.replaceRuntimeManifest(registration)
        repository.replaceRuntimeManifest(registration)

        assertEquals(
            listOf(
                CatalogEntryRecord(
                    key = "grounds.command.fly",
                    label = "Fly",
                    source = "plugin-runtime",
                    sourceVersion = "1.0.0",
                    supportedScopes = listOf(PermissionScopeKind.GLOBAL),
                    custom = false,
                    lastSeenAt = Instant.parse("2030-01-01T00:00:00Z"),
                )
            ),
            repository.listCatalogEntries(),
        )
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
                expectedTargetFingerprint = currentFingerprint(),
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
    fun recordsSyncImportsWithTheProvidedAuditActor() {
        val reviewedTargetFingerprint = currentFingerprint()
        repository.importPermissionSnapshot(
            GlobalPermissionSnapshot(
                schemaVersion = 1,
                sourceEnvironment = "prod",
                sourceServiceVersion = "1.2.3",
                snapshotId = "audit-actor-boundary",
                roles = listOf(SyncRole("imported-role", "Imported role")),
                roleGrants = emptyList(),
                inheritance = emptyList(),
                catalogEntries = emptyList(),
                keycloakMappings = emptyList(),
            ),
            expectedTargetFingerprint = reviewedTargetFingerprint,
            actions =
                listOf(
                    PermissionSyncAction(SyncEntityType.ROLE, "imported-role", SyncAction.IMPORT)
                ),
            actorUserId = "sync-user",
        )

        val event =
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("permission.sync.imported"))
                )
                .items
                .single()

        assertEquals("sync-user", event.actorUserId)
        assertEquals("audit-actor-boundary", event.metadata.get("snapshotId").asText())
        assertEquals("prod", event.metadata.get("sourceEnvironment").asText())
        assertEquals("1.2.3", event.metadata.get("sourceServiceVersion").asText())
        assertEquals(reviewedTargetFingerprint, event.metadata.get("targetFingerprint").asText())
        assertEquals("success", event.metadata.get("result").asText())
        assertEquals(
            "ROLE",
            event.metadata.get("selectedActions").get(0).get("entityType").asText(),
        )
        assertEquals(
            "imported-role",
            event.metadata.get("selectedActions").get(0).get("technicalKey").asText(),
        )
        assertEquals("IMPORT", event.metadata.get("selectedActions").get(0).get("action").asText())
    }

    @Test
    fun rejectsChangedTargetBeforeApplyingAnySnapshotWrites() {
        val reviewedTargetFingerprint = currentFingerprint()
        repository.createRole(
            testActor,
            RoleRecord(key = "changed-after-preview", name = "Changed"),
        )
        val policyVersionBeforeImport = repository.currentPolicyVersion()

        val error =
            assertThrows(PermissionSyncConflictException::class.java) {
                repository.importPermissionSnapshot(
                    GlobalPermissionSnapshot(
                        snapshotId = "stale-review",
                        roles = listOf(SyncRole("must-not-import", "Must not import")),
                        roleGrants = emptyList(),
                        inheritance = emptyList(),
                        catalogEntries = emptyList(),
                    ),
                    expectedTargetFingerprint = reviewedTargetFingerprint,
                    actions =
                        listOf(
                            PermissionSyncAction(
                                SyncEntityType.ROLE,
                                "must-not-import",
                                SyncAction.IMPORT,
                            )
                        ),
                    actorUserId = "sync-user",
                )
            }

        assertEquals(PermissionSyncConflictReason.TARGET_CHANGED, error.reason)
        assertNull(repository.getRole("must-not-import"))
        assertEquals(policyVersionBeforeImport, repository.currentPolicyVersion())
        assertTrue(
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("permission.sync.imported"))
                )
                .items
                .isEmpty()
        )
    }

    @Test
    fun rejectsDuplicateActionsWithoutWritesMetadataOrAudit() {
        repository.createRole(testActor, RoleRecord(key = "staff", name = "Project staff"))
        val reviewedTargetFingerprint = currentFingerprint()
        val policyVersionBeforeImport = repository.currentPolicyVersion()
        val syncMetadataBeforeImport = countSyncMetadata()

        val error =
            assertThrows(IllegalArgumentException::class.java) {
                repository.importPermissionSnapshot(
                    GlobalPermissionSnapshot(
                        snapshotId = "duplicate-actions",
                        roles = listOf(SyncRole("staff", "Global staff")),
                        roleGrants = emptyList(),
                        inheritance = emptyList(),
                        catalogEntries = emptyList(),
                    ),
                    expectedTargetFingerprint = reviewedTargetFingerprint,
                    actions =
                        listOf(
                            PermissionSyncAction(SyncEntityType.ROLE, "staff", SyncAction.IMPORT),
                            PermissionSyncAction(
                                SyncEntityType.ROLE,
                                "staff",
                                SyncAction.KEEP_PROJECT,
                            ),
                        ),
                    actorUserId = "sync-user",
                )
            }

        assertEquals("Duplicate sync action (entityType=ROLE, technicalKey=staff)", error.message)
        assertEquals("Project staff", repository.getRole("staff")?.name)
        assertEquals(policyVersionBeforeImport, repository.currentPolicyVersion())
        assertEquals(syncMetadataBeforeImport, countSyncMetadata())
        assertTrue(
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("permission.sync.imported"))
                )
                .items
                .isEmpty()
        )
    }

    @Test
    fun transfersDefaultRoleFromLaterKeyToEarlierKey() {
        repository.createRole(
            testActor,
            RoleRecord(key = "z-current-default", name = "Current default", isDefault = true),
        )
        repository.createRole(
            testActor,
            RoleRecord(key = "a-incoming-default", name = "Incoming default"),
        )
        val reviewedTargetFingerprint = currentFingerprint()

        repository.importPermissionSnapshot(
            GlobalPermissionSnapshot(
                snapshotId = "default-transfer",
                roles =
                    listOf(
                        SyncRole(
                            key = "a-incoming-default",
                            name = "Incoming default",
                            isDefault = true,
                        ),
                        SyncRole(
                            key = "z-current-default",
                            name = "Current default",
                            isDefault = false,
                        ),
                    ),
                roleGrants = emptyList(),
                inheritance = emptyList(),
                catalogEntries = emptyList(),
            ),
            expectedTargetFingerprint = reviewedTargetFingerprint,
            actions =
                listOf(
                    PermissionSyncAction(
                        SyncEntityType.ROLE,
                        "a-incoming-default",
                        SyncAction.USE_GLOBAL,
                    ),
                    PermissionSyncAction(
                        SyncEntityType.ROLE,
                        "z-current-default",
                        SyncAction.USE_GLOBAL,
                    ),
                ),
            actorUserId = "sync-user",
        )

        assertEquals(
            listOf("a-incoming-default"),
            repository.listRoles().filter(RoleRecord::isDefault).map(RoleRecord::key),
        )
    }

    @Test
    fun rejectsKeepingCurrentDefaultWhileApplyingDifferentDefault() {
        repository.createRole(
            testActor,
            RoleRecord(key = "z-current-default", name = "Current default", isDefault = true),
        )
        repository.createRole(
            testActor,
            RoleRecord(key = "a-incoming-default", name = "Incoming default"),
        )
        val reviewedTargetFingerprint = currentFingerprint()
        val policyVersionBeforeImport = repository.currentPolicyVersion()
        val syncMetadataBeforeImport = countSyncMetadata()

        val error =
            assertThrows(IllegalArgumentException::class.java) {
                repository.importPermissionSnapshot(
                    GlobalPermissionSnapshot(
                        snapshotId = "conflicting-default-actions",
                        roles =
                            listOf(
                                SyncRole(
                                    key = "a-incoming-default",
                                    name = "Incoming default",
                                    isDefault = true,
                                ),
                                SyncRole(
                                    key = "z-current-default",
                                    name = "Current default",
                                    isDefault = false,
                                ),
                            ),
                        roleGrants = emptyList(),
                        inheritance = emptyList(),
                        catalogEntries = emptyList(),
                    ),
                    expectedTargetFingerprint = reviewedTargetFingerprint,
                    actions =
                        listOf(
                            PermissionSyncAction(
                                SyncEntityType.ROLE,
                                "a-incoming-default",
                                SyncAction.USE_GLOBAL,
                            ),
                            PermissionSyncAction(
                                SyncEntityType.ROLE,
                                "z-current-default",
                                SyncAction.KEEP_PROJECT,
                            ),
                        ),
                    actorUserId = "sync-user",
                )
            }

        assertEquals(
            "Permission sync would leave multiple default roles (roleKeys=a-incoming-default,z-current-default)",
            error.message,
        )
        assertEquals(
            mapOf("a-incoming-default" to false, "z-current-default" to true),
            repository.listRoles().associate { it.key to it.isDefault },
        )
        assertEquals(policyVersionBeforeImport, repository.currentPolicyVersion())
        assertEquals(syncMetadataBeforeImport, countSyncMetadata())
        assertTrue(
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("permission.sync.imported"))
                )
                .items
                .isEmpty()
        )
    }

    @Test
    fun rejectsMultipleIncomingDefaultRolesBeforeWrites() {
        val reviewedTargetFingerprint = currentFingerprint()
        val policyVersionBeforeImport = repository.currentPolicyVersion()
        val syncMetadataBeforeImport = countSyncMetadata()

        val error =
            assertThrows(IllegalArgumentException::class.java) {
                repository.importPermissionSnapshot(
                    GlobalPermissionSnapshot(
                        snapshotId = "multiple-incoming-defaults",
                        roles =
                            listOf(
                                SyncRole("z-global-default", "Zulu", isDefault = true),
                                SyncRole("a-global-default", "Alpha", isDefault = true),
                            ),
                        roleGrants = emptyList(),
                        inheritance = emptyList(),
                        catalogEntries = emptyList(),
                    ),
                    expectedTargetFingerprint = reviewedTargetFingerprint,
                    actions =
                        listOf(
                            PermissionSyncAction(
                                SyncEntityType.ROLE,
                                "a-global-default",
                                SyncAction.IMPORT,
                            ),
                            PermissionSyncAction(
                                SyncEntityType.ROLE,
                                "z-global-default",
                                SyncAction.IMPORT,
                            ),
                        ),
                    actorUserId = "sync-user",
                )
            }

        assertEquals(
            "Permission sync would leave multiple default roles (roleKeys=a-global-default,z-global-default)",
            error.message,
        )
        assertTrue(repository.listRoles().isEmpty())
        assertEquals(policyVersionBeforeImport, repository.currentPolicyVersion())
        assertEquals(syncMetadataBeforeImport, countSyncMetadata())
        assertTrue(
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("permission.sync.imported"))
                )
                .items
                .isEmpty()
        )
    }

    @Test
    fun rejectsIncomingDefaultWhileRetainingProjectOnlyDefault() {
        repository.createRole(
            testActor,
            RoleRecord(key = "z-project-default", name = "Project default", isDefault = true),
        )
        val reviewedTargetFingerprint = currentFingerprint()
        val policyVersionBeforeImport = repository.currentPolicyVersion()
        val syncMetadataBeforeImport = countSyncMetadata()

        val error =
            assertThrows(IllegalArgumentException::class.java) {
                repository.importPermissionSnapshot(
                    GlobalPermissionSnapshot(
                        snapshotId = "retained-project-default",
                        roles =
                            listOf(
                                SyncRole("a-global-default", "Global default", isDefault = true)
                            ),
                        roleGrants = emptyList(),
                        inheritance = emptyList(),
                        catalogEntries = emptyList(),
                    ),
                    expectedTargetFingerprint = reviewedTargetFingerprint,
                    actions =
                        listOf(
                            PermissionSyncAction(
                                SyncEntityType.ROLE,
                                "a-global-default",
                                SyncAction.IMPORT,
                            )
                        ),
                    actorUserId = "sync-user",
                )
            }

        assertEquals(
            "Permission sync would leave multiple default roles (roleKeys=a-global-default,z-project-default)",
            error.message,
        )
        assertEquals(
            mapOf("z-project-default" to true),
            repository.listRoles().associate { it.key to it.isDefault },
        )
        assertEquals(policyVersionBeforeImport, repository.currentPolicyVersion())
        assertEquals(syncMetadataBeforeImport, countSyncMetadata())
        assertTrue(
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("permission.sync.imported"))
                )
                .items
                .isEmpty()
        )
    }

    @Test
    fun keepsCurrentDefaultWhenIncomingDefaultUsesKeepProject() {
        repository.createRole(
            testActor,
            RoleRecord(key = "z-current-default", name = "Current default", isDefault = true),
        )
        repository.createRole(
            testActor,
            RoleRecord(key = "a-incoming-default", name = "Incoming default"),
        )

        repository.importPermissionSnapshot(
            GlobalPermissionSnapshot(
                snapshotId = "kept-default-transfer",
                roles =
                    listOf(
                        SyncRole(
                            key = "a-incoming-default",
                            name = "Incoming default",
                            isDefault = true,
                        )
                    ),
                roleGrants = emptyList(),
                inheritance = emptyList(),
                catalogEntries = emptyList(),
            ),
            expectedTargetFingerprint = currentFingerprint(),
            actions =
                listOf(
                    PermissionSyncAction(
                        SyncEntityType.ROLE,
                        "a-incoming-default",
                        SyncAction.KEEP_PROJECT,
                    )
                ),
            actorUserId = "sync-user",
        )

        assertEquals(
            listOf("z-current-default"),
            repository.listRoles().filter(RoleRecord::isDefault).map(RoleRecord::key),
        )
    }

    @Test
    fun rejectsRoleRemovalWhenPostPreviewPlayerAssignmentReferencesRole() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000501")
        val assignmentId = UUID.fromString("00000000-0000-0000-0000-000000000502")
        repository.createRole(testActor, RoleRecord(key = "project-only", name = "Project only"))
        val reviewedTargetFingerprint = currentFingerprint()
        repository.createPlayerRoleGrant(
            "assignment-user",
            PlayerRoleGrantRecord(assignmentId, playerId, "project-only"),
        )
        val policyVersionBeforeImport = repository.currentPolicyVersion()
        val syncMetadataBeforeImport = countSyncMetadata()

        val error =
            assertThrows(PermissionSyncConflictException::class.java) {
                repository.importPermissionSnapshot(
                    GlobalPermissionSnapshot(
                        snapshotId = "role-in-use",
                        roles = emptyList(),
                        roleGrants = emptyList(),
                        inheritance = emptyList(),
                        catalogEntries = emptyList(),
                    ),
                    expectedTargetFingerprint = reviewedTargetFingerprint,
                    actions =
                        listOf(
                            PermissionSyncAction(
                                SyncEntityType.ROLE,
                                "project-only",
                                SyncAction.REMOVE_PROJECT_ENTRY,
                            )
                        ),
                    actorUserId = "sync-user",
                )
            }

        assertEquals(PermissionSyncConflictReason.ROLE_IN_USE, error.reason)
        assertEquals("Project only", repository.getRole("project-only")?.name)
        assertEquals(
            listOf(assignmentId),
            repository.listPlayerRoleGrantRecords(playerId).map(PlayerRoleGrantRecord::id),
        )
        assertEquals(policyVersionBeforeImport, repository.currentPolicyVersion())
        assertEquals(syncMetadataBeforeImport, countSyncMetadata())
        assertTrue(
            repository
                .listAuditEvents(
                    PermissionAuditEventQuery(actions = setOf("permission.sync.imported"))
                )
                .items
                .isEmpty()
        )
    }

    @Test
    fun normalPolicyWriterWaitsForImportFingerprintTransactionBeforeEnteringMutation() {
        val observedDataSource = PolicyLockObservingDataSource(dataSource)
        val observedRepository =
            PermissionRepository(observedDataSource, objectMapper, identityRepository, mock())
        val reviewedTargetFingerprint = currentFingerprint()
        val executor = Executors.newFixedThreadPool(2)

        try {
            val importFuture =
                executor.submit<PermissionSyncMetadataRecord> {
                    observedRepository.importPermissionSnapshot(
                        GlobalPermissionSnapshot(
                            snapshotId = "concurrent-import",
                            roles = listOf(SyncRole("imported", "Imported")),
                            roleGrants = emptyList(),
                            inheritance = emptyList(),
                            catalogEntries = emptyList(),
                        ),
                        expectedTargetFingerprint = reviewedTargetFingerprint,
                        actions =
                            listOf(
                                PermissionSyncAction(
                                    SyncEntityType.ROLE,
                                    "imported",
                                    SyncAction.IMPORT,
                                )
                            ),
                        actorUserId = "sync-user",
                    )
                }
            assertTrue(observedDataSource.importReachedFirstPolicyWrite.await(10, TimeUnit.SECONDS))

            val writerFuture =
                executor.submit<RoleRecord> {
                    observedRepository.createRole(
                        "writer-user",
                        RoleRecord(key = "writer", name = "Writer"),
                    )
                }
            assertTrue(observedDataSource.writerAttemptedPolicyLock.await(10, TimeUnit.SECONDS))
            assertEquals(1L, observedDataSource.writerReachedPolicyWrite.count)
            assertEquals(false, writerFuture.isDone)

            observedDataSource.allowImportPolicyWrite.countDown()
            assertEquals("concurrent-import", importFuture.get(10, TimeUnit.SECONDS).snapshotId)
            assertEquals("writer", writerFuture.get(10, TimeUnit.SECONDS).key)
            assertEquals(0L, observedDataSource.writerReachedPolicyWrite.count)
            assertEquals(
                setOf("imported", "writer"),
                repository.listRoles().mapTo(mutableSetOf()) { it.key },
            )
        } finally {
            observedDataSource.allowImportPolicyWrite.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun playerAssignmentWriterCannotEnterBetweenRoleUseGuardAndRoleDelete() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000504")
        repository.createRole(testActor, RoleRecord(key = "project-only", name = "Project only"))
        val reviewedTargetFingerprint = currentFingerprint()
        val observedDataSource =
            PolicyLockObservingDataSource(
                delegate = dataSource,
                importPolicyWriteSqlPrefix = "DELETE FROM permission_roles",
                writerPolicyWriteSqlPrefix = "INSERT INTO permission_player_role_grants",
            )
        val observedRepository =
            PermissionRepository(observedDataSource, objectMapper, identityRepository, mock())
        val executor = Executors.newFixedThreadPool(2)

        try {
            val importFuture =
                executor.submit<PermissionSyncMetadataRecord> {
                    observedRepository.importPermissionSnapshot(
                        GlobalPermissionSnapshot(
                            snapshotId = "guarded-role-removal",
                            roles = emptyList(),
                            roleGrants = emptyList(),
                            inheritance = emptyList(),
                            catalogEntries = emptyList(),
                        ),
                        expectedTargetFingerprint = reviewedTargetFingerprint,
                        actions =
                            listOf(
                                PermissionSyncAction(
                                    SyncEntityType.ROLE,
                                    "project-only",
                                    SyncAction.REMOVE_PROJECT_ENTRY,
                                )
                            ),
                        actorUserId = "sync-user",
                    )
                }
            assertTrue(observedDataSource.importReachedFirstPolicyWrite.await(10, TimeUnit.SECONDS))

            val writerFuture =
                executor.submit<PlayerRoleGrantRecord> {
                    observedRepository.createPlayerRoleGrant(
                        "assignment-user",
                        PlayerRoleGrantRecord(UUID.randomUUID(), playerId, "project-only"),
                    )
                }
            assertTrue(observedDataSource.writerAttemptedPolicyLock.await(10, TimeUnit.SECONDS))
            assertEquals(1L, observedDataSource.writerReachedPolicyWrite.count)
            assertEquals(false, writerFuture.isDone)

            observedDataSource.allowImportPolicyWrite.countDown()
            assertEquals("guarded-role-removal", importFuture.get(10, TimeUnit.SECONDS).snapshotId)
            assertThrows(ExecutionException::class.java) { writerFuture.get(10, TimeUnit.SECONDS) }
            assertNull(repository.getRole("project-only"))
            assertTrue(repository.listPlayerRoleGrantRecords(playerId).isEmpty())
        } finally {
            observedDataSource.allowImportPolicyWrite.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun readsAuditTotalsAndItemsFromOneSnapshot() {
        insertAuditEvent(
            id = UUID.fromString("00000000-0000-0000-0000-000000000101"),
            actorUserId = "first-user",
        )
        val snapshotRepository =
            PermissionRepository(
                InterleavingAuditDataSource(dataSource),
                objectMapper,
                identityRepository,
                mock(),
            )

        val page = snapshotRepository.listAuditEvents(PermissionAuditEventQuery(perPage = 25))

        assertEquals(page.total, page.items.size.toLong())
    }

    @Test
    fun removesNaturalKeyConflictsBeforeImportingReplacementMappings() {
        repository.createRole(testActor, RoleRecord(key = "moderator", name = "Moderator"))
        val projectMappingId = UUID.randomUUID()
        repository.createKeycloakGroupMapping(
            testActor,
            KeycloakGroupMappingRecord(projectMappingId, "/staff", "moderator"),
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
                    listOf(
                        SyncKeycloakMapping(
                            globalMappingId,
                            "/staff",
                            "moderator",
                            startsAt = Instant.parse("2029-01-01T00:00:00Z"),
                        )
                    ),
            )

        repository.importPermissionSnapshot(
            snapshot,
            expectedTargetFingerprint = currentFingerprint(),
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

        val importedMapping = repository.listKeycloakGroupMappings().single()
        assertEquals(globalMappingId, importedMapping.id)
        assertEquals(Instant.parse("2029-01-01T00:00:00Z"), importedMapping.startsAt)
    }

    @Test
    fun rejectsCyclicInheritanceInImportedSnapshot() {
        repository.createRole(testActor, RoleRecord(key = "alpha", name = "Alpha"))
        repository.createRole(testActor, RoleRecord(key = "beta", name = "Beta"))
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
            repository.importPermissionSnapshot(
                snapshot,
                expectedTargetFingerprint = currentFingerprint(),
                actions = emptyList(),
                actorUserId = "test-user",
            )
        }
        assertTrue(repository.listRoleInheritances().isEmpty())
    }

    private fun insertAuditEvent(id: UUID, actorUserId: String) {
        dataSource.connection.use { connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_audit_events (
                        id, actor_user_id, action, target, metadata, created_at
                    )
                    VALUES (?, ?, 'role.created', 'role:moderator', '{}'::jsonb, ?)
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setObject(1, id)
                    statement.setString(2, actorUserId)
                    statement.setTimestamp(3, Timestamp.from(Instant.parse("2030-01-01T00:00:00Z")))
                    statement.executeUpdate()
                }
        }
    }

    private fun currentFingerprint(): String =
        PermissionSnapshotFingerprint(objectMapper)
            .calculate(repository.permissionProjectSnapshot())

    private fun countSyncMetadata(): Long =
        dataSource.connection.use { connection ->
            connection.prepareStatement("SELECT COUNT(*) FROM permission_sync_metadata").use {
                statement ->
                statement.executeQuery().use { rows ->
                    check(rows.next())
                    rows.getLong(1)
                }
            }
        }

    private class InterleavingAuditDataSource(private val delegate: DataSource) :
        DataSource by delegate {
        private var countRead = false

        override fun getConnection(): Connection {
            val connection = delegate.connection
            return Proxy.newProxyInstance(
                Connection::class.java.classLoader,
                arrayOf(Connection::class.java),
            ) { _, method, arguments ->
                val sql = arguments?.firstOrNull() as? String
                if (method.name == "prepareStatement" && sql != null) {
                    when {
                        sql.startsWith("SELECT COUNT(*) FROM permission_audit_events") ->
                            countRead = true
                        countRead &&
                            sql.contains(
                                "SELECT id, actor_user_id, action, target, metadata, created_at"
                            ) -> {
                            insertConcurrentAuditEvent()
                            countRead = false
                        }
                    }
                }
                try {
                    method.invoke(connection, *(arguments ?: emptyArray()))
                } catch (error: InvocationTargetException) {
                    throw error.targetException
                }
            } as Connection
        }

        private fun insertConcurrentAuditEvent() {
            delegate.connection.use { connection ->
                connection
                    .prepareStatement(
                        """
                        INSERT INTO permission_audit_events (
                            id, actor_user_id, action, target, metadata, created_at
                        )
                        VALUES (?, 'second-user', 'role.created', 'role:builder', '{}'::jsonb, ?)
                        """
                            .trimIndent()
                    )
                    .use { statement ->
                        statement.setObject(
                            1,
                            UUID.fromString("00000000-0000-0000-0000-000000000102"),
                        )
                        statement.setTimestamp(
                            2,
                            Timestamp.from(Instant.parse("2030-01-01T00:00:01Z")),
                        )
                        statement.executeUpdate()
                    }
            }
        }
    }

    private class PolicyLockObservingDataSource(
        private val delegate: DataSource,
        private val importPolicyWriteSqlPrefix: String = "INSERT INTO permission_roles",
        private val writerPolicyWriteSqlPrefix: String = "INSERT INTO permission_roles",
    ) : DataSource by delegate {
        val importReachedFirstPolicyWrite = CountDownLatch(1)
        val allowImportPolicyWrite = CountDownLatch(1)
        val writerAttemptedPolicyLock = CountDownLatch(1)
        val writerReachedPolicyWrite = CountDownLatch(1)
        private val connectionSequence = AtomicInteger()

        override fun getConnection(): Connection {
            val connection = delegate.connection
            val connectionNumber = connectionSequence.incrementAndGet()
            return Proxy.newProxyInstance(
                Connection::class.java.classLoader,
                arrayOf(Connection::class.java),
            ) { _, method, arguments ->
                val sql = arguments?.firstOrNull() as? String
                if (method.name == "prepareStatement" && sql != null) {
                    if (connectionNumber == 1 && sql.startsWith(importPolicyWriteSqlPrefix)) {
                        importReachedFirstPolicyWrite.countDown()
                        check(allowImportPolicyWrite.await(10, TimeUnit.SECONDS)) {
                            "Timed out waiting to release import policy write"
                        }
                    }
                    if (connectionNumber == 2 && sql.startsWith(writerPolicyWriteSqlPrefix)) {
                        writerReachedPolicyWrite.countDown()
                    }
                }
                val result = invoke(connection, method, arguments)
                if (
                    connectionNumber == 2 &&
                        method.name == "prepareStatement" &&
                        sql?.startsWith("SELECT version FROM permission_policy_versions") == true
                ) {
                    val statement = result as PreparedStatement
                    Proxy.newProxyInstance(
                        PreparedStatement::class.java.classLoader,
                        arrayOf(PreparedStatement::class.java),
                    ) { _, statementMethod, statementArguments ->
                        if (statementMethod.name == "executeQuery") {
                            writerAttemptedPolicyLock.countDown()
                        }
                        invoke(statement, statementMethod, statementArguments)
                    } as PreparedStatement
                } else {
                    result
                }
            } as Connection
        }

        private fun invoke(
            target: Any,
            method: java.lang.reflect.Method,
            arguments: Array<out Any?>?,
        ): Any? =
            try {
                method.invoke(target, *(arguments ?: emptyArray()))
            } catch (error: InvocationTargetException) {
                throw error.targetException
            }
    }

    private fun runtimeManifest(
        source: String,
        registeredAt: Instant = Instant.parse("2030-01-01T00:00:00Z"),
        permissions: List<CatalogEntryRecord>,
    ) =
        RuntimeManifestRegistration(
            source = source,
            sourceVersion = "1.0.0",
            serverType = "paper",
            serverId = "lobby-1",
            permissions = permissions,
            registeredAt = registeredAt,
        )

    private fun runtimeCatalogEntry(key: String, label: String) =
        CatalogEntryRecord(
            key = key,
            label = label,
            source = "ignored-by-registration",
            sourceVersion = "ignored-by-registration",
            supportedScopes = listOf(PermissionScopeKind.GLOBAL),
            custom = true,
            lastSeenAt = null,
        )
}
