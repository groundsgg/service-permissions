package gg.grounds.permissions.integration

import com.fasterxml.jackson.databind.ObjectMapper
import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.domain.PermissionEffect.ALLOW
import gg.grounds.permissions.domain.PermissionGrantOriginKind.DIRECT_PERMISSION
import gg.grounds.permissions.domain.PermissionGrantOriginKind.DIRECT_ROLE
import gg.grounds.permissions.domain.PermissionGrantOriginKind.GROUP_MAPPING
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind.GLOBAL
import gg.grounds.permissions.identity.IdentityChangeConsumer
import gg.grounds.permissions.identity.IdentityEventDelivery
import gg.grounds.permissions.identity.IdentityProjectionUnavailableException
import gg.grounds.permissions.identity.IdentitySyncCoordinator
import gg.grounds.permissions.identity.IdentitySyncLifecycle
import gg.grounds.permissions.identity.IdentitySyncOutcome
import gg.grounds.permissions.identity.KeycloakAccessTokenResponse
import gg.grounds.permissions.identity.KeycloakAdminClient
import gg.grounds.permissions.identity.KeycloakAdminException
import gg.grounds.permissions.identity.KeycloakAuthorizationProvider
import gg.grounds.permissions.identity.KeycloakGroupRepresentation
import gg.grounds.permissions.identity.KeycloakUserRepresentation
import gg.grounds.permissions.identity.MinecraftIdentityChangedEvent
import gg.grounds.permissions.identity.PlayerIdentitySynchronizer
import gg.grounds.permissions.persistence.KeycloakGroupMappingRecord
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import gg.grounds.permissions.persistence.PlayerGrantRecord
import gg.grounds.permissions.persistence.PlayerIdentityRepository
import gg.grounds.permissions.persistence.PlayerRoleGrantRecord
import gg.grounds.permissions.persistence.RoleGrantRecord
import gg.grounds.permissions.persistence.RoleRecord
import gg.grounds.permissions.policy.PermissionCheckScope
import gg.grounds.permissions.policy.PolicyEngine
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import java.sql.Timestamp
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Executor
import javax.sql.DataSource
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
class PlayerPermissionLifecycleTest {
    @Inject lateinit var dataSource: DataSource
    @Inject lateinit var identityRepository: PlayerIdentityRepository
    @Inject lateinit var objectMapper: ObjectMapper
    @Inject lateinit var permissionRepository: PermissionRepository

    private val playerId = UUID.fromString("00000000-0000-0000-0000-000000001301")
    private val keycloakUserId = "keycloak-user-13"
    private val mappingId = UUID.fromString("00000000-0000-0000-0000-000000001302")
    private val visitorMappingId = UUID.fromString("00000000-0000-0000-0000-000000001303")
    private val directRoleGrantId = UUID.fromString("00000000-0000-0000-0000-000000001304")
    private val directPermissionGrantId = UUID.fromString("00000000-0000-0000-0000-000000001305")

    @BeforeEach
    fun resetDatabase() {
        permissionRepository.deleteAllPermissionData()
    }

    @Test
    fun coversReleasedPlayerPermissionLifecycle() {
        val clock = MutableClock(Instant.now())
        val keycloak = MutableKeycloakAdminClient(playerId, keycloakUserId, setOf("/builders"))
        val coordinator = coordinator(keycloak, clock)
        val consumer = IdentityChangeConsumer(objectMapper, coordinator, "grounds")
        val lifecycle = IdentitySyncLifecycle(coordinator, Executor(Runnable::run))

        assertEquals(IdentitySyncOutcome.COMPLETED, coordinator.synchronizeAll())
        assertEquals(setOf("/builders"), identityRepository.findByPlayerId(playerId)?.groupPaths)

        createPolicy()
        val initialSnapshot = snapshot()

        assertEquals(setOf("builder", "moderator"), initialSnapshot.roleKeys)
        assertTrue(decision(initialSnapshot, "grounds.build").allowed)
        assertEquals(
            GROUP_MAPPING,
            decision(initialSnapshot, "grounds.build").winningGrant?.origin?.kind,
        )
        assertEquals(
            mappingId,
            decision(initialSnapshot, "grounds.build").winningGrant?.origin?.mappingId,
        )
        assertEquals(
            DIRECT_ROLE,
            decision(initialSnapshot, "grounds.moderate").winningGrant?.origin?.kind,
        )
        assertEquals(
            DIRECT_PERMISSION,
            decision(initialSnapshot, "grounds.fly").winningGrant?.origin?.kind,
        )

        keycloak.groupPaths = setOf("/visitors")
        clock.advance(Duration.ofSeconds(1))
        val firstDuplicate = RecordingDelivery(eventPayload("group_changed"))
        val secondDuplicate = RecordingDelivery(eventPayload("group_changed"))

        consumer.process(firstDuplicate)
        consumer.process(secondDuplicate)

        assertTrue(firstDuplicate.acknowledged)
        assertTrue(secondDuplicate.acknowledged)
        assertEquals(2, keycloak.targetedUserReads)
        assertEquals(setOf("/visitors"), identityRepository.findByPlayerId(playerId)?.groupPaths)
        assertEquals(setOf("moderator", "visitor"), snapshot().roleKeys)

        val expiredAt = clock.instant().minusSeconds(1)
        permissionRepository.updatePlayerRoleGrant(
            playerId,
            directRoleGrantId,
            PlayerRoleGrantRecord(
                id = directRoleGrantId,
                playerId = playerId,
                roleKey = "moderator",
                expiresAt = expiredAt,
            ),
        )
        permissionRepository.deletePlayerGrant(playerId, directPermissionGrantId)

        val afterGrantRemoval = snapshot()
        assertFalse(decision(afterGrantRemoval, "grounds.moderate").allowed)
        assertFalse(decision(afterGrantRemoval, "grounds.fly").allowed)
        assertEquals(setOf("visitor"), afterGrantRemoval.roleKeys)

        keycloak.groupPaths = setOf("/builders")
        assertEquals(setOf("/visitors"), identityRepository.findByPlayerId(playerId)?.groupPaths)

        clock.advance(Duration.ofSeconds(1))
        lifecycle.reconcileScheduled()

        assertEquals(setOf("/builders"), identityRepository.findByPlayerId(playerId)?.groupPaths)
        assertEquals(setOf("builder"), snapshot().roleKeys)

        forceIdentityProjectionStale(clock.instant().minus(Duration.ofHours(7)))

        assertThrows(IdentityProjectionUnavailableException::class.java) { snapshot() }
    }

    private fun coordinator(
        keycloak: MutableKeycloakAdminClient,
        clock: Clock,
    ): IdentitySyncCoordinator {
        val source =
            PlayerIdentitySynchronizer(
                client = keycloak,
                authorizationProvider = KeycloakAuthorizationProvider { "Bearer test-token" },
                realm = "grounds",
                pageSize = 100,
                clock = clock,
            )
        return IdentitySyncCoordinator(
            store = identityRepository,
            source = source,
            clock = clock,
            maxStaleness = Duration.ofHours(6),
        )
    }

    private fun createPolicy() {
        permissionRepository.createRole(RoleRecord(key = "builder", name = "Builder"))
        permissionRepository.createRole(RoleRecord(key = "visitor", name = "Visitor"))
        permissionRepository.createRole(RoleRecord(key = "moderator", name = "Moderator"))
        permissionRepository.createRoleGrant(
            RoleGrantRecord(
                id = UUID.fromString("00000000-0000-0000-0000-000000001306"),
                roleKey = "builder",
                effect = ALLOW,
                pattern = "grounds.build",
                scope = PermissionScope(GLOBAL),
            )
        )
        permissionRepository.createRoleGrant(
            RoleGrantRecord(
                id = UUID.fromString("00000000-0000-0000-0000-000000001307"),
                roleKey = "visitor",
                effect = ALLOW,
                pattern = "grounds.visit",
                scope = PermissionScope(GLOBAL),
            )
        )
        permissionRepository.createRoleGrant(
            RoleGrantRecord(
                id = UUID.fromString("00000000-0000-0000-0000-000000001308"),
                roleKey = "moderator",
                effect = ALLOW,
                pattern = "grounds.moderate",
                scope = PermissionScope(GLOBAL),
            )
        )
        permissionRepository.createKeycloakGroupMapping(
            KeycloakGroupMappingRecord(mappingId, "/builders", "builder")
        )
        permissionRepository.createKeycloakGroupMapping(
            KeycloakGroupMappingRecord(visitorMappingId, "/visitors", "visitor")
        )
        permissionRepository.createPlayerRoleGrant(
            PlayerRoleGrantRecord(directRoleGrantId, playerId, "moderator")
        )
        permissionRepository.createPlayerGrant(
            PlayerGrantRecord(
                id = directPermissionGrantId,
                playerId = playerId,
                effect = ALLOW,
                pattern = "grounds.fly",
                scope = PermissionScope(GLOBAL),
            )
        )
    }

    private fun snapshot() =
        PolicyEngine.createSnapshot(
            playerId,
            permissionRepository.policyFor(
                PermissionPolicyRequest(playerId, serverType = "paper", serverId = "survival-1")
            ),
        )

    private fun decision(
        snapshot: gg.grounds.permissions.domain.EffectivePermissionSnapshot,
        permission: String,
    ) = PolicyEngine.checkPermission(snapshot, permission, PermissionCheckScope.global())

    private fun eventPayload(reason: String): ByteArray =
        objectMapper.writeValueAsBytes(
            MinecraftIdentityChangedEvent(
                realmId = "grounds",
                keycloakUserId = keycloakUserId,
                reason = reason,
            )
        )

    private fun forceIdentityProjectionStale(lastSuccessAt: Instant) {
        dataSource.connection.use { connection ->
            connection
                .prepareStatement(
                    "UPDATE permission_identity_sync_state SET last_success_at = ? WHERE id = 1"
                )
                .use { statement ->
                    statement.setTimestamp(1, Timestamp.from(lastSuccessAt))
                    assertEquals(1, statement.executeUpdate())
                }
        }
    }
}

private class MutableKeycloakAdminClient(
    private val playerId: UUID,
    private val keycloakUserId: String,
    groupPaths: Set<String>,
) : KeycloakAdminClient {
    var groupPaths: Set<String> = groupPaths
    var targetedUserReads: Int = 0
        private set

    override fun requestToken(
        realm: String,
        grantType: String,
        clientId: String,
        clientSecret: String,
    ) = KeycloakAccessTokenResponse("test-token", 60)

    override fun listUsers(
        authorization: String,
        realm: String,
        first: Int,
        max: Int,
    ): List<KeycloakUserRepresentation> = listOf(user()).drop(first).take(max)

    override fun getUser(
        authorization: String,
        realm: String,
        userId: String,
    ): KeycloakUserRepresentation {
        if (userId != keycloakUserId) throw KeycloakAdminException(404)
        targetedUserReads++
        return user()
    }

    override fun listUserGroups(
        authorization: String,
        realm: String,
        userId: String,
        first: Int,
        max: Int,
    ): List<KeycloakGroupRepresentation> {
        if (userId != keycloakUserId) throw KeycloakAdminException(404)
        return groupPaths
            .sorted()
            .mapIndexed { index, path -> KeycloakGroupRepresentation("group-$index", path) }
            .drop(first)
            .take(max)
    }

    private fun user() =
        KeycloakUserRepresentation(
            id = keycloakUserId,
            attributes =
                mapOf(
                    PlayerIdentitySynchronizer.MINECRAFT_UUID_ATTRIBUTE to
                        listOf(playerId.toString()),
                    PlayerIdentitySynchronizer.MINECRAFT_USERNAME_ATTRIBUTE to
                        listOf("LifecyclePlayer"),
                ),
        )
}

private class RecordingDelivery(override val data: ByteArray) : IdentityEventDelivery {
    var acknowledged = false
        private set

    override fun acknowledge() {
        acknowledged = true
    }

    override fun negativelyAcknowledge(delay: Duration) = error("Unexpected negative acknowledge")

    override fun terminate() = error("Unexpected terminate")
}

private class MutableClock(private var current: Instant) : Clock() {
    override fun instant(): Instant = current

    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId): Clock = this

    fun advance(duration: Duration) {
        current = current.plus(duration)
    }
}
