package gg.grounds.permissions.cache

import com.fasterxml.jackson.databind.ObjectMapper
import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionGrantSpec
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.PlayerRoleGrant
import gg.grounds.permissions.identity.IdentitySyncReadinessCheck
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import gg.grounds.permissions.persistence.PlayerGrantRecord
import gg.grounds.permissions.persistence.RoleRecord
import io.quarkus.redis.datasource.RedisDataSource
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.junit.QuarkusTestProfile
import io.quarkus.test.junit.TestProfile
import jakarta.inject.Inject
import java.sql.Connection
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import javax.sql.DataSource
import org.eclipse.microprofile.health.Readiness
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.testcontainers.containers.GenericContainer

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
@QuarkusTestResource(value = ValkeyTestResource::class, restrictToAnnotatedClass = true)
@TestProfile(ValkeyEnabledProfile::class)
class ValkeyPlayerPolicyL2Test {
    @Inject lateinit var l2: PlayerPolicyL2
    @Inject lateinit var redis: RedisDataSource
    @Inject lateinit var repository: PermissionRepository
    @Inject lateinit var objectMapper: ObjectMapper
    @Inject lateinit var dataSource: DataSource
    @Inject @field:Readiness lateinit var readinessCheck: IdentitySyncReadinessCheck

    @Test
    fun storesPlayerRowsUnderTheVersionedKeyWithATtl() {
        val data = sampleData(UUID.randomUUID(), policyVersion = 7)

        l2.putAll(listOf(data))
        val key = ValkeyPlayerPolicyL2.key(data.playerId, 7)
        awaitTrue { redis.key().exists(key) }

        assertEquals(data, l2.getAll(setOf(data.playerId), 7)[data.playerId])
        assertTrue(l2.getAll(setOf(data.playerId), 8).isEmpty())
        val ttlMillis = redis.key().pttl(key)
        assertTrue(ttlMillis in 1..Duration.ofMinutes(5).toMillis(), "ttl=$ttlMillis")

        l2.delete(data.playerId, 7)
        awaitTrue { !redis.key().exists(key) }
    }

    @Test
    fun anotherInstanceServesPlayerRowsFromL2WithoutTheDatabase() {
        repository.deleteAllPermissionData()
        val playerId = UUID.randomUUID()
        repository.createRole(RoleRecord(key = "default", name = "Default", isDefault = true))
        repository.createPlayerGrant(
            PlayerGrantRecord(
                id = UUID.randomUUID(),
                playerId = playerId,
                effect = PermissionEffect.ALLOW,
                pattern = "grounds.fly",
                scope = PermissionScope(PermissionScopeKind.GLOBAL),
            )
        )
        val request = PermissionPolicyRequest(playerId, "lobby", "lobby-1")
        val expected = repository.policyFor(request)
        val version = expected.policyVersion
        awaitTrue { redis.key().exists(ValkeyPlayerPolicyL2.key(playerId, version)) }

        // A second instance in the same region: its own L1, the shared L2.
        val connections = AtomicInteger()
        val otherInstance =
            PermissionRepository(
                CountingDataSource(dataSource, connections),
                objectMapper,
                readinessCheck,
                SnapshotCacheSettings(),
                l2,
            )
        otherInstance.snapshotCache.globals()
        val connectionsAfterGlobals = connections.get()
        val input = otherInstance.policyFor(request)

        assertEquals(connectionsAfterGlobals, connections.get(), "player rows came from the DB")
        assertEquals(expected.playerGrants, input.playerGrants)
    }

    private fun awaitTrue(condition: () -> Boolean) {
        val deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos()
        while (!condition()) {
            check(System.nanoTime() < deadline) { "condition not met within 5 s" }
            Thread.sleep(20)
        }
    }
}

class ValkeyEnabledProfile : QuarkusTestProfile {
    override fun getConfigOverrides(): Map<String, String> =
        mapOf(
            "permissions.snapshot-cache.valkey.enabled" to "true",
            // Generous, so a slow first connection on a busy runner does not pause reads.
            "permissions.snapshot-cache.valkey.timeout" to "2s",
        )
}

class ValkeyTestResource : QuarkusTestResourceLifecycleManager {
    private lateinit var valkey: GenericContainer<*>

    override fun start(): Map<String, String> {
        valkey = GenericContainer("valkey/valkey:8-alpine").withExposedPorts(6379)
        valkey.start()
        return mapOf(
            "quarkus.redis.hosts" to "redis://${valkey.host}:${valkey.getMappedPort(6379)}"
        )
    }

    override fun stop() {
        valkey.stop()
    }
}

private fun sampleData(playerId: UUID, policyVersion: Long) =
    PlayerPolicyData(
        playerId = playerId,
        policyVersion = policyVersion,
        roleGrants =
            listOf(
                PlayerRoleGrant(
                    playerId = playerId,
                    roleKey = "builder",
                    expiresAt = Instant.parse("2031-01-01T00:00:00.123456Z"),
                    grantId = UUID.randomUUID(),
                )
            ),
        grants =
            listOf(
                PlayerPermissionGrant(
                    playerId = playerId,
                    grant =
                        PermissionGrantSpec(
                            effect = PermissionEffect.DENY,
                            pattern = "grounds.fly",
                            scope = PermissionScope(PermissionScopeKind.SERVER_TYPE, "lobby"),
                            permissionGrantId = UUID.randomUUID(),
                        ),
                    grantId = UUID.randomUUID(),
                )
            ),
        groupPaths = setOf("/staff"),
        identityLastSuccessAt = Instant.parse("2030-01-01T00:00:00Z"),
    )

private class CountingDataSource(
    private val delegate: DataSource,
    private val connections: AtomicInteger,
) : DataSource by delegate {
    override fun getConnection(): Connection {
        connections.incrementAndGet()
        return delegate.connection
    }

    override fun getConnection(username: String?, password: String?): Connection {
        connections.incrementAndGet()
        return delegate.getConnection(username, password)
    }
}
