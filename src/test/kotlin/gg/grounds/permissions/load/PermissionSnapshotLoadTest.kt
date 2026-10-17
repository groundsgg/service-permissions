package gg.grounds.permissions.load

import eu.rekawek.toxiproxy.ToxiproxyClient
import eu.rekawek.toxiproxy.model.ToxicDirection
import gg.grounds.permissions.api.PermissionPolicyProvider
import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.RoleRecord
import gg.grounds.permissions.policy.PolicyEngine
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import java.sql.DriverManager
import java.time.Duration
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.Network
import org.testcontainers.postgresql.PostgreSQLContainer
import org.testcontainers.toxiproxy.ToxiproxyContainer

/**
 * Bursts of concurrent snapshot computations against a database behind an injected round-trip
 * latency (default 100 ms, the cross-region case). Opt-in, because it is slow:
 *
 * `PERMISSIONS_LOAD_TEST=true ./gradlew test --tests '*PermissionSnapshotLoadTest'`
 *
 * Settings (environment): `PERMISSIONS_LOAD_TEST_PLAYERS` (300), `PERMISSIONS_LOAD_TEST_LATENCY_MS`
 * (100), `PERMISSIONS_LOAD_TEST_POOL_SIZE` (2, as on stage), `PERMISSIONS_LOAD_TEST_VALKEY`
 * (false). Without Docker, point `PERMISSIONS_LOAD_TEST_JDBC_URL` at a latency proxy in front of
 * PostgreSQL, `PERMISSIONS_LOAD_TEST_SEED_JDBC_URL` at PostgreSQL itself and
 * `PERMISSIONS_LOAD_TEST_VALKEY_URL` at a Valkey.
 */
@QuarkusTest
@EnabledIfEnvironmentVariable(named = "PERMISSIONS_LOAD_TEST", matches = "true")
@QuarkusTestResource(value = LatencyPostgresTestResource::class, restrictToAnnotatedClass = true)
class PermissionSnapshotLoadTest {
    @Inject lateinit var policyProvider: PermissionPolicyProvider
    @Inject lateinit var repository: PermissionRepository

    // Defaults keep the application valid for the other test classes, which share its config.
    @ConfigProperty(name = "load-test.seed-jdbc-url", defaultValue = "unset")
    lateinit var seedJdbcUrl: String

    @ConfigProperty(name = "quarkus.datasource.username") lateinit var username: String

    @ConfigProperty(name = "quarkus.datasource.password") lateinit var password: String

    @ConfigProperty(name = "permissions.snapshot-cache.valkey.enabled") var valkeyEnabled = false

    private val playerCount = env("PERMISSIONS_LOAD_TEST_PLAYERS", "300").toInt()

    @Test
    fun snapshotBursts() {
        val players = List(playerCount) { UUID.randomUUID() }
        seed(players)
        repository.snapshotCache.clear()

        val results = linkedMapOf<String, BurstResult>()
        results["cold (empty cache)"] = burst(players)
        results["warm"] = burst(players)
        repository.createRole(RoleRecord(key = "load-bump-local", name = "Bump"))
        results["after policyVersion bump (this instance)"] = burst(players)
        bumpPolicyVersionElsewhere()
        repository.refreshSnapshotCache()
        results["after policyVersion bump (other instance, polled)"] = burst(players)
        if (valkeyEnabled) {
            // A restarted replica: empty L1, global definitions loaded once before the burst.
            // The bumps above moved every L2 key to a new policy version, so L2 starts cold.
            repository.snapshotCache.clear()
            repository.snapshotCache.globals()
            results["restarted replica, L2 cold"] = burst(players)
            repository.snapshotCache.clear()
            repository.snapshotCache.globals()
            // The first L2 hits in a JVM also pay for warming up JSON deserialization.
            results["restarted replica, L2 warm (first hits in this JVM)"] = burst(players)
            repository.snapshotCache.clear()
            repository.snapshotCache.globals()
            results["restarted replica, L2 warm"] = burst(players)
        }

        println(
            buildString {
                appendLine(
                    "LOAD-TEST players=$playerCount ${LatencyPostgresTestResource.describe()}"
                )
                results.forEach { (name, result) -> appendLine("LOAD-TEST $name: $result") }
            }
        )
    }

    private fun burst(players: List<UUID>): BurstResult {
        val executor = Executors.newFixedThreadPool(players.size)
        val start = CountDownLatch(1)
        try {
            val futures = players.map { playerId ->
                executor.submit<Long?> {
                    start.await()
                    val startedAt = System.nanoTime()
                    try {
                        PolicyEngine.createSnapshot(
                            playerId,
                            policyProvider.policyFor(
                                PermissionPolicyRequest(playerId, "lobby", "lobby-1")
                            ),
                        )
                        System.nanoTime() - startedAt
                    } catch (_: Exception) {
                        null
                    }
                }
            }
            val burstStartedAt = System.nanoTime()
            start.countDown()
            val latencies = futures.map { it.get(2, TimeUnit.MINUTES) }
            return BurstResult(
                latencies.filterNotNull().sorted(),
                latencies.count { it == null },
                Duration.ofNanos(System.nanoTime() - burstStartedAt),
            )
        } finally {
            executor.shutdownNow()
        }
    }

    private fun seed(players: List<UUID>) {
        DriverManager.getConnection(seedJdbcUrl, username, password).use { connection ->
            connection.autoCommit = false
            connection.createStatement().use { statement ->
                statement.execute(
                    """
                    INSERT INTO permission_roles (key, name, sort_order, is_default)
                    SELECT 'role-' || n, 'Role ' || n, n, n = 0 FROM generate_series(0, 19) n;
                    INSERT INTO permission_role_inheritance (child_role_key, parent_role_key)
                    SELECT 'role-' || n, 'role-0' FROM generate_series(1, 19) n;
                    INSERT INTO permission_role_grants (id, role_key, effect, permission_pattern, scope_kind)
                    SELECT gen_random_uuid(), 'role-' || n, 'ALLOW', 'grounds.perm.' || n || '.' || g, 'GLOBAL'
                    FROM generate_series(0, 19) n, generate_series(1, 10) g;
                    INSERT INTO permission_keycloak_group_mappings (id, keycloak_group, role_key)
                    SELECT gen_random_uuid(), '/group-' || n, 'role-' || n FROM generate_series(1, 3) n;
                    UPDATE permission_identity_sync_state SET status = 'IDLE', last_success_at = now();
                    """
                        .trimIndent()
                )
            }
            connection
                .prepareStatement(
                    """
                    WITH players AS (SELECT unnest(?::uuid[]) AS player_id),
                    role_grants AS (
                        INSERT INTO permission_player_role_grants (id, player_id, role_key)
                        SELECT gen_random_uuid(), player_id, 'role-' || (4 + n)
                        FROM players, generate_series(1, 2) n
                    ),
                    grants AS (
                        INSERT INTO permission_player_grants (id, player_id, effect, permission_pattern, scope_kind)
                        SELECT gen_random_uuid(), player_id, 'ALLOW', 'grounds.player.' || n, 'GLOBAL'
                        FROM players, generate_series(1, 3) n
                    ),
                    identities AS (
                        INSERT INTO permission_player_identities (
                            player_id, keycloak_user_id, minecraft_username,
                            minecraft_username_normalized, synced_at
                        )
                        SELECT player_id, player_id::text, 'p' || left(player_id::text, 8),
                               'p' || left(player_id::text, 8), now()
                        FROM players
                        RETURNING player_id
                    )
                    INSERT INTO permission_player_keycloak_groups (player_id, keycloak_group_path)
                    SELECT player_id, '/group-1' FROM identities
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setArray(1, connection.createArrayOf("uuid", players.toTypedArray()))
                    statement.execute()
                }
            connection.createStatement().use {
                it.execute("UPDATE permission_policy_versions SET version = version + 1")
            }
            connection.commit()
        }
    }

    private fun bumpPolicyVersionElsewhere() {
        DriverManager.getConnection(seedJdbcUrl, username, password).use { connection ->
            connection.createStatement().use {
                it.execute("UPDATE permission_policy_versions SET version = version + 1")
            }
        }
    }

    data class BurstResult(val latencies: List<Long>, val failures: Int, val wallTime: Duration) {
        private fun percentile(p: Double): String =
            if (latencies.isEmpty()) {
                "-"
            } else {
                val index = ((latencies.size - 1) * p).toInt()
                "${TimeUnit.NANOSECONDS.toMillis(latencies[index])} ms"
            }

        override fun toString(): String =
            "p50=${percentile(0.50)} p99=${percentile(0.99)} max=${percentile(1.0)} " +
                "ok=${latencies.size} failed=$failures wall=${wallTime.toMillis()} ms"
    }
}

class LatencyPostgresTestResource : QuarkusTestResourceLifecycleManager {
    private val containers = mutableListOf<GenericContainer<*>>()
    private var network: Network? = null

    override fun start(): Map<String, String> {
        val config =
            mutableMapOf(
                "quarkus.datasource.jdbc.max-size" to POOL_SIZE.toString(),
                "quarkus.flyway.create-schemas" to "true",
            )
        val externalUrl = System.getenv("PERMISSIONS_LOAD_TEST_JDBC_URL")
        if (externalUrl != null) {
            config["quarkus.datasource.jdbc.url"] = externalUrl
            config["load-test.seed-jdbc-url"] =
                System.getenv("PERMISSIONS_LOAD_TEST_SEED_JDBC_URL") ?: externalUrl
            config["quarkus.datasource.username"] = env("PERMISSIONS_LOAD_TEST_DB_USER", "app")
            config["quarkus.datasource.password"] = env("PERMISSIONS_LOAD_TEST_DB_PASSWORD", "app")
        } else {
            val network = Network.newNetwork().also { network = it }
            val postgres =
                PostgreSQLContainer("postgres:17-alpine")
                    .withNetwork(network)
                    .withNetworkAliases("postgres")
                    .also { containers += it }
            postgres.start()
            val toxiproxy =
                ToxiproxyContainer("ghcr.io/shopify/toxiproxy:2.12.0").withNetwork(network).also {
                    containers += it
                }
            toxiproxy.start()
            val proxy =
                ToxiproxyClient(toxiproxy.host, toxiproxy.controlPort)
                    .createProxy("postgres", "0.0.0.0:8666", "postgres:5432")
            proxy.toxics().latency("latency-up", ToxicDirection.UPSTREAM, LATENCY_MS / 2)
            proxy.toxics().latency("latency-down", ToxicDirection.DOWNSTREAM, LATENCY_MS / 2)
            val database = postgres.databaseName
            config["quarkus.datasource.jdbc.url"] =
                "jdbc:postgresql://${toxiproxy.host}:${toxiproxy.getMappedPort(8666)}/$database" +
                    "?currentSchema=permissions"
            val separator = if (postgres.jdbcUrl.contains("?")) "&" else "?"
            config["load-test.seed-jdbc-url"] =
                "${postgres.jdbcUrl}${separator}currentSchema=permissions"
            config["quarkus.datasource.username"] = postgres.username
            config["quarkus.datasource.password"] = postgres.password
        }
        if (VALKEY) {
            config["permissions.snapshot-cache.valkey.enabled"] = "true"
            config["quarkus.redis.hosts"] =
                System.getenv("PERMISSIONS_LOAD_TEST_VALKEY_URL")
                    ?: GenericContainer("valkey/valkey:8-alpine")
                        .withExposedPorts(6379)
                        .also { containers += it }
                        .apply { start() }
                        .let { "redis://${it.host}:${it.getMappedPort(6379)}" }
        }
        return config
    }

    override fun stop() {
        containers.reversed().forEach { it.stop() }
        network?.close()
    }

    companion object {
        private val LATENCY_MS = env("PERMISSIONS_LOAD_TEST_LATENCY_MS", "100").toLong()
        private val POOL_SIZE = env("PERMISSIONS_LOAD_TEST_POOL_SIZE", "2").toInt()
        private val VALKEY = env("PERMISSIONS_LOAD_TEST_VALKEY", "false").toBoolean()

        fun describe(): String =
            "rttLatencyMs=$LATENCY_MS poolSize=$POOL_SIZE valkey=$VALKEY" +
                if (System.getenv("PERMISSIONS_LOAD_TEST_JDBC_URL") != null) " (external proxy)"
                else ""
    }
}

private fun env(name: String, default: String): String = System.getenv(name) ?: default
