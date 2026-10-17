package gg.grounds.permissions.cache

import com.github.benmanes.caffeine.cache.AsyncCache
import com.github.benmanes.caffeine.cache.Caffeine
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.PlayerRoleGrant
import gg.grounds.permissions.domain.RoleDefinition
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** A Keycloak group that grants a role to every player in it. */
data class GroupRoleMapping(
    val mappingId: UUID,
    val keycloakGroup: String,
    val roleKey: String,
    val startsAt: Instant? = null,
    val expiresAt: Instant? = null,
)

/** Everything a snapshot needs that is the same for every player, read at one policy version. */
data class GlobalPolicyDefinitions(
    val policyVersion: Long,
    val roles: List<RoleDefinition>,
    val groupMappings: List<GroupRoleMapping>,
    val identityLastSuccessAt: Instant?,
)

/** The rows of one player that feed a snapshot, read in one statement at [policyVersion]. */
data class PlayerPolicyData(
    val playerId: UUID,
    val policyVersion: Long,
    val roleGrants: List<PlayerRoleGrant>,
    val grants: List<PlayerPermissionGrant>,
    val groupPaths: Set<String>,
    val identityLastSuccessAt: Instant?,
)

data class SnapshotCacheSettings(
    val playerTtl: Duration = Duration.ofSeconds(60),
    val maxPlayers: Long = 10_000,
    val maxConcurrentLoads: Int = 2,
    val maxBatchSize: Int = 500,
)

interface PolicyDataSource {
    fun loadGlobalDefinitions(): GlobalPolicyDefinitions

    /** Loads every requested player in one database round trip. */
    fun loadPlayerPolicyData(playerIds: Set<UUID>): Map<UUID, PlayerPolicyData>
}

/**
 * Snapshot inputs cached per service instance.
 *
 * Global definitions are kept until the policy version changes (a local write marks them stale at
 * once, the background poll notices writes from other instances). Player rows live in an L1
 * in-process cache with a short TTL and are evicted by targeted invalidations; on an L1 miss the
 * optional regional L2 is asked before the database. Concurrent misses are coalesced, per player
 * and across players, into batched loads that take one database round trip each.
 */
class PermissionSnapshotCache(
    settings: SnapshotCacheSettings,
    private val l2: PlayerPolicyL2,
    private val source: PolicyDataSource,
) : AutoCloseable {
    private val loaderThreads: ExecutorService = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "permission-snapshot-loader").apply { isDaemon = true }
    }
    private val players: AsyncCache<UUID, PlayerPolicyData> =
        Caffeine.newBuilder()
            .expireAfterWrite(settings.playerTtl)
            .maximumSize(settings.maxPlayers)
            .executor(Runnable::run)
            .buildAsync()
    private val loader =
        CoalescingPlayerLoader(
            settings.maxConcurrentLoads,
            settings.maxBatchSize,
            loaderThreads,
            ::loadBatch,
        )
    private val globalsLock = ReentrantLock()
    @Volatile private var globals: GlobalPolicyDefinitions? = null
    @Volatile private var globalsStale = false

    /** The most recently observed identity sync success, used by the identity readiness check. */
    @Volatile
    var identityLastSuccessAt: Instant? = null
        private set

    fun globals(minimumVersion: Long = 0): GlobalPolicyDefinitions {
        currentGlobals(minimumVersion)?.let {
            return it
        }
        return globalsLock.withLock {
            currentGlobals(minimumVersion)
                ?: run {
                    globalsStale = false
                    val loaded =
                        try {
                            source.loadGlobalDefinitions()
                        } catch (error: Throwable) {
                            globalsStale = true
                            throw error
                        }
                    globals = loaded
                    identityLastSuccessAt = loaded.identityLastSuccessAt
                    loaded
                }
        }
    }

    fun player(playerId: UUID): PlayerPolicyData =
        try {
            players.get(playerId) { id, _ -> loader.load(id) }.join()
        } catch (error: CompletionException) {
            throw error.cause ?: error
        }

    fun evictPlayer(playerId: UUID) {
        players.synchronous().invalidate(playerId)
        globals?.let { l2.delete(playerId, it.policyVersion) }
    }

    fun markGlobalsStale() {
        globalsStale = true
    }

    /** Applies what the background poll saw in the database. */
    fun observe(policyVersion: Long, identityLastSuccessAt: Instant?, changedPlayers: Set<UUID>) {
        this.identityLastSuccessAt = identityLastSuccessAt
        changedPlayers.forEach(::evictPlayer)
        if (globals?.policyVersion != policyVersion) {
            markGlobalsStale()
        }
    }

    /** Drops the in-process state, as after a restart. L2 entries stay. */
    fun clear() {
        players.synchronous().invalidateAll()
        globalsLock.withLock {
            globals = null
            globalsStale = false
        }
        identityLastSuccessAt = null
    }

    override fun close() {
        loaderThreads.shutdownNow()
    }

    private fun currentGlobals(minimumVersion: Long): GlobalPolicyDefinitions? = globals?.takeIf {
        !globalsStale && it.policyVersion >= minimumVersion
    }

    private fun loadBatch(playerIds: Set<UUID>): Map<UUID, PlayerPolicyData> {
        val version = globals?.policyVersion
        val fromL2 = if (version == null) emptyMap() else l2.getAll(playerIds, version)
        val missing = playerIds - fromL2.keys
        if (missing.isEmpty()) {
            return fromL2
        }
        val fromDatabase = source.loadPlayerPolicyData(missing)
        fromDatabase.values.firstOrNull()?.let { identityLastSuccessAt = it.identityLastSuccessAt }
        l2.putAll(fromDatabase.values)
        return fromL2 + fromDatabase
    }
}

/**
 * Collects concurrent player misses into batches. At most [maxConcurrentLoads] batches run at once,
 * so a burst of misses holds at most that many pooled connections and every player is loaded once.
 */
private class CoalescingPlayerLoader(
    private val maxConcurrentLoads: Int,
    private val maxBatchSize: Int,
    private val executor: ExecutorService,
    private val loadBatch: (Set<UUID>) -> Map<UUID, PlayerPolicyData>,
) {
    private val lock = Any()
    private val pending = LinkedHashMap<UUID, CompletableFuture<PlayerPolicyData>>()
    private var running = 0

    fun load(playerId: UUID): CompletableFuture<PlayerPolicyData> =
        synchronized(lock) {
            val future = pending.getOrPut(playerId) { CompletableFuture() }
            if (running < maxConcurrentLoads) {
                running++
                executor.execute(::drain)
            }
            future
        }

    private fun drain() {
        while (true) {
            val batch =
                synchronized(lock) {
                    if (pending.isEmpty()) {
                        running--
                        return
                    }
                    val taken = pending.entries.take(maxBatchSize).associate { it.toPair() }
                    taken.keys.forEach(pending::remove)
                    taken
                }
            try {
                val loaded = loadBatch(batch.keys)
                batch.forEach { (playerId, future) ->
                    val data = loaded[playerId]
                    if (data == null) {
                        future.completeExceptionally(
                            IllegalStateException("Player policy data was not loaded")
                        )
                    } else {
                        future.complete(data)
                    }
                }
            } catch (error: Throwable) {
                batch.values.forEach { it.completeExceptionally(error) }
            }
        }
    }
}
