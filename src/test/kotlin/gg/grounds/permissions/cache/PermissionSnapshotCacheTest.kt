package gg.grounds.permissions.cache

import gg.grounds.permissions.domain.RoleDefinition
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PermissionSnapshotCacheTest {
    private val source = FakePolicyDataSource()

    @Test
    fun concurrentMissesLoadEachPlayerOnceInFewBatches() {
        val cache = PermissionSnapshotCache(SnapshotCacheSettings(), DisabledPlayerPolicyL2, source)
        val players = List(200) { UUID.randomUUID() }
        source.batchDelayMillis = 50
        val executor = Executors.newFixedThreadPool(400)
        val start = CountDownLatch(1)
        try {
            val calls =
                (players + players).map { playerId ->
                    Callable {
                        start.await()
                        cache.player(playerId)
                    }
                }
            val futures = calls.map(executor::submit)
            start.countDown()
            futures.forEach { it.get(10, TimeUnit.SECONDS) }
        } finally {
            executor.shutdownNow()
        }

        assertEquals(players.toSet(), source.loadedPlayers.keys)
        assertTrue(source.loadedPlayers.values.all { it.get() == 1 }, "a player was loaded twice")
        assertTrue(source.batches.get() <= 6, "expected coalesced batches, got ${source.batches}")
    }

    @Test
    fun evictedPlayersAreReloaded() {
        val cache = PermissionSnapshotCache(SnapshotCacheSettings(), DisabledPlayerPolicyL2, source)
        val playerId = UUID.randomUUID()

        cache.player(playerId)
        cache.player(playerId)
        cache.evictPlayer(playerId)
        cache.player(playerId)

        assertEquals(2, source.loadedPlayers.getValue(playerId).get())
    }

    @Test
    fun observedVersionChangeReloadsGlobalsButKeepsUnchangedPlayers() {
        val cache = PermissionSnapshotCache(SnapshotCacheSettings(), DisabledPlayerPolicyL2, source)
        val unchanged = UUID.randomUUID()
        val changed = UUID.randomUUID()
        cache.globals()
        cache.player(unchanged)
        cache.player(changed)

        source.version.set(2)
        cache.observe(2, Instant.EPOCH, setOf(changed))

        assertEquals(2, cache.globals().policyVersion)
        assertEquals(2, source.globalLoads.get())
        cache.player(unchanged)
        cache.player(changed)
        assertEquals(1, source.loadedPlayers.getValue(unchanged).get())
        assertEquals(2, source.loadedPlayers.getValue(changed).get())
    }

    @Test
    fun globalsAreLoadedOnceUntilMarkedStale() {
        val cache = PermissionSnapshotCache(SnapshotCacheSettings(), DisabledPlayerPolicyL2, source)

        repeat(5) { cache.globals() }
        cache.markGlobalsStale()
        cache.globals()

        assertEquals(2, source.globalLoads.get())
    }

    @Test
    fun l2HitsSkipTheDatabaseAndMissesAreWrittenBack() {
        val l2 = FakePlayerPolicyL2()
        val cache = PermissionSnapshotCache(SnapshotCacheSettings(), l2, source)
        val cachedPlayer = UUID.randomUUID()
        val newPlayer = UUID.randomUUID()
        l2.entries[cachedPlayer to 1L] = source.dataFor(cachedPlayer)
        cache.globals()

        cache.player(cachedPlayer)
        cache.player(newPlayer)

        assertEquals(setOf(newPlayer), source.loadedPlayers.keys)
        assertTrue(l2.entries.containsKey(newPlayer to 1L))

        cache.evictPlayer(newPlayer)
        assertTrue(!l2.entries.containsKey(newPlayer to 1L))
    }

    private class FakePolicyDataSource : PolicyDataSource {
        val version = AtomicLong(1)
        val globalLoads = AtomicInteger()
        val batches = AtomicInteger()
        val loadedPlayers = ConcurrentHashMap<UUID, AtomicInteger>()
        @Volatile var batchDelayMillis = 0L

        override fun loadGlobalDefinitions(): GlobalPolicyDefinitions {
            globalLoads.incrementAndGet()
            return GlobalPolicyDefinitions(
                policyVersion = version.get(),
                roles = listOf(RoleDefinition(key = "default", name = "Default")),
                groupMappings = emptyList(),
                identityLastSuccessAt = null,
            )
        }

        override fun loadPlayerPolicyData(playerIds: Set<UUID>): Map<UUID, PlayerPolicyData> {
            batches.incrementAndGet()
            Thread.sleep(batchDelayMillis)
            playerIds.forEach {
                loadedPlayers.computeIfAbsent(it) { AtomicInteger() }.incrementAndGet()
            }
            return playerIds.associateWith(::dataFor)
        }

        fun dataFor(playerId: UUID) =
            PlayerPolicyData(
                playerId = playerId,
                policyVersion = version.get(),
                roleGrants = emptyList(),
                grants = emptyList(),
                groupPaths = emptySet(),
                identityLastSuccessAt = null,
            )
    }

    private class FakePlayerPolicyL2 : PlayerPolicyL2 {
        val entries = ConcurrentHashMap<Pair<UUID, Long>, PlayerPolicyData>()

        override fun getAll(playerIds: Set<UUID>, policyVersion: Long) =
            playerIds.mapNotNull { id -> entries[id to policyVersion]?.let { id to it } }.toMap()

        override fun putAll(data: Collection<PlayerPolicyData>) {
            data.forEach { entries[it.playerId to it.policyVersion] = it }
        }

        override fun delete(playerId: UUID, policyVersion: Long) {
            entries.remove(playerId to policyVersion)
        }
    }
}
