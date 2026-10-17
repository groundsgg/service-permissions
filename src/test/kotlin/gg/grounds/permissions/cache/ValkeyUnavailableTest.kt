package gg.grounds.permissions.cache

import com.fasterxml.jackson.databind.ObjectMapper
import gg.grounds.permissions.domain.RoleDefinition
import io.quarkus.redis.datasource.keys.ReactiveKeyCommands
import io.quarkus.redis.datasource.value.ReactiveValueCommands
import io.smallrye.mutiny.Uni
import java.time.Duration
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock

class ValkeyUnavailableTest {
    private val reads = AtomicInteger()
    @Volatile private var readResult: Uni<Map<String, String>> = Uni.createFrom().nothing()
    private val deletedKeys = CopyOnWriteArrayList<String>()
    private val values =
        mock<ReactiveValueCommands<String, String>>(
            defaultAnswer = { invocation ->
                when (invocation.method.name) {
                    "mget" -> {
                        reads.incrementAndGet()
                        readResult
                    }
                    else -> null
                }
            }
        )
    private val keys =
        mock<ReactiveKeyCommands<String>>(
            defaultAnswer = { invocation ->
                if (invocation.method.name == "del") {
                    (invocation.rawArguments[0] as Array<*>).forEach { deletedKeys += it as String }
                    Uni.createFrom().item(1)
                } else {
                    null
                }
            }
        )
    private val now = AtomicLong(0)
    private val l2 =
        ValkeyPlayerPolicyL2(
            values,
            keys,
            { Uni.createFrom().failure(IllegalStateException("down")) },
            ObjectMapper(),
            ttl = Duration.ofMinutes(5),
            timeout = Duration.ofMillis(50),
            nanoTime = now::get,
        )

    @Test
    fun aHangingValkeyCostsOneTimeoutThenReadsAreSkippedUntilThePauseEnds() {
        val playerIds = setOf(UUID.randomUUID())

        assertTrue(l2.getAll(playerIds, 1).isEmpty())
        assertTrue(l2.getAll(playerIds, 1).isEmpty())
        assertEquals(1, reads.get())

        now.addAndGet(ValkeyPlayerPolicyL2.OPEN_DURATION.toNanos() + 1)
        assertTrue(l2.getAll(playerIds, 1).isEmpty())
        assertEquals(2, reads.get())
    }

    @Test
    fun invalidationsAreStillSentWhileReadsArePaused() {
        readResult = Uni.createFrom().failure(IllegalStateException("down"))
        val playerId = UUID.randomUUID()
        l2.getAll(setOf(playerId), 3)

        l2.delete(playerId, 3)

        assertEquals(listOf(ValkeyPlayerPolicyL2.key(playerId, 3)), deletedKeys)
    }

    @Test
    fun snapshotsFallBackToTheDatabaseWhenValkeyFails() {
        readResult = Uni.createFrom().failure(IllegalStateException("down"))
        val playerId = UUID.randomUUID()
        val cache =
            PermissionSnapshotCache(
                SnapshotCacheSettings(),
                l2,
                object : PolicyDataSource {
                    override fun loadGlobalDefinitions() =
                        GlobalPolicyDefinitions(
                            1,
                            listOf(RoleDefinition(key = "default", name = "Default")),
                            emptyList(),
                            null,
                        )

                    override fun loadPlayerPolicyData(playerIds: Set<UUID>) =
                        playerIds.associateWith {
                            PlayerPolicyData(it, 1, emptyList(), emptyList(), emptySet(), null)
                        }
                },
            )
        cache.globals()

        assertEquals(playerId, cache.player(playerId).playerId)
        assertEquals(1, reads.get())
    }
}
