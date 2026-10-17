package gg.grounds.permissions.cache

import com.fasterxml.jackson.databind.ObjectMapper
import io.quarkus.redis.datasource.ReactiveRedisDataSource
import io.quarkus.redis.datasource.keys.ReactiveKeyCommands
import io.quarkus.redis.datasource.value.ReactiveValueCommands
import io.smallrye.mutiny.Uni
import io.vertx.mutiny.redis.client.Command
import io.vertx.mutiny.redis.client.Request
import io.vertx.mutiny.redis.client.Response
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.inject.Instance
import jakarta.enterprise.inject.Produces
import jakarta.inject.Inject
import java.time.Duration
import java.util.UUID
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger

/**
 * Regional second-level cache for player policy rows, shared by the service instances of one
 * region. It is best effort: every failure reads as a miss and never fails the request.
 */
interface PlayerPolicyL2 {
    fun getAll(playerIds: Set<UUID>, policyVersion: Long): Map<UUID, PlayerPolicyData>

    fun putAll(data: Collection<PlayerPolicyData>)

    fun delete(playerId: UUID, policyVersion: Long)
}

object DisabledPlayerPolicyL2 : PlayerPolicyL2 {
    override fun getAll(playerIds: Set<UUID>, policyVersion: Long): Map<UUID, PlayerPolicyData> =
        emptyMap()

    override fun putAll(data: Collection<PlayerPolicyData>) = Unit

    override fun delete(playerId: UUID, policyVersion: Long) = Unit
}

/**
 * Valkey-backed L2 under `perm:snap:<playerId>:<policyVersion>`. Reads wait at most [timeout].
 * After a failure reads are skipped for [OPEN_DURATION], so an unreachable Valkey costs one timeout
 * per pause instead of one per request. Writes and deletes never block the request and are always
 * sent, so an invalidation is not lost while reads are paused.
 */
class ValkeyPlayerPolicyL2(
    private val values: ReactiveValueCommands<String, String>,
    private val keys: ReactiveKeyCommands<String>,
    private val pipeline: (List<Request>) -> Uni<List<Response>>,
    private val objectMapper: ObjectMapper,
    private val ttl: Duration,
    private val timeout: Duration,
    private val nanoTime: () -> Long = System::nanoTime,
) : PlayerPolicyL2 {
    @Volatile private var openUntilNanos: Long? = null

    override fun getAll(playerIds: Set<UUID>, policyVersion: Long): Map<UUID, PlayerPolicyData> {
        if (playerIds.isEmpty() || isOpen()) {
            return emptyMap()
        }
        val keysByPlayer = playerIds.associateWith { key(it, policyVersion) }
        val cached =
            try {
                values.mget(*keysByPlayer.values.toTypedArray()).await().atMost(timeout)
            } catch (error: Exception) {
                trip(GET_OPERATION)
                return emptyMap()
            }
        return buildMap {
            keysByPlayer.forEach { (playerId, key) ->
                val json = cached[key] ?: return@forEach
                val data =
                    try {
                        objectMapper.readValue(json, PlayerPolicyData::class.java)
                    } catch (_: Exception) {
                        null
                    }
                if (data != null && data.playerId == playerId) {
                    put(playerId, data)
                }
            }
        }
    }

    override fun putAll(data: Collection<PlayerPolicyData>) {
        val requests = data.mapNotNull { entry ->
            val json =
                try {
                    objectMapper.writeValueAsString(entry)
                } catch (_: Exception) {
                    return@mapNotNull null
                }
            Request.cmd(Command.SET)
                .arg(key(entry.playerId, entry.policyVersion))
                .arg(json)
                .arg("PX")
                .arg(ttl.toMillis())
        }
        if (requests.isEmpty()) {
            return
        }
        // One pipelined round trip on one connection for the whole batch.
        pipeline(requests)
            .ifNoItem()
            .after(timeout)
            .fail()
            .subscribe()
            .with({}, { trip(PUT_OPERATION) })
    }

    override fun delete(playerId: UUID, policyVersion: Long) {
        keys
            .del(key(playerId, policyVersion))
            .ifNoItem()
            .after(timeout)
            .fail()
            .subscribe()
            .with({}, { trip(DELETE_OPERATION) })
    }

    private fun isOpen(): Boolean {
        val until = openUntilNanos ?: return false
        if (nanoTime() - until < 0) {
            return true
        }
        openUntilNanos = null
        return false
    }

    private fun trip(operation: String) {
        if (openUntilNanos == null) {
            LOG.warnf(
                "Permission snapshot L2 cache skipped after failure (operation=%s, pauseSeconds=%d, reason=%s)",
                operation,
                OPEN_DURATION.toSeconds(),
                FAILURE_REASON,
            )
        }
        openUntilNanos = nanoTime() + OPEN_DURATION.toNanos()
    }

    companion object {
        val OPEN_DURATION: Duration = Duration.ofSeconds(10)
        private const val GET_OPERATION = "get"
        private const val PUT_OPERATION = "put"
        private const val DELETE_OPERATION = "delete"
        private const val FAILURE_REASON = "valkey_unavailable"
        private val LOG: Logger = Logger.getLogger(ValkeyPlayerPolicyL2::class.java)

        fun key(playerId: UUID, policyVersion: Long): String = "perm:snap:$playerId:$policyVersion"
    }
}

@ApplicationScoped
class PlayerPolicyL2Producer
@Inject
constructor(
    @param:ConfigProperty(name = "permissions.snapshot-cache.valkey.enabled")
    private val enabled: Boolean,
    @param:ConfigProperty(name = "permissions.snapshot-cache.valkey.ttl") private val ttl: Duration,
    @param:ConfigProperty(name = "permissions.snapshot-cache.valkey.timeout")
    private val timeout: Duration,
    private val objectMapper: ObjectMapper,
    private val redis: Instance<ReactiveRedisDataSource>,
) {
    @Produces
    @ApplicationScoped
    fun playerPolicyL2(): PlayerPolicyL2 =
        if (enabled) {
            val dataSource = redis.get()
            ValkeyPlayerPolicyL2(
                dataSource.value(String::class.java),
                dataSource.key(String::class.java),
                dataSource.redis::batch,
                objectMapper,
                ttl,
                timeout,
            )
        } else {
            DisabledPlayerPolicyL2
        }
}
