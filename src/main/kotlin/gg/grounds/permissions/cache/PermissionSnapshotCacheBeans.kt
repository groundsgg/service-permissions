package gg.grounds.permissions.cache

import com.fasterxml.jackson.databind.ObjectMapper
import gg.grounds.permissions.identity.PermissionSnapshotInvalidationEvent
import gg.grounds.permissions.identity.buildNatsConnectionOptions
import gg.grounds.permissions.persistence.PermissionRepository
import io.nats.client.Connection
import io.nats.client.Nats
import io.quarkus.runtime.ShutdownEvent
import io.quarkus.runtime.StartupEvent
import io.quarkus.scheduler.Scheduled
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.event.Observes
import jakarta.enterprise.inject.Produces
import jakarta.inject.Inject
import jakarta.inject.Singleton
import java.time.Duration
import java.util.Optional
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger

@ApplicationScoped
class SnapshotCacheSettingsProducer {
    @Produces
    @Singleton
    fun snapshotCacheSettings(
        @ConfigProperty(name = "permissions.snapshot-cache.player-ttl") playerTtl: Duration,
        @ConfigProperty(name = "permissions.snapshot-cache.max-players") maxPlayers: Long,
        @ConfigProperty(name = "permissions.snapshot-cache.max-concurrent-loads")
        maxConcurrentLoads: Int,
    ): SnapshotCacheSettings =
        SnapshotCacheSettings(
            playerTtl = playerTtl,
            maxPlayers = maxPlayers,
            maxConcurrentLoads = maxConcurrentLoads,
        )
}

/**
 * Picks up writes made by other service instances; see [PermissionRepository.refreshSnapshotCache].
 */
@ApplicationScoped
class PermissionSnapshotCacheRefresher
@Inject
constructor(private val repository: PermissionRepository) {
    @Scheduled(
        identity = "permission-snapshot-cache-refresh",
        every = "{permissions.snapshot-cache.poll-interval}",
        concurrentExecution = Scheduled.ConcurrentExecution.SKIP,
    )
    fun refresh() {
        try {
            repository.refreshSnapshotCache()
        } catch (_: Exception) {
            LOG.warnf(
                "Permission snapshot cache refresh failed (reason=%s)",
                REFRESH_FAILURE_REASON,
            )
        }
    }

    private companion object {
        const val REFRESH_FAILURE_REASON = "policy_version_poll_failed"
        val LOG: Logger = Logger.getLogger(PermissionSnapshotCacheRefresher::class.java)
    }
}

/**
 * Evicts players named on `permissions.snapshot.invalidated`, so an invalidation published by any
 * instance (in any region) also clears this instance's L1 and its region's L2. Off by default: the
 * NATS user needs subscribe permission on the subject first.
 */
@ApplicationScoped
class PermissionSnapshotInvalidationSubscriber
@Inject
constructor(
    private val repository: PermissionRepository,
    private val objectMapper: ObjectMapper,
    @param:ConfigProperty(name = "permissions.snapshot-cache.nats-invalidations.enabled")
    private val enabled: Boolean,
    @param:ConfigProperty(name = "permissions.snapshot-invalidations.subject")
    private val subject: String,
    @param:ConfigProperty(name = "permissions.identity-events.nats-url")
    private val natsUrl: String,
    @param:ConfigProperty(name = "grounds.token-file") private val tokenFile: Optional<String>,
) {
    @Volatile private var connection: Connection? = null

    fun onStart(@Observes event: StartupEvent) {
        if (!enabled) {
            return
        }
        try {
            val activeConnection =
                Nats.connect(buildNatsConnectionOptions(natsUrl, tokenFile.orElse(null)))
            activeConnection
                .createDispatcher { message -> onMessage(message.data) }
                .subscribe(subject)
            connection = activeConnection
            LOG.infof("Permission snapshot invalidation subscription started (subject=%s)", subject)
        } catch (_: Exception) {
            LOG.warnf(
                "Permission snapshot invalidation subscription failed (subject=%s, reason=%s)",
                subject,
                SUBSCRIBE_FAILURE_REASON,
            )
        }
    }

    fun onStop(@Observes event: ShutdownEvent) {
        connection?.close()
        connection = null
    }

    internal fun onMessage(payload: ByteArray) {
        val playerId =
            try {
                objectMapper
                    .readValue(payload, PermissionSnapshotInvalidationEvent::class.java)
                    .playerId
            } catch (_: Exception) {
                LOG.debugf(
                    "Permission snapshot invalidation ignored (reason=%s)",
                    INVALID_EVENT_REASON,
                )
                return
            }
        repository.snapshotCache.evictPlayer(playerId)
    }

    private companion object {
        const val SUBSCRIBE_FAILURE_REASON = "nats_subscribe_failed"
        const val INVALID_EVENT_REASON = "invalid_event"
        val LOG: Logger = Logger.getLogger(PermissionSnapshotInvalidationSubscriber::class.java)
    }
}
