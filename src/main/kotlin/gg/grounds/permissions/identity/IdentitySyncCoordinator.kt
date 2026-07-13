package gg.grounds.permissions.identity

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.sql.Connection
import java.time.Clock
import java.time.Duration
import javax.sql.DataSource
import org.jboss.logging.Logger

enum class IdentitySyncOutcome {
    COMPLETED,
    ALREADY_RUNNING,
    FAILED,
}

enum class IdentityRefreshOutcome {
    UPDATED,
    REMOVED,
    FAILED,
}

sealed interface IdentitySyncLockResult<out T> {
    data class Acquired<T>(val value: T) : IdentitySyncLockResult<T>

    data object AlreadyLocked : IdentitySyncLockResult<Nothing>
}

interface IdentitySyncLock {
    fun <T> tryRun(operation: () -> T): IdentitySyncLockResult<T>
}

@ApplicationScoped
class PostgresIdentitySyncLock @Inject constructor(private val dataSource: DataSource) :
    IdentitySyncLock {
    override fun <T> tryRun(operation: () -> T): IdentitySyncLockResult<T> =
        dataSource.connection.use { connection ->
            if (!tryAcquire(connection)) {
                IdentitySyncLockResult.AlreadyLocked
            } else {
                try {
                    IdentitySyncLockResult.Acquired(operation())
                } finally {
                    release(connection)
                }
            }
        }

    private fun tryAcquire(connection: Connection): Boolean =
        connection.prepareStatement("SELECT pg_try_advisory_lock(?)").use { statement ->
            statement.setLong(1, LOCK_ID)
            statement.executeQuery().use { rows ->
                check(rows.next()) { "Identity sync advisory lock query returned no result" }
                rows.getBoolean(1)
            }
        }

    private fun release(connection: Connection) {
        connection.prepareStatement("SELECT pg_advisory_unlock(?)").use { statement ->
            statement.setLong(1, LOCK_ID)
            statement.executeQuery().use { rows ->
                check(rows.next() && rows.getBoolean(1)) {
                    "Identity sync advisory lock was not held"
                }
            }
        }
    }

    private companion object {
        const val LOCK_ID = 0x67726F756E647350L
    }
}

@ApplicationScoped
class IdentitySyncCoordinator(
    private val store: PlayerIdentityStore,
    private val source: PlayerIdentitySource,
    private val clock: Clock,
    private val syncLock: IdentitySyncLock = UnlockedIdentitySyncLock,
) {
    @Inject
    constructor(
        store: PlayerIdentityStore,
        source: PlayerIdentitySynchronizer,
        syncLock: PostgresIdentitySyncLock,
    ) : this(store, source, Clock.systemUTC(), syncLock)

    fun synchronizeAll(): IdentitySyncOutcome {
        val startedAt = clock.instant()
        return try {
            when (val result = syncLock.tryRun { synchronizeLocked(startedAt) }) {
                is IdentitySyncLockResult.Acquired -> result.value
                IdentitySyncLockResult.AlreadyLocked -> IdentitySyncOutcome.ALREADY_RUNNING
            }
        } catch (_: Exception) {
            val completedAt = clock.instant()
            LOG.errorf(
                "Player identity sync failed (durationMs=%d, reason=%s)",
                elapsedMilliseconds(startedAt, completedAt),
                SYNC_FAILURE_REASON,
            )
            IdentitySyncOutcome.FAILED
        }
    }

    private fun synchronizeLocked(startedAt: java.time.Instant): IdentitySyncOutcome {
        try {
            store.markSyncRunning(startedAt)
        } catch (_: IllegalStateException) {
            return if (store.currentSyncState().status == IdentitySyncStatus.RUNNING) {
                IdentitySyncOutcome.ALREADY_RUNNING
            } else {
                IdentitySyncOutcome.FAILED
            }
        }

        return try {
            val identities = source.loadAll()
            val completedAt = clock.instant()
            store.replaceAll(identities, completedAt)
            LOG.infof(
                "Player identity sync completed successfully (durationMs=%d, playerCount=%d)",
                elapsedMilliseconds(startedAt, completedAt),
                identities.size,
            )
            IdentitySyncOutcome.COMPLETED
        } catch (_: Exception) {
            val completedAt = clock.instant()
            runCatching { store.markSyncFailed(completedAt, SYNC_FAILURE_REASON) }
            LOG.errorf(
                "Player identity sync failed (durationMs=%d, reason=%s)",
                elapsedMilliseconds(startedAt, completedAt),
                SYNC_FAILURE_REASON,
            )
            IdentitySyncOutcome.FAILED
        }
    }

    fun refreshPlayer(keycloakUserId: String): IdentityRefreshOutcome {
        val startedAt = clock.instant()
        return try {
            val identity = source.loadPlayer(keycloakUserId)
            val outcome =
                if (identity == null) {
                    store.deleteByKeycloakUserId(keycloakUserId)
                    IdentityRefreshOutcome.REMOVED
                } else {
                    store.replacePlayer(identity)
                    IdentityRefreshOutcome.UPDATED
                }
            val completedAt = clock.instant()
            LOG.infof(
                "Player identity refresh completed successfully (keycloakUserId=%s, reason=%s, durationMs=%d)",
                keycloakUserId,
                outcome.name.lowercase(),
                elapsedMilliseconds(startedAt, completedAt),
            )
            outcome
        } catch (_: Exception) {
            val completedAt = clock.instant()
            LOG.errorf(
                "Player identity refresh failed (keycloakUserId=%s, reason=%s, durationMs=%d)",
                keycloakUserId,
                REFRESH_FAILURE_REASON,
                elapsedMilliseconds(startedAt, completedAt),
            )
            IdentityRefreshOutcome.FAILED
        }
    }

    private fun elapsedMilliseconds(
        startedAt: java.time.Instant,
        completedAt: java.time.Instant,
    ): Long = Duration.between(startedAt, completedAt).toMillis().coerceAtLeast(0)

    private companion object {
        private const val SYNC_FAILURE_REASON = "identity_sync_failed"
        private const val REFRESH_FAILURE_REASON = "identity_refresh_failed"
        private val LOG = Logger.getLogger(IdentitySyncCoordinator::class.java)
    }
}

private object UnlockedIdentitySyncLock : IdentitySyncLock {
    override fun <T> tryRun(operation: () -> T): IdentitySyncLockResult<T> =
        IdentitySyncLockResult.Acquired(operation())
}
