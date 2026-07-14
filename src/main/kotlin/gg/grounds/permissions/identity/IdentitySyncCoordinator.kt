package gg.grounds.permissions.identity

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.sql.Connection
import java.time.Clock
import java.time.Duration
import java.util.concurrent.Executor
import javax.sql.DataSource
import org.eclipse.microprofile.config.inject.ConfigProperty
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
    override fun <T> tryRun(operation: () -> T): IdentitySyncLockResult<T> {
        val connection = dataSource.connection
        var transactionStarted = false
        var operationFailure: Throwable? = null
        var result: IdentitySyncLockResult<T>? = null
        try {
            connection.autoCommit = false
            transactionStarted = true
            result =
                if (tryAcquire(connection)) {
                    IdentitySyncLockResult.Acquired(operation())
                } else {
                    IdentitySyncLockResult.AlreadyLocked
                }
        } catch (error: Throwable) {
            operationFailure = error
        } finally {
            if (transactionStarted) {
                completeTransaction(connection, operationFailure)
            }
            closeConnection(connection, operationFailure)
        }

        operationFailure?.let { throw it }
        return checkNotNull(result)
    }

    private fun tryAcquire(connection: Connection): Boolean =
        connection.prepareStatement("SELECT pg_try_advisory_xact_lock(?)").use { statement ->
            statement.setLong(1, LOCK_ID)
            statement.executeQuery().use { rows ->
                check(rows.next()) { "Identity sync advisory lock query returned no result" }
                rows.getBoolean(1)
            }
        }

    private fun completeTransaction(connection: Connection, operationFailure: Throwable?) {
        try {
            if (operationFailure == null) {
                connection.commit()
            } else {
                connection.rollback()
            }
        } catch (cleanupFailure: Throwable) {
            recordCleanupFailure(cleanupFailure, operationFailure, TRANSACTION_PHASE)
            abortConnection(connection, operationFailure ?: cleanupFailure)
        }
    }

    private fun closeConnection(connection: Connection, operationFailure: Throwable?) {
        try {
            connection.close()
        } catch (cleanupFailure: Throwable) {
            recordCleanupFailure(cleanupFailure, operationFailure, CLOSE_PHASE)
            abortConnection(connection, operationFailure ?: cleanupFailure)
        }
    }

    private fun abortConnection(connection: Connection, primaryFailure: Throwable) {
        try {
            connection.abort(DIRECT_EXECUTOR)
        } catch (abortFailure: Throwable) {
            primaryFailure.addSuppressed(abortFailure)
            LOG.warnf(
                "Identity sync lock cleanup failed (lockId=%d, phase=%s, reason=%s)",
                LOCK_ID,
                ABORT_PHASE,
                CONNECTION_CLEANUP_FAILURE_REASON,
            )
        }
    }

    private fun recordCleanupFailure(
        cleanupFailure: Throwable,
        operationFailure: Throwable?,
        phase: String,
    ) {
        operationFailure?.addSuppressed(cleanupFailure)
        LOG.warnf(
            "Identity sync lock cleanup failed (lockId=%d, phase=%s, reason=%s)",
            LOCK_ID,
            phase,
            CONNECTION_CLEANUP_FAILURE_REASON,
        )
    }

    private companion object {
        const val LOCK_ID = 0x67726F756E647350L
        const val TRANSACTION_PHASE = "transaction"
        const val CLOSE_PHASE = "close"
        const val ABORT_PHASE = "abort"
        const val CONNECTION_CLEANUP_FAILURE_REASON = "connection_cleanup_failed"
        val DIRECT_EXECUTOR = Executor(Runnable::run)
        val LOG: Logger = Logger.getLogger(PostgresIdentitySyncLock::class.java)
    }
}

@ApplicationScoped
class IdentitySyncCoordinator(
    private val store: PlayerIdentityStore,
    private val source: PlayerIdentitySource,
    private val clock: Clock,
    private val maxStaleness: Duration = DEFAULT_MAX_STALENESS,
    private val syncLock: IdentitySyncLock = UnlockedIdentitySyncLock,
) {
    @Inject
    constructor(
        store: PlayerIdentityStore,
        source: PlayerIdentitySynchronizer,
        syncLock: PostgresIdentitySyncLock,
        @ConfigProperty(name = "permissions.identity-sync.max-staleness") maxStaleness: Duration,
    ) : this(store, source, Clock.systemUTC(), maxStaleness, syncLock)

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
        val staleBefore = startedAt.minus(maxStaleness)
        if (!store.tryMarkSyncRunning(startedAt, staleBefore)) {
            return IdentitySyncOutcome.ALREADY_RUNNING
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
            markSyncFailed(startedAt, completedAt)
            LOG.errorf(
                "Player identity sync failed (durationMs=%d, reason=%s)",
                elapsedMilliseconds(startedAt, completedAt),
                SYNC_FAILURE_REASON,
            )
            IdentitySyncOutcome.FAILED
        }
    }

    private fun markSyncFailed(startedAt: java.time.Instant, completedAt: java.time.Instant) {
        repeat(SYNC_STATE_UPDATE_ATTEMPTS) {
            try {
                store.markSyncFailed(completedAt, SYNC_FAILURE_REASON)
                return
            } catch (_: Exception) {
                // Retry once before reporting the persistence outcome.
            }
        }
        LOG.errorf(
            "Player identity sync state update failed (durationMs=%d, reason=%s)",
            elapsedMilliseconds(startedAt, completedAt),
            SYNC_STATE_UPDATE_FAILURE_REASON,
        )
    }

    fun refreshPlayer(keycloakUserId: String): IdentityRefreshOutcome {
        val startedAt = clock.instant()
        return try {
            val identity = source.loadPlayer(keycloakUserId)
            val outcome =
                if (identity == null) {
                    store.deleteByKeycloakUserId(keycloakUserId, clock.instant())
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
        private const val SYNC_STATE_UPDATE_FAILURE_REASON = "identity_sync_state_update_failed"
        private const val SYNC_STATE_UPDATE_ATTEMPTS = 2
        private const val REFRESH_FAILURE_REASON = "identity_refresh_failed"
        private val DEFAULT_MAX_STALENESS = Duration.ofHours(6)
        private val LOG = Logger.getLogger(IdentitySyncCoordinator::class.java)
    }
}

private object UnlockedIdentitySyncLock : IdentitySyncLock {
    override fun <T> tryRun(operation: () -> T): IdentitySyncLockResult<T> =
        IdentitySyncLockResult.Acquired(operation())
}
