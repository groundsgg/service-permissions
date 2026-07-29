package gg.grounds.permissions.identity

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.sql.Connection
import java.time.Clock
import java.time.Duration
import java.util.UUID
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
    UNCHANGED,
    REMOVED,
    FAILED,
}

data class IdentitySyncResult(
    val outcome: IdentitySyncOutcome,
    val changedPlayerIds: Set<UUID> = emptySet(),
)

data class IdentityRefreshResult(val outcome: IdentityRefreshOutcome, val playerId: UUID? = null)

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
    private val invalidationPublisher: PermissionSnapshotInvalidationPublisher =
        NoopPermissionSnapshotInvalidationPublisher,
) {
    @Inject
    constructor(
        store: PlayerIdentityStore,
        source: PlayerIdentitySynchronizer,
        syncLock: PostgresIdentitySyncLock,
        @ConfigProperty(name = "permissions.identity-sync.max-staleness") maxStaleness: Duration,
        invalidationPublisher: PermissionSnapshotInvalidationPublisher,
    ) : this(store, source, Clock.systemUTC(), maxStaleness, syncLock, invalidationPublisher)

    fun synchronizeAll(): IdentitySyncResult {
        val startedAt = clock.instant()
        return try {
            when (val result = syncLock.tryRun { synchronizeLocked(startedAt) }) {
                is IdentitySyncLockResult.Acquired -> result.value
                IdentitySyncLockResult.AlreadyLocked ->
                    IdentitySyncResult(IdentitySyncOutcome.ALREADY_RUNNING)
            }
        } catch (_: Exception) {
            val completedAt = clock.instant()
            LOG.errorf(
                "Player identity sync failed (durationMs=%d, reason=%s)",
                elapsedMilliseconds(startedAt, completedAt),
                SYNC_FAILURE_REASON,
            )
            IdentitySyncResult(IdentitySyncOutcome.FAILED)
        }
    }

    private fun synchronizeLocked(startedAt: java.time.Instant): IdentitySyncResult {
        val staleBefore = startedAt.minus(maxStaleness)
        if (!store.tryMarkSyncRunning(startedAt, staleBefore)) {
            return IdentitySyncResult(IdentitySyncOutcome.ALREADY_RUNNING)
        }

        val result =
            try {
                val identities = reconcileOmittedExistingIdentities(source.loadAll())
                val completedAt = clock.instant()
                val changes = store.replaceAll(identities, completedAt)
                LOG.infof(
                    "Player identity sync completed successfully (durationMs=%d, playerCount=%d)",
                    elapsedMilliseconds(startedAt, completedAt),
                    identities.size,
                )
                IdentitySyncResult(IdentitySyncOutcome.COMPLETED, changes.playerIds)
            } catch (_: Exception) {
                val completedAt = clock.instant()
                markSyncFailed(startedAt, completedAt)
                LOG.errorf(
                    "Player identity sync failed (durationMs=%d, reason=%s)",
                    elapsedMilliseconds(startedAt, completedAt),
                    SYNC_FAILURE_REASON,
                )
                IdentitySyncResult(IdentitySyncOutcome.FAILED)
            }
        if (result.outcome == IdentitySyncOutcome.COMPLETED) {
            publishFullInvalidations(result.changedPlayerIds)
        }
        return result
    }

    private fun reconcileOmittedExistingIdentities(
        listedIdentities: List<ProjectedPlayerIdentity>
    ): List<ProjectedPlayerIdentity> {
        val reconciled = listedIdentities.toMutableList()
        val listedKeycloakUserIds = listedIdentities.mapTo(mutableSetOf()) { it.keycloakUserId }
        store.listKeycloakUserIds().minus(listedKeycloakUserIds).forEach { keycloakUserId ->
            source.loadPlayer(keycloakUserId)?.let { identity ->
                check(identity.keycloakUserId == keycloakUserId) {
                    "Targeted identity does not match the requested Keycloak user"
                }
                reconciled += identity
            }
        }
        return reconciled
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

    fun refreshPlayer(keycloakUserId: String): IdentityRefreshResult {
        val startedAt = clock.instant()
        return try {
            val identity = source.loadPlayer(keycloakUserId)
            val result =
                if (identity == null) {
                    val changes = store.deleteByKeycloakUserId(keycloakUserId, clock.instant())
                    val playerId = changes.playerIds.singleOrNull()
                    IdentityRefreshResult(
                        outcome =
                            if (playerId == null) {
                                IdentityRefreshOutcome.UNCHANGED
                            } else {
                                IdentityRefreshOutcome.REMOVED
                            },
                        playerId = playerId,
                    )
                } else {
                    val changes = store.replacePlayer(identity)
                    IdentityRefreshResult(
                        outcome =
                            if (identity.playerId in changes.playerIds) {
                                IdentityRefreshOutcome.UPDATED
                            } else {
                                IdentityRefreshOutcome.UNCHANGED
                            },
                        playerId = identity.playerId,
                    )
                }
            result.playerId?.let(::publishTargetedInvalidation)
            val completedAt = clock.instant()
            LOG.infof(
                "Player identity refresh completed successfully (outcome=%s, durationMs=%d)",
                result.outcome.name.lowercase(),
                elapsedMilliseconds(startedAt, completedAt),
            )
            result
        } catch (_: Exception) {
            val completedAt = clock.instant()
            LOG.errorf(
                "Player identity refresh failed (reason=%s, durationMs=%d)",
                REFRESH_FAILURE_REASON,
                elapsedMilliseconds(startedAt, completedAt),
            )
            IdentityRefreshResult(IdentityRefreshOutcome.FAILED)
        }
    }

    private fun elapsedMilliseconds(
        startedAt: java.time.Instant,
        completedAt: java.time.Instant,
    ): Long = Duration.between(startedAt, completedAt).toMillis().coerceAtLeast(0)

    private fun publishTargetedInvalidation(playerId: UUID) {
        try {
            invalidationPublisher.publish(playerId)
            LOG.debugf(
                "Permission snapshot invalidation published successfully (playerId=%s)",
                playerId,
            )
        } catch (_: Exception) {
            LOG.warnf(
                "Permission snapshot invalidation publish failed (playerId=%s, reason=%s)",
                playerId,
                SNAPSHOT_INVALIDATION_PUBLISH_FAILURE_REASON,
            )
            throw PermissionSnapshotInvalidationPublishException(
                IllegalStateException(SNAPSHOT_INVALIDATION_PUBLISH_FAILURE_REASON)
            )
        }
    }

    private fun publishFullInvalidations(playerIds: Set<UUID>) {
        playerIds.forEach { playerId ->
            try {
                invalidationPublisher.publish(playerId)
                LOG.debugf(
                    "Permission snapshot invalidation published successfully (playerId=%s)",
                    playerId,
                )
            } catch (_: Exception) {
                LOG.warnf(
                    "Permission snapshot invalidation publish failed (playerId=%s, reason=%s)",
                    playerId,
                    SNAPSHOT_INVALIDATION_PUBLISH_FAILURE_REASON,
                )
            }
        }
    }

    private companion object {
        private const val SYNC_FAILURE_REASON = "identity_sync_failed"
        private const val SYNC_STATE_UPDATE_FAILURE_REASON = "identity_sync_state_update_failed"
        private const val SYNC_STATE_UPDATE_ATTEMPTS = 2
        private const val REFRESH_FAILURE_REASON = "identity_refresh_failed"
        private const val SNAPSHOT_INVALIDATION_PUBLISH_FAILURE_REASON = "nats_publish_failed"
        private val DEFAULT_MAX_STALENESS = Duration.ofHours(6)
        private val LOG = Logger.getLogger(IdentitySyncCoordinator::class.java)
    }
}

private object UnlockedIdentitySyncLock : IdentitySyncLock {
    override fun <T> tryRun(operation: () -> T): IdentitySyncLockResult<T> =
        IdentitySyncLockResult.Acquired(operation())
}
