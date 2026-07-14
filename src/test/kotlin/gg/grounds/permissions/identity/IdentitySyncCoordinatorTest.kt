package gg.grounds.permissions.identity

import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.logging.Handler
import java.util.logging.LogRecord
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class IdentitySyncCoordinatorTest {
    @Test
    fun completesFullSyncAndUpdatesOperationalStateAndDuration() {
        val identity = identity()
        val store = RecordingIdentityStore()
        val coordinator =
            IdentitySyncCoordinator(
                store = store,
                source =
                    object : PlayerIdentitySource {
                        override fun loadAll(): List<ProjectedPlayerIdentity> = listOf(identity)

                        override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity? =
                            null
                    },
                clock =
                    SequenceClock(
                        Instant.parse("2030-01-01T00:00:00Z"),
                        Instant.parse("2030-01-01T00:00:03Z"),
                    ),
            )

        val outcome = coordinator.synchronizeAll()

        assertEquals(IdentitySyncOutcome.COMPLETED, outcome)
        assertEquals(listOf(identity), store.identities)
        assertEquals(IdentitySyncStatus.IDLE, store.state.status)
        assertEquals(Instant.parse("2030-01-01T00:00:00Z"), store.state.startedAt)
        assertEquals(Instant.parse("2030-01-01T00:00:03Z"), store.state.completedAt)
        assertEquals(3_000, store.state.durationMs)
        assertEquals(1, store.state.playerCount)
    }

    @Test
    fun returnsAlreadyRunningForAConcurrentFullSync() {
        val enteredSource = CountDownLatch(1)
        val releaseSource = CountDownLatch(1)
        val store = RecordingIdentityStore()
        val coordinator =
            IdentitySyncCoordinator(
                store = store,
                source =
                    object : PlayerIdentitySource {
                        override fun loadAll(): List<ProjectedPlayerIdentity> {
                            enteredSource.countDown()
                            check(releaseSource.await(5, TimeUnit.SECONDS))
                            return emptyList()
                        }

                        override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity? =
                            null
                    },
                clock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC),
            )
        val executor = Executors.newSingleThreadExecutor()

        try {
            val first = executor.submit<IdentitySyncOutcome> { coordinator.synchronizeAll() }
            assertTrue(enteredSource.await(5, TimeUnit.SECONDS))

            val second = coordinator.synchronizeAll()

            assertEquals(IdentitySyncOutcome.ALREADY_RUNNING, second)
            releaseSource.countDown()
            assertEquals(IdentitySyncOutcome.COMPLETED, first.get(5, TimeUnit.SECONDS))
        } finally {
            releaseSource.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun preservesNewerTargetedRefreshWhenOlderFullSnapshotCompletesLater() {
        val snapshotLoaded = CountDownLatch(1)
        val releaseFullSync = CountDownLatch(1)
        val oldIdentity =
            identity()
                .copy(
                    minecraftUsername = "OldPlayer",
                    normalizedUsername = "oldplayer",
                    groupPaths = setOf("/old-group"),
                    syncedAt = Instant.parse("2030-01-01T00:00:00Z"),
                )
        val newIdentity =
            oldIdentity.copy(
                minecraftUsername = "NewPlayer",
                normalizedUsername = "newplayer",
                groupPaths = setOf("/new-group"),
                syncedAt = Instant.parse("2030-01-01T00:00:02Z"),
            )
        val store = RecordingIdentityStore()
        val coordinator =
            IdentitySyncCoordinator(
                store = store,
                source =
                    object : PlayerIdentitySource {
                        override fun loadAll(): List<ProjectedPlayerIdentity> {
                            snapshotLoaded.countDown()
                            check(releaseFullSync.await(5, TimeUnit.SECONDS))
                            return listOf(oldIdentity)
                        }

                        override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity =
                            newIdentity
                    },
                clock =
                    SequenceClock(
                        Instant.parse("2030-01-01T00:00:01Z"),
                        Instant.parse("2030-01-01T00:00:02Z"),
                        Instant.parse("2030-01-01T00:00:03Z"),
                        Instant.parse("2030-01-01T00:00:04Z"),
                    ),
            )
        val executor = Executors.newSingleThreadExecutor()

        try {
            val fullSync = executor.submit<IdentitySyncOutcome> { coordinator.synchronizeAll() }
            assertTrue(snapshotLoaded.await(5, TimeUnit.SECONDS))

            assertEquals(
                IdentityRefreshOutcome.UPDATED,
                coordinator.refreshPlayer(newIdentity.keycloakUserId),
            )
            releaseFullSync.countDown()

            assertEquals(IdentitySyncOutcome.COMPLETED, fullSync.get(5, TimeUnit.SECONDS))
            assertEquals(listOf(newIdentity), store.identities)
            assertEquals(IdentitySyncStatus.IDLE, store.state.status)
            assertEquals(1, store.state.playerCount)
        } finally {
            releaseFullSync.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun returnsAlreadyRunningWithoutReadingKeycloakWhenAdvisoryLockIsUnavailable() {
        val store = RecordingIdentityStore()
        var sourceRead = false
        val coordinator =
            IdentitySyncCoordinator(
                store = store,
                source =
                    object : PlayerIdentitySource {
                        override fun loadAll(): List<ProjectedPlayerIdentity> {
                            sourceRead = true
                            return emptyList()
                        }

                        override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity? =
                            null
                    },
                clock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC),
                syncLock =
                    object : IdentitySyncLock {
                        override fun <T> tryRun(operation: () -> T): IdentitySyncLockResult<T> =
                            IdentitySyncLockResult.AlreadyLocked
                    },
            )

        val outcome = coordinator.synchronizeAll()

        assertEquals(IdentitySyncOutcome.ALREADY_RUNNING, outcome)
        assertFalse(sourceRead)
        assertEquals(IdentitySyncStatus.IDLE, store.state.status)
    }

    @Test
    fun returnsAlreadyRunningForPersistedRunningStateAtTheStalenessThreshold() {
        val now = Instant.parse("2030-01-01T06:00:00Z")
        val persistedStartedAt = now.minus(Duration.ofHours(6))
        val store = RecordingIdentityStore()
        store.state =
            store.state.copy(status = IdentitySyncStatus.RUNNING, startedAt = persistedStartedAt)
        var sourceRead = false
        val coordinator =
            IdentitySyncCoordinator(
                store = store,
                source =
                    object : PlayerIdentitySource {
                        override fun loadAll(): List<ProjectedPlayerIdentity> {
                            sourceRead = true
                            return emptyList()
                        }

                        override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity? =
                            null
                    },
                clock = Clock.fixed(now, ZoneOffset.UTC),
                maxStaleness = Duration.ofHours(6),
            )

        val outcome = coordinator.synchronizeAll()

        assertEquals(IdentitySyncOutcome.ALREADY_RUNNING, outcome)
        assertFalse(sourceRead)
        assertEquals(persistedStartedAt, store.state.startedAt)
    }

    @Test
    fun recoversPersistedRunningStateOlderThanTheStalenessThreshold() {
        val now = Instant.parse("2030-01-01T06:00:00Z")
        val completedAt = now.plusSeconds(2)
        val store = RecordingIdentityStore()
        store.state =
            store.state.copy(
                status = IdentitySyncStatus.RUNNING,
                startedAt = now.minus(Duration.ofHours(6)).minusMillis(1),
            )
        val coordinator =
            IdentitySyncCoordinator(
                store = store,
                source = emptyIdentitySource(),
                clock = SequenceClock(now, completedAt),
                maxStaleness = Duration.ofHours(6),
            )

        val outcome = coordinator.synchronizeAll()

        assertEquals(IdentitySyncOutcome.COMPLETED, outcome)
        assertEquals(IdentitySyncStatus.IDLE, store.state.status)
        assertEquals(now, store.state.startedAt)
        assertEquals(completedAt, store.state.completedAt)
        assertEquals(2_000, store.state.durationMs)
    }

    @Test
    fun marksRecoveredStaleSyncFailedWhenTheSourceFails() {
        val now = Instant.parse("2030-01-01T06:00:00Z")
        val failedAt = now.plusSeconds(1)
        val store = RecordingIdentityStore()
        store.state =
            store.state.copy(
                status = IdentitySyncStatus.RUNNING,
                startedAt = now.minus(Duration.ofHours(7)),
            )
        val coordinator =
            IdentitySyncCoordinator(
                store = store,
                source =
                    object : PlayerIdentitySource {
                        override fun loadAll(): List<ProjectedPlayerIdentity> {
                            throw IllegalStateException("source unavailable")
                        }

                        override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity? =
                            null
                    },
                clock = SequenceClock(now, failedAt),
                maxStaleness = Duration.ofHours(6),
            )

        val outcome = coordinator.synchronizeAll()

        assertEquals(IdentitySyncOutcome.FAILED, outcome)
        assertEquals(IdentitySyncStatus.FAILED, store.state.status)
        assertEquals(now, store.state.startedAt)
        assertEquals(failedAt, store.state.completedAt)
        assertEquals(1_000, store.state.durationMs)
        assertEquals("identity_sync_failed", store.state.failureReason)
    }

    @Test
    fun retriesAndReportsSanitizedSyncStatePersistenceFailures() {
        val store = RecordingIdentityStore(markSyncFailuresRemaining = 1)
        val coordinator =
            IdentitySyncCoordinator(
                store = store,
                source = failingIdentitySource(),
                clock =
                    SequenceClock(
                        Instant.parse("2030-01-01T00:00:00Z"),
                        Instant.parse("2030-01-01T00:00:01Z"),
                    ),
            )

        val outcome = coordinator.synchronizeAll()

        assertEquals(IdentitySyncOutcome.FAILED, outcome)
        assertEquals(2, store.markSyncFailedAttempts)
        assertEquals(IdentitySyncStatus.FAILED, store.state.status)
        assertEquals("identity_sync_failed", store.state.failureReason)
        assertFalse(store.state.failureReason!!.contains("remote-body"))
        assertFalse(store.state.failureReason!!.contains("sensitive-token"))
        val failedStore = RecordingIdentityStore(markSyncFailuresRemaining = 2)
        val failedCoordinator =
            IdentitySyncCoordinator(
                store = failedStore,
                source = failingIdentitySource(),
                clock =
                    SequenceClock(
                        Instant.parse("2030-01-01T00:00:00Z"),
                        Instant.parse("2030-01-01T00:00:01Z"),
                    ),
            )

        val (failedOutcome, messages) = captureLogs(failedCoordinator::synchronizeAll)

        assertEquals(IdentitySyncOutcome.FAILED, failedOutcome)
        assertEquals(2, failedStore.markSyncFailedAttempts)
        assertEquals(IdentitySyncStatus.RUNNING, failedStore.state.status)
        assertEquals(
            listOf(
                "Player identity sync state update failed " +
                    "(durationMs=1000, reason=identity_sync_state_update_failed)"
            ),
            messages.filter { it.contains("identity_sync_state_update_failed") },
        )
        assertFalse(messages.any { it.contains("remote-body") })
        assertFalse(messages.any { it.contains("sensitive-token") })
        assertEquals(1, messages.count { it.contains("reason=identity_sync_failed") })
    }

    @Test
    fun removesDeletedOrUnlinkedPlayerDuringSingleUserRefresh() {
        val store = RecordingIdentityStore()
        val coordinator =
            IdentitySyncCoordinator(
                store = store,
                source =
                    object : PlayerIdentitySource {
                        override fun loadAll(): List<ProjectedPlayerIdentity> = emptyList()

                        override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity? =
                            null
                    },
                clock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC),
            )

        val outcome = coordinator.refreshPlayer("deleted-user")

        assertEquals(IdentityRefreshOutcome.REMOVED, outcome)
        assertEquals(listOf("deleted-user"), store.deletedKeycloakUserIds)
    }

    @Test
    fun replacesLinkedPlayerDuringSingleUserRefresh() {
        val identity = identity()
        val store = RecordingIdentityStore()
        val coordinator =
            IdentitySyncCoordinator(
                store = store,
                source =
                    object : PlayerIdentitySource {
                        override fun loadAll(): List<ProjectedPlayerIdentity> = emptyList()

                        override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity =
                            identity
                    },
                clock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC),
            )

        val outcome = coordinator.refreshPlayer(identity.keycloakUserId)

        assertEquals(IdentityRefreshOutcome.UPDATED, outcome)
        assertEquals(listOf(identity), store.identities)
        assertTrue(store.deletedKeycloakUserIds.isEmpty())
    }

    private fun identity(): ProjectedPlayerIdentity =
        ProjectedPlayerIdentity(
            playerId = UUID.fromString("00000000-0000-0000-0000-000000000401"),
            keycloakUserId = "linked-user",
            minecraftUsername = "LinkedPlayer",
            normalizedUsername = "linkedplayer",
            groupPaths = setOf("/players"),
            syncedAt = Instant.parse("2030-01-01T00:00:00Z"),
            sourceUpdatedAt = null,
        )

    private fun emptyIdentitySource(): PlayerIdentitySource =
        object : PlayerIdentitySource {
            override fun loadAll(): List<ProjectedPlayerIdentity> = emptyList()

            override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity? = null
        }

    private fun failingIdentitySource(): PlayerIdentitySource =
        object : PlayerIdentitySource {
            override fun loadAll(): List<ProjectedPlayerIdentity> {
                throw IllegalStateException("remote-body bearer-sensitive-token")
            }

            override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity? = null
        }

    private fun captureLogs(
        operation: () -> IdentitySyncOutcome
    ): Pair<IdentitySyncOutcome, List<String>> {
        val records = mutableListOf<LogRecord>()
        val handler =
            object : Handler() {
                override fun publish(record: LogRecord) {
                    records += record
                }

                override fun flush() = Unit

                override fun close() = Unit
            }
        val logger =
            java.util.logging.Logger.getLogger(IdentitySyncCoordinator::class.java.name).apply {
                addHandler(handler)
            }
        return try {
            operation() to records.map(LogRecord::getMessage)
        } finally {
            logger.removeHandler(handler)
        }
    }
}

private class RecordingIdentityStore(private var markSyncFailuresRemaining: Int = 0) :
    PlayerIdentityStore {
    var identities: List<ProjectedPlayerIdentity> = emptyList()
    val deletedKeycloakUserIds = mutableListOf<String>()
    var markSyncFailedAttempts = 0
        private set

    var state =
        IdentitySyncState(
            status = IdentitySyncStatus.IDLE,
            startedAt = null,
            completedAt = null,
            lastSuccessAt = null,
            durationMs = null,
            playerCount = 0,
            failureReason = null,
        )

    override fun findByPlayerId(playerId: UUID): ProjectedPlayerIdentity? =
        identities.firstOrNull { it.playerId == playerId }

    override fun findByKeycloakUserId(keycloakUserId: String): ProjectedPlayerIdentity? =
        identities.firstOrNull { it.keycloakUserId == keycloakUserId }

    override fun search(query: String, page: Int, perPage: Int): PlayerSearchPage =
        PlayerSearchPage(emptyList(), page, perPage, 0)

    override fun replacePlayer(identity: ProjectedPlayerIdentity) {
        identities = identities.filterNot { it.playerId == identity.playerId } + identity
    }

    override fun deleteByKeycloakUserId(keycloakUserId: String) {
        deletedKeycloakUserIds += keycloakUserId
        identities = identities.filterNot { it.keycloakUserId == keycloakUserId }
    }

    @Synchronized
    override fun replaceAll(identities: List<ProjectedPlayerIdentity>, completedAt: Instant) {
        check(state.status == IdentitySyncStatus.RUNNING)
        val snapshotStartedAt = checkNotNull(state.startedAt)
        val reconciled = this.identities.toMutableList()
        identities.forEach { identity ->
            val conflicts =
                reconciled.filter {
                    it.playerId == identity.playerId || it.keycloakUserId == identity.keycloakUserId
                }
            if (conflicts.none { it.syncedAt.isAfter(snapshotStartedAt) }) {
                reconciled.removeAll(conflicts)
                reconciled += identity
            }
        }
        val snapshotPlayerIds = identities.mapTo(mutableSetOf()) { it.playerId }
        reconciled.removeIf {
            it.playerId !in snapshotPlayerIds && !it.syncedAt.isAfter(snapshotStartedAt)
        }
        this.identities = reconciled
        state =
            state.copy(
                status = IdentitySyncStatus.IDLE,
                completedAt = completedAt,
                lastSuccessAt = completedAt,
                durationMs = completedAt.toEpochMilli() - state.startedAt!!.toEpochMilli(),
                playerCount = reconciled.size.toLong(),
                failureReason = null,
            )
    }

    @Synchronized
    override fun markSyncRunning(startedAt: Instant) {
        check(tryMarkSyncRunning(startedAt, Instant.MIN)) { "Identity sync is already running" }
    }

    @Synchronized
    override fun tryMarkSyncRunning(startedAt: Instant, staleBefore: Instant): Boolean {
        if (
            state.status == IdentitySyncStatus.RUNNING &&
                state.startedAt?.isBefore(staleBefore) != true
        ) {
            return false
        }
        state =
            state.copy(
                status = IdentitySyncStatus.RUNNING,
                startedAt = startedAt,
                completedAt = null,
                durationMs = null,
                failureReason = null,
            )
        return true
    }

    @Synchronized
    override fun markSyncFailed(completedAt: Instant, failureReason: String) {
        markSyncFailedAttempts++
        if (markSyncFailuresRemaining > 0) {
            markSyncFailuresRemaining--
            throw IllegalStateException("database-body bearer-sensitive-token")
        }
        check(state.status == IdentitySyncStatus.RUNNING)
        state =
            state.copy(
                status = IdentitySyncStatus.FAILED,
                completedAt = completedAt,
                durationMs = completedAt.toEpochMilli() - state.startedAt!!.toEpochMilli(),
                failureReason = failureReason,
            )
    }

    override fun currentSyncState(): IdentitySyncState = state
}

private class SequenceClock(vararg instants: Instant) : Clock() {
    private val values = ArrayDeque(instants.toList())
    private var last = instants.last()

    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId): Clock = this

    override fun instant(): Instant =
        if (values.isEmpty()) last else values.removeFirst().also { last = it }
}
