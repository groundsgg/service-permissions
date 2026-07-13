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
    fun recordsSanitizedFailureReason() {
        val store = RecordingIdentityStore()
        val coordinator =
            IdentitySyncCoordinator(
                store = store,
                source =
                    object : PlayerIdentitySource {
                        override fun loadAll(): List<ProjectedPlayerIdentity> {
                            throw IllegalStateException("remote-body bearer-sensitive-token")
                        }

                        override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity? =
                            null
                    },
                clock =
                    SequenceClock(
                        Instant.parse("2030-01-01T00:00:00Z"),
                        Instant.parse("2030-01-01T00:00:01Z"),
                    ),
            )

        val outcome = coordinator.synchronizeAll()

        assertEquals(IdentitySyncOutcome.FAILED, outcome)
        assertEquals(IdentitySyncStatus.FAILED, store.state.status)
        assertEquals("identity_sync_failed", store.state.failureReason)
        assertFalse(store.state.failureReason!!.contains("remote-body"))
        assertFalse(store.state.failureReason!!.contains("sensitive-token"))
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
}

private class RecordingIdentityStore : PlayerIdentityStore {
    var identities: List<ProjectedPlayerIdentity> = emptyList()
    val deletedKeycloakUserIds = mutableListOf<String>()
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
        this.identities = identities
        state =
            state.copy(
                status = IdentitySyncStatus.IDLE,
                completedAt = completedAt,
                lastSuccessAt = completedAt,
                durationMs = completedAt.toEpochMilli() - state.startedAt!!.toEpochMilli(),
                playerCount = identities.size.toLong(),
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
