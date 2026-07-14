package gg.grounds.permissions.identity

import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import org.eclipse.microprofile.health.HealthCheckResponse
import org.eclipse.microprofile.health.Liveness
import org.eclipse.microprofile.health.Readiness
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class IdentitySyncReadinessCheckTest {
    private val now = Instant.parse("2030-01-01T12:00:00Z")
    private val store = mock<PlayerIdentityStore>()

    @Test
    fun identityProjectionHealthCheckOnlyAffectsReadiness() {
        assertTrue(
            IdentitySyncReadinessCheck::class.java.isAnnotationPresent(Readiness::class.java)
        )
        assertFalse(
            IdentitySyncReadinessCheck::class.java.isAnnotationPresent(Liveness::class.java)
        )
    }

    @Test
    fun reportsNotReadyBeforeTheFirstSuccessfulSync() {
        whenever(store.currentSyncState()).thenReturn(syncState(lastSuccessAt = null))
        val check = readinessCheck()

        val response = check.call()

        assertEquals(HealthCheckResponse.Status.DOWN, response.status)
        assertFalse(check.isIdentityPolicyAvailable())
    }

    @Test
    fun reportsReadyForAFreshProjectionWhileARefreshIsRunning() {
        whenever(store.currentSyncState())
            .thenReturn(
                syncState(
                    status = IdentitySyncStatus.RUNNING,
                    lastSuccessAt = now.minus(Duration.ofMinutes(5)),
                )
            )
        val check = readinessCheck()

        val response = check.call()

        assertEquals(HealthCheckResponse.Status.UP, response.status)
        assertTrue(check.isIdentityPolicyAvailable())
    }

    @Test
    fun reportsNotReadyWhenTheProjectionIsStale() {
        whenever(store.currentSyncState())
            .thenReturn(syncState(lastSuccessAt = now.minus(Duration.ofHours(6)).minusMillis(1)))
        val check = readinessCheck()

        val response = check.call()

        assertEquals(HealthCheckResponse.Status.DOWN, response.status)
        assertFalse(check.isIdentityPolicyAvailable())
    }

    private fun readinessCheck() =
        IdentitySyncReadinessCheck(
            store = store,
            clock = Clock.fixed(now, ZoneOffset.UTC),
            maxStaleness = Duration.ofHours(6),
        )

    private fun syncState(
        status: IdentitySyncStatus = IdentitySyncStatus.IDLE,
        lastSuccessAt: Instant?,
    ) =
        IdentitySyncState(
            status = status,
            startedAt = null,
            completedAt = lastSuccessAt,
            lastSuccessAt = lastSuccessAt,
            durationMs = null,
            playerCount = 0,
            failureReason = null,
        )
}
