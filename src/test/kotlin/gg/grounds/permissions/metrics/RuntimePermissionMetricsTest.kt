package gg.grounds.permissions.metrics

import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import java.time.Duration
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RuntimePermissionMetricsTest {
    private val registry = SimpleMeterRegistry()
    private val metrics = RuntimePermissionMetrics(registry)

    @Test
    fun `records bounded success request count and latency`() {
        metrics.recordRuntimeRequest(
            RuntimeOperation.SNAPSHOT,
            RuntimeRequestStatus.SUCCESS,
            Duration.ofMillis(12),
        )
        metrics.recordSnapshotComputation(Duration.ofMillis(4))

        assertEquals(
            1.0,
            registry
                .find("permissions.runtime.request.count")
                .tags("operation", "snapshot", "status", "success")
                .counter()!!
                .count(),
        )
        assertEquals(
            1L,
            registry
                .find("permissions.runtime.request.duration")
                .tags("operation", "snapshot", "status", "success")
                .timer()!!
                .count(),
        )
        assertEquals(
            1L,
            registry.find("permissions.runtime.snapshot.computation.duration").timer()!!.count(),
        )
    }

    @Test
    fun `records bounded denied and unavailable Kubernetes review outcomes`() {
        metrics.recordSubjectAccessReview(RuntimeReviewOutcome.DENIED, Duration.ofMillis(8))
        metrics.recordTokenReview(RuntimeReviewOutcome.UNAVAILABLE, Duration.ofMillis(15))

        assertEquals(
            1.0,
            registry
                .find("permissions.runtime.subject_access_review.count")
                .tag("outcome", "denied")
                .counter()!!
                .count(),
        )
        assertEquals(
            1.0,
            registry
                .find("permissions.runtime.token_review.count")
                .tag("outcome", "unavailable")
                .counter()!!
                .count(),
        )
    }

    @Test
    fun `records bounded auth cache hit and catalog conflict outcomes`() {
        metrics.recordAuthCacheHit(RuntimeReviewType.TOKEN)
        metrics.recordManifest(RuntimeManifestOutcome.CONFLICT)

        assertEquals(
            1.0,
            registry
                .find("permissions.runtime.auth.cache_hit")
                .tag("review", "token")
                .counter()!!
                .count(),
        )
        assertEquals(
            1.0,
            registry
                .find("permissions.runtime.manifest")
                .tag("outcome", "conflict")
                .counter()!!
                .count(),
        )
    }

    @Test
    fun `never adds unbounded runtime identifiers to metric tags`() {
        metrics.recordRuntimeRequest(
            RuntimeOperation.MANIFEST,
            RuntimeRequestStatus.CONFLICT,
            Duration.ofMillis(1),
        )
        metrics.recordTokenReview(RuntimeReviewOutcome.SUCCESS, Duration.ofMillis(1))
        metrics.recordAuthCacheHit(RuntimeReviewType.SUBJECT_ACCESS)
        metrics.recordManifest(RuntimeManifestOutcome.FAILURE)

        val forbiddenTagNames =
            setOf("playerId", "requestId", "namespace", "serviceAccount", "source", "permissionKey")
        registry.meters.forEach { meter ->
            assertTrue(meter.id.tags.none { it.key in forbiddenTagNames })
        }
    }
}
