package gg.grounds.permissions.metrics

import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Timer
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import jakarta.enterprise.context.ApplicationScoped
import java.time.Duration

@ApplicationScoped
class RuntimePermissionMetrics(private val registry: MeterRegistry) {
    fun recordRuntimeRequest(
        operation: RuntimeOperation,
        status: RuntimeRequestStatus,
        duration: Duration,
    ) {
        registry
            .counter(
                "permissions.runtime.request.count",
                "operation",
                operation.tagValue,
                "status",
                status.tagValue,
            )
            .increment()
        Timer.builder("permissions.runtime.request.duration")
            .tags("operation", operation.tagValue, "status", status.tagValue)
            .register(registry)
            .record(duration)
    }

    fun recordSnapshotComputation(duration: Duration) {
        Timer.builder("permissions.runtime.snapshot.computation.duration")
            .register(registry)
            .record(duration)
    }

    fun recordTokenReview(outcome: RuntimeReviewOutcome, duration: Duration) {
        recordReview("permissions.runtime.token_review", outcome, duration)
    }

    fun recordSubjectAccessReview(outcome: RuntimeReviewOutcome, duration: Duration) {
        recordReview("permissions.runtime.subject_access_review", outcome, duration)
    }

    fun recordAuthCacheHit(review: RuntimeReviewType) {
        registry
            .counter("permissions.runtime.auth.cache_hit", "review", review.tagValue)
            .increment()
    }

    fun recordManifest(outcome: RuntimeManifestOutcome) {
        registry.counter("permissions.runtime.manifest", "outcome", outcome.tagValue).increment()
    }

    private fun recordReview(name: String, outcome: RuntimeReviewOutcome, duration: Duration) {
        registry.counter(name + ".count", "outcome", outcome.tagValue).increment()
        Timer.builder(name + ".duration")
            .tag("outcome", outcome.tagValue)
            .register(registry)
            .record(duration)
    }

    companion object {
        internal fun noOp(): RuntimePermissionMetrics =
            RuntimePermissionMetrics(SimpleMeterRegistry())
    }
}

enum class RuntimeOperation(internal val tagValue: String) {
    SNAPSHOT("snapshot"),
    MANIFEST("manifest"),
}

enum class RuntimeRequestStatus(internal val tagValue: String) {
    SUCCESS("success"),
    INVALID("invalid"),
    UNAUTHORIZED("unauthorized"),
    FORBIDDEN("forbidden"),
    CONFLICT("conflict"),
    UNAVAILABLE("unavailable"),
    FAILURE("failure"),
}

enum class RuntimeReviewOutcome(internal val tagValue: String) {
    SUCCESS("success"),
    INVALID("invalid"),
    DENIED("denied"),
    UNAVAILABLE("unavailable"),
}

enum class RuntimeReviewType(internal val tagValue: String) {
    TOKEN("token"),
    SUBJECT_ACCESS("subject_access"),
}

enum class RuntimeManifestOutcome(internal val tagValue: String) {
    SUCCESS("success"),
    CONFLICT("conflict"),
    FAILURE("failure"),
}
