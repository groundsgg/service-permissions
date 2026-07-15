package gg.grounds.permissions.identity

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.time.Clock
import java.time.Duration
import java.time.Instant
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.eclipse.microprofile.health.HealthCheck
import org.eclipse.microprofile.health.HealthCheckResponse
import org.eclipse.microprofile.health.Readiness

@Readiness
@ApplicationScoped
class IdentitySyncReadinessCheck(
    private val store: PlayerIdentityStore,
    private val clock: Clock,
    private val maxStaleness: Duration,
) : HealthCheck {
    @Inject
    constructor(
        store: PlayerIdentityStore,
        @ConfigProperty(name = "permissions.identity-sync.max-staleness") maxStaleness: Duration,
    ) : this(store, Clock.systemUTC(), maxStaleness)

    override fun call(): HealthCheckResponse {
        val state = store.currentSyncState()
        val available = isAvailable(state, clock.instant())
        val builder =
            HealthCheckResponse.named(CHECK_NAME)
                .status(available)
                .withData("identityPolicyAvailable", available)
                .withData("syncStatus", state.status.name.lowercase())
                .withData("playerCount", state.playerCount)
        state.lastSuccessAt?.let { builder.withData("lastSuccessAt", it.toString()) }
        return builder.build()
    }

    fun isIdentityPolicyAvailable(): Boolean = isIdentityPolicyAvailable(clock.instant())

    fun isIdentityPolicyAvailable(now: Instant): Boolean =
        isAvailable(store.currentSyncState(), now)

    private fun isAvailable(state: IdentitySyncState, now: Instant): Boolean {
        val lastSuccessAt = state.lastSuccessAt ?: return false
        return !lastSuccessAt.isBefore(now.minus(maxStaleness))
    }

    private companion object {
        const val CHECK_NAME = "player-identity-projection"
    }
}
