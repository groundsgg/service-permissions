package gg.grounds.permissions.identity

import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.inject.Instance
import jakarta.inject.Inject
import java.util.UUID
import org.jboss.logging.Logger

fun interface PlayerPolicyChangeNotifier {
    fun playerChanged(playerId: UUID)
}

@ApplicationScoped
class RuntimePlayerPolicyChangeNotifier
@Inject
constructor(private val publishers: Instance<PermissionSnapshotInvalidationPublisher>) :
    PlayerPolicyChangeNotifier {
    override fun playerChanged(playerId: UUID) {
        try {
            // Resolve lazily: the publisher also uses the repository's snapshot cache.
            publishers.get().publish(playerId)
        } catch (_: Exception) {
            // The transaction has committed. Keep the successful response; periodic snapshot
            // refresh remains the fallback while the message transport is unavailable.
            LOG.warnf(
                "Permission change committed but runtime notification failed " +
                    "(playerId=%s, reason=invalidation_publish_failed)",
                playerId,
            )
        }
    }

    private companion object {
        val LOG: Logger = Logger.getLogger(RuntimePlayerPolicyChangeNotifier::class.java)
    }
}
