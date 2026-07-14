package gg.grounds.permissions.identity

import io.quarkus.runtime.ShutdownEvent
import io.quarkus.runtime.StartupEvent
import io.quarkus.scheduler.Scheduled
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.event.Observes
import jakarta.inject.Inject
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import org.eclipse.microprofile.config.inject.ConfigProperty

@ApplicationScoped
class IdentitySyncLifecycle(
    private val coordinator: IdentitySyncCoordinator,
    private val executor: Executor,
    private val enabled: Boolean = true,
) {
    private var ownedExecutor: ExecutorService? = null

    @Inject
    constructor(
        coordinator: IdentitySyncCoordinator,
        @ConfigProperty(name = "permissions.identity-sync.enabled") enabled: Boolean,
    ) : this(
        coordinator = coordinator,
        executor =
            Executors.newSingleThreadExecutor(
                Thread.ofVirtual().name("identity-sync-", 0).factory()
            ),
        enabled = enabled,
    ) {
        ownedExecutor = executor as ExecutorService
    }

    fun onStartup(@Observes event: StartupEvent) {
        if (!enabled) return
        executor.execute { coordinator.synchronizeAll() }
    }

    @Scheduled(
        every = "{permissions.identity-sync.schedule}",
        concurrentExecution = Scheduled.ConcurrentExecution.SKIP,
    )
    fun reconcileScheduled() {
        if (!enabled) return
        coordinator.synchronizeAll()
    }

    fun onShutdown(@Observes event: ShutdownEvent) {
        ownedExecutor?.shutdownNow()
    }
}
