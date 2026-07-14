package gg.grounds.permissions.identity

import io.quarkus.runtime.StartupEvent
import java.util.concurrent.Executor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class IdentitySyncLifecycleTest {
    @Test
    fun dispatchesStartupSyncWithoutBlockingStartup() {
        val coordinator = mock<IdentitySyncCoordinator>()
        whenever(coordinator.synchronizeAll()).thenReturn(IdentitySyncOutcome.COMPLETED)
        val queued = mutableListOf<Runnable>()
        val lifecycle = IdentitySyncLifecycle(coordinator, Executor(queued::add))

        lifecycle.onStartup(mock<StartupEvent>())

        assertEquals(1, queued.size)
        verify(coordinator, org.mockito.kotlin.never()).synchronizeAll()

        queued.single().run()

        verify(coordinator).synchronizeAll()
    }

    @Test
    fun scheduledReconciliationUsesTheSameCoordinatorAndAcceptsLockSkips() {
        val coordinator = mock<IdentitySyncCoordinator>()
        whenever(coordinator.synchronizeAll()).thenReturn(IdentitySyncOutcome.ALREADY_RUNNING)
        val lifecycle = IdentitySyncLifecycle(coordinator, Executor(Runnable::run))

        lifecycle.reconcileScheduled()

        verify(coordinator).synchronizeAll()
    }
}
