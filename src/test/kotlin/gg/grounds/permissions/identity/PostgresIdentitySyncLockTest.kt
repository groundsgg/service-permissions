package gg.grounds.permissions.identity

import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import java.sql.Connection
import java.sql.SQLException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.sql.DataSource
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
class PostgresIdentitySyncLockTest {

    @Inject lateinit var dataSource: DataSource

    @Test
    fun excludesASecondLockInstanceWhileTheFirstOperationIsRunning() {
        val firstLock = PostgresIdentitySyncLock(dataSource)
        val secondLock = PostgresIdentitySyncLock(dataSource)
        val operationStarted = CountDownLatch(1)
        val releaseOperation = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()

        try {
            val firstResult =
                executor.submit<IdentitySyncLockResult<String>> {
                    firstLock.tryRun {
                        operationStarted.countDown()
                        check(releaseOperation.await(5, TimeUnit.SECONDS))
                        "first"
                    }
                }
            assertTrue(operationStarted.await(5, TimeUnit.SECONDS))

            assertEquals(IdentitySyncLockResult.AlreadyLocked, secondLock.tryRun { "second" })

            releaseOperation.countDown()
            assertEquals(
                IdentitySyncLockResult.Acquired("first"),
                firstResult.get(5, TimeUnit.SECONDS),
            )
        } finally {
            releaseOperation.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun releasesTheLockAfterACompletedOperation() {
        val firstLock = PostgresIdentitySyncLock(dataSource)
        val secondLock = PostgresIdentitySyncLock(dataSource)

        assertEquals(IdentitySyncLockResult.Acquired("first"), firstLock.tryRun { "first" })
        assertEquals(IdentitySyncLockResult.Acquired("second"), secondLock.tryRun { "second" })
    }

    @Test
    fun releasesTheLockAfterAnOperationException() {
        val firstLock = PostgresIdentitySyncLock(dataSource)
        val secondLock = PostgresIdentitySyncLock(dataSource)
        val expected = IllegalStateException("operation failed")

        val thrown =
            assertThrows(IllegalStateException::class.java) {
                firstLock.tryRun<Nothing> { throw expected }
            }

        assertSame(expected, thrown)
        assertEquals(IdentitySyncLockResult.Acquired("second"), secondLock.tryRun { "second" })
    }

    @Test
    fun preservesACompletedOperationWhenTransactionCleanupFails() {
        val aborted = AtomicBoolean()
        val closed = AtomicBoolean()
        val delegate = dataSource.connection
        val brokenConnection =
            object : Connection by delegate {
                override fun commit() {
                    throw SQLException("forced commit failure")
                }

                override fun abort(executor: Executor) {
                    aborted.set(true)
                    delegate.abort(executor)
                }

                override fun close() {
                    closed.set(true)
                    delegate.close()
                }
            }
        val brokenDataSource =
            object : DataSource by dataSource {
                override fun getConnection(): Connection = brokenConnection
            }

        val result = PostgresIdentitySyncLock(brokenDataSource).tryRun { "completed" }

        assertEquals(IdentitySyncLockResult.Acquired("completed"), result)
        assertTrue(aborted.get())
        assertTrue(closed.get())
        assertEquals(
            IdentitySyncLockResult.Acquired("next"),
            PostgresIdentitySyncLock(dataSource).tryRun { "next" },
        )
    }
}
