package gg.grounds.permissions.identity

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.nats.client.api.AckPolicy
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class IdentityChangeConsumerTest {
    @TempDir lateinit var tempDir: Path

    private val coordinator = mock<IdentitySyncCoordinator>()
    private val consumer = IdentityChangeConsumer(jacksonObjectMapper(), coordinator, "grounds")

    @Test
    fun acknowledgesOnlyAfterSuccessfulCurrentStateRefresh() {
        whenever(coordinator.refreshPlayer("user-1")).thenReturn(IdentityRefreshOutcome.UPDATED)
        val delivery = RecordingDelivery(validPayload())

        consumer.process(delivery)

        assertEquals(DeliveryOutcome.ACKNOWLEDGED, delivery.outcome)
        verify(coordinator).refreshPlayer("user-1")
    }

    @Test
    fun duplicateAndOutOfOrderEventsAlwaysReloadCurrentState() {
        whenever(coordinator.refreshPlayer("user-1")).thenReturn(IdentityRefreshOutcome.UPDATED)
        val first = RecordingDelivery(validPayload(reason = "group_removed"))
        val second = RecordingDelivery(validPayload(reason = "group_added"))

        consumer.process(first)
        consumer.process(second)

        assertEquals(DeliveryOutcome.ACKNOWLEDGED, first.outcome)
        assertEquals(DeliveryOutcome.ACKNOWLEDGED, second.outcome)
        verify(coordinator, org.mockito.kotlin.times(2)).refreshPlayer("user-1")
    }

    @Test
    fun terminatesInvalidPayloadWithoutRetrying() {
        val delivery = RecordingDelivery("not-json".toByteArray())

        consumer.process(delivery)

        assertEquals(DeliveryOutcome.TERMINATED, delivery.outcome)
        verify(coordinator, never()).refreshPlayer(org.mockito.kotlin.any())
    }

    @Test
    fun negativelyAcknowledgesTransientRefreshFailures() {
        whenever(coordinator.refreshPlayer("user-1")).thenReturn(IdentityRefreshOutcome.FAILED)
        val delivery = RecordingDelivery(validPayload())

        consumer.process(delivery)

        assertEquals(DeliveryOutcome.NEGATIVELY_ACKNOWLEDGED, delivery.outcome)
        assertEquals(Duration.ofSeconds(5), delivery.retryDelay)
    }

    @Test
    fun acknowledgesAndIgnoresEventsForAnotherRealm() {
        val delivery = RecordingDelivery(validPayload(realmId = "other"))

        consumer.process(delivery)

        assertEquals(DeliveryOutcome.ACKNOWLEDGED, delivery.outcome)
        verify(coordinator, never()).refreshPlayer(org.mockito.kotlin.any())
    }

    @Test
    fun explicitDurableConsumerOverridesProjectDerivedName() {
        assertEquals(
            "platform-permissions",
            IdentityChangeConsumer.resolveDurableName(
                explicitConsumer = "platform-permissions",
                consumerPrefix = "service-permissions",
                projectId = "project-1",
            ),
        )
    }

    @Test
    fun derivesAProjectSpecificDurableConsumerName() {
        assertEquals(
            "service-permissions-project-1",
            IdentityChangeConsumer.resolveDurableName(
                explicitConsumer = null,
                consumerPrefix = "service-permissions",
                projectId = "project-1",
            ),
        )
    }

    @Test
    fun rejectsMissingConsumerIdentityAtStartupConfigurationTime() {
        assertThrows(IllegalArgumentException::class.java) {
            IdentityChangeConsumer.resolveDurableName(
                explicitConsumer = "",
                consumerPrefix = "service-permissions",
                projectId = null,
            )
        }
    }

    @Test
    fun configuresExplicitAcknowledgementForTheDurableConsumer() {
        val options =
            buildPullSubscribeOptions(
                IdentityEventConsumerConfig(
                    subject = "minecraft-identity.changed",
                    stream = "MINECRAFT_IDENTITY",
                    durableName = "service-permissions-project-1",
                )
            )

        assertEquals(AckPolicy.Explicit, options.consumerConfiguration.ackPolicy)
        assertEquals(10, options.consumerConfiguration.maxDeliver)
    }

    @Test
    fun wiresRotatingTokenSupplierIntoNatsConnectionOptions() {
        val tokenFile = tempDir.resolve("token")
        Files.writeString(tokenFile, "first-token")
        val transport = NatsIdentityEventTransport("nats://localhost:4222", tokenFile.toString())

        assertEquals(
            "nats://localhost:4222",
            transport.connectionOptions.servers.single().toString(),
        )
        assertArrayEquals("first-token".toCharArray(), transport.connectionOptions.tokenChars)

        Files.writeString(tokenFile, "rotated-token")

        assertArrayEquals("rotated-token".toCharArray(), transport.connectionOptions.tokenChars)
    }

    @Test
    fun leavesNatsConnectionUnauthenticatedWhenTokenFileIsAbsent() {
        val transport = NatsIdentityEventTransport("nats://localhost:4222", null)

        assertNull(transport.connectionOptions.tokenChars)
    }

    @Test
    fun rejectsBlankConfiguredTokenFilePath() {
        val exception =
            assertThrows(IllegalArgumentException::class.java) {
                NatsIdentityEventTransport("nats://localhost:4222", " ")
            }

        assertEquals("NATS authentication token file path must not be blank", exception.message)
    }

    private fun validPayload(realmId: String = "grounds", reason: String = "identity_updated") =
        jacksonObjectMapper()
            .writeValueAsBytes(
                MinecraftIdentityChangedEvent(
                    realmId = realmId,
                    keycloakUserId = "user-1",
                    reason = reason,
                )
            )
}

private enum class DeliveryOutcome {
    PENDING,
    ACKNOWLEDGED,
    NEGATIVELY_ACKNOWLEDGED,
    TERMINATED,
}

private class RecordingDelivery(override val data: ByteArray) : IdentityEventDelivery {
    var outcome: DeliveryOutcome = DeliveryOutcome.PENDING
        private set

    var retryDelay: Duration? = null
        private set

    override fun acknowledge() {
        outcome = DeliveryOutcome.ACKNOWLEDGED
    }

    override fun negativelyAcknowledge(delay: Duration) {
        outcome = DeliveryOutcome.NEGATIVELY_ACKNOWLEDGED
        retryDelay = delay
    }

    override fun terminate() {
        outcome = DeliveryOutcome.TERMINATED
    }
}
