package gg.grounds.permissions.identity

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.nats.client.api.AckPolicy
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class IdentityChangeConsumerTest {
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

    override fun acknowledge() {
        outcome = DeliveryOutcome.ACKNOWLEDGED
    }

    override fun negativelyAcknowledge() {
        outcome = DeliveryOutcome.NEGATIVELY_ACKNOWLEDGED
    }

    override fun terminate() {
        outcome = DeliveryOutcome.TERMINATED
    }
}
