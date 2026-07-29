package gg.grounds.permissions.identity

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.nats.client.Connection
import io.nats.client.Options
import java.time.Duration
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doThrow
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class PermissionSnapshotInvalidationPublisherTest {
    private val playerId = UUID.fromString("00000000-0000-0000-0000-000000000501")
    private val objectMapper = jacksonObjectMapper()

    @Test
    fun publishesTheVersionedInvalidationEventToTheSnapshotSubject() {
        val transport = mock<PermissionSnapshotInvalidationTransport>()
        val publisher = NatsPermissionSnapshotInvalidationPublisher(objectMapper, transport)

        publisher.publish(playerId)

        val payload = argumentCaptor<ByteArray>()
        verify(transport).publish(eq("permissions.snapshot.invalidated"), payload.capture())
        val event = objectMapper.readTree(payload.firstValue)
        assertEquals(setOf("schemaVersion", "playerId"), event.fieldNames().asSequence().toSet())
        assertEquals(1, event["schemaVersion"].intValue())
        assertEquals(playerId.toString(), event["playerId"].textValue())
    }

    @Test
    fun sanitizesTransportFailuresWithoutIncludingPayloadOrAuthenticationData() {
        val transport = mock<PermissionSnapshotInvalidationTransport>()
        doThrow(IllegalStateException("payload=secret token=secret"))
            .whenever(transport)
            .publish(any(), any())
        val publisher = NatsPermissionSnapshotInvalidationPublisher(objectMapper, transport)

        val exception =
            assertThrows(PermissionSnapshotInvalidationPublishException::class.java) {
                publisher.publish(playerId)
            }

        assertFalse(exception.message!!.contains("payload"))
        assertFalse(exception.message!!.contains("token"))
    }

    @Test
    fun noOpPublisherAcceptsInvalidationsWhenPublicationIsDisabled() {
        assertDoesNotThrow { NoopPermissionSnapshotInvalidationPublisher.publish(playerId) }
    }

    @Test
    fun opensNatsLazilyAndFlushesPublishedInvalidations() {
        val connection = mock<Connection>()
        var connectionAttempts = 0
        val transport =
            NatsPermissionSnapshotInvalidationTransport(
                Options.builder().server("nats://localhost:4222").build()
            ) {
                connectionAttempts++
                connection
            }

        assertEquals(0, connectionAttempts)

        transport.publish("permissions.snapshot.invalidated", "event".toByteArray())

        assertEquals(1, connectionAttempts)
        verify(connection).publish("permissions.snapshot.invalidated", "event".toByteArray())
        verify(connection).flush(Duration.ofSeconds(2))
    }

    @Test
    fun closesTheFailedConnectionBeforeTheNextPublishAttempt() {
        val failedConnection = mock<Connection>()
        val recoveredConnection = mock<Connection>()
        doThrow(IllegalStateException("nats unavailable")).whenever(failedConnection).flush(any())
        var connectionAttempts = 0
        val transport =
            NatsPermissionSnapshotInvalidationTransport(
                Options.builder().server("nats://localhost:4222").build()
            ) {
                connectionAttempts++
                if (connectionAttempts == 1) failedConnection else recoveredConnection
            }

        assertThrows(IllegalStateException::class.java) {
            transport.publish("permissions.snapshot.invalidated", "event".toByteArray())
        }
        transport.publish("permissions.snapshot.invalidated", "event".toByteArray())

        verify(failedConnection).close()
        verify(recoveredConnection).flush(Duration.ofSeconds(2))
    }
}
