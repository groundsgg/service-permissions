package gg.grounds.permissions.identity

import com.fasterxml.jackson.databind.ObjectMapper
import io.nats.client.Connection
import io.nats.client.Nats
import io.nats.client.Options
import jakarta.annotation.PreDestroy
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.inject.Produces
import jakarta.inject.Inject
import java.time.Duration
import java.util.Optional
import java.util.UUID
import org.eclipse.microprofile.config.inject.ConfigProperty

const val SNAPSHOT_INVALIDATION_SCHEMA_VERSION = 1

data class PermissionSnapshotInvalidationEvent(val schemaVersion: Int, val playerId: UUID)

interface PermissionSnapshotInvalidationPublisher {
    fun publish(playerId: UUID)
}

internal interface PermissionSnapshotInvalidationTransport : AutoCloseable {
    fun publish(subject: String, payload: ByteArray)
}

internal class NatsPermissionSnapshotInvalidationPublisher(
    private val objectMapper: ObjectMapper,
    private val transport: PermissionSnapshotInvalidationTransport,
    private val subject: String = DEFAULT_SUBJECT,
) : PermissionSnapshotInvalidationPublisher {
    override fun publish(playerId: UUID) {
        try {
            transport.publish(
                subject,
                objectMapper.writeValueAsBytes(
                    PermissionSnapshotInvalidationEvent(
                        schemaVersion = SNAPSHOT_INVALIDATION_SCHEMA_VERSION,
                        playerId = playerId,
                    )
                ),
            )
        } catch (exception: Exception) {
            throw PermissionSnapshotInvalidationPublishException(exception)
        }
    }

    private companion object {
        const val DEFAULT_SUBJECT = "permissions.snapshot.invalidated"
    }
}

class PermissionSnapshotInvalidationPublishException(cause: Throwable) :
    RuntimeException(
        "Permission snapshot invalidation publish failed (reason=nats_publish_failed)",
        cause,
    )

internal object NoopPermissionSnapshotInvalidationPublisher :
    PermissionSnapshotInvalidationPublisher {
    override fun publish(playerId: UUID) = Unit
}

@ApplicationScoped
internal class NatsPermissionSnapshotInvalidationTransport
internal constructor(
    private val connectionOptions: Options,
    private val connectionFactory: (Options) -> Connection,
) : PermissionSnapshotInvalidationTransport {
    @Inject
    constructor(
        @ConfigProperty(name = "permissions.identity-events.nats-url") natsUrl: String,
        @ConfigProperty(name = "grounds.token-file") tokenFile: Optional<String>,
    ) : this(
        buildNatsConnectionOptions(natsUrl, tokenFile.orElse(null)),
        { options -> Nats.connect(options) },
    )

    @Volatile private var connection: Connection? = null

    @Synchronized
    override fun publish(subject: String, payload: ByteArray) {
        val activeConnection = connection ?: openConnection()
        try {
            activeConnection.publish(subject, payload)
            activeConnection.flush(FLUSH_TIMEOUT)
        } catch (exception: Exception) {
            closeAfterFailure()
            throw exception
        }
    }

    @PreDestroy
    override fun close() {
        val activeConnection = connection ?: return
        connection = null
        activeConnection.close()
    }

    private fun openConnection(): Connection {
        closeAfterFailure()
        return connectionFactory(connectionOptions).also { connection = it }
    }

    private fun closeAfterFailure() {
        try {
            close()
        } catch (_: Exception) {
            // Preserve the connection failure for the publisher to classify.
        }
    }

    private companion object {
        val FLUSH_TIMEOUT: Duration = Duration.ofSeconds(2)
    }
}

@ApplicationScoped
internal class PermissionSnapshotInvalidationPublisherProducer
@Inject
constructor(
    private val objectMapper: ObjectMapper,
    private val transport: NatsPermissionSnapshotInvalidationTransport,
    @ConfigProperty(name = "permissions.snapshot-invalidations.subject") subject: String,
    @ConfigProperty(name = "permissions.snapshot-invalidations.enabled") enabled: Boolean,
) {
    private val subject = subject
    private val enabled = enabled

    @Produces
    @ApplicationScoped
    fun publisher(): PermissionSnapshotInvalidationPublisher =
        if (enabled) {
            NatsPermissionSnapshotInvalidationPublisher(objectMapper, transport, subject)
        } else {
            NoopPermissionSnapshotInvalidationPublisher
        }
}
