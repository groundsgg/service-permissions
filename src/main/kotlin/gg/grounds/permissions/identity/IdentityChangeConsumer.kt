package gg.grounds.permissions.identity

import com.fasterxml.jackson.databind.ObjectMapper
import io.nats.client.Connection
import io.nats.client.JetStreamSubscription
import io.nats.client.Message
import io.nats.client.Nats
import io.nats.client.PullSubscribeOptions
import io.nats.client.api.AckPolicy
import io.nats.client.api.ConsumerConfiguration
import io.quarkus.runtime.ShutdownEvent
import io.quarkus.runtime.StartupEvent
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.event.Observes
import jakarta.inject.Inject
import java.time.Duration
import java.util.Optional
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger

interface IdentityEventDelivery {
    val data: ByteArray

    fun acknowledge()

    fun negativelyAcknowledge(delay: Duration)

    fun terminate()
}

data class IdentityEventConsumerConfig(
    val subject: String,
    val stream: String,
    val durableName: String,
    val maxDeliveries: Int = IdentityChangeConsumer.DEFAULT_MAX_DELIVERIES,
) {
    init {
        require(maxDeliveries > 0) { "Identity event max deliveries must be positive" }
    }
}

interface IdentityEventSubscription : AutoCloseable {
    fun next(timeout: Duration): IdentityEventDelivery?
}

interface IdentityEventTransport : AutoCloseable {
    fun open(config: IdentityEventConsumerConfig): IdentityEventSubscription
}

@ApplicationScoped
class IdentityChangeConsumer(
    private val objectMapper: ObjectMapper,
    private val coordinator: IdentitySyncCoordinator,
    private val realmId: String,
    private val transport: IdentityEventTransport? = null,
    private val config: IdentityEventConsumerConfig? = null,
    private val executor: ExecutorService? = null,
    private val enabled: Boolean = true,
    private val retryDelay: Duration = DEFAULT_RETRY_DELAY,
) {
    private val running = AtomicBoolean(false)
    @Volatile private var subscription: IdentityEventSubscription? = null

    init {
        require(!retryDelay.isZero && !retryDelay.isNegative) {
            "Identity event retry delay must be positive"
        }
    }

    @Inject
    constructor(
        objectMapper: ObjectMapper,
        coordinator: IdentitySyncCoordinator,
        @ConfigProperty(name = "permissions.keycloak.realm") realmId: String,
        @ConfigProperty(name = "permissions.identity-events.nats-url") natsUrl: String,
        @ConfigProperty(name = "grounds.token-file") tokenFile: Optional<String>,
        @ConfigProperty(name = "permissions.identity-events.subject") subject: String,
        @ConfigProperty(name = "permissions.identity-events.stream") stream: String,
        @ConfigProperty(name = "permissions.identity-events.consumer-prefix")
        consumerPrefix: String,
        @ConfigProperty(name = "permissions.identity-events.consumer")
        explicitConsumer: Optional<String>,
        @ConfigProperty(name = "grounds.project-id") projectId: Optional<String>,
        @ConfigProperty(name = "permissions.identity-events.enabled") enabled: Boolean,
        @ConfigProperty(name = "permissions.identity-events.retry-delay") retryDelay: Duration,
        @ConfigProperty(name = "permissions.identity-events.max-deliveries") maxDeliveries: Int,
    ) : this(
        objectMapper = objectMapper,
        coordinator = coordinator,
        realmId = realmId,
        transport = NatsIdentityEventTransport(natsUrl, tokenFile.orElse(null)),
        config =
            IdentityEventConsumerConfig(
                subject = subject,
                stream = stream,
                durableName =
                    if (enabled) {
                        resolveDurableName(
                            explicitConsumer.orElse(null),
                            consumerPrefix,
                            projectId.orElse(null),
                        )
                    } else {
                        DISABLED_CONSUMER_NAME
                    },
                maxDeliveries = maxDeliveries,
            ),
        executor =
            Executors.newSingleThreadExecutor(
                Thread.ofVirtual().name("identity-events-", 0).factory()
            ),
        enabled = enabled,
        retryDelay = retryDelay,
    )

    fun onStartup(@Observes event: StartupEvent) {
        if (!enabled) return
        val eventTransport = checkNotNull(transport)
        val consumerConfig = checkNotNull(config)
        val consumerExecutor = checkNotNull(executor)
        if (running.compareAndSet(false, true)) {
            consumerExecutor.execute { consume(eventTransport, consumerConfig) }
        }
    }

    fun process(delivery: IdentityEventDelivery) {
        val event =
            try {
                objectMapper
                    .readValue(delivery.data, MinecraftIdentityChangedEvent::class.java)
                    .also(::validate)
            } catch (_: Exception) {
                delivery.terminate()
                LOG.warnf("Player identity event rejected (reason=%s)", INVALID_PAYLOAD_REASON)
                return
            }

        if (event.realmId != realmId) {
            delivery.acknowledge()
            return
        }

        when (coordinator.refreshPlayer(event.keycloakUserId)) {
            IdentityRefreshOutcome.UPDATED,
            IdentityRefreshOutcome.REMOVED -> delivery.acknowledge()
            IdentityRefreshOutcome.FAILED -> delivery.negativelyAcknowledge(retryDelay)
        }
    }

    fun onShutdown(@Observes event: ShutdownEvent) {
        running.set(false)
        subscription?.closeQuietly()
        transport?.closeQuietly()
        executor?.shutdownNow()
    }

    private fun consume(
        eventTransport: IdentityEventTransport,
        consumerConfig: IdentityEventConsumerConfig,
    ) {
        while (running.get()) {
            try {
                eventTransport.open(consumerConfig).use { openedSubscription ->
                    subscription = openedSubscription
                    LOG.infof(
                        "Player identity event consumer connected successfully (stream=%s, subject=%s, consumer=%s)",
                        consumerConfig.stream,
                        consumerConfig.subject,
                        consumerConfig.durableName,
                    )
                    while (running.get()) {
                        openedSubscription.next(FETCH_TIMEOUT)?.let(::process)
                    }
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            } catch (_: Exception) {
                if (running.get()) {
                    LOG.warnf(
                        "Player identity event consumer disconnected (stream=%s, consumer=%s, reason=%s)",
                        consumerConfig.stream,
                        consumerConfig.durableName,
                        CONSUMER_FAILURE_REASON,
                    )
                    try {
                        Thread.sleep(RECONNECT_DELAY)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        return
                    }
                }
            } finally {
                subscription = null
            }
        }
    }

    private fun validate(event: MinecraftIdentityChangedEvent) {
        require(event.realmId.isNotBlank())
        require(event.keycloakUserId.isNotBlank())
        require(event.reason.isNotBlank())
    }

    private fun AutoCloseable.closeQuietly() {
        try {
            close()
        } catch (_: Exception) {
            LOG.warnf(
                "Player identity event resource close failed (reason=%s)",
                CLOSE_FAILURE_REASON,
            )
        }
    }

    companion object {
        internal fun resolveDurableName(
            explicitConsumer: String?,
            consumerPrefix: String,
            projectId: String?,
        ): String {
            explicitConsumer?.trim()?.takeIf(String::isNotEmpty)?.let {
                return it
            }
            val normalizedProjectId = projectId?.trim()?.takeIf(String::isNotEmpty)
            requireNotNull(normalizedProjectId) {
                "A project ID or explicit identity event consumer is required"
            }
            return "${consumerPrefix.trim()}-$normalizedProjectId"
        }

        private val FETCH_TIMEOUT = Duration.ofSeconds(1)
        private val RECONNECT_DELAY = Duration.ofSeconds(5).toMillis()
        private const val INVALID_PAYLOAD_REASON = "invalid_payload"
        private const val CONSUMER_FAILURE_REASON = "event_consumer_failure"
        private const val CLOSE_FAILURE_REASON = "resource_close_failure"
        private const val DISABLED_CONSUMER_NAME = "disabled"
        internal const val DEFAULT_MAX_DELIVERIES = 10
        internal val DEFAULT_RETRY_DELAY: Duration = Duration.ofSeconds(5)
        private val LOG: Logger = Logger.getLogger(IdentityChangeConsumer::class.java)
    }
}

internal class NatsIdentityEventTransport(natsUrl: String, tokenFile: String?) :
    IdentityEventTransport {
    internal val connectionOptions = buildNatsConnectionOptions(natsUrl, tokenFile)
    @Volatile private var connection: Connection? = null

    override fun open(config: IdentityEventConsumerConfig): IdentityEventSubscription {
        close()
        val openedConnection = Nats.connect(connectionOptions)
        connection = openedConnection
        val options = buildPullSubscribeOptions(config)
        val subscription = openedConnection.jetStream().subscribe(config.subject, options)
        return NatsIdentityEventSubscription(subscription)
    }

    override fun close() {
        connection?.close()
        connection = null
    }
}

internal fun buildPullSubscribeOptions(config: IdentityEventConsumerConfig): PullSubscribeOptions =
    PullSubscribeOptions.builder()
        .stream(config.stream)
        .durable(config.durableName)
        .configuration(
            ConsumerConfiguration.builder()
                .ackPolicy(AckPolicy.Explicit)
                .maxDeliver(config.maxDeliveries.toLong())
                .build()
        )
        .build()

private class NatsIdentityEventSubscription(private val subscription: JetStreamSubscription) :
    IdentityEventSubscription {
    override fun next(timeout: Duration): IdentityEventDelivery? =
        subscription.fetch(1, timeout).firstOrNull()?.let(::NatsIdentityEventDelivery)

    override fun close() {
        subscription.unsubscribe()
    }
}

private class NatsIdentityEventDelivery(private val message: Message) : IdentityEventDelivery {
    override val data: ByteArray
        get() = message.data

    override fun acknowledge() {
        message.ack()
    }

    override fun negativelyAcknowledge(delay: Duration) {
        message.nakWithDelay(delay)
    }

    override fun terminate() {
        message.term()
    }
}
