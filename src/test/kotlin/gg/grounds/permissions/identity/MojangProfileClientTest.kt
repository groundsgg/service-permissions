package gg.grounds.permissions.identity

import com.fasterxml.jackson.databind.ObjectMapper
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.http.HttpClient
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Test

class MojangProfileClientTest {

    @Test
    fun cachesLookupOutcomeAcrossPaginatedSearchRequests() {
        val requests = AtomicInteger()
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/users/profiles/minecraft/StablePlayer") { exchange ->
            if (requests.incrementAndGet() == 1) {
                val body = """{"id":"00000000000000000000000000000411","name":"StablePlayer"}"""
                exchange.sendResponseHeaders(200, body.length.toLong())
                exchange.responseBody.use { it.write(body.toByteArray()) }
            } else {
                exchange.sendResponseHeaders(503, -1)
                exchange.close()
            }
        }
        server.start()

        try {
            val client = client(server)
            val first = client.lookupExactUsername("StablePlayer")
            val second = client.lookupExactUsername("StablePlayer")

            assertEquals(first, second)
            assertEquals(1, requests.get())
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun refreshesCachedLookupAfterConfiguredTtl() {
        val requests = AtomicInteger()
        val clock = MojangTestClock(Instant.parse("2030-01-01T00:00:00Z"))
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/users/profiles/minecraft/ExpiryPlayer") { exchange ->
            if (requests.incrementAndGet() == 1) {
                val body = """{"id":"00000000000000000000000000000412","name":"ExpiryPlayer"}"""
                exchange.sendResponseHeaders(200, body.length.toLong())
                exchange.responseBody.use { it.write(body.toByteArray()) }
            } else {
                exchange.sendResponseHeaders(503, -1)
                exchange.close()
            }
        }
        server.start()

        try {
            val client = client(server, clock = clock, cacheTtl = Duration.ofMinutes(5))
            assertEquals(
                MojangLookupResult.Found(
                    MojangProfile(
                        UUID.fromString("00000000-0000-0000-0000-000000000412"),
                        "ExpiryPlayer",
                    )
                ),
                client.lookupExactUsername("ExpiryPlayer"),
            )

            clock.currentInstant = clock.currentInstant.plus(Duration.ofMinutes(6))

            assertSame(MojangLookupResult.Unavailable, client.lookupExactUsername("ExpiryPlayer"))
            assertEquals(2, requests.get())
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun hyphenatesMojangProfileUuidWithoutPersistingOrExposingResponseBodies() {
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/users/profiles/minecraft/ExactPlayer") { exchange ->
            val body = """{"id":"00000000000000000000000000000408","name":"ExactPlayer"}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.use { it.write(body.toByteArray()) }
        }
        server.start()

        try {
            val result = client(server).lookupExactUsername("ExactPlayer")

            assertEquals(
                MojangLookupResult.Found(
                    MojangProfile(
                        UUID.fromString("00000000-0000-0000-0000-000000000408"),
                        "ExactPlayer",
                    )
                ),
                result,
            )
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun sanitizesRateLimitsAndUnexpectedBodiesAsUnavailable() {
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/users/profiles/minecraft/RateLimited") { exchange ->
            val body = "internal-only diagnostic bearer-sensitive-token"
            exchange.sendResponseHeaders(429, body.length.toLong())
            exchange.responseBody.use { it.write(body.toByteArray()) }
        }
        server.start()

        try {
            assertSame(
                MojangLookupResult.Unavailable,
                client(server).lookupExactUsername("RateLimited"),
            )
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun rejectsSuccessfulResponsesWithoutAValidProfileName() {
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/users/profiles/minecraft/MalformedPlayer") { exchange ->
            val body = """{"id":"00000000000000000000000000000409"}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.use { it.write(body.toByteArray()) }
        }
        server.start()

        try {
            assertSame(
                MojangLookupResult.Unavailable,
                client(server).lookupExactUsername("MalformedPlayer"),
            )
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun rejectsSuccessfulResponsesForADifferentUsername() {
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/users/profiles/minecraft/ExpectedPlayer") { exchange ->
            val body = """{"id":"00000000000000000000000000000410","name":"OtherPlayer"}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.use { it.write(body.toByteArray()) }
        }
        server.start()

        try {
            assertSame(
                MojangLookupResult.Unavailable,
                client(server).lookupExactUsername("ExpectedPlayer"),
            )
        } finally {
            server.stop(0)
        }
    }

    private fun client(
        server: HttpServer,
        clock: Clock = Clock.systemUTC(),
        cacheTtl: Duration = Duration.ofMinutes(5),
    ): MojangProfileClient =
        MojangProfileClient(
            objectMapper = ObjectMapper(),
            baseUrl = "http://localhost:${server.address.port}",
            timeout = Duration.ofSeconds(1),
            httpClient = HttpClient.newHttpClient(),
            clock = clock,
            cacheTtl = cacheTtl,
        )
}

private class MojangTestClock(var currentInstant: Instant) : Clock() {
    override fun getZone(): ZoneId = ZoneId.of("UTC")

    override fun withZone(zone: ZoneId): Clock = this

    override fun instant(): Instant = currentInstant
}
