package gg.grounds.permissions.identity

import com.fasterxml.jackson.databind.ObjectMapper
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.http.HttpClient
import java.time.Duration
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Test

class MojangProfileClientTest {

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
        server.createContext("/users/profiles/minecraft/UnavailablePlayer") { exchange ->
            val body = "internal-only diagnostic bearer-sensitive-token"
            exchange.sendResponseHeaders(429, body.length.toLong())
            exchange.responseBody.use { it.write(body.toByteArray()) }
        }
        server.start()

        try {
            assertSame(
                MojangLookupResult.Unavailable,
                client(server).lookupExactUsername("UnavailablePlayer"),
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

    private fun client(server: HttpServer): MojangProfileClient =
        MojangProfileClient(
            objectMapper = ObjectMapper(),
            baseUrl = "http://localhost:${server.address.port}",
            timeout = Duration.ofSeconds(1),
            httpClient = HttpClient.newHttpClient(),
        )
}
