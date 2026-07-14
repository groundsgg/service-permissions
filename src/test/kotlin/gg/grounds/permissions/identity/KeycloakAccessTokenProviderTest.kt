package gg.grounds.permissions.identity

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class KeycloakAccessTokenProviderTest {
    @Test
    fun cachesClientCredentialsTokenUntilRefreshWindow() {
        val requests = AtomicInteger()
        val requestMethods = Collections.synchronizedList(mutableListOf<String>())
        val requestContentTypes = Collections.synchronizedList(mutableListOf<String?>())
        val requestForms = Collections.synchronizedList(mutableListOf<Map<String, String>>())
        val server = tokenServer { exchange ->
            requestMethods += exchange.requestMethod
            requestContentTypes += exchange.requestHeaders.getFirst("Content-Type")
            requestForms +=
                parseForm(exchange.requestBody.readAllBytes().toString(StandardCharsets.UTF_8))
            val requestNumber = requests.incrementAndGet()
            val token = if (requestNumber == 1) "token-one" else "token-two"
            val body = """{"access_token":"$token","expires_in":60}"""
            val bytes = body.toByteArray()
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        val clock = MutableClock(Instant.parse("2030-01-01T00:00:00Z"))

        try {
            val provider =
                KeycloakAccessTokenProvider(
                    client = restClient(server),
                    realm = "grounds",
                    clientId = "service-permissions",
                    clientSecret = "client-secret",
                    clock = clock,
                    refreshSkew = Duration.ofSeconds(10),
                )

            assertEquals("Bearer token-one", provider.authorizationHeader())
            clock.advance(Duration.ofSeconds(49))
            assertEquals("Bearer token-one", provider.authorizationHeader())
            clock.advance(Duration.ofSeconds(2))
            assertEquals("Bearer token-two", provider.authorizationHeader())
            assertEquals(2, requests.get())
            assertEquals(setOf("POST"), requestMethods.toSet())
            assertTrue(
                requestContentTypes.all { contentType ->
                    contentType?.startsWith("application/x-www-form-urlencoded") == true
                }
            )
            assertEquals(
                setOf(
                    mapOf(
                        "grant_type" to "client_credentials",
                        "client_id" to "service-permissions",
                        "client_secret" to "client-secret",
                    )
                ),
                requestForms.toSet(),
            )
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun sanitizesTokenEndpointFailures() {
        val server = tokenServer { exchange ->
            val body = "remote-secret-body bearer-sensitive-token"
            val bytes = body.toByteArray()
            exchange.sendResponseHeaders(401, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }

        try {
            val provider =
                KeycloakAccessTokenProvider(
                    client = restClient(server),
                    realm = "grounds",
                    clientId = "service-permissions",
                    clientSecret = "client-secret",
                    clock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC),
                    refreshSkew = Duration.ofSeconds(10),
                )

            val error =
                assertThrows(KeycloakReadException::class.java) { provider.authorizationHeader() }

            assertEquals("Keycloak access token request failed", error.message)
            assertNull(error.cause)
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun invalidatesOnlyTheMatchingCachedToken() {
        val requests = AtomicInteger()
        val server = tokenServer { exchange ->
            val token = "token-${requests.incrementAndGet()}"
            val body = """{"access_token":"$token","expires_in":60}"""
            val bytes = body.toByteArray()
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }

        try {
            val provider =
                KeycloakAccessTokenProvider(
                    client = restClient(server),
                    realm = "grounds",
                    clientId = "service-permissions",
                    clientSecret = "client-secret",
                    clock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC),
                    refreshSkew = Duration.ofSeconds(10),
                )

            assertEquals("Bearer token-1", provider.authorizationHeader())
            provider.invalidate("Bearer token-1")
            assertEquals("Bearer token-2", provider.authorizationHeader())
            provider.invalidate("Bearer token-1")

            assertEquals("Bearer token-2", provider.authorizationHeader())
            assertEquals(2, requests.get())
        } finally {
            server.stop(0)
        }
    }

    private fun tokenServer(handler: (com.sun.net.httpserver.HttpExchange) -> Unit): HttpServer =
        HttpServer.create(InetSocketAddress("localhost", 0), 0).also { server ->
            server.createContext("/realms/grounds/protocol/openid-connect/token", handler)
            server.start()
        }

    private fun restClient(server: HttpServer): KeycloakAdminClient =
        TestHttpKeycloakAdminClient(URI.create("http://localhost:${server.address.port}"))

    private fun parseForm(body: String): Map<String, String> =
        body.split('&').associate { entry ->
            decodeFormValue(entry.substringBefore('=')) to
                decodeFormValue(entry.substringAfter('='))
        }

    private fun decodeFormValue(value: String): String =
        java.net.URLDecoder.decode(value, StandardCharsets.UTF_8)
}

internal class TestHttpKeycloakAdminClient(private val baseUri: URI) : KeycloakAdminClient {
    private val httpClient = HttpClient.newHttpClient()
    private val objectMapper = ObjectMapper().registerModule(KotlinModule.Builder().build())

    override fun requestToken(
        realm: String,
        grantType: String,
        clientId: String,
        clientSecret: String,
    ): KeycloakAccessTokenResponse {
        val body =
            formValue("grant_type", grantType) +
                "&" +
                formValue("client_id", clientId) +
                "&" +
                formValue("client_secret", clientSecret)
        return send(
            HttpRequest.newBuilder(baseUri.resolve("/realms/$realm/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            object : TypeReference<KeycloakAccessTokenResponse>() {},
        )
    }

    override fun listUsers(
        authorization: String,
        realm: String,
        first: Int,
        max: Int,
    ): List<KeycloakUserRepresentation> =
        get(
            "/admin/realms/$realm/users?first=$first&max=$max",
            authorization,
            object : TypeReference<List<KeycloakUserRepresentation>>() {},
        )

    override fun getUser(
        authorization: String,
        realm: String,
        userId: String,
    ): KeycloakUserRepresentation =
        get(
            "/admin/realms/$realm/users/${encodePathSegment(userId)}",
            authorization,
            object : TypeReference<KeycloakUserRepresentation>() {},
        )

    override fun listUserGroups(
        authorization: String,
        realm: String,
        userId: String,
        first: Int,
        max: Int,
    ): List<KeycloakGroupRepresentation> =
        get(
            "/admin/realms/$realm/users/${encodePathSegment(userId)}/groups?first=$first&max=$max",
            authorization,
            object : TypeReference<List<KeycloakGroupRepresentation>>() {},
        )

    private fun <T> get(path: String, authorization: String, responseType: TypeReference<T>): T =
        send(
            HttpRequest.newBuilder(baseUri.resolve(path))
                .header("Authorization", authorization)
                .GET()
                .build(),
            responseType,
        )

    private fun <T> send(request: HttpRequest, responseType: TypeReference<T>): T {
        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() !in 200..299) {
            throw KeycloakAdminException(response.statusCode())
        }
        return objectMapper.readValue(response.body(), responseType)
    }

    private fun formValue(name: String, value: String): String =
        "${encodeQueryValue(name)}=${encodeQueryValue(value)}"

    private fun encodePathSegment(value: String): String =
        encodeQueryValue(value).replace("+", "%20")

    private fun encodeQueryValue(value: String): String =
        URLEncoder.encode(value, StandardCharsets.UTF_8)
}

private class MutableClock(private var current: Instant) : Clock() {
    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId): Clock = this

    override fun instant(): Instant = current

    fun advance(duration: Duration) {
        current = current.plus(duration)
    }
}
