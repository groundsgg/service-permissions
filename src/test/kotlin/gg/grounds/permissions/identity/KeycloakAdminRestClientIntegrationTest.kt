package gg.grounds.permissions.identity

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentLinkedQueue
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Test

@QuarkusTest
@QuarkusTestResource(
    value = KeycloakAdminRestClientTestResource::class,
    restrictToAnnotatedClass = true,
)
class KeycloakAdminRestClientIntegrationTest {
    @Inject lateinit var client: KeycloakAdminClient

    @Test
    fun injectsConfiguredProductionAdapterAndBindsKeycloakTransport() {
        assertInstanceOf(QuarkusKeycloakAdminClient::class.java, client)

        val token =
            client.requestToken(
                realm = "test realm",
                grantType = "client_credentials",
                clientId = "service permissions",
                clientSecret = "secret+value",
            )
        val users = client.listUsers("Bearer integration-token", "test realm", 20, 10)
        val user = client.getUser("Bearer integration-token", "test realm", "user 42")
        val groups =
            client.listUserGroups("Bearer integration-token", "test realm", "user 42", 30, 15)

        assertEquals(KeycloakAccessTokenResponse("mapped-token", 90), token)
        assertEquals(
            listOf(
                KeycloakUserRepresentation(
                    id = "listed-user",
                    attributes = mapOf("minecraft_java_username" to listOf("ListedPlayer")),
                )
            ),
            users,
        )
        assertEquals(KeycloakUserRepresentation("user 42"), user)
        assertEquals(listOf(KeycloakGroupRepresentation("group-1", "/builders")), groups)

        val requests = KeycloakAdminRestClientTestResource.recordedRequests.toList()
        assertEquals(4, requests.size)
        assertEquals("POST", requests[0].method)
        assertEquals("/realms/test%20realm/protocol/openid-connect/token", requests[0].rawPath)
        assertEquals(
            mapOf(
                "grant_type" to "client_credentials",
                "client_id" to "service permissions",
                "client_secret" to "secret+value",
            ),
            parseForm(requests[0].body),
        )
        assertEquals("application/x-www-form-urlencoded", requests[0].contentType)
        assertEquals(
            RecordedKeycloakRequest(
                method = "GET",
                rawPath = "/admin/realms/test%20realm/users",
                rawQuery = "first=20&max=10",
                authorization = "Bearer integration-token",
            ),
            requests[1],
        )
        assertEquals("/admin/realms/test%20realm/users/user%2042", requests[2].rawPath)
        assertEquals(
            RecordedKeycloakRequest(
                method = "GET",
                rawPath = "/admin/realms/test%20realm/users/user%2042/groups",
                rawQuery = "first=30&max=15",
                authorization = "Bearer integration-token",
            ),
            requests[3],
        )
    }

    private fun parseForm(body: String): Map<String, String> =
        body.split('&').associate { entry ->
            decode(entry.substringBefore('=')) to decode(entry.substringAfter('='))
        }

    private fun decode(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8)
}

class KeycloakAdminRestClientTestResource : QuarkusTestResourceLifecycleManager {
    private lateinit var server: HttpServer

    override fun start(): Map<String, String> {
        recordedRequests.clear()
        server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/") { exchange -> handle(exchange) }
        server.start()
        return mapOf(
            "quarkus.rest-client.keycloak-admin.url" to "http://localhost:${server.address.port}",
            "quarkus.flyway.migrate-at-start" to "false",
        )
    }

    override fun stop() {
        server.stop(0)
        recordedRequests.clear()
    }

    private fun handle(exchange: HttpExchange) {
        val request =
            RecordedKeycloakRequest(
                method = exchange.requestMethod,
                rawPath = exchange.requestURI.rawPath,
                rawQuery = exchange.requestURI.rawQuery,
                authorization = exchange.requestHeaders.getFirst("Authorization"),
                contentType =
                    exchange.requestHeaders.getFirst("Content-Type")?.substringBefore(';'),
                body = exchange.requestBody.readAllBytes().toString(StandardCharsets.UTF_8),
            )
        recordedRequests += request

        when (exchange.requestURI.path) {
            "/realms/test realm/protocol/openid-connect/token" ->
                exchange.respond(
                    200,
                    """{"access_token":"mapped-token","expires_in":90,"ignored":true}""",
                )
            "/admin/realms/test realm/users" ->
                exchange.respond(
                    200,
                    """[{"id":"listed-user","attributes":{"minecraft_java_username":["ListedPlayer"]},"ignored":true}]""",
                )
            "/admin/realms/test realm/users/user 42" ->
                exchange.respond(200, """{"id":"user 42","attributes":{},"ignored":true}""")
            "/admin/realms/test realm/users/user 42/groups" ->
                exchange.respond(200, """[{"id":"group-1","path":"/builders","ignored":true}]""")
            else -> exchange.respond(404, "{}")
        }
    }

    companion object {
        val recordedRequests: ConcurrentLinkedQueue<RecordedKeycloakRequest> =
            ConcurrentLinkedQueue()
    }
}

data class RecordedKeycloakRequest(
    val method: String,
    val rawPath: String,
    val rawQuery: String? = null,
    val authorization: String? = null,
    val contentType: String? = null,
    val body: String = "",
)

private fun HttpExchange.respond(status: Int, body: String) {
    val bytes = body.toByteArray()
    responseHeaders.add("Content-Type", "application/json")
    sendResponseHeaders(status, bytes.size.toLong())
    responseBody.use { it.write(bytes) }
}
