package gg.grounds.permissions.identity

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Collections
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class PlayerIdentitySynchronizerTest {
    @Test
    fun readsPaginatedUsersAndGroupsAndProjectsOnlyLinkedPlayers() {
        val userPages = Collections.synchronizedList(mutableListOf<Int>())
        val groupPages = Collections.synchronizedList(mutableListOf<Int>())
        val authorizationHeaders = Collections.synchronizedList(mutableListOf<String?>())
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/admin/realms/grounds/users") { exchange ->
            authorizationHeaders += exchange.requestHeaders.getFirst("Authorization")
            val path = exchange.requestURI.path
            when {
                path.endsWith("/linked/groups") -> {
                    val first = exchange.queryParameter("first").toInt()
                    groupPages += first
                    val body =
                        if (first == 0) {
                            """[{"id":"g1","path":"/staff"},{"id":"g2","path":"/staff/moderators"}]"""
                        } else {
                            """[{"id":"g3","path":"/builders"}]"""
                        }
                    exchange.respond(200, body)
                }
                path == "/admin/realms/grounds/users" -> {
                    val first = exchange.queryParameter("first").toInt()
                    userPages += first
                    val body =
                        if (first == 0) {
                            """
                            [
                              {"id":"linked","attributes":{"minecraft_java_uuid":["00000000-0000-0000-0000-000000000301"],"minecraft_java_username":["SkyPlayer"]}},
                              {"id":"malformed","attributes":{"minecraft_java_uuid":["not-a-uuid"],"minecraft_java_username":["BrokenPlayer"]}}
                            ]
                            """
                                .trimIndent()
                        } else {
                            """[{"id":"unlinked","attributes":{"minecraft_java_uuid":["00000000-0000-0000-0000-000000000302"]}}]"""
                        }
                    exchange.respond(200, body)
                }
                else -> exchange.respond(404, "missing")
            }
        }
        server.start()

        try {
            val synchronizer = synchronizer(server, pageSize = 2)

            val identities = synchronizer.loadAll()

            assertEquals(1, identities.size)
            assertEquals(
                ProjectedPlayerIdentity(
                    playerId = UUID.fromString("00000000-0000-0000-0000-000000000301"),
                    keycloakUserId = "linked",
                    minecraftUsername = "SkyPlayer",
                    normalizedUsername = "skyplayer",
                    groupPaths = setOf("/staff", "/staff/moderators", "/builders"),
                    syncedAt = Instant.parse("2030-01-01T00:00:00Z"),
                    sourceUpdatedAt = null,
                ),
                identities.single(),
            )
            assertEquals(listOf(0, 2), userPages)
            assertEquals(listOf(0, 2), groupPages)
            assertEquals(setOf("Bearer read-token"), authorizationHeaders.toSet())
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun returnsNoProjectionForDeletedOrUnlinkedUsers() {
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/admin/realms/grounds/users") { exchange ->
            when (exchange.requestURI.path) {
                "/admin/realms/grounds/users/deleted" -> exchange.respond(404, "deleted")
                "/admin/realms/grounds/users/unlinked" ->
                    exchange.respond(200, """{"id":"unlinked","attributes":{}}""")
                else -> exchange.respond(404, "missing")
            }
        }
        server.start()

        try {
            val synchronizer = synchronizer(server, pageSize = 2)

            assertNull(synchronizer.loadPlayer("deleted"))
            assertNull(synchronizer.loadPlayer("unlinked"))
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun sanitizesGroupEndpointFailures() {
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/admin/realms/grounds/users") { exchange ->
            when (exchange.requestURI.path) {
                "/admin/realms/grounds/users" ->
                    exchange.respond(
                        200,
                        """[{"id":"linked","attributes":{"minecraft_java_uuid":["00000000-0000-0000-0000-000000000303"],"minecraft_java_username":["SkyPlayer"]}}]""",
                    )
                "/admin/realms/grounds/users/linked/groups" ->
                    exchange.respond(500, "remote-secret-body bearer-sensitive-token")
                else -> exchange.respond(404, "missing")
            }
        }
        server.start()

        try {
            val synchronizer = synchronizer(server, pageSize = 2)

            val error = assertThrows(KeycloakReadException::class.java) { synchronizer.loadAll() }

            assertEquals("Keycloak group query failed", error.message)
            assertNull(error.cause)
        } finally {
            server.stop(0)
        }
    }

    private fun synchronizer(server: HttpServer, pageSize: Int): PlayerIdentitySynchronizer =
        PlayerIdentitySynchronizer(
            client =
                TestHttpKeycloakAdminClient(URI.create("http://localhost:${server.address.port}")),
            authorizationProvider = KeycloakAuthorizationProvider { "Bearer read-token" },
            realm = "grounds",
            pageSize = pageSize,
            clock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC),
        )
}

private fun HttpExchange.queryParameter(name: String): String =
    requestURI.rawQuery
        .split('&')
        .first { it.substringBefore('=') == name }
        .substringAfter('=')
        .let { URLDecoder.decode(it, StandardCharsets.UTF_8) }

private fun HttpExchange.respond(status: Int, body: String) {
    val bytes = body.toByteArray()
    responseHeaders.add("Content-Type", "application/json")
    sendResponseHeaders(status, bytes.size.toLong())
    responseBody.use { it.write(bytes) }
}
