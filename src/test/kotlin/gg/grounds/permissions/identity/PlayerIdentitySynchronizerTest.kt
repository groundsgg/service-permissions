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
import java.util.concurrent.atomic.AtomicInteger
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
            val authorizationRequests = AtomicInteger()
            val synchronizer =
                synchronizer(
                    server,
                    pageSize = 2,
                    authorizationProvider =
                        KeycloakAuthorizationProvider {
                            "Bearer read-token-${authorizationRequests.incrementAndGet()}"
                        },
                )

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
            assertEquals(
                listOf(
                    "Bearer read-token-1",
                    "Bearer read-token-2",
                    "Bearer read-token-3",
                    "Bearer read-token-4",
                ),
                authorizationHeaders,
            )
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun rejectsUuidTextThatOnlyBecomesCanonicalDuringParsing() {
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/admin/realms/grounds/users") { exchange ->
            when (exchange.requestURI.path) {
                "/admin/realms/grounds/users" ->
                    exchange.respond(
                        200,
                        """[{"id":"non-canonical","attributes":{"minecraft_java_uuid":["1-1-1-1-1"],"minecraft_java_username":["InvalidPlayer"]}}]""",
                    )
                "/admin/realms/grounds/users/non-canonical/groups" -> exchange.respond(200, "[]")
                else -> exchange.respond(404, "missing")
            }
        }
        server.start()

        try {
            val identities = synchronizer(server, pageSize = 2).loadAll()

            assertEquals(emptyList<ProjectedPlayerIdentity>(), identities)
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
        val groupRequests = AtomicInteger()
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/admin/realms/grounds/users") { exchange ->
            when (exchange.requestURI.path) {
                "/admin/realms/grounds/users" ->
                    exchange.respond(
                        200,
                        """[{"id":"linked","attributes":{"minecraft_java_uuid":["00000000-0000-0000-0000-000000000303"],"minecraft_java_username":["SkyPlayer"]}}]""",
                    )
                "/admin/realms/grounds/users/linked/groups" ->
                    exchange.respond(
                        500,
                        "remote-secret-body bearer-sensitive-token-${groupRequests.incrementAndGet()}",
                    )
                else -> exchange.respond(404, "missing")
            }
        }
        server.start()

        try {
            val synchronizer = synchronizer(server, pageSize = 2)

            val error = assertThrows(KeycloakReadException::class.java) { synchronizer.loadAll() }

            assertEquals("Keycloak group query failed", error.message)
            assertNull(error.cause)
            assertEquals(1, groupRequests.get())
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun invalidatesAuthorizationAndRetriesOnceAfterUnauthorizedResponse() {
        val userRequests = AtomicInteger()
        val authorizationHeaders = Collections.synchronizedList(mutableListOf<String?>())
        val invalidatedAuthorizations = mutableListOf<String>()
        val authorizationProvider =
            object : KeycloakAuthorizationProvider {
                private var authorization = "Bearer read-token-1"

                override fun authorizationHeader(): String = authorization

                override fun invalidate(authorizationHeader: String) {
                    invalidatedAuthorizations += authorizationHeader
                    if (authorization == authorizationHeader) {
                        authorization = "Bearer read-token-2"
                    }
                }
            }
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/admin/realms/grounds/users") { exchange ->
            authorizationHeaders += exchange.requestHeaders.getFirst("Authorization")
            when (exchange.requestURI.path) {
                "/admin/realms/grounds/users" -> {
                    if (userRequests.incrementAndGet() == 1) {
                        exchange.respond(401, "expired bearer-sensitive-token")
                    } else {
                        exchange.respond(200, "[]")
                    }
                }
                else -> exchange.respond(404, "missing")
            }
        }
        server.start()

        try {
            val synchronizer =
                synchronizer(server, pageSize = 2, authorizationProvider = authorizationProvider)

            assertEquals(emptyList<ProjectedPlayerIdentity>(), synchronizer.loadAll())
            assertEquals(2, userRequests.get())
            assertEquals(listOf("Bearer read-token-1", "Bearer read-token-2"), authorizationHeaders)
            assertEquals(listOf("Bearer read-token-1"), invalidatedAuthorizations)
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun retriesUnauthorizedResponseExactlyOnce() {
        val userRequests = AtomicInteger()
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/admin/realms/grounds/users") { exchange ->
            userRequests.incrementAndGet()
            exchange.respond(401, "expired bearer-sensitive-token")
        }
        server.start()

        try {
            val error =
                assertThrows(KeycloakReadException::class.java) {
                    synchronizer(server, pageSize = 2).loadAll()
                }

            assertEquals("Keycloak user query failed", error.message)
            assertNull(error.cause)
            assertEquals(2, userRequests.get())
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun groupNotFoundReturnsNoProjectionForDisappearedUser() {
        val authorizationRequests = AtomicInteger()
        val authorizationHeaders = Collections.synchronizedList(mutableListOf<String?>())
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/admin/realms/grounds/users") { exchange ->
            authorizationHeaders += exchange.requestHeaders.getFirst("Authorization")
            when (exchange.requestURI.path) {
                "/admin/realms/grounds/users/disappeared" ->
                    exchange.respond(
                        200,
                        """{"id":"disappeared","attributes":{"minecraft_java_uuid":["00000000-0000-0000-0000-000000000304"],"minecraft_java_username":["GonePlayer"]}}""",
                    )
                "/admin/realms/grounds/users/disappeared/groups" -> exchange.respond(404, "deleted")
                else -> exchange.respond(404, "missing")
            }
        }
        server.start()

        try {
            val identity =
                synchronizer(
                        server,
                        pageSize = 2,
                        authorizationProvider =
                            KeycloakAuthorizationProvider {
                                "Bearer read-token-${authorizationRequests.incrementAndGet()}"
                            },
                    )
                    .loadPlayer("disappeared")

            assertNull(identity)
            assertEquals(listOf("Bearer read-token-1", "Bearer read-token-2"), authorizationHeaders)
        } finally {
            server.stop(0)
        }
    }

    private fun synchronizer(
        server: HttpServer,
        pageSize: Int,
        authorizationProvider: KeycloakAuthorizationProvider = KeycloakAuthorizationProvider {
            "Bearer read-token"
        },
    ): PlayerIdentitySynchronizer =
        PlayerIdentitySynchronizer(
            client =
                TestHttpKeycloakAdminClient(URI.create("http://localhost:${server.address.port}")),
            authorizationProvider = authorizationProvider,
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
