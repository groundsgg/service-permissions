package gg.grounds.permissions.auth

import com.fasterxml.jackson.databind.ObjectMapper
import com.sun.net.httpserver.HttpServer
import io.quarkus.security.identity.SecurityIdentity
import jakarta.ws.rs.ForbiddenException
import jakarta.ws.rs.core.Cookie
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.MultivaluedHashMap
import jakarta.ws.rs.core.MultivaluedMap
import java.lang.reflect.Proxy
import java.net.InetSocketAddress
import java.security.Principal
import java.util.Date
import java.util.Locale
import org.eclipse.microprofile.jwt.JsonWebToken
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class AdminAuthorizationServiceTest {
    @Test
    fun acceptsForgeProjectOwnerAccessWhenJwtDoesNotContainPermission() {
        val server =
            forgeAccessServer(
                path = "/v1/projects/project-a",
                response = """{"id":"project-a","role":"owner"}""",
            )
        try {
            val service =
                AdminAuthorizationService(
                    WebUserResolver(jsonWebToken(subject = "project-owner"), false),
                    jsonWebToken(subject = "project-owner"),
                    ObjectMapper(),
                    "http://localhost:${server.address.port}",
                )

            val userId =
                service.requireMinecraftPermissionsAdmin(
                    securityIdentity(),
                    StaticAuthorizationHeaders(
                        authorization = "Bearer project-owner-token",
                        projectId = "project-a",
                    ),
                )

            assertEquals("project-owner", userId)
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun rejectsForgeProjectViewersWhenJwtDoesNotContainPermission() {
        val server =
            forgeAccessServer(
                path = "/v1/projects/project-a",
                response = """{"id":"project-a","role":"viewer"}""",
            )
        try {
            val service =
                AdminAuthorizationService(
                    WebUserResolver(jsonWebToken(subject = "project-viewer"), false),
                    jsonWebToken(subject = "project-viewer"),
                    ObjectMapper(),
                    "http://localhost:${server.address.port}",
                )

            assertThrows(ForbiddenException::class.java) {
                service.requireMinecraftPermissionsAdmin(
                    securityIdentity(),
                    StaticAuthorizationHeaders(
                        authorization = "Bearer project-viewer-token",
                        projectId = "project-a",
                    ),
                )
            }
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun acceptsForgeEffectiveAccessPermissionWhenJwtDoesNotContainPermission() {
        val server = forgeAccessServer("""{"permissions":["MINECRAFT_PERMISSIONS_MANAGE"]}""")
        try {
            val service =
                AdminAuthorizationService(
                    WebUserResolver(jsonWebToken(subject = "admin-user"), false),
                    jsonWebToken(subject = "admin-user"),
                    ObjectMapper(),
                    "http://localhost:${server.address.port}",
                )

            val userId =
                service.requireMinecraftPermissionsAdmin(
                    securityIdentity(),
                    StaticAuthorizationHeaders("Bearer forge-admin-token"),
                )

            assertEquals("admin-user", userId)
        } finally {
            server.stop(0)
        }
    }

    private fun forgeAccessServer(
        response: String,
        path: String = "/v1/control-center/access/me",
    ): HttpServer {
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext(path) { exchange ->
            val bytes = response.toByteArray()
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
        return server
    }

    private fun jsonWebToken(subject: String): JsonWebToken =
        Proxy.newProxyInstance(
            JsonWebToken::class.java.classLoader,
            arrayOf(JsonWebToken::class.java),
        ) { _, method, _ ->
            when (method.name) {
                "getSubject" -> subject
                "getName" -> subject
                "getClaim" -> null
                else -> null
            }
        } as JsonWebToken

    private fun securityIdentity(): SecurityIdentity =
        Proxy.newProxyInstance(
            SecurityIdentity::class.java.classLoader,
            arrayOf(SecurityIdentity::class.java),
        ) { _, method, _ ->
            when (method.name) {
                "isAnonymous" -> false
                "getPrincipal" -> Principal { "admin-user" }
                "getRoles" -> emptySet<String>()
                else -> null
            }
        } as SecurityIdentity
}

private class StaticAuthorizationHeaders(
    private val authorization: String,
    private val projectId: String? = null,
) : HttpHeaders {
    private val headers =
        MultivaluedHashMap<String, String>().also {
            it.add(HttpHeaders.AUTHORIZATION, authorization)
            if (projectId != null) {
                it.add("X-Grounds-Project-Id", projectId)
            }
        }

    override fun getRequestHeader(name: String): List<String>? = headers[name]

    override fun getHeaderString(name: String): String? = getRequestHeader(name)?.joinToString(",")

    override fun getRequestHeaders(): MultivaluedMap<String, String> = headers

    override fun getMediaType(): MediaType? = null

    override fun getAcceptableMediaTypes(): List<MediaType> = emptyList()

    override fun getLanguage(): Locale? = null

    override fun getAcceptableLanguages(): List<Locale> = emptyList()

    override fun getDate(): Date? = null

    override fun getLength(): Int = -1

    override fun getCookies(): Map<String, Cookie> = emptyMap()
}
