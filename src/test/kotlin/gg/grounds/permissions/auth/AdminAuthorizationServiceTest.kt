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
import java.util.Optional
import org.eclipse.microprofile.jwt.JsonWebToken
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable

class AdminAuthorizationServiceTest {
    @Test
    fun appliesStageAuthorizationMatrixToDirectJwtClaims() {
        val service = service(environment = "stage", jwtPermissions = setOf(AREA, STAGE_VIEW))

        assertEquals(
            "direct-user",
            service.requireMinecraftPermissionsView(securityIdentity(), headers()),
        )
        assertThrows(ForbiddenException::class.java) {
            service.requireMinecraftPermissionsManage(securityIdentity(), headers())
        }

        val stageManager =
            service(environment = "stage", jwtPermissions = setOf(AREA, STAGE_MANAGE))
        assertEquals(
            "direct-user",
            stageManager.requireMinecraftPermissionsView(securityIdentity(), headers()),
        )
        assertEquals(
            "direct-user",
            stageManager.requireMinecraftPermissionsManage(securityIdentity(), headers()),
        )

        val withoutArea = service(environment = "stage", jwtPermissions = setOf(STAGE_VIEW))
        assertThrows(ForbiddenException::class.java) {
            withoutArea.requireMinecraftPermissionsView(securityIdentity(), headers())
        }
    }

    @Test
    fun rejectsStagePermissionsInProductionForDirectJwtClaims() {
        val service = service(environment = "prod", jwtPermissions = setOf(AREA, STAGE_MANAGE))

        assertThrows(ForbiddenException::class.java) {
            service.requireMinecraftPermissionsView(securityIdentity(), headers())
        }
        assertThrows(ForbiddenException::class.java) {
            service.requireMinecraftPermissionsManage(securityIdentity(), headers())
        }
    }

    @Test
    fun appliesStageAuthorizationMatrixToForgeEffectiveAccess() {
        assertForgeViewAndManageAccess(
            permissions = setOf(AREA, STAGE_MANAGE),
            expectedView = true,
            expectedManage = true,
        )
        assertForgeViewAndManageAccess(
            permissions = setOf(AREA, STAGE_VIEW),
            expectedView = true,
            expectedManage = false,
        )
        assertForgeViewAndManageAccess(
            permissions = setOf(STAGE_VIEW),
            expectedView = false,
            expectedManage = false,
        )
    }

    @Test
    fun rejectsStagePermissionsInProductionForForgeEffectiveAccess() {
        assertForgeViewAndManageAccess(
            permissions = setOf(AREA, STAGE_MANAGE),
            environment = "prod",
            expectedView = false,
            expectedManage = false,
        )
    }

    @Test
    fun acceptsLegacyManagePermissionOnlyInProjectModeForDirectJwtClaims() {
        val projectMode = service(jwtPermissions = setOf(LEGACY_MANAGE))
        assertEquals(
            "direct-user",
            projectMode.requireMinecraftPermissionsManage(securityIdentity(), headers()),
        )

        val sharedMode = service(environment = "stage", jwtPermissions = setOf(LEGACY_MANAGE))
        assertThrows(ForbiddenException::class.java) {
            sharedMode.requireMinecraftPermissionsManage(securityIdentity(), headers())
        }
    }

    @Test
    fun acceptsLegacyManagePermissionOnlyInProjectModeForForgeEffectiveAccess() {
        assertForgeViewAndManageAccess(
            permissions = setOf(LEGACY_MANAGE),
            environment = "",
            expectedView = true,
            expectedManage = true,
        )
        assertForgeViewAndManageAccess(
            permissions = setOf(LEGACY_MANAGE),
            environment = "stage",
            expectedView = false,
            expectedManage = false,
        )
    }

    @Test
    fun acceptsForgeProjectOwnersAndEditorsInProjectMode() {
        listOf("owner", "editor").forEachIndexed { index, role ->
            val server = forgeServer(projectRole = role)
            try {
                val service = service(forgeBaseUrl = server.baseUrl)

                assertEquals(
                    "direct-user",
                    service.requireMinecraftPermissionsManage(
                        securityIdentity(),
                        headers(
                            projectId = "project-a",
                            projectHeaderName =
                                if (index == 0) "x-grounds-project-id" else PROJECT_ID_HEADER,
                        ),
                    ),
                )
            } finally {
                server.stop()
            }
        }
    }

    @Test
    fun allowsForgeProjectViewersToReadButNotManageInProjectMode() {
        val server = forgeServer(projectRole = "viewer")
        try {
            val service = service(forgeBaseUrl = server.baseUrl)

            assertEquals(
                "direct-user",
                service.requireMinecraftPermissionsView(
                    securityIdentity(),
                    headers(projectId = "project-a"),
                ),
            )
            assertThrows(ForbiddenException::class.java) {
                service.requireMinecraftPermissionsManage(
                    securityIdentity(),
                    headers(projectId = "project-a"),
                )
            }
        } finally {
            server.stop()
        }
    }

    @Test
    fun allowsTrustedForgeProjectViewerHeaderToReadButNotManageInProjectMode() {
        val service = service(trustForgeProjectRoleHeader = true)
        val requestHeaders = headers(projectId = "project-a", projectRole = "viewer")

        assertEquals(
            "direct-user",
            service.requireMinecraftPermissionsView(securityIdentity(), requestHeaders),
        )
        assertThrows(ForbiddenException::class.java) {
            service.requireMinecraftPermissionsManage(securityIdentity(), requestHeaders)
        }
    }

    @Test
    fun acceptsTrustedForgeProjectEditorHeaderInProjectMode() {
        val service = service(trustForgeProjectRoleHeader = true)

        assertEquals(
            "direct-user",
            service.requireMinecraftPermissionsManage(
                securityIdentity(),
                headers(projectId = "project-a", projectRole = "editor"),
            ),
        )
    }

    @Test
    fun permitsForgeValidatedProjectRoleOnlyForSnapshotReadInSharedMode() {
        val server = forgeServer(projectRole = "owner")
        try {
            val service = service(environment = "stage", forgeBaseUrl = server.baseUrl)
            val requestHeaders = headers(projectId = "project-a")

            assertThrows(ForbiddenException::class.java) {
                service.requireMinecraftPermissionsView(securityIdentity(), requestHeaders)
            }
            assertEquals(
                "direct-user",
                service.requireMinecraftPermissionsSnapshotRead(securityIdentity(), requestHeaders),
            )
        } finally {
            server.stop()
        }
    }

    private fun assertForgeViewAndManageAccess(
        permissions: Set<String>,
        environment: String = "stage",
        expectedView: Boolean,
        expectedManage: Boolean,
    ) {
        val server = forgeServer(permissions = permissions)
        try {
            val service = service(environment = environment, forgeBaseUrl = server.baseUrl)
            val requestHeaders = headers()

            assertAccess(expectedView) {
                service.requireMinecraftPermissionsView(securityIdentity(), requestHeaders)
            }
            assertAccess(expectedManage) {
                service.requireMinecraftPermissionsManage(securityIdentity(), requestHeaders)
            }
        } finally {
            server.stop()
        }
    }

    private fun assertAccess(expected: Boolean, access: () -> String) {
        if (expected) {
            assertEquals("direct-user", access())
        } else {
            assertThrows(ForbiddenException::class.java, Executable { access() })
        }
    }

    private fun service(
        environment: String = "",
        jwtPermissions: Set<String> = emptySet(),
        forgeBaseUrl: String = "http://localhost:1",
        trustForgeProjectRoleHeader: Boolean = false,
    ): AdminAuthorizationService =
        AdminAuthorizationService(
            WebUserResolver(jsonWebToken(subject = "direct-user"), false),
            jsonWebToken(subject = "direct-user", permissions = jwtPermissions),
            ObjectMapper(),
            forgeBaseUrl,
            trustForgeProjectRoleHeader,
            Optional.of(environment),
        )

    private fun forgeServer(
        permissions: Set<String> = emptySet(),
        projectRole: String? = null,
    ): ForgeServer {
        val server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/v1/control-center/access/me") { exchange ->
            exchange.respondJson("""{"permissions":${permissions.toJsonArray()}}""")
        }
        server.createContext("/v1/projects/project-a") { exchange ->
            exchange.respondJson("""{"id":"project-a","role":"$projectRole"}""")
        }
        server.start()
        return ForgeServer(server)
    }

    private fun Set<String>.toJsonArray(): String =
        joinToString("\",\"", prefix = "[\"", postfix = "\"]")

    private fun jsonWebToken(subject: String, permissions: Set<String> = emptySet()): JsonWebToken =
        Proxy.newProxyInstance(
            JsonWebToken::class.java.classLoader,
            arrayOf(JsonWebToken::class.java),
        ) { _, method, arguments ->
            when (method.name) {
                "getSubject" -> subject
                "getName" -> subject
                "getClaim" -> if (arguments?.singleOrNull() == "permissions") permissions else null
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
                "getPrincipal" -> Principal { "direct-user" }
                "getRoles" -> emptySet<String>()
                else -> null
            }
        } as SecurityIdentity

    private fun headers(
        projectId: String? = null,
        projectHeaderName: String = PROJECT_ID_HEADER,
        projectRole: String? = null,
    ): StaticAuthorizationHeaders =
        StaticAuthorizationHeaders(
            authorization = "Bearer authorization-token",
            projectId = projectId,
            projectHeaderName = projectHeaderName,
            projectRole = projectRole,
        )

    private class ForgeServer(private val server: HttpServer) {
        val baseUrl = "http://localhost:${server.address.port}"

        fun stop() {
            server.stop(0)
        }
    }

    private companion object {
        private const val AREA = "GAME_AREA_ACCESS"
        private const val STAGE_VIEW = "MINECRAFT_PERMISSIONS_STAGE_VIEW"
        private const val STAGE_MANAGE = "MINECRAFT_PERMISSIONS_STAGE_MANAGE"
        private const val LEGACY_MANAGE = "MINECRAFT_PERMISSIONS_MANAGE"
        private const val PROJECT_ID_HEADER = "X-Grounds-Project-Id"
    }
}

private fun com.sun.net.httpserver.HttpExchange.respondJson(body: String) {
    val bytes = body.toByteArray()
    responseHeaders.add("Content-Type", "application/json")
    sendResponseHeaders(200, bytes.size.toLong())
    responseBody.use { it.write(bytes) }
}

private class StaticAuthorizationHeaders(
    private val authorization: String,
    private val projectId: String? = null,
    private val projectHeaderName: String = "X-Grounds-Project-Id",
    private val projectRole: String? = null,
) : HttpHeaders {
    private val headers =
        MultivaluedHashMap<String, String>().also {
            it.add(HttpHeaders.AUTHORIZATION, authorization)
            if (projectId != null) {
                it.add(projectHeaderName, projectId)
            }
            if (projectRole != null) {
                it.add("X-Grounds-Project-Role", projectRole)
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
