package gg.grounds.permissions.auth

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import io.quarkus.security.identity.SecurityIdentity
import jakarta.enterprise.context.ApplicationScoped
import jakarta.json.JsonString
import jakarta.ws.rs.ForbiddenException
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.eclipse.microprofile.jwt.JsonWebToken

@ApplicationScoped
class AdminAuthorizationService(
    private val webUserResolver: WebUserResolver,
    private val jwt: JsonWebToken,
    private val objectMapper: ObjectMapper,
    @param:ConfigProperty(name = "permissions.forge.base-url") private val forgeBaseUrl: String,
    @param:ConfigProperty(
        name = "permissions.auth.trust-forge-project-role",
        defaultValue = "false",
    )
    private val trustForgeProjectRoleHeader: Boolean,
) {
    private val httpClient: HttpClient =
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()

    fun requireMinecraftPermissionsAdmin(identity: SecurityIdentity, headers: HttpHeaders): String {
        val userId = webUserResolver.requireUser(identity)
        if (!hasMinecraftPermissionManagementAccess(identity, headers)) {
            throw ForbiddenException("missing_permission")
        }
        return userId
    }

    private fun hasMinecraftPermissionManagementAccess(
        identity: SecurityIdentity,
        headers: HttpHeaders,
    ): Boolean =
        ADMIN_PERMISSION in identity.roles ||
            JWT_PERMISSION_CLAIMS.any { claimName -> claimContainsPermission(claimName) } ||
            trustedForgeProjectRoleAllowsManagement(headers) ||
            forgeProjectAccessAllowsManagement(headers) ||
            forgeEffectiveAccessContainsPermission(headers)

    private fun trustedForgeProjectRoleAllowsManagement(headers: HttpHeaders): Boolean {
        if (!trustForgeProjectRoleHeader) {
            return false
        }
        val projectId = headerString(headers, PROJECT_ID_HEADER)?.trim()
        if (projectId.isNullOrBlank()) {
            return false
        }
        val role = headerString(headers, PROJECT_ROLE_HEADER)?.trim()
        return role in PROJECT_ADMIN_ROLES
    }

    private fun forgeProjectAccessAllowsManagement(headers: HttpHeaders): Boolean {
        val projectId = headerString(headers, PROJECT_ID_HEADER)?.trim()
        if (projectId.isNullOrBlank()) {
            return false
        }
        val authorization = headerString(headers, HttpHeaders.AUTHORIZATION)?.trim()
        if (authorization.isNullOrBlank()) {
            return false
        }

        val request =
            HttpRequest.newBuilder()
                .uri(
                    URI.create(
                        "${forgeBaseUrl.trimEnd('/')}/v1/projects/${encodePathSegment(projectId)}"
                    )
                )
                .timeout(Duration.ofSeconds(3))
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .GET()
                .build()

        val response =
            try {
                httpClient.send(request, HttpResponse.BodyHandlers.ofString())
            } catch (_: Exception) {
                return false
            }

        if (response.statusCode() == 401 || response.statusCode() == 403) {
            return false
        }
        if (response.statusCode() !in 200..299) {
            return false
        }

        return parseProjectRole(response.body()) in PROJECT_ADMIN_ROLES
    }

    private fun forgeEffectiveAccessContainsPermission(headers: HttpHeaders): Boolean {
        val authorization = headerString(headers, HttpHeaders.AUTHORIZATION)?.trim()
        if (authorization.isNullOrBlank()) {
            return false
        }

        val request =
            HttpRequest.newBuilder()
                .uri(URI.create("${forgeBaseUrl.trimEnd('/')}/v1/control-center/access/me"))
                .timeout(Duration.ofSeconds(3))
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .GET()
                .build()

        val response =
            try {
                httpClient.send(request, HttpResponse.BodyHandlers.ofString())
            } catch (_: Exception) {
                return false
            }

        if (response.statusCode() == 401 || response.statusCode() == 403) {
            return false
        }
        if (response.statusCode() !in 200..299) {
            return false
        }

        return parsePermissions(response.body()).contains(ADMIN_PERMISSION)
    }

    private fun parsePermissions(body: String): Set<String> {
        val root =
            try {
                objectMapper.readTree(body)
            } catch (_: Exception) {
                return emptySet()
            }
        val permissions = root.get("permissions")
        if (permissions == null || !permissions.isArray) {
            return emptySet()
        }
        return permissions.mapNotNull(JsonNode::asText).toSet()
    }

    private fun parseProjectRole(body: String): String? {
        val root =
            try {
                objectMapper.readTree(body)
            } catch (_: Exception) {
                return null
            }
        return root.get("role")?.asText()
    }

    private fun claimContainsPermission(claimName: String): Boolean =
        when (val claim = jwtClaim(claimName)) {
            is String -> claim == ADMIN_PERMISSION
            is Iterable<*> -> claim.any { permissionValue(it) == ADMIN_PERMISSION }
            is Array<*> -> claim.any { permissionValue(it) == ADMIN_PERMISSION }
            else -> false
        }

    private fun permissionValue(value: Any?): String? =
        when (value) {
            is JsonString -> value.string
            else -> value?.toString()
        }

    private fun jwtClaim(claimName: String): Any? =
        try {
            jwt.getClaim<Any>(claimName)
        } catch (_: IllegalStateException) {
            null
        }

    private fun headerString(headers: HttpHeaders, name: String): String? {
        headers.getHeaderString(name)?.let {
            return it
        }
        return headers.requestHeaders.entries
            .firstOrNull { (headerName, _) -> headerName.equals(name, ignoreCase = true) }
            ?.value
            ?.joinToString(",")
    }

    private fun encodePathSegment(value: String): String =
        URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

    private companion object {
        private const val ADMIN_PERMISSION = "MINECRAFT_PERMISSIONS_MANAGE"
        private const val PROJECT_ID_HEADER = "X-Grounds-Project-Id"
        private const val PROJECT_ROLE_HEADER = "X-Grounds-Project-Role"
        private val PROJECT_ADMIN_ROLES = setOf("owner", "editor")
        private val JWT_PERMISSION_CLAIMS = listOf("permissions", "platform_permissions", "groups")
    }
}
