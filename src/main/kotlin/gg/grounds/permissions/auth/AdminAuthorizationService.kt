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
import java.util.Optional
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
    @ConfigProperty(name = "permissions.instance-environment", defaultValue = " ")
    instanceEnvironmentConfig: Optional<String>,
) {
    private val instanceEnvironment =
        PermissionInstanceEnvironment.fromConfig(instanceEnvironmentConfig.orElse(null))
    private val httpClient: HttpClient =
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()

    fun requireMinecraftPermissionsView(identity: SecurityIdentity, headers: HttpHeaders): String =
        requireMinecraftPermissions(
            identity,
            headers,
            PermissionAccess.VIEW,
            allowForgeProjectRole = false,
        )

    fun requireMinecraftPermissionsManage(
        identity: SecurityIdentity,
        headers: HttpHeaders,
    ): String =
        requireMinecraftPermissions(
            identity,
            headers,
            PermissionAccess.MANAGE,
            allowForgeProjectRole = false,
        )

    fun requireMinecraftPermissionsSnapshotRead(
        identity: SecurityIdentity,
        headers: HttpHeaders,
    ): String =
        requireMinecraftPermissions(
            identity,
            headers,
            PermissionAccess.VIEW,
            allowForgeProjectRole = true,
        )

    private fun requireMinecraftPermissions(
        identity: SecurityIdentity,
        headers: HttpHeaders,
        access: PermissionAccess,
        allowForgeProjectRole: Boolean,
    ): String {
        val userId = webUserResolver.requireUser(identity)
        val projectMode = instanceEnvironment == null
        val resolution =
            resolveAccess(
                identity = identity,
                headers = headers,
                access = access,
                allowForgeProjectRole = allowForgeProjectRole || projectMode,
                allowTrustedProjectRole = projectMode,
            )

        if (hasAccess(resolution.permissions, access)) {
            return userId
        }
        if (projectRoleAllowsAccess(resolution.trustedProjectRole, access, projectMode)) {
            return userId
        }
        if (projectRoleAllowsAccess(resolution.forgeProjectRole, access, projectMode)) {
            return userId
        }
        throw ForbiddenException("missing_permission")
    }

    private fun resolveAccess(
        identity: SecurityIdentity,
        headers: HttpHeaders,
        access: PermissionAccess,
        allowForgeProjectRole: Boolean,
        allowTrustedProjectRole: Boolean,
    ): AccessResolution {
        val projectId = headerString(headers, PROJECT_ID_HEADER)?.trim()?.takeIf(String::isNotBlank)
        val permissions =
            linkedSetOf<String>().apply {
                addAll(identity.roles)
                JWT_PERMISSION_CLAIMS.forEach { claimName -> addAll(claimPermissions(claimName)) }
            }
        val trustedProjectRole =
            if (allowTrustedProjectRole) trustedForgeProjectRole(headers, projectId) else null

        if (
            !hasAccess(permissions, access) &&
                !projectRoleAllowsAccess(trustedProjectRole, access, projectMode = true)
        ) {
            permissions += forgeEffectiveAccessPermissions(headers)
        }

        val forgeProjectRole =
            if (
                !hasAccess(permissions, access) &&
                    !projectRoleAllowsAccess(trustedProjectRole, access, projectMode = true) &&
                    allowForgeProjectRole
            ) {
                forgeProjectRole(headers, projectId)
            } else {
                null
            }

        return AccessResolution(permissions, trustedProjectRole, forgeProjectRole)
    }

    private fun projectRoleAllowsAccess(
        role: String?,
        access: PermissionAccess,
        projectMode: Boolean,
    ): Boolean =
        role in PROJECT_ADMIN_ROLES ||
            (projectMode && access == PermissionAccess.VIEW && role == PROJECT_VIEWER_ROLE)

    private fun hasAccess(permissions: Set<String>, access: PermissionAccess): Boolean =
        when (instanceEnvironment) {
            null -> LEGACY_MANAGE_PERMISSION in permissions
            PermissionInstanceEnvironment.STAGE ->
                GAME_AREA_ACCESS_PERMISSION in permissions &&
                    when (access) {
                        PermissionAccess.VIEW ->
                            STAGE_VIEW_PERMISSION in permissions ||
                                STAGE_MANAGE_PERMISSION in permissions
                        PermissionAccess.MANAGE -> STAGE_MANAGE_PERMISSION in permissions
                    }
            PermissionInstanceEnvironment.PRODUCTION ->
                GAME_AREA_ACCESS_PERMISSION in permissions &&
                    when (access) {
                        PermissionAccess.VIEW ->
                            PRODUCTION_VIEW_PERMISSION in permissions ||
                                PRODUCTION_MANAGE_PERMISSION in permissions
                        PermissionAccess.MANAGE -> PRODUCTION_MANAGE_PERMISSION in permissions
                    }
        }

    private fun trustedForgeProjectRole(headers: HttpHeaders, projectId: String?): String? {
        if (!trustForgeProjectRoleHeader || projectId == null) {
            return null
        }
        return headerString(headers, PROJECT_ROLE_HEADER)?.trim()
    }

    private fun forgeProjectRole(headers: HttpHeaders, projectId: String?): String? {
        if (projectId == null) {
            return null
        }
        val authorization = headerString(headers, HttpHeaders.AUTHORIZATION)?.trim()
        if (authorization.isNullOrBlank()) {
            return null
        }

        val response =
            sendForgeRequest(
                "${forgeBaseUrl.trimEnd('/')}/v1/projects/${encodePathSegment(projectId)}",
                authorization,
            ) ?: return null
        return parseProjectRole(response)
    }

    private fun forgeEffectiveAccessPermissions(headers: HttpHeaders): Set<String> {
        val authorization = headerString(headers, HttpHeaders.AUTHORIZATION)?.trim()
        if (authorization.isNullOrBlank()) {
            return emptySet()
        }

        val response =
            sendForgeRequest(
                "${forgeBaseUrl.trimEnd('/')}/v1/control-center/access/me",
                authorization,
            ) ?: return emptySet()
        return parsePermissions(response)
    }

    private fun sendForgeRequest(url: String, authorization: String): String? {
        val request =
            HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(3))
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .GET()
                .build()

        val response =
            try {
                httpClient.send(request, HttpResponse.BodyHandlers.ofString())
            } catch (_: Exception) {
                return null
            }

        return response.body().takeIf { response.statusCode() in 200..299 }
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

    private fun claimPermissions(claimName: String): Set<String> =
        when (val claim = jwtClaim(claimName)) {
            is String -> setOf(claim)
            is Iterable<*> -> claim.mapNotNull(::permissionValue).toSet()
            is Array<*> -> claim.mapNotNull(::permissionValue).toSet()
            else -> emptySet()
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

    private data class AccessResolution(
        val permissions: Set<String>,
        val trustedProjectRole: String?,
        val forgeProjectRole: String?,
    )

    private enum class PermissionAccess {
        VIEW,
        MANAGE,
    }

    private companion object {
        private const val GAME_AREA_ACCESS_PERMISSION = "GAME_AREA_ACCESS"
        private const val LEGACY_MANAGE_PERMISSION = "MINECRAFT_PERMISSIONS_MANAGE"
        private const val STAGE_VIEW_PERMISSION = "MINECRAFT_PERMISSIONS_STAGE_VIEW"
        private const val STAGE_MANAGE_PERMISSION = "MINECRAFT_PERMISSIONS_STAGE_MANAGE"
        private const val PRODUCTION_VIEW_PERMISSION = "MINECRAFT_PERMISSIONS_PRODUCTION_VIEW"
        private const val PRODUCTION_MANAGE_PERMISSION = "MINECRAFT_PERMISSIONS_PRODUCTION_MANAGE"
        private const val PROJECT_ID_HEADER = "X-Grounds-Project-Id"
        private const val PROJECT_ROLE_HEADER = "X-Grounds-Project-Role"
        private const val PROJECT_VIEWER_ROLE = "viewer"
        private val PROJECT_ADMIN_ROLES = setOf("owner", "editor")
        private val JWT_PERMISSION_CLAIMS = listOf("permissions", "platform_permissions", "groups")
    }
}
