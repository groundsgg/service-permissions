package gg.grounds.permissions.identity

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.time.Clock
import java.util.Locale
import java.util.UUID
import org.eclipse.microprofile.config.inject.ConfigProperty

interface PlayerIdentitySource {
    fun loadAll(): List<ProjectedPlayerIdentity>

    fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity?
}

@ApplicationScoped
class PlayerIdentitySynchronizer(
    private val client: KeycloakAdminClient,
    private val authorizationProvider: KeycloakAuthorizationProvider,
    private val realm: String,
    private val pageSize: Int,
    private val clock: Clock,
) : PlayerIdentitySource {
    @Inject
    constructor(
        client: KeycloakAdminClient,
        authorizationProvider: KeycloakAccessTokenProvider,
        @ConfigProperty(name = "permissions.keycloak.realm") realm: String,
        @ConfigProperty(name = "permissions.identity-sync.page-size") pageSize: Int,
    ) : this(client, authorizationProvider, realm, pageSize, Clock.systemUTC())

    init {
        require(pageSize > 0) { "Identity sync page size must be positive" }
    }

    override fun loadAll(): List<ProjectedPlayerIdentity> {
        val authorization = authorizationProvider.authorizationHeader()
        var first = 0
        val identities = mutableListOf<ProjectedPlayerIdentity>()
        do {
            val users = readUsers(authorization, first)
            users.mapNotNullTo(identities) { user -> project(user, authorization) }
            first += users.size
        } while (users.size == pageSize)
        return identities
    }

    override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity? {
        val authorization = authorizationProvider.authorizationHeader()
        val user = readUser(authorization, keycloakUserId) ?: return null
        return project(user, authorization)
    }

    private fun project(
        user: KeycloakUserRepresentation,
        authorization: String,
    ): ProjectedPlayerIdentity? {
        val playerId =
            user.attributes[MINECRAFT_UUID_ATTRIBUTE]
                ?.firstOrNull()
                ?.takeIf(String::isNotBlank)
                ?.let { rawUuid -> runCatching { UUID.fromString(rawUuid) }.getOrNull() }
                ?: return null
        val username =
            user.attributes[MINECRAFT_USERNAME_ATTRIBUTE]
                ?.firstOrNull()
                ?.trim()
                ?.takeIf(String::isNotBlank) ?: return null
        val groups = readAllGroups(authorization, user.id)
        return ProjectedPlayerIdentity(
            playerId = playerId,
            keycloakUserId = user.id,
            minecraftUsername = username,
            normalizedUsername = username.lowercase(Locale.ROOT),
            groupPaths = groups,
            syncedAt = clock.instant(),
            sourceUpdatedAt = null,
        )
    }

    private fun readUsers(authorization: String, first: Int): List<KeycloakUserRepresentation> =
        sanitizedRead("Keycloak user query failed") {
            client.listUsers(authorization, realm, first, pageSize)
        }

    private fun readUser(
        authorization: String,
        keycloakUserId: String,
    ): KeycloakUserRepresentation? =
        try {
            client.getUser(authorization, realm, keycloakUserId)
        } catch (error: KeycloakAdminException) {
            if (error.statusCode == 404) null
            else throw KeycloakReadException("Keycloak user read failed")
        } catch (_: Exception) {
            throw KeycloakReadException("Keycloak user read failed")
        }

    private fun readAllGroups(authorization: String, keycloakUserId: String): Set<String> {
        var first = 0
        val paths = linkedSetOf<String>()
        do {
            val groups =
                sanitizedRead("Keycloak group query failed") {
                    client.listUserGroups(authorization, realm, keycloakUserId, first, pageSize)
                }
            groups.mapTo(paths) { it.path }.removeIf(String::isBlank)
            first += groups.size
        } while (groups.size == pageSize)
        return paths
    }

    private fun <T> sanitizedRead(message: String, operation: () -> T): T =
        try {
            operation()
        } catch (_: Exception) {
            throw KeycloakReadException(message)
        }

    companion object {
        const val MINECRAFT_UUID_ATTRIBUTE = "minecraft_java_uuid"
        const val MINECRAFT_USERNAME_ATTRIBUTE = "minecraft_java_username"
    }
}
