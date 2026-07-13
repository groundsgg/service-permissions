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
        var first = 0
        val identities = mutableListOf<ProjectedPlayerIdentity>()
        do {
            val users = readUsers(first)
            users.mapNotNullTo(identities, ::project)
            first += users.size
        } while (users.size == pageSize)
        return identities
    }

    override fun loadPlayer(keycloakUserId: String): ProjectedPlayerIdentity? {
        val user = readUser(keycloakUserId) ?: return null
        return project(user)
    }

    private fun project(user: KeycloakUserRepresentation): ProjectedPlayerIdentity? {
        val playerId =
            user.attributes[MINECRAFT_UUID_ATTRIBUTE]
                ?.firstOrNull()
                ?.takeIf(String::isNotBlank)
                ?.let(::parseCanonicalUuid) ?: return null
        val username =
            user.attributes[MINECRAFT_USERNAME_ATTRIBUTE]
                ?.firstOrNull()
                ?.trim()
                ?.takeIf(String::isNotBlank) ?: return null
        val groups = readAllGroups(user.id) ?: return null
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

    private fun parseCanonicalUuid(rawUuid: String): UUID? {
        val trimmedUuid = rawUuid.trim()
        val parsedUuid = runCatching { UUID.fromString(trimmedUuid) }.getOrNull() ?: return null
        return parsedUuid.takeIf { it.toString().equals(trimmedUuid, ignoreCase = true) }
    }

    private fun readUsers(first: Int): List<KeycloakUserRepresentation> =
        authorizedRead("Keycloak user query failed") { authorization ->
            client.listUsers(authorization, realm, first, pageSize)
        }!!

    private fun readUser(keycloakUserId: String): KeycloakUserRepresentation? =
        authorizedRead("Keycloak user read failed", missingOnNotFound = true) { authorization ->
            client.getUser(authorization, realm, keycloakUserId)
        }

    private fun readAllGroups(keycloakUserId: String): Set<String>? {
        var first = 0
        val paths = linkedSetOf<String>()
        do {
            val groups =
                authorizedRead("Keycloak group query failed", missingOnNotFound = true) {
                    authorization ->
                    client.listUserGroups(authorization, realm, keycloakUserId, first, pageSize)
                } ?: return null
            groups.mapTo(paths) { it.path }.removeIf(String::isBlank)
            first += groups.size
        } while (groups.size == pageSize)
        return paths
    }

    private fun <T> authorizedRead(
        message: String,
        missingOnNotFound: Boolean = false,
        retryUnauthorized: Boolean = true,
        operation: (String) -> T,
    ): T? {
        val authorization = authorizationProvider.authorizationHeader()
        return try {
            operation(authorization)
        } catch (error: KeycloakAdminException) {
            when {
                missingOnNotFound && error.statusCode == 404 -> null
                retryUnauthorized && error.statusCode == 401 -> {
                    authorizationProvider.invalidate(authorization)
                    authorizedRead(
                        message = message,
                        missingOnNotFound = missingOnNotFound,
                        retryUnauthorized = false,
                        operation = operation,
                    )
                }
                else -> throw KeycloakReadException(message)
            }
        } catch (_: Exception) {
            throw KeycloakReadException(message)
        }
    }

    companion object {
        const val MINECRAFT_UUID_ATTRIBUTE = "minecraft_java_uuid"
        const val MINECRAFT_USERNAME_ATTRIBUTE = "minecraft_java_username"
    }
}
