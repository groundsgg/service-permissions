package gg.grounds.permissions.identity

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.time.Clock
import java.time.Duration
import java.time.Instant
import org.eclipse.microprofile.config.inject.ConfigProperty

fun interface KeycloakAuthorizationProvider {
    fun authorizationHeader(): String
}

@ApplicationScoped
class KeycloakAccessTokenProvider(
    private val client: KeycloakAdminClient,
    private val realm: String,
    private val clientId: String,
    private val clientSecret: String,
    private val clock: Clock,
    private val refreshSkew: Duration,
) : KeycloakAuthorizationProvider {
    @Inject
    constructor(
        client: KeycloakAdminClient,
        @ConfigProperty(name = "permissions.keycloak.realm") realm: String,
        @ConfigProperty(name = "permissions.keycloak.client-id") clientId: String,
        @ConfigProperty(name = "permissions.keycloak.client-secret") clientSecret: String,
    ) : this(
        client = client,
        realm = realm,
        clientId = clientId,
        clientSecret = clientSecret,
        clock = Clock.systemUTC(),
        refreshSkew = DEFAULT_REFRESH_SKEW,
    )

    @Volatile private var cachedToken: CachedToken? = null

    override fun authorizationHeader(): String {
        val now = clock.instant()
        cachedToken
            ?.takeIf { now.isBefore(it.refreshAt) }
            ?.let {
                return it.authorizationHeader
            }

        return synchronized(this) {
            val synchronizedNow = clock.instant()
            cachedToken?.takeIf { synchronizedNow.isBefore(it.refreshAt) }?.authorizationHeader
                ?: requestToken(synchronizedNow).also { cachedToken = it }.authorizationHeader
        }
    }

    private fun requestToken(requestedAt: Instant): CachedToken {
        val response =
            try {
                client.requestToken(
                    realm = realm,
                    grantType = "client_credentials",
                    clientId = clientId,
                    clientSecret = clientSecret,
                )
            } catch (_: Exception) {
                throw KeycloakReadException("Keycloak access token request failed")
            }

        if (response.accessToken.isBlank() || response.expiresIn <= 0) {
            throw KeycloakReadException("Keycloak access token response was invalid")
        }

        val lifetime = Duration.ofSeconds(response.expiresIn)
        val effectiveSkew = if (lifetime > refreshSkew) refreshSkew else lifetime.dividedBy(2)
        return CachedToken(
            authorizationHeader = "Bearer ${response.accessToken}",
            refreshAt = requestedAt.plus(lifetime).minus(effectiveSkew),
        )
    }

    private data class CachedToken(val authorizationHeader: String, val refreshAt: Instant)

    private companion object {
        val DEFAULT_REFRESH_SKEW: Duration = Duration.ofSeconds(30)
    }
}
