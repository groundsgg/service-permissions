package gg.grounds.permissions.rest

import gg.grounds.permissions.auth.AdminAuthorizationService
import gg.grounds.permissions.identity.MojangLookupResult
import gg.grounds.permissions.identity.MojangProfileClient
import gg.grounds.permissions.identity.PlayerSearchItem
import gg.grounds.permissions.persistence.PlayerIdentityRepository
import io.quarkus.security.Authenticated
import io.quarkus.security.identity.SecurityIdentity
import jakarta.inject.Inject
import jakarta.ws.rs.DefaultValue
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import java.util.Locale
import java.util.UUID

@Path("/v1/permissions/players/search")
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
class PermissionPlayerSearchResource
@Inject
constructor(
    private val identityRepository: PlayerIdentityRepository,
    private val mojangProfileClient: MojangProfileClient,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {
    @GET
    fun search(
        @QueryParam("query") query: String?,
        @QueryParam("page") @DefaultValue("1") page: Int,
        @QueryParam("perPage") @DefaultValue("20") perPage: Int,
        @Context headers: HttpHeaders,
    ): PlayerSearchResponse {
        authorization.requireMinecraftPermissionsAdmin(identity, headers)
        val normalizedQuery = query?.trim().orEmpty()
        require(
            normalizedQuery.length >= MINIMUM_QUERY_LENGTH || normalizedQuery.isCompleteUuid()
        ) {
            "query must contain at least 2 characters"
        }
        require(page >= 1) { "page must be at least 1" }
        require(perPage in 1..MAXIMUM_PAGE_SIZE) { "perPage must be between 1 and 100" }

        val externalItem = externalFallback(normalizedQuery)
        val externalCount = if (externalItem == null) 0 else 1
        val combinedOffset = (page - 1L) * perPage
        val localOffset = (combinedOffset - externalCount).coerceAtLeast(0)
        val localLimit = perPage - if (externalItem != null && combinedOffset == 0L) 1 else 0
        val localPage = identityRepository.searchAtOffset(normalizedQuery, localOffset, localLimit)
        val items = buildList {
            if (externalItem != null && combinedOffset == 0L) {
                add(externalItem)
            }
            addAll(localPage.items.map { item -> item.toResponse() })
        }
        return PlayerSearchResponse(
            items = items,
            page = page,
            perPage = perPage,
            total = localPage.total + externalCount,
        )
    }

    private fun externalFallback(query: String): PlayerSearchItemResponse? {
        if (!MINECRAFT_USERNAME.matches(query)) {
            return null
        }
        if (identityRepository.findByNormalizedUsername(query.lowercase(Locale.ROOT)) != null) {
            return null
        }
        val lookupResult: MojangLookupResult? = mojangProfileClient.lookupExactUsername(query)
        return when (val result = lookupResult) {
            is MojangLookupResult.Found ->
                if (identityRepository.findByPlayerId(result.profile.playerId) == null) {
                    PlayerSearchItemResponse(
                        playerId = result.profile.playerId,
                        name = result.profile.name,
                        linked = false,
                        directRoleGrantCount = 0,
                        directPermissionGrantCount = 0,
                    )
                } else {
                    null
                }
            MojangLookupResult.NotFound,
            MojangLookupResult.Unavailable,
            null -> null
        }
    }

    private fun PlayerSearchItem.toResponse() =
        PlayerSearchItemResponse(
            playerId = playerId,
            name = minecraftUsername,
            linked = true,
            directRoleGrantCount = directRoleGrantCount,
            directPermissionGrantCount = directPermissionGrantCount,
        )

    private fun String.isCompleteUuid(): Boolean = runCatching { UUID.fromString(this) }.isSuccess

    private companion object {
        const val MINIMUM_QUERY_LENGTH = 2
        const val MAXIMUM_PAGE_SIZE = 100
        val MINECRAFT_USERNAME = Regex("^[A-Za-z0-9_]{3,16}$")
    }
}
