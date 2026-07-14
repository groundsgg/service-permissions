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

        val localPage = identityRepository.search(normalizedQuery, page, perPage)
        val localItems = localPage.items.map { item -> item.toResponse() }
        val externalItem = externalFallback(normalizedQuery, page, localPage.total)
        return PlayerSearchResponse(
            items = externalItem?.let(::listOf) ?: localItems,
            page = page,
            perPage = perPage,
            total = externalItem?.let { 1L } ?: localPage.total,
        )
    }

    private fun externalFallback(
        query: String,
        page: Int,
        localTotal: Long,
    ): PlayerSearchItemResponse? {
        if (page != 1 || localTotal != 0L || !MINECRAFT_USERNAME.matches(query)) {
            return null
        }
        if (identityRepository.findByNormalizedUsername(query.lowercase(Locale.ROOT)) != null) {
            return null
        }
        return when (val result = mojangProfileClient.lookupExactUsername(query)) {
            is MojangLookupResult.Found ->
                PlayerSearchItemResponse(
                    playerId = result.profile.playerId,
                    name = result.profile.name,
                    linked = false,
                    directRoleGrantCount = 0,
                    directPermissionGrantCount = 0,
                )
            MojangLookupResult.NotFound,
            MojangLookupResult.Unavailable -> null
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
