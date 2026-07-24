package gg.grounds.permissions.rest

import gg.grounds.permissions.auth.AdminAuthorizationService
import gg.grounds.permissions.identity.MojangLookupResult
import gg.grounds.permissions.identity.MojangProfileClient
import gg.grounds.permissions.identity.PlayerSearchItem
import gg.grounds.permissions.identity.isValidMinecraftUsername
import gg.grounds.permissions.persistence.PlayerIdentityRepository
import io.quarkus.security.Authenticated
import io.quarkus.security.identity.SecurityIdentity
import jakarta.inject.Inject
import jakarta.ws.rs.DefaultValue
import jakarta.ws.rs.GET
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.ServiceUnavailableException
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import java.util.Locale
import java.util.UUID

@Path("/v1/permissions/players")
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
    @Path("search")
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
        return PlayerSearchResponse(
            items = localPage.items.map { item -> item.toResponse() },
            page = page,
            perPage = perPage,
            total = localPage.total,
        )
    }

    @GET
    @Path("external-search")
    fun externalSearch(
        @QueryParam("query") query: String?,
        @Context headers: HttpHeaders,
    ): PlayerSearchItemResponse {
        authorization.requireMinecraftPermissionsAdmin(identity, headers)
        val normalizedQuery = query?.trim().orEmpty()
        require(isValidMinecraftUsername(normalizedQuery)) {
            "query must be a valid Minecraft username"
        }
        if (
            identityRepository.findByNormalizedUsername(normalizedQuery.lowercase(Locale.ROOT)) !=
                null
        ) {
            throw NotFoundException("player_already_known")
        }

        return when (val result = mojangProfileClient.lookupExactUsername(normalizedQuery)) {
            is MojangLookupResult.Found -> {
                if (identityRepository.findByPlayerId(result.profile.playerId) != null) {
                    throw NotFoundException("player_already_known")
                }
                PlayerSearchItemResponse(
                    playerId = result.profile.playerId,
                    name = result.profile.name,
                    linked = false,
                    directRoleGrantCount = 0,
                    directPermissionGrantCount = 0,
                    effectiveRoleCount = 0,
                    effectivePermissionGrantCount = 0,
                )
            }
            MojangLookupResult.NotFound -> throw NotFoundException("player_not_found")
            MojangLookupResult.Unavailable ->
                throw ServiceUnavailableException("external_player_lookup_unavailable")
        }
    }

    private fun PlayerSearchItem.toResponse() =
        PlayerSearchItemResponse(
            playerId = playerId,
            name = minecraftUsername,
            linked = true,
            directRoleGrantCount = directRoleGrantCount,
            directPermissionGrantCount = directPermissionGrantCount,
            effectiveRoleCount = effectiveRoleCount,
            effectivePermissionGrantCount = effectivePermissionGrantCount,
        )

    private fun String.isCompleteUuid(): Boolean = runCatching { UUID.fromString(this) }.isSuccess

    private companion object {
        const val MINIMUM_QUERY_LENGTH = 2
        const val MAXIMUM_PAGE_SIZE = 100
    }
}
