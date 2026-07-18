package gg.grounds.permissions.rest

import com.fasterxml.jackson.databind.JsonNode
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionGrantOriginKind
import gg.grounds.permissions.domain.PermissionScopeKind
import java.time.Instant
import java.util.UUID

data class ErrorResponse(val error: String)

data class PagedResponse<T>(val items: List<T>, val page: Int, val perPage: Int, val total: Long)

data class PermissionSearchParameters(
    val query: String,
    val page: Int,
    val perPage: Int,
    val sortBy: String,
    val sortDirection: String,
)

object PermissionSearchPaging {
    fun validate(
        query: String?,
        page: Int,
        perPage: Int,
        sortBy: String?,
        sortDirection: String?,
        defaultSortBy: String,
        allowedSortKeys: List<String>,
    ): PermissionSearchParameters {
        require(page >= 1) { "page must be at least 1" }
        require(perPage in 1..MAXIMUM_PAGE_SIZE) { "perPage must be between 1 and 100" }

        val resolvedSortBy =
            sortBy?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: defaultSortBy
        require(resolvedSortBy in allowedSortKeys) {
            "sortBy must be one of: ${allowedSortKeys.joinToString()}"
        }
        val resolvedDirection =
            sortDirection?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: DEFAULT_SORT_DIRECTION
        require(resolvedDirection in SORT_DIRECTIONS) {
            "sortDirection must be one of: ${SORT_DIRECTIONS.joinToString()}"
        }

        return PermissionSearchParameters(
            query = query?.trim()?.replace(WHITESPACE, " ").orEmpty(),
            page = page,
            perPage = perPage,
            sortBy = resolvedSortBy,
            sortDirection = resolvedDirection,
        )
    }

    private const val MAXIMUM_PAGE_SIZE = 100
    private const val DEFAULT_SORT_DIRECTION = "asc"
    private val SORT_DIRECTIONS = listOf("asc", "desc")
    private val WHITESPACE = Regex("\\s+")
}

data class RoleRequest(
    var key: String? = null,
    var name: String? = null,
    var description: String = "",
    var prefix: String? = null,
    var color: String? = null,
    var sortOrder: Int = 0,
    var metadata: Map<String, String> = emptyMap(),
    var default: Boolean = false,
)

data class RoleResponse(
    val key: String,
    val name: String,
    val description: String,
    val prefix: String?,
    val color: String?,
    val sortOrder: Int,
    val metadata: Map<String, String>,
    val default: Boolean,
)

data class RoleListResponse(
    val key: String,
    val name: String,
    val description: String,
    val prefix: String?,
    val color: String?,
    val sortOrder: Int,
    val metadata: Map<String, String>,
    val default: Boolean,
    val grantCount: Long,
    val inheritanceCount: Long,
    val parentRoleKeys: List<String>,
)

data class GrantRequest(
    var effect: PermissionEffect? = null,
    var permissionPattern: String? = null,
    var scopeKind: PermissionScopeKind = PermissionScopeKind.GLOBAL,
    var scopeValue: String? = null,
    var expiresAt: Instant? = null,
)

data class RoleGrantResponse(
    val id: UUID,
    val roleKey: String,
    val effect: PermissionEffect,
    val permissionPattern: String,
    val scopeKind: PermissionScopeKind,
    val scopeValue: String?,
    val expiresAt: Instant?,
)

data class PlayerRoleGrantRequest(var roleKey: String? = null, var expiresAt: Instant? = null)

data class PlayerRoleGrantResponse(
    val id: UUID,
    val playerId: UUID,
    val roleKey: String,
    val expiresAt: Instant?,
)

data class PlayerEffectiveRoleResponse(
    val id: String,
    val roleKey: String,
    val roleName: String,
    val source: PermissionGrantOriginKind,
    val expiresAt: Instant?,
    val editable: Boolean,
    val directGrant: PlayerRoleGrantResponse?,
    val inherited: Boolean,
    val assignments: List<EffectiveRoleAssignmentResponse>,
)

data class PlayerGrantResponse(
    val id: UUID,
    val playerId: UUID,
    val effect: PermissionEffect,
    val permissionPattern: String,
    val scopeKind: PermissionScopeKind,
    val scopeValue: String?,
    val expiresAt: Instant?,
)

data class KeycloakGroupMappingRequest(
    var keycloakGroup: String? = null,
    var roleKey: String? = null,
    var expiresAt: Instant? = null,
)

data class KeycloakGroupMappingResponse(
    val id: UUID,
    val keycloakGroup: String,
    val roleKey: String,
    val expiresAt: Instant?,
)

data class CatalogEntryRequest(
    var key: String? = null,
    var label: String? = null,
    var description: String = "",
    var source: String = "portal",
    var sourceVersion: String = "custom",
    var supportedScopes: List<PermissionScopeKind> = listOf(PermissionScopeKind.GLOBAL),
)

data class CatalogEntryResponse(
    val key: String,
    val label: String,
    val description: String,
    val source: String,
    val sourceVersion: String,
    val supportedScopes: List<PermissionScopeKind>,
    val custom: Boolean,
    val lastSeenAt: Instant?,
)

data class EffectivePermissionResponse(
    val playerId: UUID,
    val policyVersion: Long,
    val roleKeys: Set<String>,
    val allowPatterns: List<EffectiveGrantResponse>,
    val denyPatterns: List<EffectiveGrantResponse>,
    val roleAssignments: List<EffectiveRoleAssignmentResponse>,
    val refreshAfter: Instant,
    val expiresAt: Instant,
)

data class EffectiveGrantResponse(
    val effect: PermissionEffect,
    val permissionPattern: String,
    val scopeKind: PermissionScopeKind,
    val scopeValue: String?,
    val expiresAt: Instant?,
    val source: PermissionGrantOriginKind,
    val grantId: UUID?,
    val roleKey: String?,
    val mappingId: UUID?,
    val inheritedPath: List<String>,
    val editable: Boolean,
)

data class EffectiveRoleAssignmentResponse(
    val roleKey: String,
    val source: PermissionGrantOriginKind,
    val grantId: UUID?,
    val mappingId: UUID?,
    val inheritedPath: List<String>,
    val editable: Boolean,
)

data class PermissionCheckResponse(
    val playerId: UUID,
    val permission: String,
    val allowed: Boolean,
    val winningGrant: EffectiveGrantResponse?,
)

data class PlayerIdentityResponse(
    val playerId: UUID,
    val name: String?,
    val linked: Boolean,
    val syncedAt: Instant?,
    val sourceUpdatedAt: Instant?,
    val fresh: Boolean,
    val evaluationSafe: Boolean,
)

data class PlayerSearchItemResponse(
    val playerId: UUID,
    val name: String,
    val linked: Boolean,
    val directRoleGrantCount: Long,
    val directPermissionGrantCount: Long,
)

data class PlayerSearchResponse(
    val items: List<PlayerSearchItemResponse>,
    val page: Int,
    val perPage: Int,
    val total: Long,
)

data class IdentitySyncStatusResponse(
    val status: String,
    val startedAt: Instant?,
    val completedAt: Instant?,
    val lastSuccessAt: Instant?,
    val durationMs: Long?,
    val playerCount: Long,
    val failureReason: String?,
    val stale: Boolean,
)

data class PermissionAuditEventResponse(
    val id: UUID,
    val actorUserId: String?,
    val action: String,
    val target: String,
    val metadata: JsonNode,
    val createdAt: Instant,
)

data class PermissionAuditPageResponse(
    val items: List<PermissionAuditEventResponse>,
    val page: Int,
    val perPage: Int,
    val total: Long,
)
