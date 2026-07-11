package gg.grounds.permissions.rest

import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionScopeKind
import java.time.Instant
import java.util.UUID

data class ErrorResponse(val error: String)

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
    val refreshAfter: Instant,
    val expiresAt: Instant,
)

data class EffectiveGrantResponse(
    val effect: PermissionEffect,
    val permissionPattern: String,
    val scopeKind: PermissionScopeKind,
    val scopeValue: String?,
    val expiresAt: Instant?,
)
