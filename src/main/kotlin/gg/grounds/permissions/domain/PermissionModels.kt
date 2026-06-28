package gg.grounds.permissions.domain

import java.time.Instant
import java.util.UUID

enum class PermissionEffect {
    ALLOW,
    DENY,
}

enum class PermissionScopeKind {
    GLOBAL,
    SERVER_TYPE,
    SERVER,
}

data class PermissionScope(val kind: PermissionScopeKind, val value: String? = null) {
    init {
        require((kind == PermissionScopeKind.GLOBAL) == (value == null)) {
            "Global scopes must not have a value and non-global scopes must have a value"
        }
    }
}

data class PermissionGrant(
    val effect: PermissionEffect,
    val pattern: String,
    val scope: PermissionScope,
    val source: PermissionGrantSource,
    val expiresAt: Instant? = null,
)

data class PermissionGrantSpec(
    val effect: PermissionEffect,
    val pattern: String,
    val scope: PermissionScope,
    val expiresAt: Instant? = null,
)

enum class PermissionGrantSource {
    ROLE,
    PLAYER,
}

data class EffectivePermissionSnapshot(
    val playerId: UUID,
    val policyVersion: Long,
    val issuedAt: Instant,
    val refreshAfter: Instant,
    val expiresAt: Instant,
    val allowPatterns: List<PermissionGrant>,
    val denyPatterns: List<PermissionGrant>,
    val roleKeys: Set<String>,
    val roleMetadata: List<RoleMetadata>,
)

data class RoleMetadata(
    val key: String,
    val name: String,
    val prefix: String? = null,
    val color: String? = null,
    val sortOrder: Int = 0,
)

data class RoleDefinition(
    val key: String,
    val name: String,
    val description: String = "",
    val prefix: String? = null,
    val color: String? = null,
    val sortOrder: Int = 0,
    val isDefault: Boolean = false,
    val inheritedRoleKeys: Set<String> = emptySet(),
    val grants: List<PermissionGrantSpec> = emptyList(),
)

data class PlayerRoleGrant(val playerId: UUID, val roleKey: String, val expiresAt: Instant? = null)

data class PlayerPermissionGrant(
    val playerId: UUID,
    val grant: PermissionGrantSpec,
    val expiresAt: Instant? = null,
)

data class PermissionPolicyInput(
    val policyVersion: Long,
    val roles: List<RoleDefinition>,
    val playerRoles: List<PlayerRoleGrant> = emptyList(),
    val playerGrants: List<PlayerPermissionGrant> = emptyList(),
    val refreshAfter: Instant,
    val expiresAt: Instant,
)
