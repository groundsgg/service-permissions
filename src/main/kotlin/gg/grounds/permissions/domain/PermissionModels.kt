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
    val origin: PermissionGrantOrigin =
        PermissionGrantOrigin(
            when (source) {
                PermissionGrantSource.ROLE -> PermissionGrantOriginKind.DIRECT_ROLE
                PermissionGrantSource.PLAYER -> PermissionGrantOriginKind.DIRECT_PERMISSION
            }
        ),
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

enum class PermissionGrantOriginKind {
    DEFAULT_ROLE,
    DIRECT_ROLE,
    GROUP_MAPPING,
    DIRECT_PERMISSION,
}

data class PermissionGrantOrigin(
    val kind: PermissionGrantOriginKind,
    val roleKey: String? = null,
    val mappingId: UUID? = null,
    val inheritedPath: List<String> = emptyList(),
)

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

enum class PermissionRoleAssignmentSource {
    DIRECT,
    GROUP_MAPPING,
}

data class PlayerRoleGrant(
    val playerId: UUID,
    val roleKey: String,
    val expiresAt: Instant? = null,
    val assignmentSource: PermissionRoleAssignmentSource = PermissionRoleAssignmentSource.DIRECT,
    val mappingId: UUID? = null,
) {
    init {
        require(
            (assignmentSource == PermissionRoleAssignmentSource.GROUP_MAPPING) ==
                (mappingId != null)
        ) {
            "Group-mapped role assignments must include a mapping ID"
        }
    }
}

data class PlayerPermissionGrant(
    val playerId: UUID,
    val grant: PermissionGrantSpec,
    val assignmentExpiresAt: Instant? = null,
)

data class PermissionPolicyInput(
    val policyVersion: Long,
    val roles: List<RoleDefinition>,
    val playerRoles: List<PlayerRoleGrant> = emptyList(),
    val playerGrants: List<PlayerPermissionGrant> = emptyList(),
    val refreshAfter: Instant,
    val expiresAt: Instant,
)
