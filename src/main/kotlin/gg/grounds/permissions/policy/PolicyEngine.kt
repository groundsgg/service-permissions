package gg.grounds.permissions.policy

import gg.grounds.permissions.domain.EffectivePermissionSnapshot
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionGrant
import gg.grounds.permissions.domain.PermissionGrantSource
import gg.grounds.permissions.domain.PermissionPolicyInput
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.PlayerRoleGrant
import gg.grounds.permissions.domain.RoleDefinition
import gg.grounds.permissions.domain.RoleMetadata
import java.time.Instant
import java.util.UUID

data class PermissionCheckScope(val serverType: String? = null, val server: String? = null) {
    companion object {
        fun global(): PermissionCheckScope = PermissionCheckScope()

        fun serverType(serverType: String): PermissionCheckScope =
            PermissionCheckScope(serverType = serverType)

        fun server(server: String, serverType: String? = null): PermissionCheckScope =
            PermissionCheckScope(serverType = serverType, server = server)
    }
}

object PolicyEngine {
    fun createSnapshot(
        playerId: UUID,
        input: PermissionPolicyInput,
        now: Instant = Instant.now(),
    ): EffectivePermissionSnapshot {
        val rolesByKey = input.roles.associateBy { it.key }
        val assignedRoleKeys =
            input.roles.filter { it.isDefault }.mapTo(linkedSetOf()) { it.key } +
                input.playerRoles
                    .asSequence()
                    .filter { it.playerId == playerId }
                    .filterNot { it.isExpired(now) }
                    .map { it.roleKey }

        val roleKeys = flattenRoleKeys(assignedRoleKeys, rolesByKey)
        val roleGrants =
            roleKeys
                .asSequence()
                .mapNotNull { rolesByKey[it] }
                .flatMap { it.grants.asSequence() }
                .filterNot { it.isExpired(now) }
                .map { it.withSource(PermissionGrantSource.ROLE) }
                .toList()
        val playerGrants =
            input.playerGrants
                .asSequence()
                .filter { it.playerId == playerId }
                .filterNot { it.isExpired(now) }
                .filterNot { it.grant.isExpired(now) }
                .map { it.grant.withSource(PermissionGrantSource.PLAYER) }
                .toList()
        val grants = roleGrants + playerGrants

        return EffectivePermissionSnapshot(
            playerId = playerId,
            policyVersion = input.policyVersion,
            issuedAt = now,
            refreshAfter = input.refreshAfter,
            expiresAt = input.expiresAt,
            allowPatterns = grants.filter { it.effect == PermissionEffect.ALLOW },
            denyPatterns = grants.filter { it.effect == PermissionEffect.DENY },
            roleKeys = roleKeys,
            roleMetadata = roleKeys.mapNotNull { rolesByKey[it]?.toMetadata() },
        )
    }

    fun hasPermission(
        snapshot: EffectivePermissionSnapshot,
        permission: String,
        scope: PermissionCheckScope,
    ): Boolean {
        val candidate =
            (snapshot.allowPatterns + snapshot.denyPatterns)
                .asSequence()
                .filter { PermissionPattern.matches(it.pattern, permission) }
                .mapNotNull { grant -> grant.toCandidate(scope) }
                .maxWithOrNull(
                    compareBy<PermissionCandidate> { it.scopeSpecificity }
                        .thenBy { it.sourceSpecificity }
                        .thenBy { it.patternSpecificity }
                        .thenBy { it.effectSpecificity }
                )

        return candidate?.grant?.effect == PermissionEffect.ALLOW
    }

    private fun flattenRoleKeys(
        roleKeys: Collection<String>,
        rolesByKey: Map<String, RoleDefinition>,
    ): Set<String> {
        val flattened = linkedSetOf<String>()
        val visiting = linkedSetOf<String>()
        val visited = mutableSetOf<String>()

        fun visit(roleKey: String) {
            if (roleKey in visited) {
                return
            }
            if (!visiting.add(roleKey)) {
                throw IllegalArgumentException("Role inheritance cycle detected (roleKey=$roleKey)")
            }

            val role =
                rolesByKey[roleKey]
                    ?: throw IllegalArgumentException("Unknown role referenced (roleKey=$roleKey)")
            flattened += roleKey
            role.inheritedRoleKeys.forEach(::visit)

            visiting -= roleKey
            visited += roleKey
        }

        roleKeys.forEach(::visit)
        return flattened
    }

    private fun PermissionGrant.toCandidate(scope: PermissionCheckScope): PermissionCandidate? {
        val scopeSpecificity = this.scope.specificityFor(scope) ?: return null
        return PermissionCandidate(
            grant = this,
            scopeSpecificity = scopeSpecificity,
            sourceSpecificity =
                when (source) {
                    PermissionGrantSource.ROLE -> 0
                    PermissionGrantSource.PLAYER -> 1
                },
            patternSpecificity = PermissionPattern.specificity(pattern),
            effectSpecificity =
                when (effect) {
                    PermissionEffect.ALLOW -> 0
                    PermissionEffect.DENY -> 1
                },
        )
    }

    private fun PermissionScope.specificityFor(scope: PermissionCheckScope): Int? =
        when (kind) {
            PermissionScopeKind.GLOBAL -> 0
            PermissionScopeKind.SERVER_TYPE -> if (value == scope.serverType) 1 else null
            PermissionScopeKind.SERVER -> if (value == scope.server) 2 else null
        }

    private fun PermissionGrant.isExpired(now: Instant): Boolean =
        expiresAt?.let { !it.isAfter(now) } ?: false

    private fun PlayerPermissionGrant.isExpired(now: Instant): Boolean =
        expiresAt?.let { !it.isAfter(now) } ?: false

    private fun PlayerRoleGrant.isExpired(now: Instant): Boolean =
        expiresAt?.let { !it.isAfter(now) } ?: false

    private fun PermissionGrant.withSource(source: PermissionGrantSource): PermissionGrant =
        if (this.source == source) this else copy(source = source)

    private fun RoleDefinition.toMetadata(): RoleMetadata =
        RoleMetadata(key = key, name = name, prefix = prefix, color = color, sortOrder = sortOrder)
}

private data class PermissionCandidate(
    val grant: PermissionGrant,
    val scopeSpecificity: Int,
    val sourceSpecificity: Int,
    val patternSpecificity: Int,
    val effectSpecificity: Int,
)
