package gg.grounds.permissions.policy

import gg.grounds.permissions.domain.EffectivePermissionSnapshot
import gg.grounds.permissions.domain.EffectiveRoleAssignment
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionGrant
import gg.grounds.permissions.domain.PermissionGrantOrigin
import gg.grounds.permissions.domain.PermissionGrantOriginKind
import gg.grounds.permissions.domain.PermissionGrantSource
import gg.grounds.permissions.domain.PermissionGrantSpec
import gg.grounds.permissions.domain.PermissionPolicyInput
import gg.grounds.permissions.domain.PermissionRoleAssignmentSource
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.PlayerRoleGrant
import gg.grounds.permissions.domain.RoleDefinition
import gg.grounds.permissions.domain.RoleMetadata
import java.time.Instant
import java.util.UUID

data class PermissionCheckScope
private constructor(val serverType: String? = null, val server: String? = null) {
    companion object {
        fun global(): PermissionCheckScope = PermissionCheckScope()

        fun serverType(serverType: String): PermissionCheckScope =
            PermissionCheckScope(serverType = serverType)

        fun server(server: String, serverType: String): PermissionCheckScope =
            PermissionCheckScope(serverType = serverType, server = server)

        fun serverOnly(server: String): PermissionCheckScope = PermissionCheckScope(server = server)
    }
}

object PolicyEngine {
    fun createSnapshot(
        playerId: UUID,
        input: PermissionPolicyInput,
        now: Instant = Instant.now(),
    ): EffectivePermissionSnapshot {
        val rolesByKey = input.roles.toRoleMap()
        validateRoleGraph(input.roles.map { it.key }, rolesByKey)

        val includedPlayerRoleGrants =
            input.playerRoles
                .asSequence()
                .filter { it.playerId == playerId }
                .filterNot { it.isExpired(now) }
                .toList()
        val roleAssignments =
            input.roles
                .filter { it.isDefault }
                .map {
                    RoleAssignment(
                        roleKey = it.key,
                        origin = PermissionGrantOrigin(PermissionGrantOriginKind.DEFAULT_ROLE),
                    )
                } +
                includedPlayerRoleGrants.map { grant ->
                    RoleAssignment(
                        roleKey = grant.roleKey,
                        origin =
                            PermissionGrantOrigin(
                                kind =
                                    when (grant.assignmentSource) {
                                        PermissionRoleAssignmentSource.DIRECT ->
                                            PermissionGrantOriginKind.DIRECT_ROLE
                                        PermissionRoleAssignmentSource.GROUP_MAPPING ->
                                            PermissionGrantOriginKind.GROUP_MAPPING
                                    },
                                grantId = grant.grantId,
                                mappingId = grant.mappingId,
                            ),
                    )
                }

        val resolvedRoles = resolveRoles(roleAssignments, rolesByKey)
        val roleKeys = resolvedRoles.mapTo(linkedSetOf()) { it.roleKey }
        val roleGrants =
            resolvedRoles.flatMap { resolved ->
                rolesByKey
                    .getValue(resolved.roleKey)
                    .grants
                    .asSequence()
                    .filterNot { it.isExpired(now) }
                    .map { grant -> grant to resolved.origin }
                    .toList()
            }
        val effectiveRoleGrants =
            roleGrants.map { (grant, origin) -> grant.toGrant(PermissionGrantSource.ROLE, origin) }
        val includedPlayerGrants =
            input.playerGrants
                .asSequence()
                .filter { it.playerId == playerId }
                .filterNot { it.isExpired(now) }
                .filterNot { it.grant.isExpired(now) }
                .toList()
        val playerGrants =
            includedPlayerGrants.map {
                it.grant.toGrant(
                    PermissionGrantSource.PLAYER,
                    PermissionGrantOrigin(
                        PermissionGrantOriginKind.DIRECT_PERMISSION,
                        grantId = it.grantId,
                    ),
                )
            }
        val grants = effectiveRoleGrants + playerGrants

        return EffectivePermissionSnapshot(
            playerId = playerId,
            policyVersion = input.policyVersion,
            issuedAt = now,
            refreshAfter = input.refreshAfter,
            expiresAt =
                earliestOf(
                    listOf(input.expiresAt) +
                        includedPlayerRoleGrants.mapNotNull { it.expiresAt } +
                        roleGrants.mapNotNull { it.first.expiresAt } +
                        includedPlayerGrants.mapNotNull { it.assignmentExpiresAt } +
                        includedPlayerGrants.mapNotNull { it.grant.expiresAt }
                ),
            allowPatterns = grants.filter { it.effect == PermissionEffect.ALLOW },
            denyPatterns = grants.filter { it.effect == PermissionEffect.DENY },
            roleKeys = roleKeys,
            roleMetadata = roleKeys.mapNotNull { rolesByKey[it]?.toMetadata() },
            roleAssignments =
                resolvedRoles
                    .map { EffectiveRoleAssignment(roleKey = it.roleKey, origin = it.origin) }
                    .distinct(),
        )
    }

    fun hasPermission(
        snapshot: EffectivePermissionSnapshot,
        permission: String,
        scope: PermissionCheckScope,
        now: Instant = Instant.now(),
    ): Boolean = checkPermission(snapshot, permission, scope, now).allowed

    fun checkPermission(
        snapshot: EffectivePermissionSnapshot,
        permission: String,
        scope: PermissionCheckScope,
        now: Instant = Instant.now(),
    ): PermissionDecision {
        if (!snapshot.expiresAt.isAfter(now)) {
            return PermissionDecision(allowed = false, winningGrant = null)
        }

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

        return PermissionDecision(
            allowed = candidate?.grant?.effect == PermissionEffect.ALLOW,
            winningGrant = candidate?.grant,
        )
    }

    private fun resolveRoles(
        assignments: List<RoleAssignment>,
        rolesByKey: Map<String, RoleDefinition>,
    ): List<ResolvedRole> = buildList {
        assignments.forEach { assignment ->
            fun visit(roleKey: String, path: List<String>, visiting: Set<String>) {
                require(roleKey !in visiting) {
                    "Role inheritance cycle detected (roleKey=$roleKey)"
                }
                val role =
                    rolesByKey[roleKey]
                        ?: throw IllegalArgumentException(
                            "Unknown role referenced (roleKey=$roleKey)"
                        )
                val inheritedPath = if (path.isEmpty()) emptyList() else path + roleKey
                add(
                    ResolvedRole(
                        roleKey = roleKey,
                        origin =
                            assignment.origin.copy(roleKey = roleKey, inheritedPath = inheritedPath),
                    )
                )
                role.inheritedRoleKeys.forEach { inheritedRoleKey ->
                    visit(
                        inheritedRoleKey,
                        if (path.isEmpty()) listOf(roleKey) else path + roleKey,
                        visiting + roleKey,
                    )
                }
            }

            visit(assignment.roleKey, emptyList(), emptySet())
        }
    }

    private fun List<RoleDefinition>.toRoleMap(): Map<String, RoleDefinition> {
        val rolesByKey = linkedMapOf<String, RoleDefinition>()
        forEach { role ->
            require(rolesByKey.put(role.key, role) == null) {
                "Duplicate role key detected (roleKey=${role.key})"
            }
        }
        return rolesByKey
    }

    private fun validateRoleGraph(
        roleKeys: Collection<String>,
        rolesByKey: Map<String, RoleDefinition>,
    ) {
        flattenRoleKeys(roleKeys, rolesByKey)
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

    private fun PermissionGrantSpec.isExpired(now: Instant): Boolean =
        expiresAt?.let { !it.isAfter(now) } ?: false

    private fun PlayerPermissionGrant.isExpired(now: Instant): Boolean =
        assignmentExpiresAt?.let { !it.isAfter(now) } ?: false

    private fun PlayerRoleGrant.isExpired(now: Instant): Boolean =
        expiresAt?.let { !it.isAfter(now) } ?: false

    private fun PermissionGrantSpec.toGrant(
        source: PermissionGrantSource,
        origin: PermissionGrantOrigin,
    ): PermissionGrant =
        PermissionGrant(
            effect = effect,
            pattern = pattern,
            scope = scope,
            source = source,
            expiresAt = expiresAt,
            origin = origin.copy(permissionGrantId = permissionGrantId),
        )

    private fun earliestOf(instants: List<Instant>): Instant =
        instants.minOrNull() ?: error("Snapshot expiry candidates must not be empty")

    private fun RoleDefinition.toMetadata(): RoleMetadata =
        RoleMetadata(key = key, name = name, prefix = prefix, color = color, sortOrder = sortOrder)
}

data class PermissionDecision(val allowed: Boolean, val winningGrant: PermissionGrant?)

private data class RoleAssignment(val roleKey: String, val origin: PermissionGrantOrigin)

private data class ResolvedRole(val roleKey: String, val origin: PermissionGrantOrigin)

private data class PermissionCandidate(
    val grant: PermissionGrant,
    val scopeSpecificity: Int,
    val sourceSpecificity: Int,
    val patternSpecificity: Int,
    val effectSpecificity: Int,
)
