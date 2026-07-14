package gg.grounds.permissions.policy

import gg.grounds.permissions.domain.PermissionEffect.ALLOW
import gg.grounds.permissions.domain.PermissionEffect.DENY
import gg.grounds.permissions.domain.PermissionGrantOriginKind.DEFAULT_ROLE
import gg.grounds.permissions.domain.PermissionGrantOriginKind.DIRECT_PERMISSION
import gg.grounds.permissions.domain.PermissionGrantOriginKind.DIRECT_ROLE
import gg.grounds.permissions.domain.PermissionGrantOriginKind.GROUP_MAPPING
import gg.grounds.permissions.domain.PermissionGrantSpec
import gg.grounds.permissions.domain.PermissionPolicyInput
import gg.grounds.permissions.domain.PermissionRoleAssignmentSource
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind.GLOBAL
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.PlayerRoleGrant
import gg.grounds.permissions.domain.RoleDefinition
import java.time.Instant
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PermissionExplanationTest {
    private val playerId = UUID.fromString("00000000-0000-0000-0000-000000000321")
    private val mappingId = UUID.fromString("00000000-0000-0000-0000-000000000322")
    private val now = Instant.parse("2030-01-01T00:00:00Z")

    @Test
    fun explainsDefaultDirectMappedAndInheritedRoleSources() {
        val snapshot =
            snapshot(
                roles =
                    listOf(
                        role("default", default = true, permission = "spawn.use"),
                        role("member", permission = "home.use"),
                        role("builder", permission = "build.use"),
                        role("staff", inherits = setOf("member"), permission = "staff.chat"),
                    ),
                playerRoles =
                    listOf(
                        PlayerRoleGrant(playerId, "builder"),
                        PlayerRoleGrant(
                            playerId = playerId,
                            roleKey = "staff",
                            assignmentSource = PermissionRoleAssignmentSource.GROUP_MAPPING,
                            mappingId = mappingId,
                        ),
                    ),
            )

        assertEquals(DEFAULT_ROLE, decision(snapshot, "spawn.use").winningGrant?.origin?.kind)
        assertEquals(DIRECT_ROLE, decision(snapshot, "build.use").winningGrant?.origin?.kind)
        val mapped = decision(snapshot, "staff.chat").winningGrant?.origin
        assertEquals(GROUP_MAPPING, mapped?.kind)
        assertEquals(mappingId, mapped?.mappingId)
        val inherited =
            snapshot.allowPatterns.single {
                it.pattern == "home.use" && it.origin.kind == GROUP_MAPPING
            }
        assertEquals(listOf("staff", "member"), inherited.origin.inheritedPath)
        assertEquals("member", inherited.origin.roleKey)
    }

    @Test
    fun explainsDirectPermissionAsTheWinningSource() {
        val snapshot =
            snapshot(
                roles = listOf(role("member", permission = "kit.claim", effect = DENY)),
                playerRoles = listOf(PlayerRoleGrant(playerId, "member")),
                playerGrants =
                    listOf(
                        PlayerPermissionGrant(
                            playerId,
                            PermissionGrantSpec(ALLOW, "kit.claim", PermissionScope(GLOBAL)),
                        )
                    ),
            )

        val result = decision(snapshot, "kit.claim")

        assertTrue(result.allowed)
        assertEquals(DIRECT_PERMISSION, result.winningGrant?.origin?.kind)
    }

    @Test
    fun moreSpecificAllowIsReportedBeforeBroaderDeny() {
        val snapshot =
            snapshot(
                roles =
                    listOf(
                        RoleDefinition(
                            key = "member",
                            name = "member",
                            grants =
                                listOf(
                                    PermissionGrantSpec(DENY, "grounds.*", PermissionScope(GLOBAL)),
                                    PermissionGrantSpec(
                                        ALLOW,
                                        "grounds.chat",
                                        PermissionScope(GLOBAL),
                                    ),
                                ),
                        )
                    ),
                playerRoles = listOf(PlayerRoleGrant(playerId, "member")),
            )

        val result = decision(snapshot, "grounds.chat")

        assertTrue(result.allowed)
        assertEquals(ALLOW, result.winningGrant?.effect)
        assertEquals("grounds.chat", result.winningGrant?.pattern)
    }

    @Test
    fun denyOnlyWinsAfterScopeSourceAndPatternSpecificityTie() {
        val snapshot =
            snapshot(
                roles =
                    listOf(
                        RoleDefinition(
                            key = "member",
                            name = "member",
                            grants =
                                listOf(
                                    PermissionGrantSpec(
                                        ALLOW,
                                        "economy.pay",
                                        PermissionScope(GLOBAL),
                                    ),
                                    PermissionGrantSpec(
                                        DENY,
                                        "economy.pay",
                                        PermissionScope(GLOBAL),
                                    ),
                                ),
                        )
                    ),
                playerRoles = listOf(PlayerRoleGrant(playerId, "member")),
            )

        val result = decision(snapshot, "economy.pay")

        assertFalse(result.allowed)
        assertEquals(DENY, result.winningGrant?.effect)
    }

    private fun decision(
        snapshot: gg.grounds.permissions.domain.EffectivePermissionSnapshot,
        permission: String,
    ) = PolicyEngine.checkPermission(snapshot, permission, PermissionCheckScope.global(), now)

    private fun snapshot(
        roles: List<RoleDefinition>,
        playerRoles: List<PlayerRoleGrant> = emptyList(),
        playerGrants: List<PlayerPermissionGrant> = emptyList(),
    ) =
        PolicyEngine.createSnapshot(
            playerId,
            PermissionPolicyInput(
                policyVersion = 1,
                roles = roles,
                playerRoles = playerRoles,
                playerGrants = playerGrants,
                refreshAfter = now.plusSeconds(60),
                expiresAt = now.plusSeconds(300),
            ),
            now,
        )

    private fun role(
        key: String,
        default: Boolean = false,
        inherits: Set<String> = emptySet(),
        permission: String,
        effect: gg.grounds.permissions.domain.PermissionEffect = ALLOW,
    ) =
        RoleDefinition(
            key = key,
            name = key,
            isDefault = default,
            inheritedRoleKeys = inherits,
            grants = listOf(PermissionGrantSpec(effect, permission, PermissionScope(GLOBAL))),
        )
}
