package gg.grounds.permissions.policy

import gg.grounds.permissions.domain.PermissionEffect.ALLOW
import gg.grounds.permissions.domain.PermissionEffect.DENY
import gg.grounds.permissions.domain.PermissionGrant
import gg.grounds.permissions.domain.PermissionGrantSource.PLAYER
import gg.grounds.permissions.domain.PermissionGrantSource.ROLE
import gg.grounds.permissions.domain.PermissionPolicyInput
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind.GLOBAL
import gg.grounds.permissions.domain.PermissionScopeKind.SERVER
import gg.grounds.permissions.domain.PermissionScopeKind.SERVER_TYPE
import gg.grounds.permissions.domain.PlayerRoleGrant
import gg.grounds.permissions.domain.RoleDefinition
import java.time.Instant
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PolicyEngineTest {
    private val now: Instant = Instant.parse("2026-06-28T12:00:00Z")
    private val playerId: UUID = UUID.fromString("00000000-0000-0000-0000-000000000123")

    @Test
    fun defaultRoleIsIncluded() {
        val snapshot =
            PolicyEngine.createSnapshot(
                playerId = playerId,
                input =
                    policy(
                        roles =
                            listOf(
                                role(
                                    key = "default",
                                    default = true,
                                    grants = listOf(allow("chat.read")),
                                )
                            )
                    ),
                now = now,
            )

        assertTrue(PolicyEngine.hasPermission(snapshot, "chat.read", PermissionCheckScope.global()))
        assertTrue(snapshot.roleKeys.contains("default"))
    }

    @Test
    fun multipleRolesCombine() {
        val snapshot =
            PolicyEngine.createSnapshot(
                playerId = playerId,
                input =
                    policy(
                        roles =
                            listOf(
                                role("builder", grants = listOf(allow("build.place"))),
                                role("moderator", grants = listOf(allow("chat.mute"))),
                            ),
                        playerRoles =
                            listOf(
                                PlayerRoleGrant(playerId, "builder"),
                                PlayerRoleGrant(playerId, "moderator"),
                            ),
                    ),
                now = now,
            )

        assertTrue(
            PolicyEngine.hasPermission(snapshot, "build.place", PermissionCheckScope.global())
        )
        assertTrue(PolicyEngine.hasPermission(snapshot, "chat.mute", PermissionCheckScope.global()))
    }

    @Test
    fun inheritedRoleGrantsApply() {
        val snapshot =
            PolicyEngine.createSnapshot(
                playerId = playerId,
                input =
                    policy(
                        roles =
                            listOf(
                                role("member", grants = listOf(allow("home.teleport"))),
                                role("vip", inherits = setOf("member")),
                            ),
                        playerRoles = listOf(PlayerRoleGrant(playerId, "vip")),
                    ),
                now = now,
            )

        assertTrue(
            PolicyEngine.hasPermission(snapshot, "home.teleport", PermissionCheckScope.global())
        )
        assertTrue(snapshot.roleKeys.containsAll(setOf("vip", "member")))
    }

    @Test
    fun cycleInputIsRejectedByTheFlattener() {
        assertThrows(IllegalArgumentException::class.java) {
            PolicyEngine.createSnapshot(
                playerId = playerId,
                input =
                    policy(
                        roles =
                            listOf(
                                role("alpha", inherits = setOf("beta")),
                                role("beta", inherits = setOf("alpha")),
                            ),
                        playerRoles = listOf(PlayerRoleGrant(playerId, "alpha")),
                    ),
                now = now,
            )
        }
    }

    @Test
    fun expiredGrantsAreIgnored() {
        val snapshot =
            PolicyEngine.createSnapshot(
                playerId = playerId,
                input =
                    policy(
                        roles =
                            listOf(
                                role(
                                    "member",
                                    grants =
                                        listOf(allow("fly.use", expiresAt = now.minusSeconds(1))),
                                )
                            ),
                        playerRoles = listOf(PlayerRoleGrant(playerId, "member")),
                        playerGrants =
                            listOf(allow("warp.use", PLAYER, expiresAt = now.minusSeconds(1))),
                    ),
                now = now,
            )

        assertFalse(PolicyEngine.hasPermission(snapshot, "fly.use", PermissionCheckScope.global()))
        assertFalse(PolicyEngine.hasPermission(snapshot, "warp.use", PermissionCheckScope.global()))
    }

    @Test
    fun serverBeatsServerTypeAndServerTypeBeatsGlobal() {
        val snapshot =
            snapshot(
                grants =
                    listOf(
                        allow("region.edit", ROLE, PermissionScope(GLOBAL)),
                        deny("region.edit", ROLE, PermissionScope(SERVER_TYPE, "survival")),
                        allow("region.edit", ROLE, PermissionScope(SERVER, "survival-1")),
                    )
            )

        assertTrue(
            PolicyEngine.hasPermission(
                snapshot,
                "region.edit",
                PermissionCheckScope.server(server = "survival-1", serverType = "survival"),
            )
        )
        assertFalse(
            PolicyEngine.hasPermission(
                snapshot,
                "region.edit",
                PermissionCheckScope.server(server = "survival-2", serverType = "survival"),
            )
        )
    }

    @Test
    fun directPlayerGrantBeatsRoleGrantAtTheSameScope() {
        val snapshot =
            snapshot(grants = listOf(deny("kit.claim", ROLE), allow("kit.claim", PLAYER)))

        assertTrue(PolicyEngine.hasPermission(snapshot, "kit.claim", PermissionCheckScope.global()))
    }

    @Test
    fun exactPatternBeatsWildcardPattern() {
        val snapshot = snapshot(grants = listOf(deny("chat.*", ROLE), allow("chat.send", ROLE)))

        assertTrue(PolicyEngine.hasPermission(snapshot, "chat.send", PermissionCheckScope.global()))
    }

    @Test
    fun prefixWildcardPatternMatchesOnlyChildren() {
        val snapshot = snapshot(grants = listOf(allow("chat.*", ROLE)))

        assertTrue(PolicyEngine.hasPermission(snapshot, "chat.send", PermissionCheckScope.global()))
        assertFalse(PolicyEngine.hasPermission(snapshot, "chat", PermissionCheckScope.global()))
    }

    @Test
    fun starPatternMatchesEveryPermission() {
        val snapshot = snapshot(grants = listOf(allow("*", ROLE)))

        assertTrue(
            PolicyEngine.hasPermission(snapshot, "any.permission", PermissionCheckScope.global())
        )
    }

    @Test
    fun denyBeatsAllowWhenSpecificityTies() {
        val snapshot =
            snapshot(grants = listOf(allow("economy.pay", ROLE), deny("economy.pay", ROLE)))

        assertFalse(
            PolicyEngine.hasPermission(snapshot, "economy.pay", PermissionCheckScope.global())
        )
    }

    @Test
    fun noMatchingAllowReturnsDenied() {
        val snapshot = snapshot(grants = listOf(allow("chat.read", ROLE)))

        assertFalse(
            PolicyEngine.hasPermission(snapshot, "chat.write", PermissionCheckScope.global())
        )
    }

    private fun snapshot(grants: List<PermissionGrant>) =
        PolicyEngine.createSnapshot(
            playerId = playerId,
            input =
                policy(
                    roles = listOf(role("member", grants = grants.filter { it.source == ROLE })),
                    playerRoles = listOf(PlayerRoleGrant(playerId, "member")),
                    playerGrants = grants.filter { it.source == PLAYER },
                ),
            now = now,
        )

    private fun policy(
        roles: List<RoleDefinition>,
        playerRoles: List<PlayerRoleGrant> = emptyList(),
        playerGrants: List<PermissionGrant> = emptyList(),
    ) =
        PermissionPolicyInput(
            policyVersion = 1,
            roles = roles,
            playerRoles = playerRoles,
            playerGrants = playerGrants,
            refreshAfter = now.plusSeconds(60),
            expiresAt = now.plusSeconds(300),
        )

    private fun role(
        key: String,
        default: Boolean = false,
        inherits: Set<String> = emptySet(),
        grants: List<PermissionGrant> = emptyList(),
    ) =
        RoleDefinition(
            key = key,
            name = key,
            isDefault = default,
            inheritedRoleKeys = inherits,
            grants = grants,
        )

    private fun allow(
        pattern: String,
        source: gg.grounds.permissions.domain.PermissionGrantSource = ROLE,
        scope: PermissionScope = PermissionScope(GLOBAL),
        expiresAt: Instant? = null,
    ) =
        PermissionGrant(
            effect = ALLOW,
            pattern = pattern,
            scope = scope,
            source = source,
            expiresAt = expiresAt,
        )

    private fun deny(
        pattern: String,
        source: gg.grounds.permissions.domain.PermissionGrantSource = ROLE,
        scope: PermissionScope = PermissionScope(GLOBAL),
        expiresAt: Instant? = null,
    ) =
        PermissionGrant(
            effect = DENY,
            pattern = pattern,
            scope = scope,
            source = source,
            expiresAt = expiresAt,
        )
}
