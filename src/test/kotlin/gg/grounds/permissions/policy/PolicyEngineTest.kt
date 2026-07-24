package gg.grounds.permissions.policy

import gg.grounds.permissions.domain.EffectivePermissionSnapshot
import gg.grounds.permissions.domain.PermissionEffect.ALLOW
import gg.grounds.permissions.domain.PermissionEffect.DENY
import gg.grounds.permissions.domain.PermissionGrant
import gg.grounds.permissions.domain.PermissionGrantSource.PLAYER
import gg.grounds.permissions.domain.PermissionGrantSource.ROLE
import gg.grounds.permissions.domain.PermissionGrantSpec
import gg.grounds.permissions.domain.PermissionPolicyInput
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind.ENVIRONMENT
import gg.grounds.permissions.domain.PermissionScopeKind.GLOBAL
import gg.grounds.permissions.domain.PermissionScopeKind.SERVER
import gg.grounds.permissions.domain.PermissionScopeKind.SERVER_TYPE
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.PlayerRoleGrant
import gg.grounds.permissions.domain.RoleDefinition
import java.time.Instant
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
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
                                    grants = listOf(allowSpec("chat.read")),
                                )
                            )
                    ),
                now = now,
            )

        assertTrue(hasPermission(snapshot, "chat.read", PermissionCheckScope.global()))
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
                                role("builder", grants = listOf(allowSpec("build.place"))),
                                role("moderator", grants = listOf(allowSpec("chat.mute"))),
                            ),
                        playerRoles =
                            listOf(
                                PlayerRoleGrant(playerId, "builder"),
                                PlayerRoleGrant(playerId, "moderator"),
                            ),
                    ),
                now = now,
            )

        assertTrue(hasPermission(snapshot, "build.place", PermissionCheckScope.global()))
        assertTrue(hasPermission(snapshot, "chat.mute", PermissionCheckScope.global()))
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
                                role("member", grants = listOf(allowSpec("home.teleport"))),
                                role("vip", inherits = setOf("member")),
                            ),
                        playerRoles = listOf(PlayerRoleGrant(playerId, "vip")),
                    ),
                now = now,
            )

        assertTrue(hasPermission(snapshot, "home.teleport", PermissionCheckScope.global()))
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
    fun unassignedCycleInputIsRejectedDuringSnapshotCreation() {
        assertThrows(IllegalArgumentException::class.java) {
            PolicyEngine.createSnapshot(
                playerId = playerId,
                input =
                    policy(
                        roles =
                            listOf(
                                role("member", grants = listOf(allowSpec("chat.read"))),
                                role("alpha", inherits = setOf("beta")),
                                role("beta", inherits = setOf("alpha")),
                            ),
                        playerRoles = listOf(PlayerRoleGrant(playerId, "member")),
                    ),
                now = now,
            )
        }
    }

    @Test
    fun duplicateRoleKeysAreRejectedDuringSnapshotCreation() {
        assertThrows(IllegalArgumentException::class.java) {
            PolicyEngine.createSnapshot(
                playerId = playerId,
                input =
                    policy(
                        roles =
                            listOf(
                                role("member", grants = listOf(allowSpec("chat.read"))),
                                role("member", grants = listOf(allowSpec("chat.write"))),
                            )
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
                                        listOf(
                                            allowSpec("fly.use", expiresAt = now.minusSeconds(1))
                                        ),
                                )
                            ),
                        playerRoles = listOf(PlayerRoleGrant(playerId, "member")),
                        playerGrants =
                            listOf(
                                PlayerPermissionGrant(
                                    playerId,
                                    allowSpec("warp.use"),
                                    assignmentExpiresAt = now.minusSeconds(1),
                                )
                            ),
                    ),
                now = now,
            )

        assertFalse(hasPermission(snapshot, "fly.use", PermissionCheckScope.global()))
        assertFalse(hasPermission(snapshot, "warp.use", PermissionCheckScope.global()))
    }

    @Test
    fun expiredSnapshotsDenyOtherwiseMatchingAllows() {
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
                                    grants = listOf(allowSpec("chat.read")),
                                )
                            ),
                        expiresAt = now.minusSeconds(1),
                    ),
                now = now.minusSeconds(2),
            )

        assertFalse(hasPermission(snapshot, "chat.read", PermissionCheckScope.global(), now = now))
    }

    @Test
    fun directPlayerGrantsApplyOnlyToTheMatchingPlayer() {
        val otherPlayerId = UUID.fromString("00000000-0000-0000-0000-000000000456")
        val input =
            policy(
                roles = emptyList(),
                playerGrants = listOf(PlayerPermissionGrant(playerId, allowSpec("warp.use"))),
            )

        val matchingSnapshot = PolicyEngine.createSnapshot(playerId, input, now)
        val otherSnapshot = PolicyEngine.createSnapshot(otherPlayerId, input, now)

        assertTrue(hasPermission(matchingSnapshot, "warp.use", PermissionCheckScope.global()))
        assertFalse(hasPermission(otherSnapshot, "warp.use", PermissionCheckScope.global()))
    }

    @Test
    fun snapshotDerivesGrantSourcesFromContainers() {
        val snapshot =
            PolicyEngine.createSnapshot(
                playerId = playerId,
                input =
                    policy(
                        roles = listOf(role("member", grants = listOf(denySpec("kit.claim")))),
                        playerRoles = listOf(PlayerRoleGrant(playerId, "member")),
                        playerGrants =
                            listOf(PlayerPermissionGrant(playerId, allowSpec("kit.claim"))),
                    ),
                now = now,
            )

        assertTrue(hasPermission(snapshot, "kit.claim", PermissionCheckScope.global()))
    }

    @Test
    fun snapshotExpiryIsCappedByPlayerRoleAssignmentExpiry() {
        val roleAssignmentExpiresAt = now.plusSeconds(30)

        val snapshot =
            PolicyEngine.createSnapshot(
                playerId = playerId,
                input =
                    policy(
                        roles = listOf(role("member", grants = listOf(allowSpec("chat.read")))),
                        playerRoles =
                            listOf(
                                PlayerRoleGrant(
                                    playerId = playerId,
                                    roleKey = "member",
                                    expiresAt = roleAssignmentExpiresAt,
                                )
                            ),
                    ),
                now = now,
            )

        assertEquals(roleAssignmentExpiresAt, snapshot.expiresAt)
    }

    @Test
    fun snapshotExpiryIsCappedByPlayerDirectGrantContainerExpiry() {
        val containerExpiresAt = now.plusSeconds(45)

        val snapshot =
            PolicyEngine.createSnapshot(
                playerId = playerId,
                input =
                    policy(
                        roles = emptyList(),
                        playerGrants =
                            listOf(
                                PlayerPermissionGrant(
                                    playerId = playerId,
                                    grant = allowSpec("warp.use"),
                                    assignmentExpiresAt = containerExpiresAt,
                                )
                            ),
                    ),
                now = now,
            )

        assertEquals(containerExpiresAt, snapshot.expiresAt)
    }

    @Test
    fun snapshotExpiryIsCappedByPermissionGrantExpiry() {
        val grantExpiresAt = now.plusSeconds(20)

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
                                        listOf(allowSpec("fly.use", expiresAt = grantExpiresAt)),
                                )
                            ),
                        playerRoles = listOf(PlayerRoleGrant(playerId, "member")),
                    ),
                now = now,
            )

        assertEquals(grantExpiresAt, snapshot.expiresAt)
    }

    @Test
    fun snapshotExpiryIsCappedByPlayerDirectPermissionGrantExpiry() {
        val grantExpiresAt = now.plusSeconds(25)

        val snapshot =
            PolicyEngine.createSnapshot(
                playerId = playerId,
                input =
                    policy(
                        roles = emptyList(),
                        playerGrants =
                            listOf(
                                PlayerPermissionGrant(
                                    playerId = playerId,
                                    grant = allowSpec("warp.use", expiresAt = grantExpiresAt),
                                )
                            ),
                    ),
                now = now,
            )

        assertEquals(grantExpiresAt, snapshot.expiresAt)
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
            hasPermission(
                snapshot,
                "region.edit",
                PermissionCheckScope.server(server = "survival-1", serverType = "survival"),
            )
        )
        assertFalse(
            hasPermission(
                snapshot,
                "region.edit",
                PermissionCheckScope.server(server = "survival-2", serverType = "survival"),
            )
        )
    }

    @Test
    fun environmentBeatsGlobalAndLosesToServerType() {
        val snapshot =
            snapshot(
                grants =
                    listOf(
                        allow("region.edit", ROLE, PermissionScope(GLOBAL)),
                        deny("region.edit", ROLE, PermissionScope(ENVIRONMENT, "stage")),
                        allow("region.edit", ROLE, PermissionScope(SERVER_TYPE, "lobby")),
                    )
            )

        assertFalse(
            hasPermission(
                snapshot,
                "region.edit",
                PermissionCheckScope.of(environment = "stage", serverType = "survival"),
            )
        )
        assertTrue(
            hasPermission(
                snapshot,
                "region.edit",
                PermissionCheckScope.of(environment = "stage", serverType = "lobby"),
            )
        )
    }

    @Test
    fun environmentGrantsDoNotLeakIntoOtherEnvironments() {
        val snapshot =
            snapshot(
                grants =
                    listOf(
                        deny("region.edit", ROLE, PermissionScope(GLOBAL)),
                        allow("region.edit", ROLE, PermissionScope(ENVIRONMENT, "stage")),
                    )
            )

        assertTrue(
            hasPermission(snapshot, "region.edit", PermissionCheckScope.of(environment = "stage"))
        )
        assertFalse(
            hasPermission(snapshot, "region.edit", PermissionCheckScope.of(environment = "prod"))
        )
        assertFalse(hasPermission(snapshot, "region.edit", PermissionCheckScope.global()))
    }

    @Test
    fun globalGrantsStillApplyInsideAnEnvironment() {
        val snapshot =
            snapshot(grants = listOf(allow("region.edit", ROLE, PermissionScope(GLOBAL))))

        assertTrue(
            hasPermission(
                snapshot,
                "region.edit",
                PermissionCheckScope.of(
                    environment = "stage",
                    serverType = "lobby",
                    server = "lobby-1",
                ),
            )
        )
    }

    @Test
    fun serverTypeGrantsApplyToServerChecksOnlyWhenServerTypeIsSupplied() {
        val snapshot =
            snapshot(
                grants =
                    listOf(
                        allow("region.edit", ROLE, PermissionScope(GLOBAL)),
                        deny("region.edit", ROLE, PermissionScope(SERVER_TYPE, "survival")),
                    )
            )

        assertFalse(
            hasPermission(
                snapshot,
                "region.edit",
                PermissionCheckScope.server(server = "survival-1", serverType = "survival"),
            )
        )
        assertTrue(
            hasPermission(
                snapshot,
                "region.edit",
                PermissionCheckScope.serverOnly(server = "survival-1"),
            )
        )
    }

    @Test
    fun directPlayerGrantBeatsRoleGrantAtTheSameScope() {
        val snapshot =
            snapshot(grants = listOf(deny("kit.claim", ROLE), allow("kit.claim", PLAYER)))

        assertTrue(hasPermission(snapshot, "kit.claim", PermissionCheckScope.global()))
    }

    @Test
    fun exactPatternBeatsWildcardPattern() {
        val snapshot = snapshot(grants = listOf(deny("chat.*", ROLE), allow("chat.send", ROLE)))

        assertTrue(hasPermission(snapshot, "chat.send", PermissionCheckScope.global()))
    }

    @Test
    fun playerWildcardGrantBeatsRoleExactGrant() {
        val snapshot = snapshot(grants = listOf(deny("chat.send", ROLE), allow("*", PLAYER)))

        assertTrue(hasPermission(snapshot, "chat.send", PermissionCheckScope.global()))
    }

    @Test
    fun prefixWildcardPatternMatchesOnlyChildren() {
        val snapshot = snapshot(grants = listOf(allow("chat.*", ROLE)))

        assertTrue(hasPermission(snapshot, "chat.send", PermissionCheckScope.global()))
        assertFalse(hasPermission(snapshot, "chat", PermissionCheckScope.global()))
        assertFalse(hasPermission(snapshot, "chat.", PermissionCheckScope.global()))
    }

    @Test
    fun starPatternMatchesEveryPermission() {
        val snapshot = snapshot(grants = listOf(allow("*", ROLE)))

        assertTrue(hasPermission(snapshot, "any.permission", PermissionCheckScope.global()))
    }

    @Test
    fun denyBeatsAllowWhenSpecificityTies() {
        val snapshot =
            snapshot(grants = listOf(allow("economy.pay", ROLE), deny("economy.pay", ROLE)))

        assertFalse(hasPermission(snapshot, "economy.pay", PermissionCheckScope.global()))
    }

    @Test
    fun noMatchingAllowReturnsDenied() {
        val snapshot = snapshot(grants = listOf(allow("chat.read", ROLE)))

        assertFalse(hasPermission(snapshot, "chat.write", PermissionCheckScope.global()))
    }

    private fun hasPermission(
        snapshot: EffectivePermissionSnapshot,
        permission: String,
        scope: PermissionCheckScope,
        now: Instant = this.now,
    ): Boolean = PolicyEngine.hasPermission(snapshot, permission, scope, now)

    private fun snapshot(grants: List<PermissionGrant>) =
        PolicyEngine.createSnapshot(
            playerId = playerId,
            input =
                policy(
                    roles =
                        listOf(
                            role(
                                "member",
                                grants = grants.filter { it.source == ROLE }.map { it.toSpec() },
                            )
                        ),
                    playerRoles = listOf(PlayerRoleGrant(playerId, "member")),
                    playerGrants =
                        grants
                            .filter { it.source == PLAYER }
                            .map { PlayerPermissionGrant(playerId, it.toSpec()) },
                ),
            now = now,
        )

    private fun policy(
        roles: List<RoleDefinition>,
        playerRoles: List<PlayerRoleGrant> = emptyList(),
        playerGrants: List<PlayerPermissionGrant> = emptyList(),
        expiresAt: Instant = now.plusSeconds(300),
    ) =
        PermissionPolicyInput(
            policyVersion = 1,
            roles = roles,
            playerRoles = playerRoles,
            playerGrants = playerGrants,
            refreshAfter = now.plusSeconds(60),
            expiresAt = expiresAt,
        )

    private fun role(
        key: String,
        default: Boolean = false,
        inherits: Set<String> = emptySet(),
        grants: List<PermissionGrantSpec> = emptyList(),
    ) =
        RoleDefinition(
            key = key,
            name = key,
            isDefault = default,
            inheritedRoleKeys = inherits,
            grants = grants,
        )

    private fun allowSpec(
        pattern: String,
        scope: PermissionScope = PermissionScope(GLOBAL),
        expiresAt: Instant? = null,
    ) = PermissionGrantSpec(effect = ALLOW, pattern = pattern, scope = scope, expiresAt = expiresAt)

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

    private fun denySpec(
        pattern: String,
        scope: PermissionScope = PermissionScope(GLOBAL),
        expiresAt: Instant? = null,
    ) = PermissionGrantSpec(effect = DENY, pattern = pattern, scope = scope, expiresAt = expiresAt)

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

    private fun PermissionGrant.toSpec() =
        PermissionGrantSpec(
            effect = effect,
            pattern = pattern,
            scope = scope,
            expiresAt = expiresAt,
        )
}
