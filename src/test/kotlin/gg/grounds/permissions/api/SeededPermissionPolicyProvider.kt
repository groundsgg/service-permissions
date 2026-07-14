package gg.grounds.permissions.api

import gg.grounds.permissions.domain.PermissionPolicyInput
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.PlayerRoleGrant
import gg.grounds.permissions.domain.RoleDefinition
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.inject.Alternative
import java.time.Duration
import java.time.Instant

@Alternative
@ApplicationScoped
class SeededPermissionPolicyProvider : PermissionPolicyProvider {
    private var policyVersion: Long = 1
    private var roles: List<RoleDefinition> = emptyList()
    private var playerRoles: List<PlayerRoleGrant> = emptyList()
    private var playerGrants: List<PlayerPermissionGrant> = emptyList()
    private var refreshAfterOffset: Duration = Duration.ofMinutes(5)
    private var expiresAfterOffset: Duration = Duration.ofMinutes(10)

    @Synchronized
    fun replacePolicy(
        policyVersion: Long = 1,
        roles: List<RoleDefinition> = emptyList(),
        playerRoles: List<PlayerRoleGrant> = emptyList(),
        playerGrants: List<PlayerPermissionGrant> = emptyList(),
        refreshAfterOffset: Duration = Duration.ofMinutes(5),
        expiresAfterOffset: Duration = Duration.ofMinutes(10),
    ) {
        this.policyVersion = policyVersion
        this.roles = roles
        this.playerRoles = playerRoles
        this.playerGrants = playerGrants
        this.refreshAfterOffset = refreshAfterOffset
        this.expiresAfterOffset = expiresAfterOffset
    }

    @Synchronized
    override fun policyFor(request: PermissionPolicyRequest): PermissionPolicyInput {
        val now = Instant.now()

        return PermissionPolicyInput(
            policyVersion = policyVersion,
            roles = roles,
            playerRoles = playerRoles,
            playerGrants = playerGrants,
            refreshAfter = now.plus(refreshAfterOffset),
            expiresAt = now.plus(expiresAfterOffset),
        )
    }
}
