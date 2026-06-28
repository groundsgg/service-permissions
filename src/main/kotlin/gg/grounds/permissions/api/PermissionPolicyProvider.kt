package gg.grounds.permissions.api

import gg.grounds.permissions.domain.PermissionPolicyInput
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.PlayerRoleGrant
import gg.grounds.permissions.domain.RoleDefinition
import jakarta.enterprise.context.ApplicationScoped
import java.time.Duration
import java.time.Instant
import java.util.UUID

data class PermissionPolicyRequest(
    val playerId: UUID,
    val keycloakGroups: Set<String>,
    val serverType: String,
    val serverId: String,
)

interface PermissionPolicyProvider {
    fun policyFor(request: PermissionPolicyRequest): PermissionPolicyInput
}

@ApplicationScoped
class InMemoryPermissionPolicyProvider : PermissionPolicyProvider {
    private var policyVersion: Long = 1
    private var roles: List<RoleDefinition> = emptyList()
    private var keycloakRoleMappings: Map<String, Set<String>> = emptyMap()
    private var playerRoles: List<PlayerRoleGrant> = emptyList()
    private var playerGrants: List<PlayerPermissionGrant> = emptyList()
    private var refreshAfterOffset: Duration = Duration.ofMinutes(5)
    private var expiresAfterOffset: Duration = Duration.ofMinutes(10)

    @Synchronized
    fun replacePolicy(
        policyVersion: Long = 1,
        roles: List<RoleDefinition> = emptyList(),
        keycloakRoleMappings: Map<String, Set<String>> = emptyMap(),
        playerRoles: List<PlayerRoleGrant> = emptyList(),
        playerGrants: List<PlayerPermissionGrant> = emptyList(),
        refreshAfterOffset: Duration = Duration.ofMinutes(5),
        expiresAfterOffset: Duration = Duration.ofMinutes(10),
    ) {
        this.policyVersion = policyVersion
        this.roles = roles
        this.keycloakRoleMappings = keycloakRoleMappings
        this.playerRoles = playerRoles
        this.playerGrants = playerGrants
        this.refreshAfterOffset = refreshAfterOffset
        this.expiresAfterOffset = expiresAfterOffset
    }

    @Synchronized
    override fun policyFor(request: PermissionPolicyRequest): PermissionPolicyInput {
        val now = Instant.now()
        val mappedRoles =
            request.keycloakGroups
                .asSequence()
                .flatMap { keycloakRoleMappings[it].orEmpty().asSequence() }
                .distinct()
                .map { roleKey -> PlayerRoleGrant(request.playerId, roleKey) }
                .toList()

        return PermissionPolicyInput(
            policyVersion = policyVersion,
            roles = roles,
            playerRoles = playerRoles + mappedRoles,
            playerGrants = playerGrants,
            refreshAfter = now.plus(refreshAfterOffset),
            expiresAt = now.plus(expiresAfterOffset),
        )
    }
}
