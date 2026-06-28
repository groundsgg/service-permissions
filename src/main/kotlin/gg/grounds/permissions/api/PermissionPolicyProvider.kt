package gg.grounds.permissions.api

import gg.grounds.permissions.domain.PermissionPolicyInput
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
class EmptyPermissionPolicyProvider : PermissionPolicyProvider {
    override fun policyFor(request: PermissionPolicyRequest): PermissionPolicyInput {
        val now = Instant.now()

        return PermissionPolicyInput(
            policyVersion = 1,
            roles = emptyList(),
            playerRoles = emptyList(),
            playerGrants = emptyList(),
            refreshAfter = now.plus(REFRESH_AFTER_OFFSET),
            expiresAt = now.plus(EXPIRES_AFTER_OFFSET),
        )
    }

    companion object {
        private val REFRESH_AFTER_OFFSET = Duration.ofMinutes(5)
        private val EXPIRES_AFTER_OFFSET = Duration.ofMinutes(10)
    }
}
