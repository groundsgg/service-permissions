package gg.grounds.permissions.api

import gg.grounds.permissions.domain.PermissionPolicyInput
import gg.grounds.permissions.persistence.PermissionRepository
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.util.UUID

data class PermissionPolicyRequest(val playerId: UUID, val serverType: String, val serverId: String)

interface PermissionPolicyProvider {
    fun policyFor(request: PermissionPolicyRequest): PermissionPolicyInput
}

@ApplicationScoped
class DatabasePermissionPolicyProvider
@Inject
constructor(private val repository: PermissionRepository) : PermissionPolicyProvider {
    override fun policyFor(request: PermissionPolicyRequest): PermissionPolicyInput =
        repository.policyFor(request)
}
