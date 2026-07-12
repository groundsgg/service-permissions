package gg.grounds.permissions.sync

import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionSyncMetadataRecord
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject

@ApplicationScoped
class PermissionSyncService @Inject constructor(private val repository: PermissionRepository) {
    fun preview(snapshot: GlobalPermissionSnapshot): PermissionSyncDiff =
        PermissionSyncDiff.calculate(repository.permissionProjectSnapshot(), snapshot)

    fun import(
        request: PermissionSyncImportRequest,
        actorUserId: String,
    ): PermissionSyncMetadataRecord {
        val diff = preview(request.snapshot)
        request.validatedAgainst(diff)
        return repository.importPermissionSnapshot(request.snapshot, request.actions, actorUserId)
    }
}
