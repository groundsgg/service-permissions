package gg.grounds.permissions.sync

import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionScopeKind
import java.time.Instant
import java.util.UUID

data class SyncRole(
    val key: String,
    val name: String,
    val description: String = "",
    val prefix: String? = null,
    val color: String? = null,
    val sortOrder: Int = 0,
    val metadata: Map<String, String> = emptyMap(),
    val isDefault: Boolean = false,
)

data class SyncRoleGrant(
    val id: UUID,
    val roleKey: String,
    val effect: PermissionEffect,
    val permissionPattern: String,
    val scopeKind: PermissionScopeKind,
    val scopeValue: String? = null,
    val expiresAt: Instant? = null,
)

data class SyncInheritance(val parentRoleKey: String, val childRoleKey: String)

data class SyncCatalogEntry(
    val permissionKey: String,
    val label: String,
    val description: String = "",
    val source: String,
    val sourceVersion: String,
    val supportedScopes: List<PermissionScopeKind>,
    val custom: Boolean = false,
    val lastSeenAt: Instant? = null,
)

data class SyncKeycloakMapping(
    val id: UUID,
    val keycloakGroup: String,
    val roleKey: String,
    val expiresAt: Instant? = null,
)

data class SyncPlayerGrant(val technicalKey: String)

data class GlobalPermissionSnapshot(
    val snapshotId: String,
    val roles: List<SyncRole>,
    val roleGrants: List<SyncRoleGrant>,
    val inheritance: List<SyncInheritance>,
    val catalogEntries: List<SyncCatalogEntry>,
    val keycloakMappings: List<SyncKeycloakMapping>? = emptyList(),
    val playerGrants: List<SyncPlayerGrant>? = emptyList(),
    val playerRoleGrants: List<SyncPlayerGrant>? = emptyList(),
    val createdAt: Instant? = null,
) {
    init {
        require(playerGrants.orEmpty().isEmpty()) { "playerGrants must not be provided" }
        require(playerRoleGrants.orEmpty().isEmpty()) { "playerRoleGrants must not be provided" }
        require(snapshotId.isNotBlank()) { "snapshotId must not be blank" }
    }
}

data class PermissionProjectSnapshot(
    val roles: List<SyncRole>,
    val roleGrants: List<SyncRoleGrant>,
    val inheritance: List<SyncInheritance>,
    val catalogEntries: List<SyncCatalogEntry>,
    val keycloakMappings: List<SyncKeycloakMapping>,
)

enum class SyncEntityType {
    ROLE,
    ROLE_GRANT,
    INHERITANCE,
    CATALOG_ENTRY,
    KEYCLOAK_MAPPING,
}

enum class SyncChangeKind {
    IMPORT,
    CONFLICT,
    PROJECT_ONLY,
}

data class SyncChange(
    val entityType: SyncEntityType,
    val technicalKey: String,
    val kind: SyncChangeKind,
)

data class PermissionSyncDiff(
    val changes: List<SyncChange>,
    val projectOnlyEntries: Set<SyncChange>,
) {
    val conflicts: Set<SyncChange> =
        changes.filterTo(linkedSetOf()) { it.kind == SyncChangeKind.CONFLICT }

    companion object {
        fun calculate(
            project: PermissionProjectSnapshot,
            global: GlobalPermissionSnapshot,
        ): PermissionSyncDiff {
            val changes = buildList {
                compare(
                    SyncEntityType.ROLE,
                    project.roles.associateBy { it.key },
                    global.roles.associateBy { it.key },
                )
                compare(
                    SyncEntityType.ROLE_GRANT,
                    project.roleGrants.associateBy { it.id },
                    global.roleGrants.associateBy { it.id },
                )
                compare(
                    SyncEntityType.INHERITANCE,
                    project.inheritance.associateBy { it.key() },
                    global.inheritance.associateBy { it.key() },
                )
                compare(
                    SyncEntityType.CATALOG_ENTRY,
                    project.catalogEntries.associateBy { it.permissionKey },
                    global.catalogEntries.associateBy { it.permissionKey },
                )
                compare(
                    SyncEntityType.KEYCLOAK_MAPPING,
                    project.keycloakMappings.associateBy { it.id },
                    global.keycloakMappings.orEmpty().associateBy { it.id },
                )
            }
            return PermissionSyncDiff(
                changes,
                changes.filterTo(linkedSetOf()) { it.kind == SyncChangeKind.PROJECT_ONLY },
            )
        }

        private fun MutableList<SyncChange>.compare(
            type: SyncEntityType,
            project: Map<Any, Any>,
            global: Map<Any, Any>,
        ) {
            (project.keys + global.keys).distinct().sortedBy(Any::toString).forEach { key ->
                val projectValue = project[key]
                val globalValue = global[key]
                when {
                    projectValue == null ->
                        add(SyncChange(type, key.toString(), SyncChangeKind.IMPORT))
                    globalValue == null ->
                        add(SyncChange(type, key.toString(), SyncChangeKind.PROJECT_ONLY))
                    projectValue != globalValue ->
                        add(SyncChange(type, key.toString(), SyncChangeKind.CONFLICT))
                }
            }
        }

        private fun SyncInheritance.key() = "$parentRoleKey->$childRoleKey"
    }
}

enum class SyncAction {
    IMPORT,
    KEEP_PROJECT,
    USE_GLOBAL,
    REMOVE_PROJECT_ENTRY,
}

data class PermissionSyncAction(
    val entityType: SyncEntityType,
    val technicalKey: String,
    val action: SyncAction,
)

data class PermissionSyncImportRequest(
    val snapshot: GlobalPermissionSnapshot,
    val actions: List<PermissionSyncAction> = emptyList(),
) {
    fun validatedAgainst(diff: PermissionSyncDiff): PermissionSyncImportRequest {
        val actionsByKey = actions.associateBy { it.entityType to it.technicalKey }
        diff.conflicts.forEach { change ->
            val action = actionsByKey[change.entityType to change.technicalKey]?.action
            require(
                action in setOf(SyncAction.IMPORT, SyncAction.KEEP_PROJECT, SyncAction.USE_GLOBAL)
            ) {
                "Explicit action required (entityType=${change.entityType}, technicalKey=${change.technicalKey})"
            }
        }
        actions.forEach { action ->
            val change =
                diff.changes.firstOrNull {
                    it.entityType == action.entityType && it.technicalKey == action.technicalKey
                }
            require(change != null) {
                "Unknown sync action (entityType=${action.entityType}, technicalKey=${action.technicalKey})"
            }
            require(
                when (change.kind) {
                    SyncChangeKind.PROJECT_ONLY -> action.action == SyncAction.REMOVE_PROJECT_ENTRY
                    SyncChangeKind.IMPORT -> action.action == SyncAction.IMPORT
                    SyncChangeKind.CONFLICT -> action.action != SyncAction.REMOVE_PROJECT_ENTRY
                }
            ) {
                "Invalid sync action (entityType=${action.entityType}, technicalKey=${action.technicalKey})"
            }
        }
        return this
    }
}

data class PermissionSyncPreviewResponse(
    val snapshotId: String,
    val changes: List<SyncChange>,
    val conflicts: Set<SyncChange>,
    val projectOnlyEntries: Set<SyncChange>,
)
