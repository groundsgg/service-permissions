package gg.grounds.permissions.sync

import com.fasterxml.jackson.annotation.JsonProperty
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionScopeKind
import java.time.Instant
import java.util.UUID
import org.eclipse.microprofile.openapi.annotations.media.Schema

@Schema(description = "Permission role contained in an environment snapshot.")
data class SyncRole(
    val key: String,
    val name: String,
    val description: String = "",
    val prefix: String? = null,
    val color: String? = null,
    val sortOrder: Int = 0,
    val metadata: Map<String, String> = emptyMap(),
    @get:JsonProperty("default") @param:JsonProperty("default") val isDefault: Boolean = false,
)

@Schema(description = "Role permission grant contained in an environment snapshot.")
data class SyncRoleGrant(
    val id: UUID,
    val roleKey: String,
    val effect: PermissionEffect,
    val permissionPattern: String,
    val scopeKind: PermissionScopeKind,
    val scopeValue: String? = null,
    val expiresAt: Instant? = null,
)

@Schema(description = "Parent-child role inheritance edge contained in an environment snapshot.")
data class SyncInheritance(val parentRoleKey: String, val childRoleKey: String)

@Schema(description = "Permission catalog entry contained in an environment snapshot.")
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

@Schema(description = "Keycloak group-to-role mapping contained in an environment snapshot.")
data class SyncKeycloakMapping(
    val id: UUID,
    val keycloakGroup: String,
    val roleKey: String,
    val expiresAt: Instant? = null,
)

@Schema(description = "Rejected player-specific grant marker in a global environment snapshot.")
data class SyncPlayerGrant(val technicalKey: String)

@Schema(
    description =
        "Transferable global permission snapshot. Player-specific grant arrays must be absent or empty."
)
data class GlobalPermissionSnapshot(
    @field:Schema(constValue = "1") val schemaVersion: Int = 0,
    @field:Schema(enumeration = ["project", "stage", "prod"]) val sourceEnvironment: String = "",
    val sourceServiceVersion: String = "",
    @field:Schema(minLength = 1, pattern = "\\S") val snapshotId: String,
    val roles: List<SyncRole>,
    val roleGrants: List<SyncRoleGrant>,
    val inheritance: List<SyncInheritance>,
    val catalogEntries: List<SyncCatalogEntry>,
    val keycloakMappings: List<SyncKeycloakMapping>? = emptyList(),
    @field:Schema(maxItems = 0) val playerGrants: List<SyncPlayerGrant>? = emptyList(),
    @field:Schema(maxItems = 0) val playerRoleGrants: List<SyncPlayerGrant>? = emptyList(),
    val createdAt: Instant? = null,
) {
    init {
        require(playerGrants.orEmpty().isEmpty()) { "playerGrants must not be provided" }
        require(playerRoleGrants.orEmpty().isEmpty()) { "playerRoleGrants must not be provided" }
        require(snapshotId.isNotBlank()) { "snapshotId must not be blank" }
    }
}

@Schema(description = "Current project permission state used for environment comparison.")
data class PermissionProjectSnapshot(
    val roles: List<SyncRole>,
    val roleGrants: List<SyncRoleGrant>,
    val inheritance: List<SyncInheritance>,
    val catalogEntries: List<SyncCatalogEntry>,
    val keycloakMappings: List<SyncKeycloakMapping>,
)

@Schema(description = "Permission entity category used by environment synchronization.")
enum class SyncEntityType {
    ROLE,
    ROLE_GRANT,
    INHERITANCE,
    CATALOG_ENTRY,
    KEYCLOAK_MAPPING,
}

@Schema(description = "Kind of difference between target and imported permission state.")
enum class SyncChangeKind {
    IMPORT,
    CONFLICT,
    PROJECT_ONLY,
}

@Schema(description = "One permission entity difference in an environment-sync preview.")
data class SyncChange(
    val entityType: SyncEntityType,
    val technicalKey: String,
    val kind: SyncChangeKind,
)

@Schema(description = "Calculated differences between project and global permission state.")
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
            val normalizedProject = PermissionSyncPolicyProjection.normalize(project)
            val normalizedGlobal = PermissionSyncPolicyProjection.normalize(global)
            val changes = buildList {
                compare(
                    SyncEntityType.ROLE,
                    normalizedProject.roles.associateBy { it.key },
                    normalizedGlobal.roles.associateBy { it.key },
                )
                compare(
                    SyncEntityType.ROLE_GRANT,
                    normalizedProject.roleGrants.associateBy { it.id },
                    normalizedGlobal.roleGrants.associateBy { it.id },
                )
                compare(
                    SyncEntityType.INHERITANCE,
                    normalizedProject.inheritance.associateBy { it.key() },
                    normalizedGlobal.inheritance.associateBy { it.key() },
                )
                compare(
                    SyncEntityType.CATALOG_ENTRY,
                    normalizedProject.catalogEntries.associateBy { it.permissionKey },
                    normalizedGlobal.catalogEntries.associateBy { it.permissionKey },
                )
                compare(
                    SyncEntityType.KEYCLOAK_MAPPING,
                    normalizedProject.keycloakMappings.associateBy { it.id },
                    normalizedGlobal.keycloakMappings.associateBy { it.id },
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

@Schema(description = "Resolution action applied to an environment-sync change.")
enum class SyncAction {
    IMPORT,
    KEEP_PROJECT,
    USE_GLOBAL,
    REMOVE_PROJECT_ENTRY,
}

@Schema(description = "Selected resolution for one environment-sync entity change.")
data class PermissionSyncAction(
    val entityType: SyncEntityType,
    val technicalKey: String,
    val action: SyncAction,
)

@Schema(
    description =
        "Environment import request. Each entityType and technicalKey pair must be unique, and every action must match the previewed change and its allowed resolution."
)
data class PermissionSyncImportRequest(
    val snapshot: GlobalPermissionSnapshot,
    @field:Schema(minLength = 1, pattern = "\\S") val expectedTargetFingerprint: String,
    val actions: List<PermissionSyncAction> = emptyList(),
) {
    init {
        require(expectedTargetFingerprint.isNotBlank()) {
            "expectedTargetFingerprint must not be blank"
        }
        val duplicateKey =
            actions
                .groupingBy { it.entityType to it.technicalKey }
                .eachCount()
                .filterValues { it > 1 }
                .keys
                .sortedWith(compareBy({ it.first.ordinal }, { it.second }))
                .firstOrNull()
        require(duplicateKey == null) {
            "Duplicate sync action (entityType=${duplicateKey?.first}, technicalKey=${duplicateKey?.second})"
        }
    }

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

@Schema(description = "Preview of permission changes produced by an environment snapshot.")
data class PermissionSyncPreviewResponse(
    val snapshotId: String,
    val targetFingerprint: String,
    val changes: List<SyncChange>,
    val conflicts: Set<SyncChange>,
    val projectOnlyEntries: Set<SyncChange>,
)
