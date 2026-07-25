package gg.grounds.permissions.sync

object PermissionSyncPolicyProjection {
    fun normalize(snapshot: PermissionProjectSnapshot): PermissionProjectSnapshot =
        PermissionProjectSnapshot(
            roles = normalizeRoles(snapshot.roles),
            roleGrants = snapshot.roleGrants.sortedBy { it.id.toString() },
            inheritance =
                snapshot.inheritance.sortedWith(
                    compareBy(SyncInheritance::parentRoleKey, SyncInheritance::childRoleKey)
                ),
            catalogEntries = normalizeCatalogEntries(snapshot.catalogEntries),
            keycloakMappings = snapshot.keycloakMappings.sortedBy { it.id.toString() },
        )

    fun normalize(snapshot: GlobalPermissionSnapshot): PermissionProjectSnapshot =
        PermissionProjectSnapshot(
            roles = normalizeRoles(snapshot.roles),
            roleGrants = snapshot.roleGrants.sortedBy { it.id.toString() },
            inheritance =
                snapshot.inheritance.sortedWith(
                    compareBy(SyncInheritance::parentRoleKey, SyncInheritance::childRoleKey)
                ),
            catalogEntries = normalizeCatalogEntries(snapshot.catalogEntries),
            keycloakMappings = snapshot.keycloakMappings.orEmpty().sortedBy { it.id.toString() },
        )

    private fun normalizeRoles(roles: List<SyncRole>): List<SyncRole> =
        roles.map { it.copy(metadata = it.metadata.toSortedMap()) }.sortedBy(SyncRole::key)

    private fun normalizeCatalogEntries(entries: List<SyncCatalogEntry>): List<SyncCatalogEntry> =
        entries
            .map { entry ->
                entry.copy(
                    supportedScopes = entry.supportedScopes.sortedBy { it.name },
                    lastSeenAt = null,
                )
            }
            .sortedBy(SyncCatalogEntry::permissionKey)
}
