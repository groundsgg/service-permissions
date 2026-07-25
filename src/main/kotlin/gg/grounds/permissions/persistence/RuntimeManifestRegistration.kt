package gg.grounds.permissions.persistence

import java.time.Instant

data class RuntimeManifestRegistration(
    val source: String,
    val sourceVersion: String,
    val serverType: String?,
    val serverId: String?,
    val permissions: List<CatalogEntryRecord>,
    val registeredAt: Instant,
)
