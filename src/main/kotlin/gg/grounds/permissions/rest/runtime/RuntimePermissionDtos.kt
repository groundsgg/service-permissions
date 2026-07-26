package gg.grounds.permissions.rest.runtime

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonSetter
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionGrantSource
import gg.grounds.permissions.domain.PermissionScopeKind
import java.time.Instant
import java.util.UUID
import org.eclipse.microprofile.openapi.annotations.media.Schema

data class RuntimePermissionSnapshotResponse(
    val playerId: UUID,
    val policyVersion: Long,
    val issuedAt: Instant,
    val refreshAfter: Instant,
    val expiresAt: Instant,
    val allowPatterns: List<RuntimePermissionGrantDto>,
    val denyPatterns: List<RuntimePermissionGrantDto>,
    val roleKeys: Set<String>,
    val roleMetadata: List<RuntimeRoleMetadataDto>,
)

data class RuntimePermissionGrantDto(
    val effect: PermissionEffect,
    val pattern: String,
    val scope: PermissionScopeDto,
    val source: PermissionGrantSource,
    val expiresAt: Instant?,
)

data class PermissionScopeDto(val kind: PermissionScopeKind, val value: String?)

data class RuntimeRoleMetadataDto(
    val key: String,
    val name: String,
    val prefix: String?,
    val color: String?,
    val sortOrder: Int,
)

@JsonIgnoreProperties(ignoreUnknown = false)
data class RuntimeManifestRequest(
    val sourceVersion: String?,
    val serverType: String?,
    val serverId: String?,
    val permissions: List<RuntimeManifestPermissionRequest>?,
) {
    @field:JsonIgnore @field:Schema(hidden = true) private var bodySourcePresent: Boolean = false

    @JsonSetter("source")
    private fun recordBodySource(@Suppress("UNUSED_PARAMETER") value: Any?) {
        bodySourcePresent = true
    }

    @JsonIgnore fun containsBodySource(): Boolean = bodySourcePresent
}

@JsonIgnoreProperties(ignoreUnknown = false)
data class RuntimeManifestPermissionRequest(
    val key: String?,
    val label: String?,
    val description: String?,
    val supportedScopes: List<PermissionScopeKind>?,
)
