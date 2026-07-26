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

@Schema(description = "Effective permission snapshot consumed by a runtime workload.")
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

@Schema(description = "Effective runtime permission grant.")
data class RuntimePermissionGrantDto(
    val effect: PermissionEffect,
    val pattern: String,
    val scope: PermissionScopeDto,
    val source: PermissionGrantSource,
    val expiresAt: Instant?,
)

@Schema(description = "Scope that limits where a runtime permission grant applies.")
data class PermissionScopeDto(val kind: PermissionScopeKind, val value: String?)

@Schema(description = "Display metadata for an effective runtime role.")
data class RuntimeRoleMetadataDto(
    val key: String,
    val name: String,
    val prefix: String?,
    val color: String?,
    val sortOrder: Int,
)

@JsonIgnoreProperties(ignoreUnknown = false)
@Schema(
    description =
        "Complete permission catalog manifest published by one runtime source; permission keys must be unique and source must not appear in the body.",
    requiredProperties = ["sourceVersion", "permissions"],
)
data class RuntimeManifestRequest(
    @field:Schema(nullable = false, minLength = 1, pattern = "\\S") val sourceVersion: String?,
    @field:Schema(required = false, nullable = true, minLength = 1, pattern = "\\S")
    val serverType: String?,
    @field:Schema(required = false, nullable = true, minLength = 1, pattern = "\\S")
    val serverId: String?,
    @field:Schema(nullable = false, minItems = 1)
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
@Schema(
    description = "Permission catalog entry contained in a runtime manifest.",
    requiredProperties = ["key", "label", "supportedScopes"],
)
data class RuntimeManifestPermissionRequest(
    @field:Schema(nullable = false, minLength = 1, pattern = "^[a-z0-9._-]+$") val key: String?,
    @field:Schema(nullable = false, minLength = 1, pattern = "\\S") val label: String?,
    @field:Schema(required = false, nullable = true) val description: String?,
    @field:Schema(nullable = false, minItems = 1) val supportedScopes: List<PermissionScopeKind>?,
)
