package gg.grounds.permissions.sync

import gg.grounds.permissions.auth.PermissionInstanceEnvironment
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionSyncMetadataRecord
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.time.Instant
import java.util.Optional
import java.util.UUID
import org.eclipse.microprofile.config.inject.ConfigProperty

@ApplicationScoped
class PermissionSyncService
@Inject
constructor(
    private val repository: PermissionRepository,
    @ConfigProperty(name = "permissions.instance-environment", defaultValue = " ")
    instanceEnvironmentConfig: Optional<String>,
    @param:ConfigProperty(name = "quarkus.application.version", defaultValue = "dev")
    private val serviceVersion: String,
    private val fingerprint: PermissionSnapshotFingerprint,
) {
    private val instanceEnvironment =
        PermissionInstanceEnvironment.fromConfig(instanceEnvironmentConfig.orElse(null))

    fun snapshot(): GlobalPermissionSnapshot {
        val current = repository.permissionProjectSnapshot()
        return GlobalPermissionSnapshot(
            schemaVersion = SNAPSHOT_SCHEMA_VERSION,
            sourceEnvironment = sourceEnvironment(),
            sourceServiceVersion = serviceVersion,
            snapshotId = UUID.randomUUID().toString(),
            roles = current.roles,
            roleGrants = current.roleGrants,
            inheritance = current.inheritance,
            catalogEntries = current.catalogEntries,
            keycloakMappings = current.keycloakMappings,
            createdAt = Instant.now(),
        )
    }

    fun preview(snapshot: GlobalPermissionSnapshot): PermissionSyncPreviewResponse {
        validateCompatibility(snapshot)
        val target = repository.permissionProjectSnapshot()
        val diff = PermissionSyncDiff.calculate(target, snapshot)
        return PermissionSyncPreviewResponse(
            snapshotId = snapshot.snapshotId,
            targetFingerprint = fingerprint.calculate(target),
            changes = diff.changes,
            conflicts = diff.conflicts,
            projectOnlyEntries = diff.projectOnlyEntries,
        )
    }

    fun import(
        request: PermissionSyncImportRequest,
        actorUserId: String,
    ): PermissionSyncMetadataRecord {
        validateCompatibility(request.snapshot)
        return repository.importPermissionSnapshot(
            snapshot = request.snapshot,
            expectedTargetFingerprint = request.expectedTargetFingerprint,
            actions = request.actions,
            actorUserId = actorUserId,
        )
    }

    private fun validateCompatibility(snapshot: GlobalPermissionSnapshot) {
        if (snapshot.schemaVersion != SNAPSHOT_SCHEMA_VERSION) {
            throw PermissionSyncConflictException(PermissionSyncConflictReason.UNSUPPORTED_SCHEMA)
        }
        if (snapshot.sourceEnvironment != expectedSourceEnvironment()) {
            throw PermissionSyncConflictException(PermissionSyncConflictReason.INCOMPATIBLE_SOURCE)
        }
    }

    private fun sourceEnvironment(): String =
        instanceEnvironment?.configValue ?: PROJECT_ENVIRONMENT

    private fun expectedSourceEnvironment(): String =
        when (instanceEnvironment) {
            null,
            PermissionInstanceEnvironment.STAGE ->
                PermissionInstanceEnvironment.PRODUCTION.configValue
            PermissionInstanceEnvironment.PRODUCTION ->
                PermissionInstanceEnvironment.STAGE.configValue
        }

    private companion object {
        const val SNAPSHOT_SCHEMA_VERSION = 1
        const val PROJECT_ENVIRONMENT = "project"
    }
}

enum class PermissionSyncConflictReason(val wireValue: String) {
    UNSUPPORTED_SCHEMA("unsupported_schema"),
    INCOMPATIBLE_SOURCE("incompatible_source"),
    TARGET_CHANGED("target_changed"),
}

class PermissionSyncConflictException(val reason: PermissionSyncConflictReason) :
    RuntimeException(reason.wireValue)
