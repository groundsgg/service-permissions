package gg.grounds.permissions.identity

import java.time.Instant
import java.util.UUID

class IdentityProjectionUnavailableException :
    IllegalStateException("Player identity projection is unavailable")

data class ProjectedPlayerIdentity(
    val playerId: UUID,
    val keycloakUserId: String,
    val minecraftUsername: String,
    val normalizedUsername: String,
    val groupPaths: Set<String>,
    val syncedAt: Instant,
    val sourceUpdatedAt: Instant?,
)

data class PlayerSearchItem(
    val playerId: UUID,
    val minecraftUsername: String,
    val directRoleGrantCount: Long,
    val directPermissionGrantCount: Long,
)

data class PlayerSearchPage(
    val items: List<PlayerSearchItem>,
    val page: Int,
    val perPage: Int,
    val total: Long,
)

enum class IdentitySyncStatus {
    IDLE,
    RUNNING,
    FAILED,
}

data class IdentitySyncState(
    val status: IdentitySyncStatus,
    val startedAt: Instant?,
    val completedAt: Instant?,
    val lastSuccessAt: Instant?,
    val durationMs: Long?,
    val playerCount: Long,
    val failureReason: String?,
)

interface PlayerIdentityStore {
    fun findByPlayerId(playerId: UUID): ProjectedPlayerIdentity?

    fun findByKeycloakUserId(keycloakUserId: String): ProjectedPlayerIdentity?

    fun search(query: String, page: Int, perPage: Int): PlayerSearchPage

    fun replacePlayer(identity: ProjectedPlayerIdentity)

    fun deleteByKeycloakUserId(keycloakUserId: String)

    fun replaceAll(identities: List<ProjectedPlayerIdentity>, completedAt: Instant)

    fun markSyncRunning(startedAt: Instant)

    fun tryMarkSyncRunning(startedAt: Instant, staleBefore: Instant): Boolean

    fun markSyncFailed(completedAt: Instant, failureReason: String)

    fun currentSyncState(): IdentitySyncState
}
