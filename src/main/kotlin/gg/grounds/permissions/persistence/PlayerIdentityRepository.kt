package gg.grounds.permissions.persistence

import gg.grounds.permissions.identity.IdentitySyncState
import gg.grounds.permissions.identity.IdentitySyncStatus
import gg.grounds.permissions.identity.PlayerIdentityStore
import gg.grounds.permissions.identity.PlayerSearchItem
import gg.grounds.permissions.identity.PlayerSearchPage
import gg.grounds.permissions.identity.ProjectedPlayerIdentity
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.util.Locale
import java.util.UUID
import javax.sql.DataSource

internal const val PLAYER_IDENTITY_MUTATION_LOCK_ID = 0x67726F756E647349L

@ApplicationScoped
class PlayerIdentityRepository @Inject constructor(private val dataSource: DataSource) :
    PlayerIdentityStore {

    override fun findByPlayerId(playerId: UUID): ProjectedPlayerIdentity? =
        findIdentity("player_id = ?") { statement -> statement.setObject(1, playerId) }

    override fun findByKeycloakUserId(keycloakUserId: String): ProjectedPlayerIdentity? =
        findIdentity("keycloak_user_id = ?") { statement -> statement.setString(1, keycloakUserId) }

    override fun listKeycloakUserIds(): Set<String> =
        dataSource.connection.use { connection ->
            connection
                .prepareStatement(
                    "SELECT keycloak_user_id FROM permission_player_identities ORDER BY keycloak_user_id"
                )
                .use { statement ->
                    statement.executeQuery().use { rows ->
                        buildSet {
                            while (rows.next()) {
                                add(rows.getString("keycloak_user_id"))
                            }
                        }
                    }
                }
        }

    fun findByNormalizedUsername(normalizedUsername: String): ProjectedPlayerIdentity? =
        findIdentity("minecraft_username_normalized = ?") { statement ->
            statement.setString(1, normalizedUsername.trim().lowercase(Locale.ROOT))
        }

    override fun search(query: String, page: Int, perPage: Int): PlayerSearchPage {
        require(page >= 1) { "Page must be at least one (page=$page)" }
        require(perPage >= 1) { "perPage must be at least one (perPage=$perPage)" }
        return searchAtOffset(query, (page - 1L) * perPage, perPage)
            .copy(page = page, perPage = perPage)
    }

    fun searchAtOffset(query: String, offset: Long, limit: Int): PlayerSearchPage {
        require(offset >= 0) { "offset must not be negative (offset=$offset)" }
        require(limit >= 0) { "limit must not be negative (limit=$limit)" }

        val normalizedQuery = query.trim().lowercase(Locale.ROOT)
        val searchPattern = "%${normalizedQuery.escapeLikePattern()}%"
        val result =
            dataSource.connection.use { connection ->
                connection
                    .prepareStatement(
                        """
                        WITH matching_identities AS (
                            SELECT identities.player_id,
                                   identities.minecraft_username,
                                   identities.minecraft_username_normalized,
                                   COALESCE(role_grants.direct_role_grant_count, 0) AS direct_role_grant_count,
                                   COALESCE(permission_grants.direct_permission_grant_count, 0) AS direct_permission_grant_count
                            FROM permission_player_identities identities
                            LEFT JOIN (
                                SELECT player_id, COUNT(*) AS direct_role_grant_count
                                FROM permission_player_role_grants
                                GROUP BY player_id
                            ) role_grants ON role_grants.player_id = identities.player_id
                            LEFT JOIN (
                                SELECT player_id, COUNT(*) AS direct_permission_grant_count
                                FROM permission_player_grants
                                GROUP BY player_id
                            ) permission_grants ON permission_grants.player_id = identities.player_id
                            WHERE ? = ''
                               OR identities.minecraft_username_normalized LIKE ? ESCAPE '\'
                               OR identities.player_id::text = ?
                        ),
                        paged_identities AS (
                            SELECT *
                            FROM matching_identities
                            ORDER BY minecraft_username_normalized ASC, player_id ASC
                            LIMIT ? OFFSET ?
                        )
                        SELECT paged_identities.player_id,
                               paged_identities.minecraft_username,
                               paged_identities.minecraft_username_normalized,
                               paged_identities.direct_role_grant_count,
                               paged_identities.direct_permission_grant_count,
                               totals.total_count
                        FROM (SELECT COUNT(*) AS total_count FROM matching_identities) totals
                        LEFT JOIN paged_identities ON TRUE
                        ORDER BY paged_identities.minecraft_username_normalized ASC,
                                 paged_identities.player_id ASC
                        """
                            .trimIndent()
                    )
                    .use { statement ->
                        statement.setString(1, normalizedQuery)
                        statement.setString(2, searchPattern)
                        statement.setString(3, normalizedQuery)
                        statement.setInt(4, limit)
                        statement.setLong(5, offset)
                        statement.executeQuery().use { resultSet ->
                            var total = 0L
                            val items = buildList {
                                while (resultSet.next()) {
                                    total = resultSet.getLong("total_count")
                                    if (resultSet.getObject("player_id") != null) {
                                        add(resultSet.toSearchItem())
                                    }
                                }
                            }
                            SearchResult(items, total)
                        }
                    }
            }

        return PlayerSearchPage(
            items = result.items,
            page = 1,
            perPage = limit,
            total = result.total,
        )
    }

    override fun replacePlayer(identity: ProjectedPlayerIdentity) {
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                acquireMutationLock(connection)
                if (clearTombstoneIfAccepted(connection, identity)) {
                    deleteRelinkedIdentity(connection, identity)
                    upsertIdentity(connection, identity)
                    replaceGroups(connection, identity.playerId, identity.groupPaths)
                }
                connection.commit()
            } catch (error: Throwable) {
                connection.rollback()
                throw error
            }
        }
    }

    override fun deleteByKeycloakUserId(keycloakUserId: String, deletedAt: Instant) {
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                acquireMutationLock(connection)
                upsertTombstone(connection, keycloakUserId, deletedAt)
                connection
                    .prepareStatement(
                        "DELETE FROM permission_player_identities WHERE keycloak_user_id = ?"
                    )
                    .use { statement ->
                        statement.setString(1, keycloakUserId)
                        statement.executeUpdate()
                    }
                connection.commit()
            } catch (error: Throwable) {
                connection.rollback()
                throw error
            }
        }
    }

    override fun replaceAll(identities: List<ProjectedPlayerIdentity>, completedAt: Instant) {
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                acquireMutationLock(connection)
                createReconciliationStage(connection)
                identities.forEach { identity -> stageIdentity(connection, identity) }
                clearObsoleteTombstones(connection)
                deleteRelinkedIdentities(connection)
                reconcileIdentities(connection)
                reconcileGroups(connection)
                deleteMissingIdentities(connection)
                completeSync(connection, completedAt)
                connection.commit()
            } catch (error: Throwable) {
                connection.rollback()
                throw error
            }
        }
    }

    override fun markSyncRunning(startedAt: Instant) {
        dataSource.connection.use { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_identity_sync_state
                    SET status = 'RUNNING',
                        started_at = ?,
                        completed_at = NULL,
                        duration_ms = NULL,
                        failure_reason = NULL
                    WHERE id = 1 AND status <> 'RUNNING'
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setTimestamp(1, Timestamp.from(startedAt))
                    check(statement.executeUpdate() == 1) { "Identity sync is already running" }
                }
        }
    }

    override fun tryMarkSyncRunning(startedAt: Instant, staleBefore: Instant): Boolean =
        dataSource.connection.use { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_identity_sync_state
                    SET status = 'RUNNING',
                        started_at = ?,
                        completed_at = NULL,
                        duration_ms = NULL,
                        failure_reason = NULL
                    WHERE id = 1
                      AND (status <> 'RUNNING' OR started_at < ?)
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setTimestamp(1, Timestamp.from(startedAt))
                    statement.setTimestamp(2, Timestamp.from(staleBefore))
                    statement.executeUpdate() == 1
                }
        }

    override fun markSyncFailed(completedAt: Instant, failureReason: String) {
        dataSource.connection.use { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_identity_sync_state
                    SET status = 'FAILED',
                        completed_at = ?,
                        duration_ms = CASE
                            WHEN started_at IS NULL THEN NULL
                            ELSE GREATEST(0, EXTRACT(EPOCH FROM (?::timestamptz - started_at)) * 1000)::BIGINT
                        END,
                        failure_reason = ?
                    WHERE id = 1 AND status = 'RUNNING'
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setTimestamp(1, Timestamp.from(completedAt))
                    statement.setTimestamp(2, Timestamp.from(completedAt))
                    statement.setString(3, failureReason)
                    check(statement.executeUpdate() == 1) { "Identity sync is not running" }
                }
        }
    }

    override fun currentSyncState(): IdentitySyncState =
        dataSource.connection.use { connection ->
            connection
                .prepareStatement(
                    """
                    SELECT status, started_at, completed_at, last_success_at, duration_ms, player_count,
                           failure_reason
                    FROM permission_identity_sync_state
                    WHERE id = 1
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.executeQuery().use { rows ->
                        check(rows.next()) { "Identity sync state row is missing" }
                        rows.toIdentitySyncState()
                    }
                }
        }

    private fun findIdentity(
        predicate: String,
        bind: (java.sql.PreparedStatement) -> Unit,
    ): ProjectedPlayerIdentity? =
        dataSource.connection.use { connection ->
            connection.prepareStatement(identityQuery(predicate)).use { statement ->
                bind(statement)
                statement.executeQuery().use { rows ->
                    if (rows.next()) rows.toIdentity() else null
                }
            }
        }

    private fun acquireMutationLock(connection: Connection) {
        connection.prepareStatement("SELECT pg_advisory_xact_lock(?)").use { statement ->
            statement.setLong(1, PLAYER_IDENTITY_MUTATION_LOCK_ID)
            statement.execute()
        }
    }

    private fun createReconciliationStage(connection: Connection) {
        connection
            .prepareStatement(
                """
                CREATE TEMP TABLE permission_player_identity_stage (
                    player_id UUID PRIMARY KEY,
                    keycloak_user_id TEXT NOT NULL,
                    minecraft_username TEXT NOT NULL,
                    minecraft_username_normalized TEXT NOT NULL,
                    synced_at TIMESTAMPTZ NOT NULL,
                    source_updated_at TIMESTAMPTZ
                ) ON COMMIT DROP
                """
                    .trimIndent()
            )
            .use { it.executeUpdate() }
        connection
            .prepareStatement(
                """
                CREATE TEMP TABLE permission_player_group_stage (
                    player_id UUID NOT NULL,
                    keycloak_group_path TEXT NOT NULL,
                    PRIMARY KEY (player_id, keycloak_group_path)
                ) ON COMMIT DROP
                """
                    .trimIndent()
            )
            .use { it.executeUpdate() }
    }

    private fun stageIdentity(connection: Connection, identity: ProjectedPlayerIdentity) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_player_identity_stage (
                    player_id, keycloak_user_id, minecraft_username, minecraft_username_normalized,
                    synced_at, source_updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setObject(1, identity.playerId)
                statement.setString(2, identity.keycloakUserId)
                statement.setString(3, identity.minecraftUsername)
                statement.setString(4, identity.normalizedUsername)
                statement.setTimestamp(5, Timestamp.from(identity.syncedAt))
                statement.setTimestamp(6, identity.sourceUpdatedAt?.let(Timestamp::from))
                statement.executeUpdate()
            }
        connection
            .prepareStatement(
                """
                INSERT INTO permission_player_group_stage (player_id, keycloak_group_path)
                VALUES (?, ?)
                """
                    .trimIndent()
            )
            .use { statement ->
                identity.groupPaths.forEach { groupPath ->
                    statement.setObject(1, identity.playerId)
                    statement.setString(2, groupPath)
                    statement.addBatch()
                }
                statement.executeBatch()
            }
    }

    private fun reconcileIdentities(connection: Connection) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_player_identities (
                    player_id, keycloak_user_id, minecraft_username, minecraft_username_normalized,
                    synced_at, source_updated_at
                )
                SELECT player_id, keycloak_user_id, minecraft_username, minecraft_username_normalized,
                       synced_at, source_updated_at
                FROM permission_player_identity_stage stage
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM permission_player_identity_tombstones tombstone
                    WHERE tombstone.keycloak_user_id = stage.keycloak_user_id
                      AND tombstone.deleted_at > (
                          SELECT started_at
                          FROM permission_identity_sync_state
                          WHERE id = 1
                      )
                )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM permission_player_identities existing
                    WHERE (
                        existing.player_id = stage.player_id
                        OR existing.keycloak_user_id = stage.keycloak_user_id
                    )
                      AND existing.synced_at > (
                          SELECT started_at
                          FROM permission_identity_sync_state
                          WHERE id = 1
                      )
                )
                ON CONFLICT (player_id) DO UPDATE
                SET keycloak_user_id = EXCLUDED.keycloak_user_id,
                    minecraft_username = EXCLUDED.minecraft_username,
                    minecraft_username_normalized = EXCLUDED.minecraft_username_normalized,
                    synced_at = EXCLUDED.synced_at,
                    source_updated_at = EXCLUDED.source_updated_at
                WHERE permission_player_identities.synced_at <= (
                    SELECT started_at
                    FROM permission_identity_sync_state
                    WHERE id = 1
                )
                """
                    .trimIndent()
            )
            .use { it.executeUpdate() }
    }

    private fun deleteRelinkedIdentities(connection: Connection) {
        connection
            .prepareStatement(
                """
                DELETE FROM permission_player_identities identities
                USING permission_player_identity_stage stage
                WHERE identities.keycloak_user_id = stage.keycloak_user_id
                  AND identities.player_id <> stage.player_id
                  AND NOT EXISTS (
                      SELECT 1
                      FROM permission_player_identity_tombstones tombstone
                      WHERE tombstone.keycloak_user_id = stage.keycloak_user_id
                        AND tombstone.deleted_at > (
                            SELECT started_at
                            FROM permission_identity_sync_state
                            WHERE id = 1
                        )
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM permission_player_identities existing
                      WHERE (
                          existing.player_id = stage.player_id
                          OR existing.keycloak_user_id = stage.keycloak_user_id
                      )
                        AND existing.synced_at > (
                            SELECT started_at
                            FROM permission_identity_sync_state
                            WHERE id = 1
                        )
                  )
                """
                    .trimIndent()
            )
            .use { it.executeUpdate() }
    }

    private fun clearObsoleteTombstones(connection: Connection) {
        connection
            .prepareStatement(
                """
                DELETE FROM permission_player_identity_tombstones tombstone
                USING permission_player_identity_stage stage
                WHERE tombstone.keycloak_user_id = stage.keycloak_user_id
                  AND tombstone.deleted_at <= (
                      SELECT started_at
                      FROM permission_identity_sync_state
                      WHERE id = 1
                  )
                """
                    .trimIndent()
            )
            .use { it.executeUpdate() }
    }

    private fun reconcileGroups(connection: Connection) {
        connection
            .prepareStatement(
                """
                DELETE FROM permission_player_keycloak_groups
                WHERE player_id IN (
                    SELECT stage.player_id
                    FROM permission_player_identity_stage stage
                    JOIN permission_player_identities identities
                      ON identities.player_id = stage.player_id
                     AND identities.keycloak_user_id = stage.keycloak_user_id
                     AND identities.synced_at = stage.synced_at
                )
                """
                    .trimIndent()
            )
            .use { it.executeUpdate() }
        connection
            .prepareStatement(
                """
                INSERT INTO permission_player_keycloak_groups (player_id, keycloak_group_path)
                SELECT player_id, keycloak_group_path
                FROM permission_player_group_stage groups
                WHERE EXISTS (
                    SELECT 1
                    FROM permission_player_identity_stage stage
                    JOIN permission_player_identities identities
                      ON identities.player_id = stage.player_id
                     AND identities.keycloak_user_id = stage.keycloak_user_id
                     AND identities.synced_at = stage.synced_at
                    WHERE stage.player_id = groups.player_id
                )
                """
                    .trimIndent()
            )
            .use { it.executeUpdate() }
    }

    private fun deleteMissingIdentities(connection: Connection) {
        connection
            .prepareStatement(
                """
                DELETE FROM permission_player_identities identities
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM permission_player_identity_stage stage
                    WHERE stage.player_id = identities.player_id
                )
                  AND identities.synced_at <= (
                      SELECT started_at
                      FROM permission_identity_sync_state
                      WHERE id = 1
                  )
                """
                    .trimIndent()
            )
            .use { it.executeUpdate() }
    }

    private fun completeSync(connection: Connection, completedAt: Instant) {
        connection
            .prepareStatement(
                """
                UPDATE permission_identity_sync_state
                SET status = 'IDLE',
                    completed_at = ?,
                    last_success_at = ?,
                    duration_ms = CASE
                        WHEN started_at IS NULL THEN NULL
                        ELSE GREATEST(0, EXTRACT(EPOCH FROM (?::timestamptz - started_at)) * 1000)::BIGINT
                    END,
                    player_count = (SELECT COUNT(*) FROM permission_player_identities),
                    failure_reason = NULL
                WHERE id = 1 AND status = 'RUNNING'
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setTimestamp(1, Timestamp.from(completedAt))
                statement.setTimestamp(2, Timestamp.from(completedAt))
                statement.setTimestamp(3, Timestamp.from(completedAt))
                check(statement.executeUpdate() == 1) { "Identity sync is not running" }
            }
    }

    private fun upsertIdentity(connection: Connection, identity: ProjectedPlayerIdentity) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_player_identities (
                    player_id, keycloak_user_id, minecraft_username, minecraft_username_normalized,
                    synced_at, source_updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (player_id) DO UPDATE
                SET keycloak_user_id = EXCLUDED.keycloak_user_id,
                    minecraft_username = EXCLUDED.minecraft_username,
                    minecraft_username_normalized = EXCLUDED.minecraft_username_normalized,
                    synced_at = EXCLUDED.synced_at,
                    source_updated_at = EXCLUDED.source_updated_at
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setObject(1, identity.playerId)
                statement.setString(2, identity.keycloakUserId)
                statement.setString(3, identity.minecraftUsername)
                statement.setString(4, identity.normalizedUsername)
                statement.setTimestamp(5, Timestamp.from(identity.syncedAt))
                statement.setTimestamp(6, identity.sourceUpdatedAt?.let(Timestamp::from))
                statement.executeUpdate()
            }
    }

    private fun clearTombstoneIfAccepted(
        connection: Connection,
        identity: ProjectedPlayerIdentity,
    ): Boolean {
        connection
            .prepareStatement(
                """
                DELETE FROM permission_player_identity_tombstones
                WHERE keycloak_user_id = ? AND deleted_at <= ?
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setString(1, identity.keycloakUserId)
                statement.setTimestamp(2, Timestamp.from(identity.syncedAt))
                statement.executeUpdate()
            }
        return connection
            .prepareStatement(
                """
                SELECT NOT EXISTS (
                    SELECT 1
                    FROM permission_player_identity_tombstones
                    WHERE keycloak_user_id = ?
                )
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setString(1, identity.keycloakUserId)
                statement.executeQuery().use { rows ->
                    check(rows.next())
                    rows.getBoolean(1)
                }
            }
    }

    private fun upsertTombstone(
        connection: Connection,
        keycloakUserId: String,
        deletedAt: Instant,
    ) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_player_identity_tombstones (keycloak_user_id, deleted_at)
                VALUES (?, ?)
                ON CONFLICT (keycloak_user_id) DO UPDATE
                SET deleted_at = EXCLUDED.deleted_at
                WHERE permission_player_identity_tombstones.deleted_at < EXCLUDED.deleted_at
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setString(1, keycloakUserId)
                statement.setTimestamp(2, Timestamp.from(deletedAt))
                statement.executeUpdate()
            }
    }

    private fun deleteRelinkedIdentity(connection: Connection, identity: ProjectedPlayerIdentity) {
        connection
            .prepareStatement(
                """
                DELETE FROM permission_player_identities
                WHERE keycloak_user_id = ? AND player_id <> ?
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setString(1, identity.keycloakUserId)
                statement.setObject(2, identity.playerId)
                statement.executeUpdate()
            }
    }

    private fun replaceGroups(connection: Connection, playerId: UUID, groupPaths: Set<String>) {
        connection
            .prepareStatement("DELETE FROM permission_player_keycloak_groups WHERE player_id = ?")
            .use { statement ->
                statement.setObject(1, playerId)
                statement.executeUpdate()
            }
        connection
            .prepareStatement(
                """
                INSERT INTO permission_player_keycloak_groups (player_id, keycloak_group_path)
                VALUES (?, ?)
                """
                    .trimIndent()
            )
            .use { statement ->
                groupPaths.forEach { groupPath ->
                    statement.setObject(1, playerId)
                    statement.setString(2, groupPath)
                    statement.addBatch()
                }
                statement.executeBatch()
            }
    }

    private fun identityQuery(predicate: String) =
        """
        SELECT identities.player_id,
               identities.keycloak_user_id,
               identities.minecraft_username,
               identities.minecraft_username_normalized,
               identities.synced_at,
               identities.source_updated_at,
               COALESCE(
                   array_agg(groups.keycloak_group_path ORDER BY groups.keycloak_group_path)
                       FILTER (WHERE groups.keycloak_group_path IS NOT NULL),
                   ARRAY[]::text[]
               ) AS group_paths
        FROM permission_player_identities identities
        LEFT JOIN permission_player_keycloak_groups groups ON groups.player_id = identities.player_id
        WHERE identities.$predicate
        GROUP BY identities.player_id, identities.keycloak_user_id, identities.minecraft_username,
                 identities.minecraft_username_normalized, identities.synced_at, identities.source_updated_at
        """
            .trimIndent()

    private fun ResultSet.toIdentity() =
        ProjectedPlayerIdentity(
            playerId = getObject("player_id", UUID::class.java),
            keycloakUserId = getString("keycloak_user_id"),
            minecraftUsername = getString("minecraft_username"),
            normalizedUsername = getString("minecraft_username_normalized"),
            groupPaths =
                (getArray("group_paths").array as Array<*>).filterIsInstance<String>().toSet(),
            syncedAt = getTimestamp("synced_at").toInstant(),
            sourceUpdatedAt = getTimestamp("source_updated_at")?.toInstant(),
        )

    private fun ResultSet.toSearchItem() =
        PlayerSearchItem(
            playerId = getObject("player_id", UUID::class.java),
            minecraftUsername = getString("minecraft_username"),
            directRoleGrantCount = getLong("direct_role_grant_count"),
            directPermissionGrantCount = getLong("direct_permission_grant_count"),
        )

    private fun ResultSet.toIdentitySyncState() =
        IdentitySyncState(
            status = IdentitySyncStatus.valueOf(getString("status")),
            startedAt = getTimestamp("started_at")?.toInstant(),
            completedAt = getTimestamp("completed_at")?.toInstant(),
            lastSuccessAt = getTimestamp("last_success_at")?.toInstant(),
            durationMs = getLongOrNull("duration_ms"),
            playerCount = getLong("player_count"),
            failureReason = getString("failure_reason"),
        )

    private fun ResultSet.getLongOrNull(column: String): Long? =
        getLong(column).takeUnless { wasNull() }

    private fun String.escapeLikePattern(): String = buildString {
        this@escapeLikePattern.forEach { character ->
            if (character == '\\' || character == '%' || character == '_') {
                append('\\')
            }
            append(character)
        }
    }

    private data class SearchResult(val items: List<PlayerSearchItem>, val total: Long)
}
