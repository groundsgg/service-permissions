package gg.grounds.permissions.persistence

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.cache.DisabledPlayerPolicyL2
import gg.grounds.permissions.cache.GlobalPolicyDefinitions
import gg.grounds.permissions.cache.GroupRoleMapping
import gg.grounds.permissions.cache.PermissionSnapshotCache
import gg.grounds.permissions.cache.PlayerPolicyData
import gg.grounds.permissions.cache.PlayerPolicyL2
import gg.grounds.permissions.cache.PolicyDataSource
import gg.grounds.permissions.cache.SnapshotCacheSettings
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionGrantSpec
import gg.grounds.permissions.domain.PermissionPolicyInput
import gg.grounds.permissions.domain.PermissionRoleAssignmentSource
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.PlayerRoleGrant
import gg.grounds.permissions.domain.RoleDefinition
import gg.grounds.permissions.identity.IdentityProjectionUnavailableException
import gg.grounds.permissions.identity.IdentitySyncReadinessCheck
import gg.grounds.permissions.sync.GlobalPermissionSnapshot
import gg.grounds.permissions.sync.PermissionProjectSnapshot
import gg.grounds.permissions.sync.PermissionSnapshotFingerprint
import gg.grounds.permissions.sync.PermissionSyncAction
import gg.grounds.permissions.sync.PermissionSyncConflictException
import gg.grounds.permissions.sync.PermissionSyncConflictReason
import gg.grounds.permissions.sync.PermissionSyncDiff
import gg.grounds.permissions.sync.PermissionSyncImportRequest
import gg.grounds.permissions.sync.PermissionSyncPolicyProjection
import gg.grounds.permissions.sync.SyncAction
import gg.grounds.permissions.sync.SyncCatalogEntry
import gg.grounds.permissions.sync.SyncEntityType
import gg.grounds.permissions.sync.SyncInheritance
import gg.grounds.permissions.sync.SyncKeycloakMapping
import gg.grounds.permissions.sync.SyncRole
import gg.grounds.permissions.sync.SyncRoleGrant
import jakarta.annotation.PreDestroy
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Duration
import java.time.Instant
import java.time.OffsetDateTime
import java.util.UUID
import javax.sql.DataSource
import org.eclipse.microprofile.health.Readiness
import org.eclipse.microprofile.openapi.annotations.media.Schema
import org.postgresql.util.PGobject
import org.postgresql.util.PSQLException

data class RoleRecord(
    val key: String,
    val name: String,
    val description: String = "",
    val prefix: String? = null,
    val color: String? = null,
    val sortOrder: Int = 0,
    val metadata: Map<String, String> = emptyMap(),
    val isDefault: Boolean = false,
)

data class RoleAggregateCountsRecord(
    val role: RoleRecord,
    val grantCount: Long,
    val inheritanceCount: Long,
    val inheritedRoleKeys: Set<String> = emptySet(),
)

data class RoleGrantRecord(
    val id: UUID,
    val roleKey: String,
    val effect: PermissionEffect,
    val pattern: String,
    val scope: PermissionScope,
    val expiresAt: Instant? = null,
    val startsAt: Instant? = null,
)

data class PlayerRoleGrantRecord(
    val id: UUID,
    val playerId: UUID,
    val roleKey: String,
    val expiresAt: Instant? = null,
    val startsAt: Instant? = null,
)

data class PlayerGrantRecord(
    val id: UUID,
    val playerId: UUID,
    val effect: PermissionEffect,
    val pattern: String,
    val scope: PermissionScope,
    val expiresAt: Instant? = null,
    val startsAt: Instant? = null,
)

data class KeycloakGroupMappingRecord(
    val id: UUID,
    val keycloakGroup: String,
    val roleKey: String,
    val expiresAt: Instant? = null,
    val startsAt: Instant? = null,
)

data class CatalogEntryRecord(
    val key: String,
    val label: String,
    val description: String = "",
    val source: String,
    val sourceVersion: String,
    val supportedScopes: List<PermissionScopeKind>,
    val custom: Boolean,
    val lastSeenAt: Instant? = null,
)

@Schema(description = "Metadata recorded after a permission environment import.")
data class PermissionSyncMetadataRecord(
    val snapshotId: String,
    val actorUserId: String,
    val importedAt: Instant,
)

data class PagedRecords<T>(val items: List<T>, val total: Long)

data class PermissionAuditEventRecord(
    val id: UUID,
    val actorUserId: String?,
    val action: String,
    val target: String,
    val metadata: JsonNode,
    val createdAt: Instant,
)

data class PermissionAuditEventQuery(
    val query: String = "",
    val actions: Set<String> = emptySet(),
    val from: Instant? = null,
    val to: Instant? = null,
    val page: Int = 1,
    val perPage: Int = 25,
)

data class PermissionAuditEventPage(
    val items: List<PermissionAuditEventRecord>,
    val page: Int,
    val perPage: Int,
    val total: Long,
)

@ApplicationScoped
class PermissionRepository
@Inject
constructor(
    private val dataSource: DataSource,
    private val objectMapper: ObjectMapper,
    @param:Readiness private val identityReadinessCheck: IdentitySyncReadinessCheck,
    snapshotCacheSettings: SnapshotCacheSettings,
    playerPolicyL2: PlayerPolicyL2,
) {
    constructor(
        dataSource: DataSource,
        objectMapper: ObjectMapper,
        identityReadinessCheck: IdentitySyncReadinessCheck,
    ) : this(
        dataSource,
        objectMapper,
        identityReadinessCheck,
        SnapshotCacheSettings(),
        DisabledPlayerPolicyL2,
    )

    internal val snapshotCache =
        PermissionSnapshotCache(
            snapshotCacheSettings,
            playerPolicyL2,
            object : PolicyDataSource {
                override fun loadGlobalDefinitions() = read(::loadGlobalDefinitions)

                override fun loadPlayerPolicyData(playerIds: Set<UUID>) = read { connection ->
                    loadPlayerPolicyData(connection, playerIds)
                }
            },
        )

    @PreDestroy fun closeSnapshotCache() = snapshotCache.close()

    private var lastSnapshotPollAt: Instant? = null
    private val seenPlayerAuditEvents = mutableMapOf<UUID, Instant>()

    fun createRole(actorUserId: String, role: RoleRecord): RoleRecord =
        try {
            write(
                actorUserId,
                "role.created",
                "role:${role.key}",
                auditMetadata { put("roleKey", role.key) },
            ) { connection ->
                connection
                    .prepareStatement(
                        """
                        INSERT INTO permission_roles (
                            key, name, description, prefix, color, sort_order, metadata, is_default
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """
                            .trimIndent()
                    )
                    .use { statement ->
                        statement.setString(1, role.key)
                        statement.setString(2, role.name)
                        statement.setString(3, role.description)
                        statement.setString(4, role.prefix)
                        statement.setString(5, role.color)
                        statement.setInt(6, role.sortOrder)
                        statement.setObject(7, jsonb(role.metadata))
                        statement.setBoolean(8, role.isDefault)
                        statement.executeUpdate()
                    }
                role
            }
        } catch (error: PSQLException) {
            if (
                error.sqlState == POSTGRES_UNIQUE_VIOLATION &&
                    error.serverErrorMessage?.constraint == PERMISSION_ROLES_PRIMARY_KEY
            ) {
                throw DuplicateRoleKeyException(role.key, error)
            }
            throw error
        }

    fun listRoles(): List<RoleRecord> = read(::listRoles)

    private fun listRoles(connection: Connection): List<RoleRecord> =
        connection
            .prepareStatement(
                """
                SELECT key, name, description, prefix, color, sort_order, metadata, is_default
                FROM permission_roles
                ORDER BY sort_order ASC, key ASC
                """
                    .trimIndent()
            )
            .use { statement -> statement.executeQuery().use { rows -> rows.toRoleRecords() } }

    fun listAuditEvents(query: PermissionAuditEventQuery): PermissionAuditEventPage {
        validateAuditEventQuery(query)
        val predicates = auditEventPredicates(query)
        return consistentRead { connection ->
            val whereClause = predicates.whereClause()
            val total =
                connection
                    .prepareStatement("SELECT COUNT(*) FROM permission_audit_events$whereClause")
                    .use { statement ->
                        predicates.bind(connection, statement)
                        statement.executeQuery().use { rows ->
                            check(rows.next())
                            rows.getLong(1)
                        }
                    }
            val items =
                connection
                    .prepareStatement(
                        """
                        SELECT id, actor_user_id, action, target, metadata, created_at
                        FROM permission_audit_events$whereClause
                        ORDER BY created_at DESC, id DESC
                        LIMIT ? OFFSET ?
                        """
                            .trimIndent()
                    )
                    .use { statement ->
                        val nextParameter = predicates.bind(connection, statement)
                        statement.setInt(nextParameter, query.perPage)
                        statement.setLong(
                            nextParameter + 1,
                            (query.page - 1).toLong() * query.perPage,
                        )
                        statement.executeQuery().use { rows ->
                            buildList {
                                while (rows.next()) {
                                    add(rows.toPermissionAuditEventRecord())
                                }
                            }
                        }
                    }
            PermissionAuditEventPage(items, query.page, query.perPage, total)
        }
    }

    fun listRolesWithAggregateCounts(): List<RoleAggregateCountsRecord> = read { connection ->
        val inheritedRoles = listRoleInheritance(connection)
        connection
            .prepareStatement(
                """
                SELECT roles.key, roles.name, roles.description, roles.prefix, roles.color,
                       roles.sort_order, roles.metadata, roles.is_default,
                       COALESCE(grants.grant_count, 0) AS grant_count,
                       COALESCE(inheritances.inheritance_count, 0) AS inheritance_count
                FROM permission_roles roles
                LEFT JOIN (
                    SELECT role_key, COUNT(*) AS grant_count
                    FROM permission_role_grants
                    GROUP BY role_key
                ) grants ON grants.role_key = roles.key
                LEFT JOIN (
                    SELECT child_role_key, COUNT(*) AS inheritance_count
                    FROM permission_role_inheritance
                    GROUP BY child_role_key
                ) inheritances ON inheritances.child_role_key = roles.key
                ORDER BY roles.sort_order ASC, roles.key ASC
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.executeQuery().use { rows -> rows.toRoleAggregateCountsRecords() }
            }
            .map { record ->
                record.copy(inheritedRoleKeys = inheritedRoles[record.role.key].orEmpty())
            }
    }

    fun getRole(roleKey: String): RoleRecord? = listRoles().firstOrNull { it.key == roleKey }

    fun updateRole(actorUserId: String, roleKey: String, role: RoleRecord): RoleRecord {
        writeIfChanged(
            actorUserId,
            "role.updated",
            "role:$roleKey",
            auditMetadata { put("roleKey", roleKey) },
        ) { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_roles
                    SET name = ?, description = ?, prefix = ?, color = ?, sort_order = ?,
                        metadata = ?, is_default = ?, updated_at = now()
                    WHERE key = ?
                      AND (
                          name IS DISTINCT FROM ? OR description IS DISTINCT FROM ? OR
                          prefix IS DISTINCT FROM ? OR color IS DISTINCT FROM ? OR
                          sort_order IS DISTINCT FROM ? OR metadata IS DISTINCT FROM ? OR
                          is_default IS DISTINCT FROM ?
                      )
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, role.name)
                    statement.setString(2, role.description)
                    statement.setString(3, role.prefix)
                    statement.setString(4, role.color)
                    statement.setInt(5, role.sortOrder)
                    statement.setObject(6, jsonb(role.metadata))
                    statement.setBoolean(7, role.isDefault)
                    statement.setString(8, roleKey)
                    statement.setString(9, role.name)
                    statement.setString(10, role.description)
                    statement.setString(11, role.prefix)
                    statement.setString(12, role.color)
                    statement.setInt(13, role.sortOrder)
                    statement.setObject(14, jsonb(role.metadata))
                    statement.setBoolean(15, role.isDefault)
                    val changed = statement.executeUpdate() > 0
                    require(
                        changed ||
                            entityExists(connection, "permission_roles", "key = ?") {
                                it.setString(1, roleKey)
                            }
                    ) {
                        "Role not found (roleKey=$roleKey)"
                    }
                    changed
                }
        }
        return role.copy(key = roleKey)
    }

    fun deleteRole(actorUserId: String, roleKey: String) {
        write(
            actorUserId,
            "role.deleted",
            "role:$roleKey",
            auditMetadata { put("roleKey", roleKey) },
        ) { connection ->
            connection.prepareStatement("DELETE FROM permission_roles WHERE key = ?").use {
                statement ->
                statement.setString(1, roleKey)
                require(statement.executeUpdate() == 1) { "Role not found (roleKey=$roleKey)" }
            }
        }
    }

    fun addRoleInheritance(actorUserId: String, childRoleKey: String, parentRoleKey: String) {
        writeIfChanged(
            actorUserId,
            "role.inheritance.created",
            "role:$childRoleKey",
            auditMetadata {
                put("roleKey", childRoleKey)
                put("parentRoleKey", parentRoleKey)
            },
        ) { connection ->
            require(childRoleKey != parentRoleKey) {
                "Role inheritance would create a cycle (childRoleKey=$childRoleKey, parentRoleKey=$parentRoleKey)"
            }
            require(
                !roleHasAncestor(
                    connection,
                    roleKey = parentRoleKey,
                    ancestorRoleKey = childRoleKey,
                )
            ) {
                "Role inheritance would create a cycle (childRoleKey=$childRoleKey, parentRoleKey=$parentRoleKey)"
            }
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_role_inheritance (parent_role_key, child_role_key)
                    VALUES (?, ?)
                    ON CONFLICT (parent_role_key, child_role_key) DO NOTHING
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, parentRoleKey)
                    statement.setString(2, childRoleKey)
                    statement.executeUpdate() > 0
                }
        }
    }

    fun removeRoleInheritance(actorUserId: String, childRoleKey: String, parentRoleKey: String) {
        writeIfChanged(
            actorUserId,
            "role.inheritance.deleted",
            "role:$childRoleKey",
            auditMetadata {
                put("roleKey", childRoleKey)
                put("parentRoleKey", parentRoleKey)
            },
        ) { connection ->
            connection
                .prepareStatement(
                    """
                    DELETE FROM permission_role_inheritance
                    WHERE child_role_key = ? AND parent_role_key = ?
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, childRoleKey)
                    statement.setString(2, parentRoleKey)
                    statement.executeUpdate() > 0
                }
        }
    }

    fun createRoleGrant(actorUserId: String, grant: RoleGrantRecord): RoleGrantRecord =
        write(
            actorUserId,
            "role.grant.created",
            "role:${grant.roleKey}",
            auditMetadata { putGrantMetadata(grant) },
        ) { connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_role_grants (
                        id, role_key, effect, permission_pattern, scope_kind, scope_value, starts_at,
                        expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setObject(1, grant.id)
                    statement.setString(2, grant.roleKey)
                    statement.setString(3, grant.effect.name)
                    statement.setString(4, grant.pattern)
                    statement.setString(5, grant.scope.kind.name)
                    statement.setString(6, grant.scope.value)
                    statement.setTimestamp(7, grant.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(8, grant.expiresAt?.let(Timestamp::from))
                    statement.executeUpdate()
                }
            grant
        }

    fun listRoleGrantRecords(roleKey: String): List<RoleGrantRecord> = read { connection ->
        listRoleGrantRecords(connection, roleKey)
    }

    private fun listRoleGrantRecords(
        connection: Connection,
        roleKey: String,
    ): List<RoleGrantRecord> =
        connection
            .prepareStatement(
                """
                SELECT id, role_key, effect, permission_pattern, scope_kind, scope_value, starts_at,
                       expires_at
                FROM permission_role_grants
                WHERE role_key = ?
                ORDER BY created_at ASC, id ASC
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setString(1, roleKey)
                statement.executeQuery().use { rows ->
                    buildList {
                        while (rows.next()) {
                            add(rows.toRoleGrantRecord())
                        }
                    }
                }
            }

    fun searchRoleGrantRecords(
        roleKey: String,
        query: String,
        page: Int,
        perPage: Int,
        sortBy: String,
        sortDirection: String,
    ): PagedRecords<RoleGrantRecord> = consistentRead { connection ->
        val pattern = searchPattern(query)
        val total =
            connection
                .prepareStatement(
                    """
                    SELECT COUNT(*)
                    FROM permission_role_grants
                    WHERE role_key = ?
                      AND (
                          permission_pattern ILIKE ? ESCAPE '\'
                          OR effect ILIKE ? ESCAPE '\'
                          OR scope_kind ILIKE ? ESCAPE '\'
                          OR COALESCE(scope_value, '') ILIKE ? ESCAPE '\'
                      )
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, roleKey)
                    (2..5).forEach { statement.setString(it, pattern) }
                    statement.executeQuery().use { rows ->
                        check(rows.next())
                        rows.getLong(1)
                    }
                }
        val orderBy =
            searchOrderBy(
                sortBy = sortBy,
                sortDirection = sortDirection,
                allowedSorts =
                    mapOf(
                        "permission" to listOf("LOWER(permission_pattern)"),
                        "effect" to listOf("effect"),
                        "scope" to listOf("scope_kind", "LOWER(COALESCE(scope_value, ''))"),
                        "activation" to listOf("starts_at"),
                        "expiration" to listOf("expires_at"),
                    ),
                tieBreaker = "id",
            )
        val items =
            connection
                .prepareStatement(
                    """
                    SELECT id, role_key, effect, permission_pattern, scope_kind, scope_value,
                           starts_at, expires_at
                    FROM permission_role_grants
                    WHERE role_key = ?
                      AND (
                          permission_pattern ILIKE ? ESCAPE '\'
                          OR effect ILIKE ? ESCAPE '\'
                          OR scope_kind ILIKE ? ESCAPE '\'
                          OR COALESCE(scope_value, '') ILIKE ? ESCAPE '\'
                      )
                    ORDER BY $orderBy
                    OFFSET ? LIMIT ?
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, roleKey)
                    (2..5).forEach { statement.setString(it, pattern) }
                    statement.setLong(6, pageOffset(page, perPage))
                    statement.setInt(7, perPage)
                    statement.executeQuery().use { rows ->
                        buildList {
                            while (rows.next()) {
                                add(rows.toRoleGrantRecord())
                            }
                        }
                    }
                }
        PagedRecords(items, total)
    }

    fun listRoleInheritances(): List<SyncInheritance> = read(::listRoleInheritances)

    private fun listRoleInheritances(connection: Connection): List<SyncInheritance> =
        connection
            .prepareStatement(
                "SELECT parent_role_key, child_role_key FROM permission_role_inheritance ORDER BY parent_role_key, child_role_key"
            )
            .use { statement ->
                statement.executeQuery().use { rows ->
                    buildList {
                        while (rows.next()) {
                            add(
                                SyncInheritance(
                                    rows.getString("parent_role_key"),
                                    rows.getString("child_role_key"),
                                )
                            )
                        }
                    }
                }
            }

    fun updateRoleGrant(
        actorUserId: String,
        roleKey: String,
        grantId: UUID,
        grant: RoleGrantRecord,
    ): RoleGrantRecord {
        writeIfChanged(
            actorUserId,
            "role.grant.updated",
            "role:$roleKey",
            auditMetadata { putGrantMetadata(grant.copy(id = grantId, roleKey = roleKey)) },
        ) { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_role_grants
                    SET effect = ?, permission_pattern = ?, scope_kind = ?, scope_value = ?,
                        starts_at = ?, expires_at = ?
                    WHERE id = ? AND role_key = ?
                      AND (
                          effect IS DISTINCT FROM ? OR permission_pattern IS DISTINCT FROM ? OR
                          scope_kind IS DISTINCT FROM ? OR scope_value IS DISTINCT FROM ? OR
                          starts_at IS DISTINCT FROM ? OR
                          expires_at IS DISTINCT FROM ?
                      )
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, grant.effect.name)
                    statement.setString(2, grant.pattern)
                    statement.setString(3, grant.scope.kind.name)
                    statement.setString(4, grant.scope.value)
                    statement.setTimestamp(5, grant.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(6, grant.expiresAt?.let(Timestamp::from))
                    statement.setObject(7, grantId)
                    statement.setString(8, roleKey)
                    statement.setString(9, grant.effect.name)
                    statement.setString(10, grant.pattern)
                    statement.setString(11, grant.scope.kind.name)
                    statement.setString(12, grant.scope.value)
                    statement.setTimestamp(13, grant.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(14, grant.expiresAt?.let(Timestamp::from))
                    val changed = statement.executeUpdate() > 0
                    require(
                        changed ||
                            entityExists(
                                connection,
                                "permission_role_grants",
                                "id = ? AND role_key = ?",
                            ) {
                                it.setObject(1, grantId)
                                it.setString(2, roleKey)
                            }
                    ) {
                        "Role grant not found (grantId=$grantId)"
                    }
                    changed
                }
        }
        return grant.copy(id = grantId, roleKey = roleKey)
    }

    fun deleteRoleGrant(actorUserId: String, roleKey: String, grantId: UUID) {
        writeIfChanged(
            actorUserId,
            "role.grant.deleted",
            "role:$roleKey",
            auditMetadata {
                put("roleKey", roleKey)
                put("grantId", grantId.toString())
            },
        ) { connection ->
            connection
                .prepareStatement(
                    "DELETE FROM permission_role_grants WHERE id = ? AND role_key = ?"
                )
                .use { statement ->
                    statement.setObject(1, grantId)
                    statement.setString(2, roleKey)
                    statement.executeUpdate() > 0
                }
        }
    }

    fun createPlayerRoleGrant(
        actorUserId: String,
        grant: PlayerRoleGrantRecord,
    ): PlayerRoleGrantRecord =
        write(
            actorUserId,
            "player.role_grant.created",
            "player:${grant.playerId}",
            auditMetadata { putPlayerRoleGrantMetadata(grant) },
        ) { connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_player_role_grants (
                        id, player_id, role_key, starts_at, expires_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setObject(1, grant.id)
                    statement.setObject(2, grant.playerId)
                    statement.setString(3, grant.roleKey)
                    statement.setTimestamp(4, grant.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(5, grant.expiresAt?.let(Timestamp::from))
                    statement.executeUpdate()
                }
            grant
        }

    fun listPlayerRoleGrantRecords(playerId: UUID): List<PlayerRoleGrantRecord> =
        read { connection ->
            connection
                .prepareStatement(
                    """
                    SELECT id, player_id, role_key, starts_at, expires_at
                    FROM permission_player_role_grants
                    WHERE player_id = ?
                    ORDER BY created_at ASC, id ASC
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setObject(1, playerId)
                    statement.executeQuery().use { rows ->
                        buildList {
                            while (rows.next()) {
                                add(
                                    PlayerRoleGrantRecord(
                                        id = rows.getObject("id", UUID::class.java),
                                        playerId = rows.getObject("player_id", UUID::class.java),
                                        roleKey = rows.getString("role_key"),
                                        startsAt = rows.instantOrNull("starts_at"),
                                        expiresAt = rows.instantOrNull("expires_at"),
                                    )
                                )
                            }
                        }
                    }
                }
        }

    fun updatePlayerRoleGrant(
        actorUserId: String,
        playerId: UUID,
        grantId: UUID,
        grant: PlayerRoleGrantRecord,
    ): PlayerRoleGrantRecord {
        writeIfChanged(
            actorUserId,
            "player.role_grant.updated",
            "player:$playerId",
            auditMetadata {
                putPlayerRoleGrantMetadata(grant.copy(id = grantId, playerId = playerId))
            },
        ) { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_player_role_grants
                    SET role_key = ?, starts_at = ?, expires_at = ?
                    WHERE id = ? AND player_id = ?
                      AND (
                          role_key IS DISTINCT FROM ? OR starts_at IS DISTINCT FROM ? OR
                          expires_at IS DISTINCT FROM ?
                      )
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, grant.roleKey)
                    statement.setTimestamp(2, grant.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(3, grant.expiresAt?.let(Timestamp::from))
                    statement.setObject(4, grantId)
                    statement.setObject(5, playerId)
                    statement.setString(6, grant.roleKey)
                    statement.setTimestamp(7, grant.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(8, grant.expiresAt?.let(Timestamp::from))
                    val changed = statement.executeUpdate() > 0
                    require(
                        changed ||
                            entityExists(
                                connection,
                                "permission_player_role_grants",
                                "id = ? AND player_id = ?",
                            ) {
                                it.setObject(1, grantId)
                                it.setObject(2, playerId)
                            }
                    ) {
                        "Player role grant not found (grantId=$grantId)"
                    }
                    changed
                }
        }
        return grant.copy(id = grantId, playerId = playerId)
    }

    fun deletePlayerRoleGrant(actorUserId: String, playerId: UUID, grantId: UUID) {
        writeIfChanged(
            actorUserId,
            "player.role_grant.deleted",
            "player:$playerId",
            auditMetadata {
                put("playerId", playerId.toString())
                put("grantId", grantId.toString())
            },
        ) { connection ->
            connection
                .prepareStatement(
                    "DELETE FROM permission_player_role_grants WHERE id = ? AND player_id = ?"
                )
                .use { statement ->
                    statement.setObject(1, grantId)
                    statement.setObject(2, playerId)
                    statement.executeUpdate() > 0
                }
        }
    }

    fun createPlayerGrant(actorUserId: String, grant: PlayerGrantRecord): PlayerGrantRecord =
        write(
            actorUserId,
            "player.grant.created",
            "player:${grant.playerId}",
            auditMetadata { putPlayerGrantMetadata(grant) },
        ) { connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_player_grants (
                        id, player_id, effect, permission_pattern, scope_kind, scope_value, starts_at,
                        expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setObject(1, grant.id)
                    statement.setObject(2, grant.playerId)
                    statement.setString(3, grant.effect.name)
                    statement.setString(4, grant.pattern)
                    statement.setString(5, grant.scope.kind.name)
                    statement.setString(6, grant.scope.value)
                    statement.setTimestamp(7, grant.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(8, grant.expiresAt?.let(Timestamp::from))
                    statement.executeUpdate()
                }
            grant
        }

    fun listPlayerGrantRecords(playerId: UUID): List<PlayerGrantRecord> = read { connection ->
        connection
            .prepareStatement(
                """
                SELECT id, player_id, effect, permission_pattern, scope_kind, scope_value, starts_at,
                       expires_at
                FROM permission_player_grants
                WHERE player_id = ?
                ORDER BY created_at ASC, id ASC
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setObject(1, playerId)
                statement.executeQuery().use { rows ->
                    buildList {
                        while (rows.next()) {
                            add(rows.toPlayerGrantRecord())
                        }
                    }
                }
            }
    }

    fun searchPlayerGrantRecords(
        playerId: UUID,
        query: String,
        page: Int,
        perPage: Int,
        sortBy: String,
        sortDirection: String,
    ): PagedRecords<PlayerGrantRecord> = consistentRead { connection ->
        val pattern = searchPattern(query)
        val total =
            connection
                .prepareStatement(
                    """
                    SELECT COUNT(*)
                    FROM permission_player_grants
                    WHERE player_id = ?
                      AND (
                          permission_pattern ILIKE ? ESCAPE '\'
                          OR effect ILIKE ? ESCAPE '\'
                          OR scope_kind ILIKE ? ESCAPE '\'
                          OR COALESCE(scope_value, '') ILIKE ? ESCAPE '\'
                      )
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setObject(1, playerId)
                    (2..5).forEach { statement.setString(it, pattern) }
                    statement.executeQuery().use { rows ->
                        check(rows.next())
                        rows.getLong(1)
                    }
                }
        val orderBy =
            searchOrderBy(
                sortBy = sortBy,
                sortDirection = sortDirection,
                allowedSorts =
                    mapOf(
                        "permission" to listOf("LOWER(permission_pattern)"),
                        "effect" to listOf("effect"),
                        "scope" to listOf("scope_kind", "LOWER(COALESCE(scope_value, ''))"),
                        "activation" to listOf("starts_at"),
                        "expiration" to listOf("expires_at"),
                    ),
                tieBreaker = "id",
            )
        val items =
            connection
                .prepareStatement(
                    """
                    SELECT id, player_id, effect, permission_pattern, scope_kind, scope_value,
                           starts_at, expires_at
                    FROM permission_player_grants
                    WHERE player_id = ?
                      AND (
                          permission_pattern ILIKE ? ESCAPE '\'
                          OR effect ILIKE ? ESCAPE '\'
                          OR scope_kind ILIKE ? ESCAPE '\'
                          OR COALESCE(scope_value, '') ILIKE ? ESCAPE '\'
                      )
                    ORDER BY $orderBy
                    OFFSET ? LIMIT ?
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setObject(1, playerId)
                    (2..5).forEach { statement.setString(it, pattern) }
                    statement.setLong(6, pageOffset(page, perPage))
                    statement.setInt(7, perPage)
                    statement.executeQuery().use { rows ->
                        buildList {
                            while (rows.next()) {
                                add(rows.toPlayerGrantRecord())
                            }
                        }
                    }
                }
        PagedRecords(items, total)
    }

    fun updatePlayerGrant(
        actorUserId: String,
        playerId: UUID,
        grantId: UUID,
        grant: PlayerGrantRecord,
    ): PlayerGrantRecord {
        writeIfChanged(
            actorUserId,
            "player.grant.updated",
            "player:$playerId",
            auditMetadata { putPlayerGrantMetadata(grant.copy(id = grantId, playerId = playerId)) },
        ) { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_player_grants
                    SET effect = ?, permission_pattern = ?, scope_kind = ?, scope_value = ?,
                        starts_at = ?, expires_at = ?
                    WHERE id = ? AND player_id = ?
                      AND (
                          effect IS DISTINCT FROM ? OR permission_pattern IS DISTINCT FROM ? OR
                          scope_kind IS DISTINCT FROM ? OR scope_value IS DISTINCT FROM ? OR
                          starts_at IS DISTINCT FROM ? OR
                          expires_at IS DISTINCT FROM ?
                      )
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, grant.effect.name)
                    statement.setString(2, grant.pattern)
                    statement.setString(3, grant.scope.kind.name)
                    statement.setString(4, grant.scope.value)
                    statement.setTimestamp(5, grant.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(6, grant.expiresAt?.let(Timestamp::from))
                    statement.setObject(7, grantId)
                    statement.setObject(8, playerId)
                    statement.setString(9, grant.effect.name)
                    statement.setString(10, grant.pattern)
                    statement.setString(11, grant.scope.kind.name)
                    statement.setString(12, grant.scope.value)
                    statement.setTimestamp(13, grant.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(14, grant.expiresAt?.let(Timestamp::from))
                    val changed = statement.executeUpdate() > 0
                    require(
                        changed ||
                            entityExists(
                                connection,
                                "permission_player_grants",
                                "id = ? AND player_id = ?",
                            ) {
                                it.setObject(1, grantId)
                                it.setObject(2, playerId)
                            }
                    ) {
                        "Player grant not found (grantId=$grantId)"
                    }
                    changed
                }
        }
        return grant.copy(id = grantId, playerId = playerId)
    }

    fun deletePlayerGrant(actorUserId: String, playerId: UUID, grantId: UUID) {
        writeIfChanged(
            actorUserId,
            "player.grant.deleted",
            "player:$playerId",
            auditMetadata {
                put("playerId", playerId.toString())
                put("grantId", grantId.toString())
            },
        ) { connection ->
            connection
                .prepareStatement(
                    "DELETE FROM permission_player_grants WHERE id = ? AND player_id = ?"
                )
                .use { statement ->
                    statement.setObject(1, grantId)
                    statement.setObject(2, playerId)
                    statement.executeUpdate() > 0
                }
        }
    }

    fun createKeycloakGroupMapping(
        actorUserId: String,
        mapping: KeycloakGroupMappingRecord,
    ): KeycloakGroupMappingRecord =
        write(
            actorUserId,
            "keycloak_group.mapping.created",
            "keycloakGroup:${mapping.keycloakGroup}",
            auditMetadata { putKeycloakMappingMetadata(mapping) },
        ) { connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_keycloak_group_mappings (
                        id, keycloak_group, role_key, starts_at, expires_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setObject(1, mapping.id)
                    statement.setString(2, mapping.keycloakGroup)
                    statement.setString(3, mapping.roleKey)
                    statement.setTimestamp(4, mapping.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(5, mapping.expiresAt?.let(Timestamp::from))
                    statement.executeUpdate()
                }
            mapping
        }

    fun listKeycloakGroupMappings(): List<KeycloakGroupMappingRecord> =
        read(::listKeycloakGroupMappings)

    private fun listKeycloakGroupMappings(
        connection: Connection
    ): List<KeycloakGroupMappingRecord> =
        connection
            .prepareStatement(
                """
                SELECT id, keycloak_group, role_key, starts_at, expires_at
                FROM permission_keycloak_group_mappings
                ORDER BY keycloak_group ASC, role_key ASC
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.executeQuery().use { rows ->
                    buildList {
                        while (rows.next()) {
                            add(rows.toKeycloakGroupMapping())
                        }
                    }
                }
            }

    fun searchKeycloakGroupMappings(
        query: String,
        page: Int,
        perPage: Int,
        sortBy: String,
        sortDirection: String,
    ): PagedRecords<KeycloakGroupMappingRecord> = consistentRead { connection ->
        val pattern = searchPattern(query)
        val total =
            connection
                .prepareStatement(
                    """
                    SELECT COUNT(*)
                    FROM permission_keycloak_group_mappings
                    WHERE keycloak_group ILIKE ? ESCAPE '\'
                       OR role_key ILIKE ? ESCAPE '\'
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, pattern)
                    statement.setString(2, pattern)
                    statement.executeQuery().use { rows ->
                        check(rows.next())
                        rows.getLong(1)
                    }
                }
        val orderBy =
            searchOrderBy(
                sortBy = sortBy,
                sortDirection = sortDirection,
                allowedSorts =
                    mapOf(
                        "group" to listOf("LOWER(keycloak_group)"),
                        "role" to listOf("LOWER(role_key)"),
                        "activation" to listOf("starts_at"),
                        "expiration" to listOf("expires_at"),
                    ),
                tieBreaker = "id",
            )
        val items =
            connection
                .prepareStatement(
                    """
                    SELECT id, keycloak_group, role_key, starts_at, expires_at
                    FROM permission_keycloak_group_mappings
                    WHERE keycloak_group ILIKE ? ESCAPE '\'
                       OR role_key ILIKE ? ESCAPE '\'
                    ORDER BY $orderBy
                    OFFSET ? LIMIT ?
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, pattern)
                    statement.setString(2, pattern)
                    statement.setLong(3, pageOffset(page, perPage))
                    statement.setInt(4, perPage)
                    statement.executeQuery().use { rows ->
                        buildList {
                            while (rows.next()) {
                                add(rows.toKeycloakGroupMapping())
                            }
                        }
                    }
                }
        PagedRecords(items, total)
    }

    fun updateKeycloakGroupMapping(
        actorUserId: String,
        mappingId: UUID,
        mapping: KeycloakGroupMappingRecord,
    ): KeycloakGroupMappingRecord {
        writeIfChanged(
            actorUserId,
            "keycloak_group.mapping.updated",
            "keycloakGroup:${mapping.keycloakGroup}",
            auditMetadata { putKeycloakMappingMetadata(mapping.copy(id = mappingId)) },
        ) { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_keycloak_group_mappings
                    SET keycloak_group = ?, role_key = ?, starts_at = ?, expires_at = ?
                    WHERE id = ?
                      AND (
                          keycloak_group IS DISTINCT FROM ? OR role_key IS DISTINCT FROM ? OR
                          starts_at IS DISTINCT FROM ? OR
                          expires_at IS DISTINCT FROM ?
                      )
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, mapping.keycloakGroup)
                    statement.setString(2, mapping.roleKey)
                    statement.setTimestamp(3, mapping.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(4, mapping.expiresAt?.let(Timestamp::from))
                    statement.setObject(5, mappingId)
                    statement.setString(6, mapping.keycloakGroup)
                    statement.setString(7, mapping.roleKey)
                    statement.setTimestamp(8, mapping.startsAt?.let(Timestamp::from))
                    statement.setTimestamp(9, mapping.expiresAt?.let(Timestamp::from))
                    val changed = statement.executeUpdate() > 0
                    require(
                        changed ||
                            entityExists(
                                connection,
                                "permission_keycloak_group_mappings",
                                "id = ?",
                            ) {
                                it.setObject(1, mappingId)
                            }
                    ) {
                        "Keycloak group mapping not found (mappingId=$mappingId)"
                    }
                    changed
                }
        }
        return mapping.copy(id = mappingId)
    }

    fun deleteKeycloakGroupMapping(actorUserId: String, mappingId: UUID) {
        writeIfChanged(
            actorUserId,
            "keycloak_group.mapping.deleted",
            "keycloakGroupMapping:$mappingId",
            auditMetadata { put("mappingId", mappingId.toString()) },
        ) { connection ->
            connection
                .prepareStatement("DELETE FROM permission_keycloak_group_mappings WHERE id = ?")
                .use { statement ->
                    statement.setObject(1, mappingId)
                    statement.executeUpdate() > 0
                }
        }
    }

    fun upsertCatalogEntry(actorUserId: String, entry: CatalogEntryRecord): CatalogEntryRecord {
        writeIfChanged(
            actorUserId,
            "catalog.entry.upserted",
            "permission:${entry.key}",
            auditMetadata { put("catalogKey", entry.key) },
            policyChange = false,
        ) { connection ->
            require(!entry.custom || !catalogEntryOwnedByRuntime(connection, entry.key)) {
                "Catalog entry is owned by runtime registration (permissionKey=${entry.key})"
            }
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_catalog_entries (
                        permission_key, label, description, source, source_version,
                        supported_scopes, custom, last_seen_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (permission_key) DO UPDATE SET
                        label = EXCLUDED.label,
                        description = EXCLUDED.description,
                        source = EXCLUDED.source,
                        source_version = EXCLUDED.source_version,
                        supported_scopes = EXCLUDED.supported_scopes,
                        custom = EXCLUDED.custom,
                        last_seen_at = EXCLUDED.last_seen_at,
                        updated_at = now()
                    WHERE permission_catalog_entries.label IS DISTINCT FROM EXCLUDED.label
                       OR permission_catalog_entries.description IS DISTINCT FROM EXCLUDED.description
                       OR permission_catalog_entries.source IS DISTINCT FROM EXCLUDED.source
                       OR permission_catalog_entries.source_version IS DISTINCT FROM EXCLUDED.source_version
                       OR permission_catalog_entries.supported_scopes IS DISTINCT FROM EXCLUDED.supported_scopes
                       OR permission_catalog_entries.custom IS DISTINCT FROM EXCLUDED.custom
                       OR permission_catalog_entries.last_seen_at IS DISTINCT FROM EXCLUDED.last_seen_at
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, entry.key)
                    statement.setString(2, entry.label)
                    statement.setString(3, entry.description)
                    statement.setString(4, entry.source)
                    statement.setString(5, entry.sourceVersion)
                    statement.setArray(
                        6,
                        connection.createArrayOf(
                            "text",
                            entry.supportedScopes.map { it.name }.toTypedArray(),
                        ),
                    )
                    statement.setBoolean(7, entry.custom)
                    statement.setTimestamp(8, entry.lastSeenAt?.let(Timestamp::from))
                    statement.executeUpdate() > 0
                }
        }
        return entry
    }

    fun replaceRuntimeManifest(registration: RuntimeManifestRegistration) {
        require(
            registration.permissions.map(CatalogEntryRecord::key).distinct().size ==
                registration.permissions.size
        ) {
            "Runtime manifest permission keys must be unique"
        }
        write(
            actorUserId = RUNTIME_CATALOG_ACTOR,
            action = "catalog.runtime_manifest.replaced",
            target = "catalog-source:${registration.source}",
            metadata =
                auditMetadata {
                    put("source", registration.source)
                    put("sourceVersion", registration.sourceVersion)
                    put("serverType", registration.serverType)
                    put("serverId", registration.serverId)
                    put("permissionCount", registration.permissions.size)
                },
            policyChange = false,
        ) { connection ->
            assertRuntimeCatalogOwnership(connection, registration)
            registration.permissions.forEach { entry ->
                upsertRuntimeCatalogEntry(connection, registration, entry)
            }
            deleteStaleRuntimeCatalogEntries(connection, registration)
            insertRuntimeManifestRegistration(connection, registration)
        }
    }

    fun listCatalogEntries(): List<CatalogEntryRecord> = read(::listCatalogEntries)

    private fun listCatalogEntries(connection: Connection): List<CatalogEntryRecord> =
        connection
            .prepareStatement(
                """
                SELECT permission_key, label, description, source, source_version,
                       supported_scopes, custom, last_seen_at
                FROM permission_catalog_entries
                ORDER BY permission_key ASC
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.executeQuery().use { rows ->
                    buildList {
                        while (rows.next()) {
                            add(rows.toCatalogEntry())
                        }
                    }
                }
            }

    fun searchCatalogEntries(
        query: String,
        page: Int,
        perPage: Int,
        sortBy: String,
        sortDirection: String,
    ): PagedRecords<CatalogEntryRecord> = consistentRead { connection ->
        val pattern = searchPattern(query)
        val total =
            connection
                .prepareStatement(
                    """
                    SELECT COUNT(*)
                    FROM permission_catalog_entries
                    WHERE permission_key ILIKE ? ESCAPE '\'
                       OR label ILIKE ? ESCAPE '\'
                       OR description ILIKE ? ESCAPE '\'
                       OR source ILIKE ? ESCAPE '\'
                       OR source_version ILIKE ? ESCAPE '\'
                    """
                        .trimIndent()
                )
                .use { statement ->
                    (1..5).forEach { statement.setString(it, pattern) }
                    statement.executeQuery().use { rows ->
                        check(rows.next())
                        rows.getLong(1)
                    }
                }
        val orderBy =
            searchOrderBy(
                sortBy = sortBy,
                sortDirection = sortDirection,
                allowedSorts =
                    mapOf(
                        "permission" to listOf("LOWER(permission_key)"),
                        "label" to listOf("LOWER(label)"),
                        "source" to listOf("LOWER(source)"),
                        "lastseen" to listOf("last_seen_at"),
                    ),
                tieBreaker = "permission_key",
            )
        val items =
            connection
                .prepareStatement(
                    """
                    SELECT permission_key, label, description, source, source_version,
                           supported_scopes, custom, last_seen_at
                    FROM permission_catalog_entries
                    WHERE permission_key ILIKE ? ESCAPE '\'
                       OR label ILIKE ? ESCAPE '\'
                       OR description ILIKE ? ESCAPE '\'
                       OR source ILIKE ? ESCAPE '\'
                       OR source_version ILIKE ? ESCAPE '\'
                    ORDER BY $orderBy
                    OFFSET ? LIMIT ?
                    """
                        .trimIndent()
                )
                .use { statement ->
                    (1..5).forEach { statement.setString(it, pattern) }
                    statement.setLong(6, pageOffset(page, perPage))
                    statement.setInt(7, perPage)
                    statement.executeQuery().use { rows ->
                        buildList {
                            while (rows.next()) {
                                add(rows.toCatalogEntry())
                            }
                        }
                    }
                }
        PagedRecords(items, total)
    }

    fun permissionProjectSnapshot(): PermissionProjectSnapshot =
        consistentRead(::permissionProjectSnapshot)

    private fun permissionProjectSnapshot(connection: Connection): PermissionProjectSnapshot {
        val roles = listRoles(connection)
        return PermissionProjectSnapshot(
            roles = roles.map { it.toSync() },
            roleGrants =
                roles
                    .flatMap { role -> listRoleGrantRecords(connection, role.key) }
                    .map { it.toSync() },
            inheritance = listRoleInheritances(connection),
            catalogEntries = listCatalogEntries(connection).map { it.toSync() },
            keycloakMappings = listKeycloakGroupMappings(connection).map { it.toSync() },
        )
    }

    fun importPermissionSnapshot(
        snapshot: GlobalPermissionSnapshot,
        expectedTargetFingerprint: String,
        actions: List<PermissionSyncAction>,
        actorUserId: String,
    ): PermissionSyncMetadataRecord {
        val request = PermissionSyncImportRequest(snapshot, expectedTargetFingerprint, actions)
        val sourcePolicy = PermissionSyncPolicyProjection.normalize(snapshot)
        return dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                lockPolicyVersion(connection)
                val currentTarget = permissionProjectSnapshot(connection)
                val currentTargetFingerprint =
                    PermissionSnapshotFingerprint(objectMapper).calculate(currentTarget)
                if (currentTargetFingerprint != expectedTargetFingerprint) {
                    throw PermissionSyncConflictException(
                        PermissionSyncConflictReason.TARGET_CHANGED
                    )
                }
                request.validatedAgainst(PermissionSyncDiff.calculate(currentTarget, snapshot))
                val actionMap = request.actions.associateBy { it.entityType to it.technicalKey }
                validateEffectiveDefaultRoles(currentTarget.roles, sourcePolicy.roles, actionMap)
                rejectRoleRemovalsWithPlayerAssignments(connection, request.actions)
                demoteCurrentDefaultBeforeAppliedDefault(connection, sourcePolicy.roles, actionMap)
                request.actions
                    .filter { it.action == SyncAction.REMOVE_PROJECT_ENTRY }
                    .forEach { action ->
                        deleteSyncEntry(connection, action.entityType, action.technicalKey)
                    }
                sourcePolicy.roles.forEach { role ->
                    val action = actionMap[SyncEntityType.ROLE to role.key]?.action
                    if (action != SyncAction.KEEP_PROJECT) upsertRole(connection, role)
                }
                sourcePolicy.roleGrants.forEach { grant ->
                    val action = actionMap[SyncEntityType.ROLE_GRANT to grant.id.toString()]?.action
                    if (action != SyncAction.KEEP_PROJECT) upsertRoleGrant(connection, grant)
                }
                sourcePolicy.inheritance.forEach { inheritance ->
                    val action = actionMap[SyncEntityType.INHERITANCE to inheritance.key()]?.action
                    if (action != SyncAction.KEEP_PROJECT) {
                        require(inheritance.parentRoleKey != inheritance.childRoleKey) {
                            "Role inheritance would create a cycle (childRoleKey=${inheritance.childRoleKey}, parentRoleKey=${inheritance.parentRoleKey})"
                        }
                        require(
                            !roleHasAncestor(
                                connection,
                                roleKey = inheritance.parentRoleKey,
                                ancestorRoleKey = inheritance.childRoleKey,
                            )
                        ) {
                            "Role inheritance would create a cycle (childRoleKey=${inheritance.childRoleKey}, parentRoleKey=${inheritance.parentRoleKey})"
                        }
                        upsertInheritance(connection, inheritance)
                    }
                }
                val targetCatalogEntries =
                    currentTarget.catalogEntries.associateBy(SyncCatalogEntry::permissionKey)
                sourcePolicy.catalogEntries.forEach { entry ->
                    val action =
                        actionMap[SyncEntityType.CATALOG_ENTRY to entry.permissionKey]?.action
                    if (action != SyncAction.KEEP_PROJECT) {
                        upsertCatalog(
                            connection,
                            entry.copy(
                                lastSeenAt = targetCatalogEntries[entry.permissionKey]?.lastSeenAt
                            ),
                        )
                    }
                }
                sourcePolicy.keycloakMappings.forEach { mapping ->
                    val action =
                        actionMap[SyncEntityType.KEYCLOAK_MAPPING to mapping.id.toString()]?.action
                    if (action != SyncAction.KEEP_PROJECT) upsertMapping(connection, mapping)
                }
                incrementPolicyVersion(connection)
                val importedAt = Instant.now()
                connection
                    .prepareStatement(
                        "INSERT INTO permission_sync_metadata (snapshot_id, actor_user_id, imported_at) VALUES (?, ?, ?)"
                    )
                    .use { statement ->
                        statement.setString(1, snapshot.snapshotId)
                        statement.setString(2, actorUserId)
                        statement.setTimestamp(3, Timestamp.from(importedAt))
                        statement.executeUpdate()
                    }
                insertAuditEvent(
                    connection = connection,
                    actorUserId = actorUserId,
                    action = "permission.sync.imported",
                    target = "snapshot:${snapshot.snapshotId}",
                    metadata =
                        objectMapper.createObjectNode().apply {
                            put("snapshotId", snapshot.snapshotId)
                            put("sourceEnvironment", snapshot.sourceEnvironment)
                            put("sourceServiceVersion", snapshot.sourceServiceVersion)
                            put("targetFingerprint", expectedTargetFingerprint)
                            set<JsonNode>(
                                "selectedActions",
                                objectMapper.valueToTree(request.actions),
                            )
                            put("result", "success")
                        },
                )
                connection.commit()
                snapshotCache.markGlobalsStale()
                PermissionSyncMetadataRecord(snapshot.snapshotId, actorUserId, importedAt)
            } catch (error: Throwable) {
                connection.rollback()
                throw error
            }
        }
    }

    fun deleteCustomCatalogEntry(actorUserId: String, permissionKey: String) {
        writeIfChanged(
            actorUserId,
            "catalog.entry.deleted",
            "permission:$permissionKey",
            auditMetadata { put("catalogKey", permissionKey) },
            policyChange = false,
        ) { connection ->
            connection
                .prepareStatement(
                    "DELETE FROM permission_catalog_entries WHERE permission_key = ? AND custom = TRUE"
                )
                .use { statement ->
                    statement.setString(1, permissionKey)
                    statement.executeUpdate() > 0
                }
        }
    }

    // Compatibility overloads keep internal callers and test fixtures independent of audit actor
    // wiring.
    // Production entry points must pass their authenticated or runtime actor explicitly.
    fun createRole(role: RoleRecord): RoleRecord = createRole(REPOSITORY_SYSTEM_ACTOR, role)

    fun updateRole(roleKey: String, role: RoleRecord): RoleRecord =
        updateRole(REPOSITORY_SYSTEM_ACTOR, roleKey, role)

    fun deleteRole(roleKey: String) = deleteRole(REPOSITORY_SYSTEM_ACTOR, roleKey)

    fun addRoleInheritance(childRoleKey: String, parentRoleKey: String) =
        addRoleInheritance(REPOSITORY_SYSTEM_ACTOR, childRoleKey, parentRoleKey)

    fun removeRoleInheritance(childRoleKey: String, parentRoleKey: String) =
        removeRoleInheritance(REPOSITORY_SYSTEM_ACTOR, childRoleKey, parentRoleKey)

    fun createRoleGrant(grant: RoleGrantRecord): RoleGrantRecord =
        createRoleGrant(REPOSITORY_SYSTEM_ACTOR, grant)

    fun updateRoleGrant(roleKey: String, grantId: UUID, grant: RoleGrantRecord): RoleGrantRecord =
        updateRoleGrant(REPOSITORY_SYSTEM_ACTOR, roleKey, grantId, grant)

    fun deleteRoleGrant(roleKey: String, grantId: UUID) =
        deleteRoleGrant(REPOSITORY_SYSTEM_ACTOR, roleKey, grantId)

    fun createPlayerRoleGrant(grant: PlayerRoleGrantRecord): PlayerRoleGrantRecord =
        createPlayerRoleGrant(REPOSITORY_SYSTEM_ACTOR, grant)

    fun updatePlayerRoleGrant(
        playerId: UUID,
        grantId: UUID,
        grant: PlayerRoleGrantRecord,
    ): PlayerRoleGrantRecord =
        updatePlayerRoleGrant(REPOSITORY_SYSTEM_ACTOR, playerId, grantId, grant)

    fun deletePlayerRoleGrant(playerId: UUID, grantId: UUID) =
        deletePlayerRoleGrant(REPOSITORY_SYSTEM_ACTOR, playerId, grantId)

    fun createPlayerGrant(grant: PlayerGrantRecord): PlayerGrantRecord =
        createPlayerGrant(REPOSITORY_SYSTEM_ACTOR, grant)

    fun updatePlayerGrant(
        playerId: UUID,
        grantId: UUID,
        grant: PlayerGrantRecord,
    ): PlayerGrantRecord = updatePlayerGrant(REPOSITORY_SYSTEM_ACTOR, playerId, grantId, grant)

    fun deletePlayerGrant(playerId: UUID, grantId: UUID) =
        deletePlayerGrant(REPOSITORY_SYSTEM_ACTOR, playerId, grantId)

    fun createKeycloakGroupMapping(
        mapping: KeycloakGroupMappingRecord
    ): KeycloakGroupMappingRecord = createKeycloakGroupMapping(REPOSITORY_SYSTEM_ACTOR, mapping)

    fun updateKeycloakGroupMapping(
        mappingId: UUID,
        mapping: KeycloakGroupMappingRecord,
    ): KeycloakGroupMappingRecord =
        updateKeycloakGroupMapping(REPOSITORY_SYSTEM_ACTOR, mappingId, mapping)

    fun deleteKeycloakGroupMapping(mappingId: UUID) =
        deleteKeycloakGroupMapping(REPOSITORY_SYSTEM_ACTOR, mappingId)

    fun upsertCatalogEntry(entry: CatalogEntryRecord): CatalogEntryRecord =
        upsertCatalogEntry(REPOSITORY_SYSTEM_ACTOR, entry)

    fun importPermissionSnapshot(
        snapshot: GlobalPermissionSnapshot,
        expectedTargetFingerprint: String,
        actions: List<PermissionSyncAction>,
    ): PermissionSyncMetadataRecord =
        importPermissionSnapshot(
            snapshot,
            expectedTargetFingerprint,
            actions,
            REPOSITORY_SYSTEM_ACTOR,
        )

    fun deleteCustomCatalogEntry(permissionKey: String) =
        deleteCustomCatalogEntry(REPOSITORY_SYSTEM_ACTOR, permissionKey)

    fun currentPolicyVersion(): Long = read(::currentPolicyVersion)

    private fun currentPolicyVersion(connection: Connection): Long =
        connection
            .prepareStatement("SELECT version FROM permission_policy_versions WHERE id = 1")
            .use { statement ->
                statement.executeQuery().use { rows ->
                    check(rows.next()) { "Permission policy version row is missing" }
                    rows.getLong("version")
                }
            }

    /**
     * Builds the policy input from cached global definitions and the player's cached rows. A miss
     * costs one database round trip; see [PermissionSnapshotCache].
     */
    fun policyFor(
        request: PermissionPolicyRequest,
        now: Instant = Instant.now(),
    ): PermissionPolicyInput {
        var (globals, player) = cachedPolicyData(request.playerId)
        if (!globals.definesRolesOf(player)) {
            // A role the cached rows reference is gone or not loaded yet: reload both once.
            snapshotCache.evictPlayer(request.playerId)
            snapshotCache.markGlobalsStale()
            val reloaded = cachedPolicyData(request.playerId)
            globals = reloaded.first
            player = reloaded.second
        }
        val mappedRoles =
            if (globals.groupMappings.isEmpty()) {
                emptyList()
            } else {
                if (
                    !identityReadinessCheck.isIdentityPolicyAvailable(
                        snapshotCache.identityLastSuccessAt,
                        now,
                    )
                ) {
                    throw IdentityProjectionUnavailableException()
                }
                globals.groupMappings
                    .filter { it.keycloakGroup in player.groupPaths }
                    .map { mapping ->
                        PlayerRoleGrant(
                            playerId = request.playerId,
                            roleKey = mapping.roleKey,
                            startsAt = mapping.startsAt,
                            expiresAt = mapping.expiresAt,
                            assignmentSource = PermissionRoleAssignmentSource.GROUP_MAPPING,
                            mappingId = mapping.mappingId,
                        )
                    }
            }

        return PermissionPolicyInput(
            policyVersion = globals.policyVersion,
            roles = globals.roles,
            playerRoles = player.roleGrants + mappedRoles,
            playerGrants = player.grants,
            refreshAfter = now.plus(REFRESH_AFTER_OFFSET),
            expiresAt = now.plus(EXPIRES_AFTER_OFFSET),
        )
    }

    /**
     * Polls the policy version, the identity sync state and the player-scoped writes since the last
     * poll in one round trip, so writes made by other instances reach this instance's cache.
     */
    @Synchronized
    fun refreshSnapshotCache() {
        val poll = read { connection ->
            connection
                .prepareStatement(
                    """
                    SELECT
                        (SELECT version FROM permission_policy_versions WHERE id = 1) AS policy_version,
                        (SELECT last_success_at FROM permission_identity_sync_state WHERE id = 1)
                            AS identity_last_success_at,
                        now() AS polled_at,
                        (
                            SELECT COALESCE(
                                json_agg(json_build_object('id', id, 'target', target, 'createdAt', created_at)),
                                '[]'::json
                            )
                            FROM permission_audit_events
                            WHERE action = ANY (?)
                              AND created_at >= COALESCE(?, now()) - ?::interval
                        ) AS player_events
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setArray(
                        1,
                        connection.createArrayOf("text", PLAYER_AUDIT_ACTIONS.toTypedArray()),
                    )
                    statement.setTimestamp(2, lastSnapshotPollAt?.let(Timestamp::from))
                    statement.setString(3, "${SNAPSHOT_POLL_OVERLAP.toSeconds()} seconds")
                    statement.executeQuery().use { rows ->
                        check(rows.next())
                        SnapshotPoll(
                            policyVersion = rows.getLong("policy_version"),
                            identityLastSuccessAt = rows.instantOrNull("identity_last_success_at"),
                            polledAt = rows.getTimestamp("polled_at").toInstant(),
                            playerEvents = objectMapper.readTree(rows.getString("player_events")),
                        )
                    }
                }
        }
        val changedPlayers =
            poll.playerEvents
                .filter { event ->
                    seenPlayerAuditEvents.putIfAbsent(event.uuid("id"), poll.polledAt) == null
                }
                .mapNotNull { event ->
                    event.text("target")?.removePrefix(PLAYER_TARGET_PREFIX)?.let(UUID::fromString)
                }
                .toSet()
        seenPlayerAuditEvents.values.removeIf {
            it.isBefore(poll.polledAt.minus(SNAPSHOT_POLL_OVERLAP.multipliedBy(2)))
        }
        lastSnapshotPollAt = poll.polledAt
        snapshotCache.observe(poll.policyVersion, poll.identityLastSuccessAt, changedPlayers)
        snapshotCache.globals(poll.policyVersion)
    }

    private fun cachedPolicyData(playerId: UUID): Pair<GlobalPolicyDefinitions, PlayerPolicyData> {
        val globals = snapshotCache.globals()
        val player = snapshotCache.player(playerId)
        return if (player.policyVersion > globals.policyVersion) {
            snapshotCache.globals(player.policyVersion) to player
        } else {
            globals to player
        }
    }

    private fun GlobalPolicyDefinitions.definesRolesOf(player: PlayerPolicyData): Boolean {
        val roleKeys = roles.mapTo(mutableSetOf()) { it.key }
        return player.roleGrants.all { it.roleKey in roleKeys }
    }

    private fun loadGlobalDefinitions(connection: Connection): GlobalPolicyDefinitions =
        connection
            .prepareStatement(
                """
                SELECT
                    (SELECT version FROM permission_policy_versions WHERE id = 1) AS policy_version,
                    (SELECT last_success_at FROM permission_identity_sync_state WHERE id = 1)
                        AS identity_last_success_at,
                    (
                        SELECT COALESCE(json_agg(json_build_object(
                            'key', key, 'name', name, 'description', description, 'prefix', prefix,
                            'color', color, 'sortOrder', sort_order, 'isDefault', is_default
                        ) ORDER BY sort_order ASC, key ASC), '[]'::json)
                        FROM permission_roles
                    ) AS roles,
                    (
                        SELECT COALESCE(json_agg(json_build_object(
                            'child', child_role_key, 'parent', parent_role_key
                        ) ORDER BY child_role_key ASC, parent_role_key ASC), '[]'::json)
                        FROM permission_role_inheritance
                    ) AS inheritance,
                    (
                        SELECT COALESCE(json_agg(json_build_object(
                            'id', id, 'roleKey', role_key, 'effect', effect,
                            'pattern', permission_pattern, 'scopeKind', scope_kind,
                            'scopeValue', scope_value, 'startsAt', starts_at, 'expiresAt', expires_at
                        ) ORDER BY created_at ASC, id ASC), '[]'::json)
                        FROM permission_role_grants
                    ) AS role_grants,
                    (
                        SELECT COALESCE(json_agg(json_build_object(
                            'id', id, 'group', keycloak_group, 'roleKey', role_key,
                            'startsAt', starts_at, 'expiresAt', expires_at
                        ) ORDER BY created_at ASC, id ASC), '[]'::json)
                        FROM permission_keycloak_group_mappings
                    ) AS group_mappings
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.executeQuery().use { rows ->
                    check(rows.next()) { "Permission policy version row is missing" }
                    val inheritedRoles =
                        objectMapper
                            .readTree(rows.getString("inheritance"))
                            .groupBy({ it.text("child")!! }, { it.text("parent")!! })
                    val grants =
                        objectMapper
                            .readTree(rows.getString("role_grants"))
                            .groupBy({ it.text("roleKey")!! }, { it.toGrantSpec() })
                    GlobalPolicyDefinitions(
                        policyVersion = rows.getLong("policy_version"),
                        roles =
                            objectMapper.readTree(rows.getString("roles")).map { role ->
                                val key = role.text("key")!!
                                RoleDefinition(
                                    key = key,
                                    name = role.text("name")!!,
                                    description = role.text("description")!!,
                                    prefix = role.text("prefix"),
                                    color = role.text("color"),
                                    sortOrder = role.get("sortOrder").asInt(),
                                    isDefault = role.get("isDefault").asBoolean(),
                                    inheritedRoleKeys = inheritedRoles[key].orEmpty().toSet(),
                                    grants = grants[key].orEmpty(),
                                )
                            },
                        groupMappings =
                            objectMapper.readTree(rows.getString("group_mappings")).map { mapping ->
                                GroupRoleMapping(
                                    mappingId = mapping.uuid("id"),
                                    keycloakGroup = mapping.text("group")!!,
                                    roleKey = mapping.text("roleKey")!!,
                                    startsAt = mapping.instant("startsAt"),
                                    expiresAt = mapping.instant("expiresAt"),
                                )
                            },
                        identityLastSuccessAt = rows.instantOrNull("identity_last_success_at"),
                    )
                }
            }

    private fun loadPlayerPolicyData(
        connection: Connection,
        playerIds: Set<UUID>,
    ): Map<UUID, PlayerPolicyData> =
        connection
            .prepareStatement(
                """
                SELECT
                    players.player_id,
                    (SELECT version FROM permission_policy_versions WHERE id = 1) AS policy_version,
                    (SELECT last_success_at FROM permission_identity_sync_state WHERE id = 1)
                        AS identity_last_success_at,
                    ARRAY(
                        SELECT keycloak_group_path
                        FROM permission_player_keycloak_groups groups
                        WHERE groups.player_id = players.player_id
                        ORDER BY keycloak_group_path
                    ) AS group_paths,
                    (
                        SELECT COALESCE(json_agg(json_build_object(
                            'id', id, 'roleKey', role_key, 'startsAt', starts_at, 'expiresAt', expires_at
                        ) ORDER BY created_at ASC, id ASC), '[]'::json)
                        FROM permission_player_role_grants role_grants
                        WHERE role_grants.player_id = players.player_id
                    ) AS role_grants,
                    (
                        SELECT COALESCE(json_agg(json_build_object(
                            'id', id, 'effect', effect, 'pattern', permission_pattern,
                            'scopeKind', scope_kind, 'scopeValue', scope_value,
                            'startsAt', starts_at, 'expiresAt', expires_at
                        ) ORDER BY created_at ASC, id ASC), '[]'::json)
                        FROM permission_player_grants grants
                        WHERE grants.player_id = players.player_id
                    ) AS grants
                FROM unnest(?::uuid[]) AS players(player_id)
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setArray(1, connection.createArrayOf("uuid", playerIds.toTypedArray()))
                statement.executeQuery().use { rows ->
                    buildMap {
                        while (rows.next()) {
                            val playerId = rows.getObject("player_id", UUID::class.java)
                            put(
                                playerId,
                                PlayerPolicyData(
                                    playerId = playerId,
                                    policyVersion = rows.getLong("policy_version"),
                                    roleGrants =
                                        objectMapper.readTree(rows.getString("role_grants")).map {
                                            grant ->
                                            PlayerRoleGrant(
                                                grantId = grant.uuid("id"),
                                                playerId = playerId,
                                                roleKey = grant.text("roleKey")!!,
                                                startsAt = grant.instant("startsAt"),
                                                expiresAt = grant.instant("expiresAt"),
                                            )
                                        },
                                    grants =
                                        objectMapper.readTree(rows.getString("grants")).map { grant
                                            ->
                                            PlayerPermissionGrant(
                                                grantId = grant.uuid("id"),
                                                playerId = playerId,
                                                grant = grant.toGrantSpec(),
                                                assignmentStartsAt = grant.instant("startsAt"),
                                                assignmentExpiresAt = grant.instant("expiresAt"),
                                            )
                                        },
                                    groupPaths =
                                        (rows.getArray("group_paths").array as Array<*>)
                                            .filterIsInstance<String>()
                                            .toSet(),
                                    identityLastSuccessAt =
                                        rows.instantOrNull("identity_last_success_at"),
                                ),
                            )
                        }
                    }
                }
            }

    private fun JsonNode.text(field: String): String? =
        get(field)?.takeUnless(JsonNode::isNull)?.asText()

    private fun JsonNode.uuid(field: String): UUID = UUID.fromString(text(field))

    private fun JsonNode.instant(field: String): Instant? =
        text(field)?.let { OffsetDateTime.parse(it).toInstant() }

    private fun JsonNode.toGrantSpec(): PermissionGrantSpec =
        PermissionGrantSpec(
            effect = PermissionEffect.valueOf(text("effect")!!),
            pattern = text("pattern")!!,
            scope =
                PermissionScope(
                    kind = PermissionScopeKind.valueOf(text("scopeKind")!!),
                    value = text("scopeValue"),
                ),
            startsAt = instant("startsAt"),
            expiresAt = instant("expiresAt"),
            permissionGrantId = uuid("id"),
        )

    private data class SnapshotPoll(
        val policyVersion: Long,
        val identityLastSuccessAt: Instant?,
        val polledAt: Instant,
        val playerEvents: JsonNode,
    )

    fun requiresIdentityProjection(): Boolean = read(::hasKeycloakGroupMappings)

    fun deleteAllPermissionData() {
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                lockPolicyVersion(connection)
                listOf(
                        "permission_player_keycloak_groups",
                        "permission_player_identity_tombstones",
                        "permission_player_identities",
                        "permission_audit_events",
                        "permission_runtime_registrations",
                        "permission_catalog_entries",
                        "permission_keycloak_group_mappings",
                        "permission_player_grants",
                        "permission_player_role_grants",
                        "permission_role_grants",
                        "permission_role_inheritance",
                        "permission_roles",
                    )
                    .forEach { table ->
                        connection.prepareStatement("DELETE FROM $table").use { it.executeUpdate() }
                    }
                connection
                    .prepareStatement(
                        "UPDATE permission_policy_versions SET version = 1, updated_at = now() WHERE id = 1"
                    )
                    .use { it.executeUpdate() }
                connection
                    .prepareStatement(
                        """
                        UPDATE permission_identity_sync_state
                        SET status = 'IDLE',
                            started_at = NULL,
                            completed_at = NULL,
                            last_success_at = NULL,
                            duration_ms = NULL,
                            player_count = 0,
                            failure_reason = NULL
                        WHERE id = 1
                        """
                            .trimIndent()
                    )
                    .use { it.executeUpdate() }
                connection.commit()
                snapshotCache.clear()
            } catch (error: Throwable) {
                connection.rollback()
                throw error
            }
        }
    }

    private fun listRoleInheritance(connection: Connection): Map<String, Set<String>> =
        connection
            .prepareStatement(
                """
                SELECT child_role_key, parent_role_key
                FROM permission_role_inheritance
                ORDER BY child_role_key ASC, parent_role_key ASC
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.executeQuery().use { rows ->
                    buildMap<String, MutableSet<String>> {
                        while (rows.next()) {
                            getOrPut(rows.getString("child_role_key")) { linkedSetOf() } +=
                                rows.getString("parent_role_key")
                        }
                    }
                }
            }

    private fun hasKeycloakGroupMappings(connection: Connection): Boolean =
        connection
            .prepareStatement("SELECT EXISTS (SELECT 1 FROM permission_keycloak_group_mappings)")
            .use { statement ->
                statement.executeQuery().use { rows ->
                    check(rows.next()) { "Failed to determine whether group mappings exist" }
                    rows.getBoolean(1)
                }
            }

    /** Keeps this instance's snapshot cache in step with its own committed writes. */
    private fun afterPolicyWrite(target: String) {
        snapshotCache.markGlobalsStale()
        if (target.startsWith(PLAYER_TARGET_PREFIX)) {
            snapshotCache.evictPlayer(UUID.fromString(target.removePrefix(PLAYER_TARGET_PREFIX)))
        }
    }

    private fun <T> read(block: (Connection) -> T): T =
        dataSource.connection.use { connection -> block(connection) }

    private fun <T> consistentRead(block: (Connection) -> T): T =
        dataSource.connection.use { connection ->
            connection.transactionIsolation = Connection.TRANSACTION_REPEATABLE_READ
            connection.autoCommit = false
            try {
                val result = block(connection)
                connection.commit()
                result
            } catch (error: Throwable) {
                connection.rollback()
                throw error
            }
        }

    private fun auditMetadata(block: ObjectNode.() -> Unit): ObjectNode =
        objectMapper.createObjectNode().apply(block)

    private fun ObjectNode.putGrantMetadata(grant: RoleGrantRecord) {
        put("roleKey", grant.roleKey)
        put("grantId", grant.id.toString())
        put("permissionPattern", grant.pattern)
        put("effect", grant.effect.name)
        put("scopeKind", grant.scope.kind.name)
        put("scopeValue", grant.scope.value)
        put("startsAt", grant.startsAt?.toString())
        put("expiresAt", grant.expiresAt?.toString())
    }

    private fun ObjectNode.putPlayerRoleGrantMetadata(grant: PlayerRoleGrantRecord) {
        put("playerId", grant.playerId.toString())
        put("grantId", grant.id.toString())
        put("roleKey", grant.roleKey)
        put("startsAt", grant.startsAt?.toString())
        put("expiresAt", grant.expiresAt?.toString())
    }

    private fun ObjectNode.putPlayerGrantMetadata(grant: PlayerGrantRecord) {
        put("playerId", grant.playerId.toString())
        put("grantId", grant.id.toString())
        put("permissionPattern", grant.pattern)
        put("effect", grant.effect.name)
        put("scopeKind", grant.scope.kind.name)
        put("scopeValue", grant.scope.value)
        put("startsAt", grant.startsAt?.toString())
        put("expiresAt", grant.expiresAt?.toString())
    }

    private fun ObjectNode.putKeycloakMappingMetadata(mapping: KeycloakGroupMappingRecord) {
        put("mappingId", mapping.id.toString())
        put("keycloakGroup", mapping.keycloakGroup)
        put("roleKey", mapping.roleKey)
        put("startsAt", mapping.startsAt?.toString())
        put("expiresAt", mapping.expiresAt?.toString())
    }

    /**
     * Runs a mutation under the policy version lock, which serializes every write across replicas.
     * The version only moves when [policyChange] is set: it tells runtimes and caches that snapshot
     * inputs changed, and catalog-only writes (runtime manifests on every server start) never do.
     */
    private fun <T> write(
        actorUserId: String,
        action: String,
        target: String,
        metadata: JsonNode,
        policyChange: Boolean = true,
        block: (Connection) -> T,
    ): T =
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                lockPolicyVersion(connection)
                val result = block(connection)
                if (policyChange) {
                    incrementPolicyVersion(connection)
                }
                insertAuditEvent(connection, actorUserId, action, target, metadata)
                connection.commit()
                if (policyChange) {
                    afterPolicyWrite(target)
                }
                result
            } catch (error: Throwable) {
                connection.rollback()
                throw error
            }
        }

    private fun writeIfChanged(
        actorUserId: String,
        action: String,
        target: String,
        metadata: JsonNode,
        policyChange: Boolean = true,
        block: (Connection) -> Boolean,
    ) {
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                lockPolicyVersion(connection)
                val changed = block(connection)
                if (changed) {
                    if (policyChange) {
                        incrementPolicyVersion(connection)
                    }
                    insertAuditEvent(connection, actorUserId, action, target, metadata)
                }
                connection.commit()
                if (changed && policyChange) {
                    afterPolicyWrite(target)
                }
            } catch (error: Throwable) {
                connection.rollback()
                throw error
            }
        }
    }

    private fun entityExists(
        connection: Connection,
        table: String,
        predicate: String,
        bind: (java.sql.PreparedStatement) -> Unit,
    ): Boolean =
        connection.prepareStatement("SELECT 1 FROM $table WHERE $predicate").use { statement ->
            bind(statement)
            statement.executeQuery().use(ResultSet::next)
        }

    private fun incrementPolicyVersion(connection: Connection) {
        connection
            .prepareStatement(
                "UPDATE permission_policy_versions SET version = version + 1, updated_at = now() WHERE id = 1"
            )
            .use { it.executeUpdate() }
    }

    private fun lockPolicyVersion(connection: Connection) {
        connection
            .prepareStatement(
                "SELECT version FROM permission_policy_versions WHERE id = 1 FOR UPDATE"
            )
            .use { statement -> statement.executeQuery().use { rows -> check(rows.next()) } }
    }

    private fun insertAuditEvent(
        connection: Connection,
        actorUserId: String?,
        action: String,
        target: String,
        metadata: JsonNode,
    ) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_audit_events (id, actor_user_id, action, target, metadata)
                VALUES (?, ?, ?, ?, ?)
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setObject(1, UUID.randomUUID())
                statement.setString(2, actorUserId)
                statement.setString(3, action)
                statement.setString(4, target)
                statement.setObject(5, jsonb(metadata))
                statement.executeUpdate()
            }
    }

    private fun roleHasAncestor(
        connection: Connection,
        roleKey: String,
        ancestorRoleKey: String,
    ): Boolean =
        connection
            .prepareStatement(
                """
                WITH RECURSIVE ancestors(role_key) AS (
                    SELECT parent_role_key
                    FROM permission_role_inheritance
                    WHERE child_role_key = ?
                    UNION
                    SELECT inheritance.parent_role_key
                    FROM permission_role_inheritance inheritance
                    JOIN ancestors ON inheritance.child_role_key = ancestors.role_key
                )
                SELECT 1
                FROM ancestors
                WHERE role_key = ?
                LIMIT 1
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setString(1, roleKey)
                statement.setString(2, ancestorRoleKey)
                statement.executeQuery().use { rows -> rows.next() }
            }

    private fun catalogEntryOwnedByRuntime(connection: Connection, permissionKey: String): Boolean =
        connection
            .prepareStatement(
                """
                SELECT 1
                FROM permission_catalog_entries
                WHERE permission_key = ? AND custom = FALSE
                LIMIT 1
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setString(1, permissionKey)
                statement.executeQuery().use { rows -> rows.next() }
            }

    private fun assertRuntimeCatalogOwnership(
        connection: Connection,
        registration: RuntimeManifestRegistration,
    ) {
        if (registration.permissions.isEmpty()) {
            return
        }
        connection
            .prepareStatement(
                """
                SELECT permission_key, source, custom
                FROM permission_catalog_entries
                WHERE permission_key = ANY (?)
                ORDER BY permission_key ASC
                FOR UPDATE
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setArray(
                    1,
                    connection.createArrayOf(
                        "text",
                        registration.permissions.map(CatalogEntryRecord::key).toTypedArray(),
                    ),
                )
                statement.executeQuery().use { rows ->
                    while (rows.next()) {
                        val existingSource = rows.getString("source")
                        if (rows.getBoolean("custom") || existingSource != registration.source) {
                            throw CatalogSourceConflictException(
                                permissionKey = rows.getString("permission_key"),
                                existingSource = existingSource,
                                requestedSource = registration.source,
                            )
                        }
                    }
                }
            }
    }

    private fun upsertRuntimeCatalogEntry(
        connection: Connection,
        registration: RuntimeManifestRegistration,
        entry: CatalogEntryRecord,
    ) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_catalog_entries (
                    permission_key, label, description, source, source_version,
                    supported_scopes, custom, last_seen_at
                )
                VALUES (?, ?, ?, ?, ?, ?, FALSE, ?)
                ON CONFLICT (permission_key) DO UPDATE SET
                    label = EXCLUDED.label,
                    description = EXCLUDED.description,
                    source = EXCLUDED.source,
                    source_version = EXCLUDED.source_version,
                    supported_scopes = EXCLUDED.supported_scopes,
                    custom = FALSE,
                    last_seen_at = EXCLUDED.last_seen_at,
                    updated_at = now()
                WHERE permission_catalog_entries.label IS DISTINCT FROM EXCLUDED.label
                   OR permission_catalog_entries.description IS DISTINCT FROM EXCLUDED.description
                   OR permission_catalog_entries.source IS DISTINCT FROM EXCLUDED.source
                   OR permission_catalog_entries.source_version IS DISTINCT FROM EXCLUDED.source_version
                   OR permission_catalog_entries.supported_scopes IS DISTINCT FROM EXCLUDED.supported_scopes
                   OR permission_catalog_entries.custom IS DISTINCT FROM FALSE
                   OR permission_catalog_entries.last_seen_at IS DISTINCT FROM EXCLUDED.last_seen_at
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setString(1, entry.key)
                statement.setString(2, entry.label)
                statement.setString(3, entry.description)
                statement.setString(4, registration.source)
                statement.setString(5, registration.sourceVersion)
                statement.setArray(
                    6,
                    connection.createArrayOf(
                        "text",
                        entry.supportedScopes.map { it.name }.toTypedArray(),
                    ),
                )
                statement.setTimestamp(7, Timestamp.from(registration.registeredAt))
                statement.executeUpdate()
            }
    }

    private fun deleteStaleRuntimeCatalogEntries(
        connection: Connection,
        registration: RuntimeManifestRegistration,
    ) {
        connection
            .prepareStatement(
                """
                DELETE FROM permission_catalog_entries
                WHERE custom = FALSE
                  AND source = ?
                  AND permission_key <> ALL (?)
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setString(1, registration.source)
                statement.setArray(
                    2,
                    connection.createArrayOf(
                        "text",
                        registration.permissions.map(CatalogEntryRecord::key).toTypedArray(),
                    ),
                )
                statement.executeUpdate()
            }
    }

    private fun insertRuntimeManifestRegistration(
        connection: Connection,
        registration: RuntimeManifestRegistration,
    ) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_runtime_registrations (
                    id, source, source_version, server_type, server_id, registered_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setObject(1, UUID.randomUUID())
                statement.setString(2, registration.source)
                statement.setString(3, registration.sourceVersion)
                statement.setString(4, registration.serverType)
                statement.setString(5, registration.serverId)
                statement.setTimestamp(6, Timestamp.from(registration.registeredAt))
                statement.executeUpdate()
            }
    }

    private fun upsertRole(connection: Connection, role: SyncRole) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_roles (key, name, description, prefix, color, sort_order, metadata, is_default)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (key) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description,
                    prefix=EXCLUDED.prefix, color=EXCLUDED.color, sort_order=EXCLUDED.sort_order,
                    metadata=EXCLUDED.metadata, is_default=EXCLUDED.is_default, updated_at=now()
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setString(1, role.key)
                statement.setString(2, role.name)
                statement.setString(3, role.description)
                statement.setString(4, role.prefix)
                statement.setString(5, role.color)
                statement.setInt(6, role.sortOrder)
                statement.setObject(7, jsonb(role.metadata))
                statement.setBoolean(8, role.isDefault)
                statement.executeUpdate()
            }
    }

    private fun upsertRoleGrant(connection: Connection, grant: SyncRoleGrant) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_role_grants (
                    id, role_key, effect, permission_pattern, scope_kind, scope_value, starts_at,
                    expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET role_key=EXCLUDED.role_key, effect=EXCLUDED.effect,
                    permission_pattern=EXCLUDED.permission_pattern, scope_kind=EXCLUDED.scope_kind,
                    scope_value=EXCLUDED.scope_value, starts_at=EXCLUDED.starts_at,
                    expires_at=EXCLUDED.expires_at
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setObject(1, grant.id)
                statement.setString(2, grant.roleKey)
                statement.setString(3, grant.effect.name)
                statement.setString(4, grant.permissionPattern)
                statement.setString(5, grant.scopeKind.name)
                statement.setString(6, grant.scopeValue)
                statement.setTimestamp(7, grant.startsAt?.let(Timestamp::from))
                statement.setTimestamp(8, grant.expiresAt?.let(Timestamp::from))
                statement.executeUpdate()
            }
    }

    private fun upsertInheritance(connection: Connection, inheritance: SyncInheritance) {
        connection
            .prepareStatement(
                "INSERT INTO permission_role_inheritance (parent_role_key, child_role_key) VALUES (?, ?) ON CONFLICT DO NOTHING"
            )
            .use { statement ->
                statement.setString(1, inheritance.parentRoleKey)
                statement.setString(2, inheritance.childRoleKey)
                statement.executeUpdate()
            }
    }

    private fun upsertCatalog(connection: Connection, entry: SyncCatalogEntry) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_catalog_entries (permission_key, label, description, source, source_version, supported_scopes, custom, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (permission_key) DO UPDATE SET label=EXCLUDED.label, description=EXCLUDED.description,
                    source=EXCLUDED.source, source_version=EXCLUDED.source_version, supported_scopes=EXCLUDED.supported_scopes,
                    custom=EXCLUDED.custom, last_seen_at=EXCLUDED.last_seen_at, updated_at=now()
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setString(1, entry.permissionKey)
                statement.setString(2, entry.label)
                statement.setString(3, entry.description)
                statement.setString(4, entry.source)
                statement.setString(5, entry.sourceVersion)
                statement.setArray(
                    6,
                    connection.createArrayOf(
                        "text",
                        entry.supportedScopes.map { it.name }.toTypedArray(),
                    ),
                )
                statement.setBoolean(7, entry.custom)
                statement.setTimestamp(8, entry.lastSeenAt?.let(Timestamp::from))
                statement.executeUpdate()
            }
    }

    private fun upsertMapping(connection: Connection, mapping: SyncKeycloakMapping) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_keycloak_group_mappings (
                    id, keycloak_group, role_key, starts_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET
                    keycloak_group=EXCLUDED.keycloak_group, role_key=EXCLUDED.role_key,
                    starts_at=EXCLUDED.starts_at, expires_at=EXCLUDED.expires_at
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setObject(1, mapping.id)
                statement.setString(2, mapping.keycloakGroup)
                statement.setString(3, mapping.roleKey)
                statement.setTimestamp(4, mapping.startsAt?.let(Timestamp::from))
                statement.setTimestamp(5, mapping.expiresAt?.let(Timestamp::from))
                statement.executeUpdate()
            }
    }

    private fun deleteSyncEntry(connection: Connection, type: SyncEntityType, key: String) {
        if (type == SyncEntityType.INHERITANCE) {
            val parts = key.split("->", limit = 2)
            require(parts.size == 2) { "Invalid inheritance technical key (technicalKey=$key)" }
            connection
                .prepareStatement(
                    "DELETE FROM permission_role_inheritance WHERE parent_role_key = ? AND child_role_key = ?"
                )
                .use { statement ->
                    statement.setString(1, parts[0])
                    statement.setString(2, parts[1])
                    statement.executeUpdate()
                }
            return
        }
        val (table, column) =
            when (type) {
                SyncEntityType.ROLE -> "permission_roles" to "key"
                SyncEntityType.ROLE_GRANT -> "permission_role_grants" to "id"
                SyncEntityType.CATALOG_ENTRY -> "permission_catalog_entries" to "permission_key"
                SyncEntityType.KEYCLOAK_MAPPING -> "permission_keycloak_group_mappings" to "id"
            }
        connection.prepareStatement("DELETE FROM $table WHERE $column = ?").use { statement ->
            statement.setObject(1, if (column == "id") UUID.fromString(key) else key)
            statement.executeUpdate()
        }
    }

    private fun validateEffectiveDefaultRoles(
        currentRoles: List<SyncRole>,
        sourceRoles: List<SyncRole>,
        actionMap: Map<Pair<SyncEntityType, String>, PermissionSyncAction>,
    ) {
        val effectiveRoles = currentRoles.associateByTo(linkedMapOf(), SyncRole::key)
        actionMap
            .filter { (key, action) ->
                key.first == SyncEntityType.ROLE && action.action == SyncAction.REMOVE_PROJECT_ENTRY
            }
            .keys
            .forEach { (_, roleKey) -> effectiveRoles.remove(roleKey) }
        sourceRoles.forEach { role ->
            val action = actionMap[SyncEntityType.ROLE to role.key]?.action
            if (action != SyncAction.KEEP_PROJECT) effectiveRoles[role.key] = role
        }
        val defaultRoleKeys =
            effectiveRoles.values.filter(SyncRole::isDefault).map(SyncRole::key).sorted()
        require(defaultRoleKeys.size <= 1) {
            "Permission sync would leave multiple default roles (roleKeys=${defaultRoleKeys.joinToString(",")})"
        }
    }

    private fun rejectRoleRemovalsWithPlayerAssignments(
        connection: Connection,
        actions: List<PermissionSyncAction>,
    ) {
        actions
            .asSequence()
            .filter {
                it.entityType == SyncEntityType.ROLE && it.action == SyncAction.REMOVE_PROJECT_ENTRY
            }
            .map(PermissionSyncAction::technicalKey)
            .sorted()
            .forEach { roleKey ->
                if (
                    entityExists(connection, "permission_player_role_grants", "role_key = ?") {
                        statement ->
                        statement.setString(1, roleKey)
                    }
                ) {
                    throw PermissionSyncConflictException(PermissionSyncConflictReason.ROLE_IN_USE)
                }
            }
    }

    private fun demoteCurrentDefaultBeforeAppliedDefault(
        connection: Connection,
        sourceRoles: List<SyncRole>,
        actionMap: Map<Pair<SyncEntityType, String>, PermissionSyncAction>,
    ) {
        val appliedDefaultRole =
            sourceRoles.firstOrNull { role ->
                role.isDefault &&
                    actionMap[SyncEntityType.ROLE to role.key]?.action != SyncAction.KEEP_PROJECT
            } ?: return
        connection
            .prepareStatement(
                "UPDATE permission_roles SET is_default = FALSE, updated_at = now() WHERE is_default = TRUE AND key <> ?"
            )
            .use { statement ->
                statement.setString(1, appliedDefaultRole.key)
                statement.executeUpdate()
            }
    }

    private fun RoleRecord.toSync() =
        SyncRole(key, name, description, prefix, color, sortOrder, metadata, isDefault)

    private fun RoleGrantRecord.toSync() =
        SyncRoleGrant(id, roleKey, effect, pattern, scope.kind, scope.value, expiresAt, startsAt)

    private fun CatalogEntryRecord.toSync() =
        SyncCatalogEntry(
            key,
            label,
            description,
            source,
            sourceVersion,
            supportedScopes,
            custom,
            lastSeenAt,
        )

    private fun KeycloakGroupMappingRecord.toSync() =
        SyncKeycloakMapping(id, keycloakGroup, roleKey, expiresAt, startsAt)

    private fun SyncInheritance.key() = "$parentRoleKey->$childRoleKey"

    private fun ResultSet.toRoleRecords(): List<RoleRecord> = buildList {
        while (next()) {
            add(
                RoleRecord(
                    key = getString("key"),
                    name = getString("name"),
                    description = getString("description"),
                    prefix = getString("prefix"),
                    color = getString("color"),
                    sortOrder = getInt("sort_order"),
                    metadata = metadataMap(getString("metadata")),
                    isDefault = getBoolean("is_default"),
                )
            )
        }
    }

    private fun ResultSet.toRoleAggregateCountsRecords(): List<RoleAggregateCountsRecord> =
        buildList {
            while (next()) {
                add(
                    RoleAggregateCountsRecord(
                        role =
                            RoleRecord(
                                key = getString("key"),
                                name = getString("name"),
                                description = getString("description"),
                                prefix = getString("prefix"),
                                color = getString("color"),
                                sortOrder = getInt("sort_order"),
                                metadata = metadataMap(getString("metadata")),
                                isDefault = getBoolean("is_default"),
                            ),
                        grantCount = getLong("grant_count"),
                        inheritanceCount = getLong("inheritance_count"),
                    )
                )
            }
        }

    private fun ResultSet.toCatalogEntry(): CatalogEntryRecord =
        CatalogEntryRecord(
            key = getString("permission_key"),
            label = getString("label"),
            description = getString("description"),
            source = getString("source"),
            sourceVersion = getString("source_version"),
            supportedScopes =
                ((getArray("supported_scopes").array as Array<*>).filterIsInstance<String>()).map(
                    PermissionScopeKind::valueOf
                ),
            custom = getBoolean("custom"),
            lastSeenAt = instantOrNull("last_seen_at"),
        )

    private fun ResultSet.toRoleGrantRecord(): RoleGrantRecord =
        RoleGrantRecord(
            id = getObject("id", UUID::class.java),
            roleKey = getString("role_key"),
            effect = PermissionEffect.valueOf(getString("effect")),
            pattern = getString("permission_pattern"),
            scope =
                PermissionScope(
                    kind = PermissionScopeKind.valueOf(getString("scope_kind")),
                    value = getString("scope_value"),
                ),
            startsAt = instantOrNull("starts_at"),
            expiresAt = instantOrNull("expires_at"),
        )

    private fun ResultSet.toPlayerGrantRecord(): PlayerGrantRecord =
        PlayerGrantRecord(
            id = getObject("id", UUID::class.java),
            playerId = getObject("player_id", UUID::class.java),
            effect = PermissionEffect.valueOf(getString("effect")),
            pattern = getString("permission_pattern"),
            scope =
                PermissionScope(
                    kind = PermissionScopeKind.valueOf(getString("scope_kind")),
                    value = getString("scope_value"),
                ),
            startsAt = instantOrNull("starts_at"),
            expiresAt = instantOrNull("expires_at"),
        )

    private fun ResultSet.toKeycloakGroupMapping(): KeycloakGroupMappingRecord =
        KeycloakGroupMappingRecord(
            id = getObject("id", UUID::class.java),
            keycloakGroup = getString("keycloak_group"),
            roleKey = getString("role_key"),
            startsAt = instantOrNull("starts_at"),
            expiresAt = instantOrNull("expires_at"),
        )

    private fun ResultSet.toPermissionAuditEventRecord(): PermissionAuditEventRecord =
        PermissionAuditEventRecord(
            id = getObject("id", UUID::class.java),
            actorUserId = getString("actor_user_id"),
            action = getString("action"),
            target = getString("target"),
            metadata = objectMapper.readTree(getString("metadata")),
            createdAt = getTimestamp("created_at").toInstant(),
        )

    private fun ResultSet.instantOrNull(column: String): Instant? =
        getTimestamp(column)?.toInstant()

    private fun jsonb(value: Any): PGobject =
        PGobject().apply {
            type = "jsonb"
            this.value = objectMapper.writeValueAsString(value)
        }

    private fun validateAuditEventQuery(query: PermissionAuditEventQuery) {
        require(query.page >= 1) { "page must be at least 1" }
        require(query.perPage in 1..100) { "perPage must be between 1 and 100" }
        require(query.from == null || query.to == null || query.from <= query.to) {
            "from must be before or equal to to"
        }
    }

    private fun auditEventPredicates(query: PermissionAuditEventQuery): AuditEventPredicates {
        val predicates = mutableListOf<AuditEventPredicate>()
        if (query.actions.isNotEmpty()) {
            predicates +=
                AuditEventPredicate("action = ANY (?)") { connection, statement, parameter ->
                    statement.setArray(
                        parameter,
                        connection.createArrayOf("text", query.actions.sorted().toTypedArray()),
                    )
                    parameter + 1
                }
        }
        query.from?.let { from ->
            predicates +=
                AuditEventPredicate("created_at >= ?") { _, statement, parameter ->
                    statement.setTimestamp(parameter, Timestamp.from(from))
                    parameter + 1
                }
        }
        query.to?.let { to ->
            predicates +=
                AuditEventPredicate("created_at <= ?") { _, statement, parameter ->
                    statement.setTimestamp(parameter, Timestamp.from(to))
                    parameter + 1
                }
        }
        query.query
            .takeIf { it.isNotBlank() }
            ?.let { search ->
                predicates +=
                    AuditEventPredicate(
                        "(LOWER(action) LIKE ? OR LOWER(target) LIKE ? OR LOWER(COALESCE(actor_user_id, '')) LIKE ?)"
                    ) { _, statement, parameter ->
                        val pattern = "%${search.lowercase()}%"
                        statement.setString(parameter, pattern)
                        statement.setString(parameter + 1, pattern)
                        statement.setString(parameter + 2, pattern)
                        parameter + 3
                    }
            }
        return AuditEventPredicates(predicates)
    }

    private data class AuditEventPredicate(
        val clause: String,
        val bind: (Connection, java.sql.PreparedStatement, Int) -> Int,
    )

    private class AuditEventPredicates(private val predicates: List<AuditEventPredicate>) {
        fun whereClause(): String =
            predicates
                .takeIf { it.isNotEmpty() }
                ?.joinToString(" AND ", prefix = " WHERE ") { it.clause } ?: ""

        fun bind(connection: Connection, statement: java.sql.PreparedStatement): Int =
            predicates.fold(1) { parameter, predicate ->
                predicate.bind(connection, statement, parameter)
            }
    }

    private fun metadataMap(json: String): Map<String, String> =
        objectMapper.readValue(json, STRING_MAP_TYPE)

    private fun searchPattern(query: String): String =
        "%${query.trim().replace(SEARCH_WHITESPACE, " ").escapeLikePattern()}%"

    private fun String.escapeLikePattern(): String =
        replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    private fun pageOffset(page: Int, perPage: Int): Long = (page - 1L) * perPage

    private fun searchOrderBy(
        sortBy: String,
        sortDirection: String,
        allowedSorts: Map<String, List<String>>,
        tieBreaker: String,
    ): String {
        val expressions =
            requireNotNull(allowedSorts[sortBy]) { "Unsupported sort key (sortBy=$sortBy)" }
        val direction =
            when (sortDirection) {
                "asc" -> "ASC"
                "desc" -> "DESC"
                else ->
                    throw IllegalArgumentException(
                        "Unsupported sort direction (sortDirection=$sortDirection)"
                    )
            }
        return expressions.joinToString { "$it $direction NULLS LAST" } + ", $tieBreaker ASC"
    }

    companion object {
        private const val REPOSITORY_SYSTEM_ACTOR = "system:repository"
        private const val RUNTIME_CATALOG_ACTOR = "runtime:catalog"
        private const val POSTGRES_UNIQUE_VIOLATION = "23505"
        private const val PERMISSION_ROLES_PRIMARY_KEY = "permission_roles_pkey"
        private val REFRESH_AFTER_OFFSET = Duration.ofMinutes(5)
        private val EXPIRES_AFTER_OFFSET = Duration.ofMinutes(10)
        private val STRING_MAP_TYPE = object : TypeReference<Map<String, String>>() {}
        private val SEARCH_WHITESPACE = Regex("\\s+")
        private const val PLAYER_TARGET_PREFIX = "player:"
        private val PLAYER_AUDIT_ACTIONS =
            listOf(
                "player.role_grant.created",
                "player.role_grant.updated",
                "player.role_grant.deleted",
                "player.grant.created",
                "player.grant.updated",
                "player.grant.deleted",
            )

        /** How far each poll looks back, so writes that commit late are still seen. */
        private val SNAPSHOT_POLL_OVERLAP = Duration.ofSeconds(60)
    }
}
