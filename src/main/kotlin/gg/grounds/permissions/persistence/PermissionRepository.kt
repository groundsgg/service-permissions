package gg.grounds.permissions.persistence

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import gg.grounds.permissions.api.PermissionPolicyRequest
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
import gg.grounds.permissions.sync.PermissionSyncAction
import gg.grounds.permissions.sync.SyncAction
import gg.grounds.permissions.sync.SyncCatalogEntry
import gg.grounds.permissions.sync.SyncEntityType
import gg.grounds.permissions.sync.SyncInheritance
import gg.grounds.permissions.sync.SyncKeycloakMapping
import gg.grounds.permissions.sync.SyncRole
import gg.grounds.permissions.sync.SyncRoleGrant
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Duration
import java.time.Instant
import java.util.UUID
import javax.sql.DataSource
import org.eclipse.microprofile.health.Readiness
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
)

data class PlayerRoleGrantRecord(
    val id: UUID,
    val playerId: UUID,
    val roleKey: String,
    val expiresAt: Instant? = null,
)

data class PlayerGrantRecord(
    val id: UUID,
    val playerId: UUID,
    val effect: PermissionEffect,
    val pattern: String,
    val scope: PermissionScope,
    val expiresAt: Instant? = null,
)

data class KeycloakGroupMappingRecord(
    val id: UUID,
    val keycloakGroup: String,
    val roleKey: String,
    val expiresAt: Instant? = null,
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

data class PermissionSyncMetadataRecord(
    val snapshotId: String,
    val actorUserId: String,
    val importedAt: Instant,
)

data class PagedRecords<T>(val items: List<T>, val total: Long)

@ApplicationScoped
class PermissionRepository
@Inject
constructor(
    private val dataSource: DataSource,
    private val objectMapper: ObjectMapper,
    private val identityRepository: PlayerIdentityRepository,
    @param:Readiness private val identityReadinessCheck: IdentitySyncReadinessCheck,
) {

    fun createRole(role: RoleRecord): RoleRecord =
        try {
            write("role.created", "role:${role.key}") { connection ->
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

    fun listRoles(): List<RoleRecord> = read { connection ->
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

    fun updateRole(roleKey: String, role: RoleRecord): RoleRecord =
        write("role.updated", "role:$roleKey") { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_roles
                    SET name = ?, description = ?, prefix = ?, color = ?, sort_order = ?,
                        metadata = ?, is_default = ?, updated_at = now()
                    WHERE key = ?
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
                    require(statement.executeUpdate() == 1) { "Role not found (roleKey=$roleKey)" }
                }
            role.copy(key = roleKey)
        }

    fun deleteRole(roleKey: String) {
        write("role.deleted", "role:$roleKey") { connection ->
            connection.prepareStatement("DELETE FROM permission_roles WHERE key = ?").use {
                statement ->
                statement.setString(1, roleKey)
                require(statement.executeUpdate() == 1) { "Role not found (roleKey=$roleKey)" }
            }
        }
    }

    fun addRoleInheritance(childRoleKey: String, parentRoleKey: String) {
        write("role.inheritance.created", "role:$childRoleKey") { connection ->
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
                    statement.executeUpdate()
                }
        }
    }

    fun removeRoleInheritance(childRoleKey: String, parentRoleKey: String) {
        write("role.inheritance.deleted", "role:$childRoleKey") { connection ->
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
                    statement.executeUpdate()
                }
        }
    }

    fun createRoleGrant(grant: RoleGrantRecord): RoleGrantRecord =
        write("role.grant.created", "role:${grant.roleKey}") { connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_role_grants (
                        id, role_key, effect, permission_pattern, scope_kind, scope_value, expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
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
                    statement.setTimestamp(7, grant.expiresAt?.let(Timestamp::from))
                    statement.executeUpdate()
                }
            grant
        }

    fun listRoleGrantRecords(roleKey: String): List<RoleGrantRecord> = read { connection ->
        connection
            .prepareStatement(
                """
                SELECT id, role_key, effect, permission_pattern, scope_kind, scope_value, expires_at
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
                        "expiration" to listOf("expires_at"),
                    ),
                tieBreaker = "id",
            )
        val items =
            connection
                .prepareStatement(
                    """
                    SELECT id, role_key, effect, permission_pattern, scope_kind, scope_value,
                           expires_at
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

    fun listRoleInheritances(): List<SyncInheritance> = read { connection ->
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
    }

    fun updateRoleGrant(roleKey: String, grantId: UUID, grant: RoleGrantRecord): RoleGrantRecord =
        write("role.grant.updated", "role:$roleKey") { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_role_grants
                    SET effect = ?, permission_pattern = ?, scope_kind = ?, scope_value = ?, expires_at = ?
                    WHERE id = ? AND role_key = ?
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, grant.effect.name)
                    statement.setString(2, grant.pattern)
                    statement.setString(3, grant.scope.kind.name)
                    statement.setString(4, grant.scope.value)
                    statement.setTimestamp(5, grant.expiresAt?.let(Timestamp::from))
                    statement.setObject(6, grantId)
                    statement.setString(7, roleKey)
                    require(statement.executeUpdate() == 1) {
                        "Role grant not found (grantId=$grantId)"
                    }
                }
            grant.copy(id = grantId, roleKey = roleKey)
        }

    fun deleteRoleGrant(roleKey: String, grantId: UUID) {
        write("role.grant.deleted", "role:$roleKey") { connection ->
            connection
                .prepareStatement(
                    "DELETE FROM permission_role_grants WHERE id = ? AND role_key = ?"
                )
                .use { statement ->
                    statement.setObject(1, grantId)
                    statement.setString(2, roleKey)
                    statement.executeUpdate()
                }
        }
    }

    fun createPlayerRoleGrant(grant: PlayerRoleGrantRecord): PlayerRoleGrantRecord =
        write("player.role_grant.created", "player:${grant.playerId}") { connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_player_role_grants (id, player_id, role_key, expires_at)
                    VALUES (?, ?, ?, ?)
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setObject(1, grant.id)
                    statement.setObject(2, grant.playerId)
                    statement.setString(3, grant.roleKey)
                    statement.setTimestamp(4, grant.expiresAt?.let(Timestamp::from))
                    statement.executeUpdate()
                }
            grant
        }

    fun listPlayerRoleGrantRecords(playerId: UUID): List<PlayerRoleGrantRecord> =
        read { connection ->
            connection
                .prepareStatement(
                    """
                    SELECT id, player_id, role_key, expires_at
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
                                        expiresAt = rows.instantOrNull("expires_at"),
                                    )
                                )
                            }
                        }
                    }
                }
        }

    fun updatePlayerRoleGrant(
        playerId: UUID,
        grantId: UUID,
        grant: PlayerRoleGrantRecord,
    ): PlayerRoleGrantRecord =
        write("player.role_grant.updated", "player:$playerId") { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_player_role_grants
                    SET role_key = ?, expires_at = ?
                    WHERE id = ? AND player_id = ?
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, grant.roleKey)
                    statement.setTimestamp(2, grant.expiresAt?.let(Timestamp::from))
                    statement.setObject(3, grantId)
                    statement.setObject(4, playerId)
                    require(statement.executeUpdate() == 1) {
                        "Player role grant not found (grantId=$grantId)"
                    }
                }
            grant.copy(id = grantId, playerId = playerId)
        }

    fun deletePlayerRoleGrant(playerId: UUID, grantId: UUID) {
        write("player.role_grant.deleted", "player:$playerId") { connection ->
            connection
                .prepareStatement(
                    "DELETE FROM permission_player_role_grants WHERE id = ? AND player_id = ?"
                )
                .use { statement ->
                    statement.setObject(1, grantId)
                    statement.setObject(2, playerId)
                    statement.executeUpdate()
                }
        }
    }

    fun createPlayerGrant(grant: PlayerGrantRecord): PlayerGrantRecord =
        write("player.grant.created", "player:${grant.playerId}") { connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_player_grants (
                        id, player_id, effect, permission_pattern, scope_kind, scope_value, expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
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
                    statement.setTimestamp(7, grant.expiresAt?.let(Timestamp::from))
                    statement.executeUpdate()
                }
            grant
        }

    fun listPlayerGrantRecords(playerId: UUID): List<PlayerGrantRecord> = read { connection ->
        connection
            .prepareStatement(
                """
                SELECT id, player_id, effect, permission_pattern, scope_kind, scope_value, expires_at
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
                        "expiration" to listOf("expires_at"),
                    ),
                tieBreaker = "id",
            )
        val items =
            connection
                .prepareStatement(
                    """
                    SELECT id, player_id, effect, permission_pattern, scope_kind, scope_value,
                           expires_at
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
        playerId: UUID,
        grantId: UUID,
        grant: PlayerGrantRecord,
    ): PlayerGrantRecord =
        write("player.grant.updated", "player:$playerId") { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_player_grants
                    SET effect = ?, permission_pattern = ?, scope_kind = ?, scope_value = ?, expires_at = ?
                    WHERE id = ? AND player_id = ?
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, grant.effect.name)
                    statement.setString(2, grant.pattern)
                    statement.setString(3, grant.scope.kind.name)
                    statement.setString(4, grant.scope.value)
                    statement.setTimestamp(5, grant.expiresAt?.let(Timestamp::from))
                    statement.setObject(6, grantId)
                    statement.setObject(7, playerId)
                    require(statement.executeUpdate() == 1) {
                        "Player grant not found (grantId=$grantId)"
                    }
                }
            grant.copy(id = grantId, playerId = playerId)
        }

    fun deletePlayerGrant(playerId: UUID, grantId: UUID) {
        write("player.grant.deleted", "player:$playerId") { connection ->
            connection
                .prepareStatement(
                    "DELETE FROM permission_player_grants WHERE id = ? AND player_id = ?"
                )
                .use { statement ->
                    statement.setObject(1, grantId)
                    statement.setObject(2, playerId)
                    statement.executeUpdate()
                }
        }
    }

    fun createKeycloakGroupMapping(
        mapping: KeycloakGroupMappingRecord
    ): KeycloakGroupMappingRecord =
        write("keycloak_group.mapping.created", "keycloakGroup:${mapping.keycloakGroup}") {
            connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO permission_keycloak_group_mappings (
                        id, keycloak_group, role_key, expires_at
                    )
                    VALUES (?, ?, ?, ?)
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setObject(1, mapping.id)
                    statement.setString(2, mapping.keycloakGroup)
                    statement.setString(3, mapping.roleKey)
                    statement.setTimestamp(4, mapping.expiresAt?.let(Timestamp::from))
                    statement.executeUpdate()
                }
            mapping
        }

    fun listKeycloakGroupMappings(): List<KeycloakGroupMappingRecord> = read { connection ->
        connection
            .prepareStatement(
                """
                SELECT id, keycloak_group, role_key, expires_at
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
                        "expiration" to listOf("expires_at"),
                    ),
                tieBreaker = "id",
            )
        val items =
            connection
                .prepareStatement(
                    """
                    SELECT id, keycloak_group, role_key, expires_at
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
        mappingId: UUID,
        mapping: KeycloakGroupMappingRecord,
    ): KeycloakGroupMappingRecord =
        write("keycloak_group.mapping.updated", "keycloakGroup:${mapping.keycloakGroup}") {
            connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE permission_keycloak_group_mappings
                    SET keycloak_group = ?, role_key = ?, expires_at = ?
                    WHERE id = ?
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setString(1, mapping.keycloakGroup)
                    statement.setString(2, mapping.roleKey)
                    statement.setTimestamp(3, mapping.expiresAt?.let(Timestamp::from))
                    statement.setObject(4, mappingId)
                    require(statement.executeUpdate() == 1) {
                        "Keycloak group mapping not found (mappingId=$mappingId)"
                    }
                }
            mapping.copy(id = mappingId)
        }

    fun deleteKeycloakGroupMapping(mappingId: UUID) {
        write("keycloak_group.mapping.deleted", "keycloakGroupMapping:$mappingId") { connection ->
            connection
                .prepareStatement("DELETE FROM permission_keycloak_group_mappings WHERE id = ?")
                .use { statement ->
                    statement.setObject(1, mappingId)
                    statement.executeUpdate()
                }
        }
    }

    fun upsertCatalogEntry(entry: CatalogEntryRecord): CatalogEntryRecord =
        write("catalog.entry.upserted", "permission:${entry.key}") { connection ->
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
                    statement.executeUpdate()
                }
            entry
        }

    fun listCatalogEntries(): List<CatalogEntryRecord> = read { connection ->
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
        PermissionProjectSnapshot(
            roles = listRoles().map { it.toSync() },
            roleGrants =
                listRoles().flatMap { role -> listRoleGrantRecords(role.key) }.map { it.toSync() },
            inheritance = listRoleInheritances(),
            catalogEntries = listCatalogEntries().map { it.toSync() },
            keycloakMappings = listKeycloakGroupMappings().map { it.toSync() },
        )

    fun importPermissionSnapshot(
        snapshot: GlobalPermissionSnapshot,
        actions: List<PermissionSyncAction>,
        actorUserId: String,
    ): PermissionSyncMetadataRecord =
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                val actionMap = actions.associateBy { it.entityType to it.technicalKey }
                actions
                    .filter { it.action == SyncAction.REMOVE_PROJECT_ENTRY }
                    .forEach { action ->
                        deleteSyncEntry(connection, action.entityType, action.technicalKey)
                    }
                snapshot.roles.forEach { role ->
                    val action = actionMap[SyncEntityType.ROLE to role.key]?.action
                    if (action != SyncAction.KEEP_PROJECT) upsertRole(connection, role)
                }
                snapshot.roleGrants.forEach { grant ->
                    val action = actionMap[SyncEntityType.ROLE_GRANT to grant.id.toString()]?.action
                    if (action != SyncAction.KEEP_PROJECT) upsertRoleGrant(connection, grant)
                }
                snapshot.inheritance.forEach { inheritance ->
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
                snapshot.catalogEntries.forEach { entry ->
                    val action =
                        actionMap[SyncEntityType.CATALOG_ENTRY to entry.permissionKey]?.action
                    if (action != SyncAction.KEEP_PROJECT) upsertCatalog(connection, entry)
                }
                snapshot.keycloakMappings.orEmpty().forEach { mapping ->
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
                    connection,
                    "permission.sync.imported",
                    "snapshot:${snapshot.snapshotId}",
                )
                connection.commit()
                PermissionSyncMetadataRecord(snapshot.snapshotId, actorUserId, importedAt)
            } catch (error: Throwable) {
                connection.rollback()
                throw error
            }
        }

    fun deleteCustomCatalogEntry(permissionKey: String) {
        write("catalog.entry.deleted", "permission:$permissionKey") { connection ->
            connection
                .prepareStatement(
                    "DELETE FROM permission_catalog_entries WHERE permission_key = ? AND custom = TRUE"
                )
                .use { statement ->
                    statement.setString(1, permissionKey)
                    statement.executeUpdate()
                }
        }
    }

    fun currentPolicyVersion(): Long = read { connection ->
        connection
            .prepareStatement("SELECT version FROM permission_policy_versions WHERE id = 1")
            .use { statement ->
                statement.executeQuery().use { rows ->
                    check(rows.next()) { "Permission policy version row is missing" }
                    rows.getLong("version")
                }
            }
    }

    fun policyFor(
        request: PermissionPolicyRequest,
        now: Instant = Instant.now(),
    ): PermissionPolicyInput {
        val roles = listRoleDefinitions()
        val directPlayerRoles = listPlayerRoleGrants(request.playerId)
        val mappedRoles =
            if (hasKeycloakGroupMappings()) {
                if (!identityReadinessCheck.isIdentityPolicyAvailable(now)) {
                    throw IdentityProjectionUnavailableException()
                }
                val groupPaths =
                    identityRepository.findByPlayerId(request.playerId)?.groupPaths.orEmpty()
                listMappedRoleGrants(request.playerId, groupPaths)
            } else {
                emptyList()
            }
        val playerGrants = listPlayerGrants(request.playerId)

        return PermissionPolicyInput(
            policyVersion = currentPolicyVersion(),
            roles = roles,
            playerRoles = directPlayerRoles + mappedRoles,
            playerGrants = playerGrants,
            refreshAfter = now.plus(REFRESH_AFTER_OFFSET),
            expiresAt = now.plus(EXPIRES_AFTER_OFFSET),
        )
    }

    fun requiresIdentityProjection(): Boolean = hasKeycloakGroupMappings()

    fun deleteAllPermissionData() {
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
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
            } catch (error: Throwable) {
                connection.rollback()
                throw error
            }
        }
    }

    private fun listRoleDefinitions(): List<RoleDefinition> = read { connection ->
        val inheritedRoles = listRoleInheritance(connection)
        val grants = listRoleGrants(connection)
        listRoles().map { role ->
            RoleDefinition(
                key = role.key,
                name = role.name,
                description = role.description,
                prefix = role.prefix,
                color = role.color,
                sortOrder = role.sortOrder,
                isDefault = role.isDefault,
                inheritedRoleKeys = inheritedRoles[role.key].orEmpty(),
                grants = grants[role.key].orEmpty(),
            )
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

    private fun listRoleGrants(connection: Connection): Map<String, List<PermissionGrantSpec>> =
        connection
            .prepareStatement(
                """
                SELECT role_key, effect, permission_pattern, scope_kind, scope_value, expires_at
                FROM permission_role_grants
                ORDER BY created_at ASC, id ASC
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.executeQuery().use { rows ->
                    buildMap<String, MutableList<PermissionGrantSpec>> {
                        while (rows.next()) {
                            getOrPut(rows.getString("role_key")) { mutableListOf() } +=
                                rows.toGrantSpec()
                        }
                    }
                }
            }

    private fun listPlayerRoleGrants(playerId: UUID): List<PlayerRoleGrant> = read { connection ->
        connection
            .prepareStatement(
                """
                SELECT id, player_id, role_key, expires_at
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
                                PlayerRoleGrant(
                                    grantId = rows.getObject("id", UUID::class.java),
                                    playerId = rows.getObject("player_id", UUID::class.java),
                                    roleKey = rows.getString("role_key"),
                                    expiresAt = rows.instantOrNull("expires_at"),
                                )
                            )
                        }
                    }
                }
            }
    }

    private fun hasKeycloakGroupMappings(): Boolean = read { connection ->
        connection
            .prepareStatement("SELECT EXISTS (SELECT 1 FROM permission_keycloak_group_mappings)")
            .use { statement ->
                statement.executeQuery().use { rows ->
                    check(rows.next()) { "Failed to determine whether group mappings exist" }
                    rows.getBoolean(1)
                }
            }
    }

    private fun listMappedRoleGrants(
        playerId: UUID,
        keycloakGroups: Set<String>,
    ): List<PlayerRoleGrant> {
        if (keycloakGroups.isEmpty()) {
            return emptyList()
        }

        return read { connection ->
            connection
                .prepareStatement(
                    """
                    SELECT id, role_key, expires_at
                    FROM permission_keycloak_group_mappings
                    WHERE keycloak_group = ANY (?)
                    ORDER BY created_at ASC, id ASC
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setArray(
                        1,
                        connection.createArrayOf("text", keycloakGroups.toTypedArray()),
                    )
                    statement.executeQuery().use { rows ->
                        buildList {
                            while (rows.next()) {
                                add(
                                    PlayerRoleGrant(
                                        playerId = playerId,
                                        roleKey = rows.getString("role_key"),
                                        expiresAt = rows.instantOrNull("expires_at"),
                                        assignmentSource =
                                            PermissionRoleAssignmentSource.GROUP_MAPPING,
                                        mappingId = rows.getObject("id", UUID::class.java),
                                    )
                                )
                            }
                        }
                    }
                }
        }
    }

    private fun listPlayerGrants(playerId: UUID): List<PlayerPermissionGrant> = read { connection ->
        connection
            .prepareStatement(
                """
                SELECT id, player_id, effect, permission_pattern, scope_kind, scope_value, expires_at
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
                            add(
                                PlayerPermissionGrant(
                                    grantId = rows.getObject("id", UUID::class.java),
                                    playerId = rows.getObject("player_id", UUID::class.java),
                                    grant = rows.toGrantSpec(),
                                )
                            )
                        }
                    }
                }
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

    private fun <T> write(action: String, target: String, block: (Connection) -> T): T =
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                val result = block(connection)
                incrementPolicyVersion(connection)
                insertAuditEvent(connection, action, target)
                connection.commit()
                result
            } catch (error: Throwable) {
                connection.rollback()
                throw error
            }
        }

    private fun incrementPolicyVersion(connection: Connection) {
        connection
            .prepareStatement(
                "UPDATE permission_policy_versions SET version = version + 1, updated_at = now() WHERE id = 1"
            )
            .use { it.executeUpdate() }
    }

    private fun insertAuditEvent(connection: Connection, action: String, target: String) {
        connection
            .prepareStatement(
                """
                INSERT INTO permission_audit_events (id, action, target, metadata)
                VALUES (?, ?, ?, '{}'::jsonb)
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setObject(1, UUID.randomUUID())
                statement.setString(2, action)
                statement.setString(3, target)
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
                INSERT INTO permission_role_grants (id, role_key, effect, permission_pattern, scope_kind, scope_value, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET role_key=EXCLUDED.role_key, effect=EXCLUDED.effect,
                    permission_pattern=EXCLUDED.permission_pattern, scope_kind=EXCLUDED.scope_kind,
                    scope_value=EXCLUDED.scope_value, expires_at=EXCLUDED.expires_at
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
                statement.setTimestamp(7, grant.expiresAt?.let(Timestamp::from))
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
                INSERT INTO permission_keycloak_group_mappings (id, keycloak_group, role_key, expires_at)
                VALUES (?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET keycloak_group=EXCLUDED.keycloak_group,
                    role_key=EXCLUDED.role_key, expires_at=EXCLUDED.expires_at
                """
                    .trimIndent()
            )
            .use { statement ->
                statement.setObject(1, mapping.id)
                statement.setString(2, mapping.keycloakGroup)
                statement.setString(3, mapping.roleKey)
                statement.setTimestamp(4, mapping.expiresAt?.let(Timestamp::from))
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

    private fun RoleRecord.toSync() =
        SyncRole(key, name, description, prefix, color, sortOrder, metadata, isDefault)

    private fun RoleGrantRecord.toSync() =
        SyncRoleGrant(id, roleKey, effect, pattern, scope.kind, scope.value, expiresAt)

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
        SyncKeycloakMapping(id, keycloakGroup, roleKey, expiresAt)

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
            expiresAt = instantOrNull("expires_at"),
        )

    private fun ResultSet.toKeycloakGroupMapping(): KeycloakGroupMappingRecord =
        KeycloakGroupMappingRecord(
            id = getObject("id", UUID::class.java),
            keycloakGroup = getString("keycloak_group"),
            roleKey = getString("role_key"),
            expiresAt = instantOrNull("expires_at"),
        )

    private fun ResultSet.toGrantSpec(): PermissionGrantSpec =
        PermissionGrantSpec(
            effect = PermissionEffect.valueOf(getString("effect")),
            pattern = getString("permission_pattern"),
            scope =
                PermissionScope(
                    kind = PermissionScopeKind.valueOf(getString("scope_kind")),
                    value = getString("scope_value"),
                ),
            expiresAt = instantOrNull("expires_at"),
        )

    private fun ResultSet.instantOrNull(column: String): Instant? =
        getTimestamp(column)?.toInstant()

    private fun jsonb(value: Map<String, String>): PGobject =
        PGobject().apply {
            type = "jsonb"
            this.value = objectMapper.writeValueAsString(value)
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
        private const val POSTGRES_UNIQUE_VIOLATION = "23505"
        private const val PERMISSION_ROLES_PRIMARY_KEY = "permission_roles_pkey"
        private val REFRESH_AFTER_OFFSET = Duration.ofMinutes(5)
        private val EXPIRES_AFTER_OFFSET = Duration.ofMinutes(10)
        private val STRING_MAP_TYPE = object : TypeReference<Map<String, String>>() {}
        private val SEARCH_WHITESPACE = Regex("\\s+")
    }
}
