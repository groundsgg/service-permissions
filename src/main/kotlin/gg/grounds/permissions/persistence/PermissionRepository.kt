package gg.grounds.permissions.persistence

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionGrantSpec
import gg.grounds.permissions.domain.PermissionPolicyInput
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.PlayerRoleGrant
import gg.grounds.permissions.domain.RoleDefinition
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Duration
import java.time.Instant
import java.util.UUID
import javax.sql.DataSource
import org.postgresql.util.PGobject

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

@ApplicationScoped
class PermissionRepository
@Inject
constructor(private val dataSource: DataSource, private val objectMapper: ObjectMapper) {

    fun createRole(role: RoleRecord): RoleRecord =
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

    fun policyFor(request: PermissionPolicyRequest): PermissionPolicyInput {
        val now = Instant.now()
        val roles = listRoleDefinitions()
        val directPlayerRoles = listPlayerRoleGrants(request.playerId)
        val mappedRoles = listMappedRoleGrants(request)
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

    fun deleteAllPermissionData() {
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                listOf(
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
                SELECT player_id, role_key, expires_at
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

    private fun listMappedRoleGrants(request: PermissionPolicyRequest): List<PlayerRoleGrant> {
        if (request.keycloakGroups.isEmpty()) {
            return emptyList()
        }

        return read { connection ->
            connection
                .prepareStatement(
                    """
                    SELECT role_key, expires_at
                    FROM permission_keycloak_group_mappings
                    WHERE keycloak_group = ANY (?)
                    ORDER BY created_at ASC, id ASC
                    """
                        .trimIndent()
                )
                .use { statement ->
                    statement.setArray(
                        1,
                        connection.createArrayOf("text", request.keycloakGroups.toTypedArray()),
                    )
                    statement.executeQuery().use { rows ->
                        buildList {
                            while (rows.next()) {
                                add(
                                    PlayerRoleGrant(
                                        playerId = request.playerId,
                                        roleKey = rows.getString("role_key"),
                                        expiresAt = rows.instantOrNull("expires_at"),
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
                SELECT player_id, effect, permission_pattern, scope_kind, scope_value, expires_at
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

    companion object {
        private val REFRESH_AFTER_OFFSET = Duration.ofMinutes(5)
        private val EXPIRES_AFTER_OFFSET = Duration.ofMinutes(10)
        private val STRING_MAP_TYPE = object : TypeReference<Map<String, String>>() {}
    }
}
