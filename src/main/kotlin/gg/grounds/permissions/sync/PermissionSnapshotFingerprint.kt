package gg.grounds.permissions.sync

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.ObjectNode
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

@ApplicationScoped
class PermissionSnapshotFingerprint @Inject constructor(private val objectMapper: ObjectMapper) {
    fun calculate(snapshot: PermissionProjectSnapshot): String {
        val canonical = objectMapper.createObjectNode()
        canonical.set<ArrayNode>("roles", canonicalRoles(snapshot.roles))
        canonical.set<ArrayNode>("roleGrants", canonicalRoleGrants(snapshot.roleGrants))
        canonical.set<ArrayNode>("inheritance", canonicalInheritance(snapshot.inheritance))
        canonical.set<ArrayNode>("catalogEntries", canonicalCatalogEntries(snapshot.catalogEntries))
        canonical.set<ArrayNode>(
            "keycloakMappings",
            canonicalKeycloakMappings(snapshot.keycloakMappings),
        )
        val digest =
            MessageDigest.getInstance("SHA-256")
                .digest(
                    objectMapper.writeValueAsString(canonical).toByteArray(StandardCharsets.UTF_8)
                )
        return digest.joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }

    private fun canonicalRoles(roles: List<SyncRole>): ArrayNode =
        objectMapper.createArrayNode().apply {
            roles.sortedBy(SyncRole::key).forEach { role ->
                add(
                    objectMapper.createObjectNode().apply {
                        put("key", role.key)
                        put("name", role.name)
                        put("description", role.description)
                        putNullable("prefix", role.prefix)
                        putNullable("color", role.color)
                        put("sortOrder", role.sortOrder)
                        set<ObjectNode>(
                            "metadata",
                            objectMapper.createObjectNode().apply {
                                role.metadata.toSortedMap().forEach { (key, value) ->
                                    put(key, value)
                                }
                            },
                        )
                        put("default", role.isDefault)
                    }
                )
            }
        }

    private fun canonicalRoleGrants(grants: List<SyncRoleGrant>): ArrayNode =
        objectMapper.createArrayNode().apply {
            grants
                .sortedBy { it.id.toString() }
                .forEach { grant ->
                    add(
                        objectMapper.createObjectNode().apply {
                            put("id", grant.id.toString())
                            put("roleKey", grant.roleKey)
                            put("effect", grant.effect.name)
                            put("permissionPattern", grant.permissionPattern)
                            put("scopeKind", grant.scopeKind.name)
                            putNullable("scopeValue", grant.scopeValue)
                            putNullable("expiresAt", grant.expiresAt?.toString())
                        }
                    )
                }
        }

    private fun canonicalInheritance(inheritance: List<SyncInheritance>): ArrayNode =
        objectMapper.createArrayNode().apply {
            inheritance
                .sortedWith(
                    compareBy(SyncInheritance::parentRoleKey, SyncInheritance::childRoleKey)
                )
                .forEach { entry ->
                    add(
                        objectMapper.createObjectNode().apply {
                            put("parentRoleKey", entry.parentRoleKey)
                            put("childRoleKey", entry.childRoleKey)
                        }
                    )
                }
        }

    private fun canonicalCatalogEntries(entries: List<SyncCatalogEntry>): ArrayNode =
        objectMapper.createArrayNode().apply {
            entries.sortedBy(SyncCatalogEntry::permissionKey).forEach { entry ->
                add(
                    objectMapper.createObjectNode().apply {
                        put("permissionKey", entry.permissionKey)
                        put("label", entry.label)
                        put("description", entry.description)
                        put("source", entry.source)
                        put("sourceVersion", entry.sourceVersion)
                        set<ArrayNode>(
                            "supportedScopes",
                            objectMapper.createArrayNode().apply {
                                entry.supportedScopes.map { it.name }.sorted().forEach(::add)
                            },
                        )
                        put("custom", entry.custom)
                    }
                )
            }
        }

    private fun canonicalKeycloakMappings(mappings: List<SyncKeycloakMapping>): ArrayNode =
        objectMapper.createArrayNode().apply {
            mappings
                .sortedBy { it.id.toString() }
                .forEach { mapping ->
                    add(
                        objectMapper.createObjectNode().apply {
                            put("id", mapping.id.toString())
                            put("keycloakGroup", mapping.keycloakGroup)
                            put("roleKey", mapping.roleKey)
                            putNullable("expiresAt", mapping.expiresAt?.toString())
                        }
                    )
                }
        }

    private fun ObjectNode.putNullable(field: String, value: String?) {
        if (value == null) putNull(field) else put(field, value)
    }
}
