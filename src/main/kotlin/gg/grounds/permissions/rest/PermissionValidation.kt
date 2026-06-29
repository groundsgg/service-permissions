package gg.grounds.permissions.rest

import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import java.util.UUID

object PermissionValidation {
    private val roleKeyRegex = Regex("^[a-z0-9._-]+$")
    private val permissionPatternRegex = Regex("^[a-z0-9._*-]+$")

    fun roleKey(value: String?): String {
        val roleKey = required(value, "roleKey")
        require(roleKeyRegex.matches(roleKey)) {
            "roleKey must contain only lowercase letters, numbers, dots, underscores, or hyphens"
        }
        return roleKey
    }

    fun permissionKey(value: String?): String {
        val permissionKey = required(value, "permissionKey")
        require(permissionPatternRegex.matches(permissionKey)) {
            "permissionKey must contain only lowercase letters, numbers, dots, underscores, hyphens, or wildcard stars"
        }
        return permissionKey
    }

    fun permissionPattern(value: String?): String {
        val permissionPattern = required(value, "permissionPattern")
        require(permissionPatternRegex.matches(permissionPattern)) {
            "permissionPattern must contain only lowercase letters, numbers, dots, underscores, hyphens, or wildcard stars"
        }
        return permissionPattern
    }

    fun displayName(value: String?): String = required(value, "name")

    fun label(value: String?): String = required(value, "label")

    fun keycloakGroup(value: String?): String = required(value, "keycloakGroup")

    fun uuid(value: String, fieldName: String): UUID =
        runCatching { UUID.fromString(value.trim()) }
            .getOrElse { throw IllegalArgumentException("$fieldName must be a valid UUID") }

    fun scope(kind: PermissionScopeKind, rawValue: String?): PermissionScope {
        val value = rawValue?.trim()?.takeIf { it.isNotEmpty() }
        if (kind == PermissionScopeKind.GLOBAL) {
            require(value == null) { "scopeValue must be empty for GLOBAL scope" }
        } else {
            require(value != null) { "scopeValue is required for ${kind.name} scope" }
        }
        return PermissionScope(kind, value)
    }

    private fun required(value: String?, fieldName: String): String {
        val trimmed = value?.trim()
        require(!trimmed.isNullOrEmpty()) { "$fieldName must not be blank" }
        return trimmed
    }
}
