package gg.grounds.permissions.rest

import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import java.text.Normalizer
import java.util.Locale
import java.util.UUID

object PermissionValidation {
    private val combiningMarksRegex = Regex("\\p{M}+")
    private val roleKeyRegex = Regex("^[a-z0-9._-]+$")
    private val roleSlugSeparatorRegex = Regex("[^a-z0-9]+")
    private val permissionKeyRegex = Regex("^[a-z0-9._-]+$")

    fun roleKey(value: String?): String {
        val roleKey = required(value, "roleKey")
        require(roleKeyRegex.matches(roleKey)) {
            "roleKey must contain only lowercase letters, numbers, dots, underscores, or hyphens"
        }
        return roleKey
    }

    fun roleKeyFromName(value: String?): String {
        val name = displayName(value)
        val roleKey =
            Normalizer.normalize(name, Normalizer.Form.NFKD)
                .replace(combiningMarksRegex, "")
                .lowercase(Locale.ROOT)
                .replace("ß", "ss")
                .replace(roleSlugSeparatorRegex, "-")
                .trim('-')
        require(roleKey.isNotEmpty()) { "role_name_invalid" }
        return roleKey
    }

    fun permissionKey(value: String?): String {
        val permissionKey = required(value, "permissionKey")
        require(permissionKeyRegex.matches(permissionKey)) {
            "permissionKey must contain only lowercase letters, numbers, dots, underscores, or hyphens"
        }
        return permissionKey
    }

    fun permissionPattern(value: String?): String {
        val permissionPattern = required(value, "permissionPattern")
        require(isSupportedPermissionPattern(permissionPattern)) {
            "permissionPattern must be a concrete key, '*', or a suffix wildcard ending in '.*'"
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

    private fun isSupportedPermissionPattern(value: String): Boolean =
        value == "*" ||
            permissionKeyRegex.matches(value) ||
            (value.endsWith(".*") && permissionKeyRegex.matches(value.removeSuffix(".*")))
}
