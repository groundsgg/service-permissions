package gg.grounds.permissions.policy

object PermissionPattern {
    fun matches(pattern: String, permission: String): Boolean =
        when {
            pattern == "*" -> true
            pattern.endsWith(".*") -> permission.startsWith(pattern.removeSuffix("*"))
            else -> pattern == permission
        }

    internal fun specificity(pattern: String): Int =
        when {
            pattern == "*" -> 0
            pattern.endsWith(".*") -> 1_000 + pattern.removeSuffix(".*").length
            else -> 2_000 + pattern.length
        }
}
