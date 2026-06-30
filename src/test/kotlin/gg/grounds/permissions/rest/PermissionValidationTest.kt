package gg.grounds.permissions.rest

import gg.grounds.permissions.domain.PermissionScopeKind
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class PermissionValidationTest {

    @Test
    fun acceptsLowercaseRoleKeysWithSeparators() {
        assertEquals("default-player", PermissionValidation.roleKey("default-player"))
        assertEquals("staff.moderator", PermissionValidation.roleKey("staff.moderator"))
    }

    @Test
    fun rejectsInvalidRoleKeys() {
        val error =
            assertThrows(IllegalArgumentException::class.java) {
                PermissionValidation.roleKey("Bad Role")
            }

        assertEquals(
            "roleKey must contain only lowercase letters, numbers, dots, underscores, or hyphens",
            error.message,
        )
    }

    @Test
    fun rejectsInvalidPermissionPatterns() {
        val error =
            assertThrows(IllegalArgumentException::class.java) {
                PermissionValidation.permissionPattern("grounds command fly")
            }

        assertEquals(
            "permissionPattern must be a concrete key, '*', or a suffix wildcard ending in '.*'",
            error.message,
        )
    }

    @Test
    fun rejectsUnsupportedWildcardPermissionPatterns() {
        PermissionValidation.permissionPattern("*")
        PermissionValidation.permissionPattern("grounds.command.*")
        PermissionValidation.permissionPattern("grounds.command.fly")

        val middleWildcardError =
            assertThrows(IllegalArgumentException::class.java) {
                PermissionValidation.permissionPattern("grounds.*.fly")
            }
        val partialWildcardError =
            assertThrows(IllegalArgumentException::class.java) {
                PermissionValidation.permissionPattern("grounds.command*")
            }

        assertEquals(
            "permissionPattern must be a concrete key, '*', or a suffix wildcard ending in '.*'",
            middleWildcardError.message,
        )
        assertEquals(
            "permissionPattern must be a concrete key, '*', or a suffix wildcard ending in '.*'",
            partialWildcardError.message,
        )
    }

    @Test
    fun validatesScopeValueRules() {
        PermissionValidation.scope(PermissionScopeKind.GLOBAL, null)
        PermissionValidation.scope(PermissionScopeKind.SERVER_TYPE, "paper")

        val globalError =
            assertThrows(IllegalArgumentException::class.java) {
                PermissionValidation.scope(PermissionScopeKind.GLOBAL, "paper")
            }
        val scopedError =
            assertThrows(IllegalArgumentException::class.java) {
                PermissionValidation.scope(PermissionScopeKind.SERVER, null)
            }

        assertEquals("scopeValue must be empty for GLOBAL scope", globalError.message)
        assertEquals("scopeValue is required for SERVER scope", scopedError.message)
    }
}
