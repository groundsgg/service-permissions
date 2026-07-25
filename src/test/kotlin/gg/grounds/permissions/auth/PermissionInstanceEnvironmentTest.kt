package gg.grounds.permissions.auth

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class PermissionInstanceEnvironmentTest {
    @Test
    fun parsesAbsentAndBlankValuesAsProjectMode() {
        listOf(null, "", " \t\n ").forEach { value ->
            assertNull(PermissionInstanceEnvironment.fromConfig(value))
        }
    }

    @Test
    fun parsesStageWireValue() {
        assertEquals(
            PermissionInstanceEnvironment.STAGE,
            PermissionInstanceEnvironment.fromConfig("stage"),
        )
    }

    @Test
    fun parsesProdWireValueAsProduction() {
        assertEquals(
            PermissionInstanceEnvironment.PRODUCTION,
            PermissionInstanceEnvironment.fromConfig("prod"),
        )
    }

    @Test
    fun trimsSurroundingWhitespaceBeforeParsing() {
        assertEquals(
            PermissionInstanceEnvironment.STAGE,
            PermissionInstanceEnvironment.fromConfig(" \tstage\n"),
        )
        assertEquals(
            PermissionInstanceEnvironment.PRODUCTION,
            PermissionInstanceEnvironment.fromConfig("  prod  "),
        )
    }

    @Test
    fun rejectsUnsupportedNonblankValuesWithoutLeakingOtherConfiguration() {
        val exception =
            assertThrows(IllegalArgumentException::class.java) {
                PermissionInstanceEnvironment.fromConfig("development")
            }

        val message = exception.message.orEmpty()
        assertEquals(true, message.contains("PERMISSIONS_INSTANCE_ENVIRONMENT"))
        assertFalse(message.contains("PERMISSIONS_KEYCLOAK_CLIENT_SECRET"))
    }
}
