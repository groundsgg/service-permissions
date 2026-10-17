package gg.grounds.permissions.rest

import java.sql.SQLException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.postgresql.util.PSQLException
import org.postgresql.util.PSQLState
import org.postgresql.util.ServerErrorMessage

class RootCauseSummaryTest {
    @Test
    fun reportsTheInnermostCauseWithItsMessage() {
        val summary =
            RootCauseSummary.of(
                IllegalStateException("wrapper", SQLException("Sorry, acquisition timeout!"))
            )

        assertEquals(SQLException::class.java.name, summary.type)
        assertEquals("Sorry, acquisition timeout!", summary.message)
    }

    @Test
    fun keepsClientSideDriverMessages() {
        val summary =
            RootCauseSummary.of(
                RuntimeException(
                    PSQLException(
                        "This connection has been closed.",
                        PSQLState.CONNECTION_DOES_NOT_EXIST,
                    )
                )
            )

        assertEquals("08003", summary.sqlState)
        assertEquals("This connection has been closed.", summary.message)
    }

    @Test
    fun dropsServerReportedMessagesBecauseTheyCanEchoRowValues() {
        val serverError =
            PSQLException(
                ServerErrorMessage(
                    "SERROR\u0000C23505\u0000Mduplicate key value violates unique constraint " +
                        "\"permission_roles_pkey\"\u0000DKey (key)=(secret-role) already exists.\u0000"
                )
            )

        val summary = RootCauseSummary.of(RuntimeException(serverError))

        assertEquals(PSQLException::class.java.name, summary.type)
        assertEquals("23505", summary.sqlState)
        assertNull(summary.message)
    }

    @Test
    fun dropsMessagesOfNonSqlRootCauses() {
        val summary =
            RootCauseSummary.of(RuntimeException(IllegalArgumentException("secret-like-value")))

        assertEquals(IllegalArgumentException::class.java.name, summary.type)
        assertNull(summary.sqlState)
        assertNull(summary.message)
    }

    @Test
    fun stopsOnCauseCycles() {
        val first = RuntimeException("first")
        val second = RuntimeException("second", first)
        first.initCause(second)

        assertEquals(RuntimeException::class.java.name, RootCauseSummary.of(first).type)
    }
}
