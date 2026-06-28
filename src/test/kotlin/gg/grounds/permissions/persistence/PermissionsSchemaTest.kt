package gg.grounds.permissions.persistence

import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import javax.sql.DataSource
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.testcontainers.postgresql.PostgreSQLContainer

@QuarkusTest
@QuarkusTestResource(PermissionsPostgresTestResource::class)
class PermissionsSchemaTest {

    @Inject lateinit var dataSource: DataSource

    @Test
    fun flywayCreatesPolicyVersion() {
        dataSource.connection.use { connection ->
            connection
                .prepareStatement("SELECT version FROM permission_policy_versions WHERE id = 1")
                .use { statement ->
                    statement.executeQuery().use { resultSet ->
                        assertTrue(resultSet.next())
                        assertEquals(1L, resultSet.getLong("version"))
                    }
                }
        }
    }
}

class PermissionsPostgresTestResource : QuarkusTestResourceLifecycleManager {
    private lateinit var postgres: PostgreSQLContainer

    override fun start(): Map<String, String> {
        postgres = PostgreSQLContainer("postgres:17-alpine")
        postgres.start()

        return mapOf(
            "quarkus.datasource.jdbc.url" to postgres.permissionsJdbcUrl(),
            "quarkus.datasource.username" to postgres.username,
            "quarkus.datasource.password" to postgres.password,
            "quarkus.flyway.create-schemas" to "true",
        )
    }

    override fun stop() {
        postgres.stop()
    }

    private fun PostgreSQLContainer.permissionsJdbcUrl(): String {
        val separator = if (jdbcUrl.contains("?")) "&" else "?"
        return "$jdbcUrl${separator}currentSchema=permissions"
    }
}
