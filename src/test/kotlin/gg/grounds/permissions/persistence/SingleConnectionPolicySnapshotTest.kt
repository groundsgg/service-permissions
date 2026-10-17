package gg.grounds.permissions.persistence

import com.fasterxml.jackson.databind.ObjectMapper
import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.domain.PermissionPolicyInput
import gg.grounds.permissions.identity.IdentitySyncReadinessCheck
import gg.grounds.permissions.identity.ProjectedPlayerIdentity
import io.agroal.api.AgroalDataSource
import io.agroal.api.configuration.supplier.AgroalDataSourceConfigurationSupplier
import io.agroal.api.security.NamePrincipal
import io.agroal.api.security.SimplePassword
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * A snapshot must be computed on a single pooled connection. With a pool of one, any nested
 * connection acquisition inside the snapshot path waits for itself until the acquisition timeout.
 */
@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
class SingleConnectionPolicySnapshotTest {

    @Inject lateinit var repository: PermissionRepository

    @Inject lateinit var identityRepository: PlayerIdentityRepository

    @Inject lateinit var objectMapper: ObjectMapper

    @ConfigProperty(name = "quarkus.datasource.jdbc.url") lateinit var jdbcUrl: String

    @ConfigProperty(name = "quarkus.datasource.username") lateinit var username: String

    @ConfigProperty(name = "quarkus.datasource.password") lateinit var password: String

    @Test
    fun concurrentSnapshotsSucceedWithASingleConnectionPool() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000901")
        seedGroupMappedPlayer(playerId)

        singleConnectionPool().use { pool ->
            val poolIdentityRepository = PlayerIdentityRepository(pool)
            val poolRepository =
                PermissionRepository(
                    pool,
                    objectMapper,
                    poolIdentityRepository,
                    IdentitySyncReadinessCheck(poolIdentityRepository, Duration.ofHours(6)),
                )
            val executor = Executors.newFixedThreadPool(CONCURRENT_REQUESTS)
            try {
                val snapshots =
                    executor
                        .invokeAll(
                            List(CONCURRENT_REQUESTS) {
                                Callable<PermissionPolicyInput> {
                                    poolRepository.policyFor(
                                        PermissionPolicyRequest(playerId, "lobby", "lobby-1")
                                    )
                                }
                            },
                            30,
                            TimeUnit.SECONDS,
                        )
                        .map { it.get() }

                snapshots.forEach { input ->
                    assertEquals(
                        setOf("default", "staff"),
                        input.roles.mapTo(linkedSetOf()) { it.key },
                    )
                    assertEquals(listOf("staff"), input.playerRoles.map { it.roleKey })
                }
            } finally {
                executor.shutdownNow()
            }
        }
    }

    private fun seedGroupMappedPlayer(playerId: UUID) {
        repository.deleteAllPermissionData()
        repository.createRole(
            "test-user",
            RoleRecord(key = "default", name = "Default", isDefault = true),
        )
        repository.createRole("test-user", RoleRecord(key = "staff", name = "Staff"))
        repository.addRoleInheritance("test-user", "staff", "default")
        repository.createKeycloakGroupMapping(
            "test-user",
            KeycloakGroupMappingRecord(UUID.randomUUID(), "/staff", "staff"),
        )
        val syncedAt = Instant.now()
        identityRepository.markSyncRunning(syncedAt.minusSeconds(1))
        identityRepository.replaceAll(
            listOf(
                ProjectedPlayerIdentity(
                    playerId = playerId,
                    keycloakUserId = "keycloak-single-connection",
                    minecraftUsername = "SingleConnection",
                    normalizedUsername = "singleconnection",
                    groupPaths = setOf("/staff"),
                    syncedAt = syncedAt,
                    sourceUpdatedAt = null,
                )
            ),
            syncedAt,
        )
    }

    private fun singleConnectionPool(): AgroalDataSource =
        AgroalDataSource.from(
            AgroalDataSourceConfigurationSupplier().connectionPoolConfiguration { pool ->
                pool
                    .maxSize(1)
                    .acquisitionTimeout(Duration.ofSeconds(2))
                    .connectionFactoryConfiguration { factory ->
                        factory
                            .jdbcUrl(jdbcUrl)
                            .principal(NamePrincipal(username))
                            .credential(SimplePassword(password))
                    }
            }
        )

    private companion object {
        const val CONCURRENT_REQUESTS = 4
    }
}
