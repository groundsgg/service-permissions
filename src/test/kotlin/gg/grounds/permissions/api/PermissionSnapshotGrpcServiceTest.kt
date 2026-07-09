package gg.grounds.permissions.api

import gg.grounds.grpc.permissions.GetPlayerSnapshotRequest
import gg.grounds.grpc.permissions.PermissionCatalogService
import gg.grounds.grpc.permissions.PermissionEffect.PERMISSION_EFFECT_DENY
import gg.grounds.grpc.permissions.PermissionGrantSource.PERMISSION_GRANT_SOURCE_PLAYER
import gg.grounds.grpc.permissions.PermissionManifestEntry
import gg.grounds.grpc.permissions.PermissionScopeKind.PERMISSION_SCOPE_KIND_GLOBAL
import gg.grounds.grpc.permissions.PermissionScopeKind.PERMISSION_SCOPE_KIND_SERVER
import gg.grounds.grpc.permissions.PermissionScopeKind.PERMISSION_SCOPE_KIND_SERVER_TYPE
import gg.grounds.grpc.permissions.PermissionSnapshotService
import gg.grounds.grpc.permissions.RefreshOnlinePlayersRequest
import gg.grounds.grpc.permissions.RegisterPermissionManifestRequest
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionGrantSpec
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.RoleDefinition
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import io.grpc.Status
import io.grpc.StatusRuntimeException
import io.quarkus.grpc.GrpcClient
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.junit.QuarkusTestProfile
import io.quarkus.test.junit.TestProfile
import jakarta.inject.Inject
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
@TestProfile(PermissionSnapshotGrpcServiceTest.Profile::class)
class PermissionSnapshotGrpcServiceTest {

    @Inject lateinit var policyProvider: SeededPermissionPolicyProvider
    @Inject lateinit var repository: PermissionRepository

    @GrpcClient("permission-snapshot") lateinit var service: PermissionSnapshotService

    @GrpcClient("permission-catalog") lateinit var catalogService: PermissionCatalogService

    @BeforeEach
    fun resetPolicy() {
        policyProvider.replacePolicy()
        repository.deleteAllPermissionData()
    }

    @Test
    fun snapshotIncludesDefaultMappedRolesAndDirectDeny() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000123")
        policyProvider.replacePolicy(
            policyVersion = 7,
            roles =
                listOf(
                    RoleDefinition(
                        key = "player",
                        name = "Player",
                        prefix = "[P]",
                        color = "green",
                        sortOrder = 100,
                        isDefault = true,
                    ),
                    RoleDefinition(key = "moderator", name = "Moderator", sortOrder = 50),
                ),
            keycloakRoleMappings = mapOf("/staff" to setOf("moderator")),
            playerGrants =
                listOf(
                    PlayerPermissionGrant(
                        playerId = playerId,
                        grant =
                            PermissionGrantSpec(
                                effect = PermissionEffect.DENY,
                                pattern = "grounds.command.op",
                                scope = PermissionScope(PermissionScopeKind.GLOBAL),
                            ),
                    )
                ),
        )

        val snapshot =
            service
                .getPlayerSnapshot(
                    GetPlayerSnapshotRequest.newBuilder()
                        .setPlayerId(playerId.toString())
                        .addKeycloakGroups("/staff")
                        .setServerType("paper")
                        .setServerId("survival-1")
                        .build()
                )
                .await()
                .indefinitely()

        assertTrue(snapshot.roleKeysList.containsAll(listOf("player", "moderator")))
        assertEquals(7, snapshot.policyVersion)
        assertNotNull(snapshot.issuedAt)
        assertNotNull(snapshot.refreshAfter)
        assertNotNull(snapshot.expiresAt)

        val denyGrant = snapshot.denyPatternsList.single { it.pattern == "grounds.command.op" }
        assertEquals(PERMISSION_EFFECT_DENY, denyGrant.effect)
        assertEquals(PERMISSION_GRANT_SOURCE_PLAYER, denyGrant.source)
        assertEquals(PERMISSION_SCOPE_KIND_GLOBAL, denyGrant.scope.kind)

        val playerRole = snapshot.roleMetadataList.single { it.key == "player" }
        assertEquals("Player", playerRole.name)
        assertEquals("[P]", playerRole.prefix)
        assertEquals("green", playerRole.color)
        assertEquals(100, playerRole.sortOrder)
    }

    @Test
    fun getPlayerSnapshotRejectsInvalidPlayerIdAsInvalidArgument() {
        val error =
            assertThrows(StatusRuntimeException::class.java) {
                service
                    .getPlayerSnapshot(
                        GetPlayerSnapshotRequest.newBuilder().setPlayerId("not-a-uuid").build()
                    )
                    .await()
                    .indefinitely()
            }

        assertEquals(Status.INVALID_ARGUMENT.code, error.status.code)
        assertEquals("player_id must be a valid UUID", error.status.description)
    }

    @Test
    fun getPlayerSnapshotRejectsBlankServerContextAsInvalidArgument() {
        val error =
            assertThrows(StatusRuntimeException::class.java) {
                service
                    .getPlayerSnapshot(
                        GetPlayerSnapshotRequest.newBuilder()
                            .setPlayerId("00000000-0000-0000-0000-000000000123")
                            .setServerType("   ")
                            .build()
                    )
                    .await()
                    .indefinitely()
            }

        assertEquals(Status.INVALID_ARGUMENT.code, error.status.code)
        assertEquals("server_type must not be blank", error.status.description)
    }

    @Test
    fun snapshotIgnoresBlankKeycloakGroups() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000123")
        policyProvider.replacePolicy(
            roles = listOf(RoleDefinition(key = "admin", name = "Admin")),
            keycloakRoleMappings = mapOf("" to setOf("admin"), "   " to setOf("admin")),
        )

        val snapshot =
            service
                .getPlayerSnapshot(
                    GetPlayerSnapshotRequest.newBuilder()
                        .setPlayerId(playerId.toString())
                        .addKeycloakGroups("")
                        .addKeycloakGroups("   ")
                        .build()
                )
                .await()
                .indefinitely()

        assertFalse(snapshot.roleKeysList.contains("admin"))
    }

    @Test
    fun refreshOnlinePlayersRejectsBlankServerContextAsInvalidArgument() {
        val error =
            assertThrows(StatusRuntimeException::class.java) {
                service
                    .refreshOnlinePlayers(
                        RefreshOnlinePlayersRequest.newBuilder().setServerId("   ").build()
                    )
                    .await()
                    .indefinitely()
            }

        assertEquals(Status.INVALID_ARGUMENT.code, error.status.code)
        assertEquals("server_id must not be blank", error.status.description)
    }

    @Test
    fun registerPermissionManifestRejectsEmptyManifestAsInvalidArgument() {
        val error =
            assertThrows(StatusRuntimeException::class.java) {
                catalogService
                    .registerPermissionManifest(
                        RegisterPermissionManifestRequest.newBuilder()
                            .setSource("plugin-config")
                            .setSourceVersion("1.0.0")
                            .build()
                    )
                    .await()
                    .indefinitely()
            }

        assertEquals(Status.INVALID_ARGUMENT.code, error.status.code)
        assertEquals("permissions must not be empty", error.status.description)
    }

    @Test
    fun registerPermissionManifestRejectsMissingRequiredFieldsAsInvalidArgument() {
        val error =
            assertThrows(StatusRuntimeException::class.java) {
                catalogService
                    .registerPermissionManifest(
                        RegisterPermissionManifestRequest.newBuilder()
                            .setSource("plugin-config")
                            .setSourceVersion("1.0.0")
                            .addPermissions(
                                PermissionManifestEntry.newBuilder()
                                    .setKey("grounds.command.fly")
                                    .addSupportedScopes(PERMISSION_SCOPE_KIND_GLOBAL)
                                    .build()
                            )
                            .build()
                    )
                    .await()
                    .indefinitely()
            }

        assertEquals(Status.INVALID_ARGUMENT.code, error.status.code)
        assertEquals("permissions[0].label must not be blank", error.status.description)
    }

    @Test
    fun registerPermissionManifestAcceptsValidManifest() {
        val reply =
            catalogService
                .registerPermissionManifest(
                    RegisterPermissionManifestRequest.newBuilder()
                        .setSource("plugin-config")
                        .setSourceVersion("1.0.0")
                        .addPermissions(
                            PermissionManifestEntry.newBuilder()
                                .setKey("grounds.command.fly")
                                .setLabel("Fly command")
                                .addSupportedScopes(PERMISSION_SCOPE_KIND_GLOBAL)
                                .addSupportedScopes(PERMISSION_SCOPE_KIND_SERVER_TYPE)
                                .addSupportedScopes(PERMISSION_SCOPE_KIND_SERVER)
                                .build()
                        )
                        .build()
                )
                .await()
                .indefinitely()

        assertTrue(reply.accepted)
        assertEquals("manifest accepted", reply.message)
    }

    @Test
    fun registerPermissionManifestPersistsRuntimeCatalogEntry() {
        catalogService
            .registerPermissionManifest(
                RegisterPermissionManifestRequest.newBuilder()
                    .setSource("plugin-config")
                    .setSourceVersion("1.0.0")
                    .addPermissions(
                        PermissionManifestEntry.newBuilder()
                            .setKey("grounds.command.fly")
                            .setLabel("Fly command")
                            .setDescription("Allows flight")
                            .addSupportedScopes(PERMISSION_SCOPE_KIND_GLOBAL)
                            .build()
                    )
                    .build()
            )
            .await()
            .indefinitely()

        val catalogEntry = repository.listCatalogEntries().single()

        assertEquals("grounds.command.fly", catalogEntry.key)
        assertEquals("Fly command", catalogEntry.label)
        assertEquals("Allows flight", catalogEntry.description)
        assertEquals("plugin-config", catalogEntry.source)
        assertEquals("1.0.0", catalogEntry.sourceVersion)
        assertEquals(listOf(PermissionScopeKind.GLOBAL), catalogEntry.supportedScopes)
        assertFalse(catalogEntry.custom)
        assertNotNull(catalogEntry.lastSeenAt)
    }

    @Test
    fun registerPermissionManifestRejectsUnknownSupportedScopeAsInvalidArgument() {
        val error =
            assertThrows(StatusRuntimeException::class.java) {
                catalogService
                    .registerPermissionManifest(
                        RegisterPermissionManifestRequest.newBuilder()
                            .setSource("plugin-config")
                            .setSourceVersion("1.0.0")
                            .addPermissions(
                                PermissionManifestEntry.newBuilder()
                                    .setKey("grounds.command.fly")
                                    .setLabel("Fly command")
                                    .addSupportedScopesValue(99)
                                    .build()
                            )
                            .build()
                    )
                    .await()
                    .indefinitely()
            }

        assertEquals(Status.INVALID_ARGUMENT.code, error.status.code)
        assertEquals(
            "permissions[0].supported_scopes must contain only supported values",
            error.status.description,
        )
    }

    @Test
    fun registerPermissionManifestRejectsDuplicatePermissionKeysAsInvalidArgument() {
        val error =
            assertThrows(StatusRuntimeException::class.java) {
                catalogService
                    .registerPermissionManifest(
                        RegisterPermissionManifestRequest.newBuilder()
                            .setSource("plugin-config")
                            .setSourceVersion("1.0.0")
                            .addPermissions(
                                PermissionManifestEntry.newBuilder()
                                    .setKey("grounds.command.fly")
                                    .setLabel("Fly command")
                                    .addSupportedScopes(PERMISSION_SCOPE_KIND_GLOBAL)
                                    .build()
                            )
                            .addPermissions(
                                PermissionManifestEntry.newBuilder()
                                    .setKey("grounds.command.fly")
                                    .setLabel("Fly command duplicate")
                                    .addSupportedScopes(PERMISSION_SCOPE_KIND_GLOBAL)
                                    .build()
                            )
                            .build()
                    )
                    .await()
                    .indefinitely()
            }

        assertEquals(Status.INVALID_ARGUMENT.code, error.status.code)
        assertEquals("permissions[1].key must be unique", error.status.description)
    }

    class Profile : QuarkusTestProfile {
        override fun getConfigOverrides(): Map<String, String> =
            mapOf(
                "quarkus.grpc.clients.permission-snapshot.host" to "localhost",
                "quarkus.grpc.clients.permission-snapshot.port" to "9001",
                "quarkus.grpc.clients.permission-snapshot.plain-text" to "true",
                "quarkus.grpc.clients.permission-catalog.host" to "localhost",
                "quarkus.grpc.clients.permission-catalog.port" to "9001",
                "quarkus.grpc.clients.permission-catalog.plain-text" to "true",
            )

        override fun getEnabledAlternatives(): Set<Class<*>> =
            setOf(SeededPermissionPolicyProvider::class.java)
    }
}
