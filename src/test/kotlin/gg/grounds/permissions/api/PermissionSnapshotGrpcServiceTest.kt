package gg.grounds.permissions.api

import gg.grounds.grpc.permissions.GetPlayerSnapshotRequest
import gg.grounds.grpc.permissions.PermissionSnapshotService
import gg.grounds.permissions.domain.PermissionEffect
import gg.grounds.permissions.domain.PermissionGrantSpec
import gg.grounds.permissions.domain.PermissionScope
import gg.grounds.permissions.domain.PermissionScopeKind
import gg.grounds.permissions.domain.PlayerPermissionGrant
import gg.grounds.permissions.domain.RoleDefinition
import io.quarkus.grpc.GrpcClient
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.junit.QuarkusTestProfile
import io.quarkus.test.junit.TestProfile
import jakarta.inject.Inject
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

@QuarkusTest
@TestProfile(PermissionSnapshotGrpcServiceTest.Profile::class)
class PermissionSnapshotGrpcServiceTest {

    @Inject lateinit var policyProvider: InMemoryPermissionPolicyProvider

    @GrpcClient("permission-snapshot") lateinit var service: PermissionSnapshotService

    @BeforeEach
    fun resetPolicy() {
        policyProvider.replacePolicy()
    }

    @Test
    fun snapshotIncludesDefaultMappedRolesAndDirectDeny() {
        val playerId = UUID.fromString("00000000-0000-0000-0000-000000000123")
        policyProvider.replacePolicy(
            policyVersion = 7,
            roles =
                listOf(
                    RoleDefinition(key = "player", name = "Player", isDefault = true),
                    RoleDefinition(key = "moderator", name = "Moderator"),
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
        assertTrue(snapshot.denyPatternsList.any { it.pattern == "grounds.command.op" })
    }

    class Profile : QuarkusTestProfile {
        override fun getConfigOverrides(): Map<String, String> =
            mapOf(
                "quarkus.grpc.clients.permission-snapshot.host" to "localhost",
                "quarkus.grpc.clients.permission-snapshot.port" to "9001",
                "quarkus.grpc.clients.permission-snapshot.plain-text" to "true",
                "quarkus.flyway.migrate-at-start" to "false",
            )
    }
}
