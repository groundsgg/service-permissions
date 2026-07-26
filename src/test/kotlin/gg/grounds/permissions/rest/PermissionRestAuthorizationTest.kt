package gg.grounds.permissions.rest

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import gg.grounds.permissions.identity.IdentitySyncState
import gg.grounds.permissions.identity.IdentitySyncStatus
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PlayerIdentityRepository
import gg.grounds.permissions.sync.PermissionProjectSnapshot
import io.quarkus.test.InjectMock
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager
import io.quarkus.test.junit.QuarkusTest
import io.quarkus.test.junit.QuarkusTestProfile
import io.quarkus.test.junit.TestProfile
import io.quarkus.test.security.TestSecurity
import io.restassured.RestAssured.given
import io.restassured.response.Response
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import org.hamcrest.Matchers.equalTo
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.junit.jupiter.params.provider.ValueSource
import org.mockito.kotlin.whenever

@QuarkusTest
@TestProfile(PermissionRestAuthorizationTestProfile::class)
@QuarkusTestResource(value = SharedProjectForgeTestResource::class, restrictToAnnotatedClass = true)
class PermissionRestAuthorizationTest {

    @InjectMock lateinit var repository: PermissionRepository
    @InjectMock lateinit var identityRepository: PlayerIdentityRepository
    @InjectMock lateinit var identitySyncDispatcher: IdentitySyncDispatcher

    @BeforeEach
    fun mockRepository() {
        whenever(repository.listRolesWithAggregateCounts()).thenReturn(emptyList())
        whenever(repository.permissionProjectSnapshot())
            .thenReturn(
                PermissionProjectSnapshot(
                    emptyList(),
                    emptyList(),
                    emptyList(),
                    emptyList(),
                    emptyList(),
                )
            )
        whenever(identityRepository.currentSyncState())
            .thenReturn(
                IdentitySyncState(
                    status = IdentitySyncStatus.IDLE,
                    startedAt = null,
                    completedAt = null,
                    lastSuccessAt = null,
                    durationMs = null,
                    playerCount = 0,
                    failureReason = null,
                )
            )
    }

    @Test
    fun rejectsAnonymousRequests() {
        given()
            .header("X-Request-ID", "anonymous-request-123")
            .get("/v1/permissions/roles")
            .then()
            .statusCode(401)
            .contentType("application/problem+json")
            .body("type", equalTo("about:blank"))
            .body("title", equalTo("Unauthorized"))
            .body("status", equalTo(401))
            .body("detail", equalTo("Authentication is required."))
            .body("instance", equalTo("/v1/permissions/roles"))
            .body("requestId", equalTo("anonymous-request-123"))
            .body("error", equalTo("authentication_required"))
        given().get("/v1/permissions/players/search?query=ab").then().statusCode(401)
        given().post("/v1/permissions/identity-sync").then().statusCode(401)
    }

    @Test
    @TestSecurity(user = "user-alpha")
    fun rejectsAuthenticatedUsersWithoutMinecraftPermissionsAccess() {
        given()
            .header("X-Request-ID", "denied-request-123")
            .get("/v1/permissions/roles")
            .then()
            .statusCode(403)
            .contentType("application/problem+json")
            .body("type", equalTo("about:blank"))
            .body("title", equalTo("Forbidden"))
            .body("status", equalTo(403))
            .body("detail", equalTo("The authenticated user lacks the required permission."))
            .body("instance", equalTo("/v1/permissions/roles"))
            .body("requestId", equalTo("denied-request-123"))
            .body("error", equalTo("missing_permission"))
        given().get("/v1/permissions/players/search?query=ab").then().statusCode(403)
        given().post("/v1/permissions/identity-sync").then().statusCode(403)
    }

    @Test
    @TestSecurity(user = "user-without-access")
    fun rejectsAuthenticatedUsersWithoutSnapshotReadAccess() {
        given().get("/v1/permissions/sync/snapshot").then().statusCode(403)
    }

    @ParameterizedTest(name = "stage view reaches read endpoint {0}")
    @MethodSource("readEndpoints")
    @TestSecurity(
        user = "stage-viewer",
        roles = ["GAME_AREA_ACCESS", "MINECRAFT_PERMISSIONS_STAGE_VIEW"],
    )
    fun allowsStageViewAccessToEveryReadEndpoint(endpoint: RestEndpoint) {
        endpoint.request().then().statusCode(endpoint.authorizedStatus)
    }

    @ParameterizedTest(name = "stage view cannot mutate through {0}")
    @MethodSource("mutationEndpoints")
    @TestSecurity(
        user = "stage-viewer",
        roles = ["GAME_AREA_ACCESS", "MINECRAFT_PERMISSIONS_STAGE_VIEW"],
    )
    fun rejectsStageViewAccessToEveryMutationEndpoint(endpoint: RestEndpoint) {
        endpoint.request().then().statusCode(403)
    }

    @ParameterizedTest(name = "stage manage reaches mutation endpoint {0}")
    @MethodSource("mutationEndpoints")
    @TestSecurity(
        user = "stage-manager",
        roles = ["GAME_AREA_ACCESS", "MINECRAFT_PERMISSIONS_STAGE_MANAGE"],
    )
    fun allowsStageManageAccessToEveryMutationEndpoint(endpoint: RestEndpoint) {
        endpoint.request().then().statusCode(endpoint.authorizedStatus)
    }

    @ParameterizedTest(name = "shared project {0} reaches only sync snapshot")
    @ValueSource(strings = ["owner", "editor"])
    @TestSecurity(user = "project-administrator")
    fun limitsSharedProjectRoleExceptionToSyncSnapshot(projectRole: String) {
        val headers =
            mapOf(
                "X-Grounds-Project-Id" to "project-a",
                "X-Grounds-Project-Role" to projectRole,
                "Authorization" to "Forge-Test $projectRole",
            )

        SYNC_SNAPSHOT.request(headers).then().statusCode(200)
        val deniedEndpoints = READ_ENDPOINTS.filterNot { it == SYNC_SNAPSHOT } + MUTATION_ENDPOINTS
        deniedEndpoints.forEach { endpoint -> endpoint.request(headers).then().statusCode(403) }
    }

    @Test
    @TestSecurity(
        user = "production-viewer",
        roles = ["GAME_AREA_ACCESS", "MINECRAFT_PERMISSIONS_PRODUCTION_VIEW"],
    )
    fun rejectsProductionPermissionsOnStageInstance() {
        given().get("/v1/permissions/roles").then().statusCode(403)
    }

    data class RestEndpoint(
        val label: String,
        val method: String,
        val path: String,
        val body: String? = null,
        val authorizedStatus: Int = 400,
    ) {
        fun request(headers: Map<String, String> = emptyMap()): Response {
            val request = given()
            headers.forEach(request::header)
            body?.let { request.contentType("application/json").body(it) }
            return request.request(method, path)
        }

        override fun toString(): String = label
    }

    private companion object {
        private const val PLAYER_ID = "00000000-0000-0000-0000-000000000001"
        private const val GRANT_ID = "00000000-0000-0000-0000-000000000002"
        private const val MAPPING_ID = "00000000-0000-0000-0000-000000000003"
        private const val SNAPSHOT =
            """{"schemaVersion":1,"sourceEnvironment":"prod","sourceServiceVersion":"test-version","snapshotId":"snapshot-1","roles":[],"roleGrants":[],"inheritance":[],"catalogEntries":[]}"""
        private val ROLE_BODY = """{"name":"Authorization Matrix Role"}"""

        private val SYNC_SNAPSHOT =
            RestEndpoint(
                "GET /sync/snapshot",
                "GET",
                "/v1/permissions/sync/snapshot",
                authorizedStatus = 200,
            )

        private val READ_ENDPOINTS =
            listOf(
                RestEndpoint("GET /roles", "GET", "/v1/permissions/roles", authorizedStatus = 200),
                RestEndpoint(
                    "GET /roles/{roleKey}",
                    "GET",
                    "/v1/permissions/roles/missing-role",
                    authorizedStatus = 404,
                ),
                RestEndpoint(
                    "GET /roles/{roleKey}/grants",
                    "GET",
                    "/v1/permissions/roles/missing-role/grants",
                    authorizedStatus = 200,
                ),
                RestEndpoint(
                    "GET /roles/{roleKey}/grants/search",
                    "GET",
                    "/v1/permissions/roles/missing-role/grants/search?page=0",
                ),
                RestEndpoint(
                    "GET /catalog",
                    "GET",
                    "/v1/permissions/catalog",
                    authorizedStatus = 200,
                ),
                RestEndpoint("GET /catalog/search", "GET", "/v1/permissions/catalog/search?page=0"),
                RestEndpoint(
                    "GET /keycloak-groups",
                    "GET",
                    "/v1/permissions/keycloak-groups",
                    authorizedStatus = 200,
                ),
                RestEndpoint(
                    "GET /keycloak-groups/search",
                    "GET",
                    "/v1/permissions/keycloak-groups/search?page=0",
                ),
                RestEndpoint(
                    "GET /players/search",
                    "GET",
                    "/v1/permissions/players/search?query=x",
                ),
                RestEndpoint(
                    "GET /players/external-search",
                    "GET",
                    "/v1/permissions/players/external-search?query=x",
                ),
                RestEndpoint(
                    "GET /players/{playerId}/roles",
                    "GET",
                    "/v1/permissions/players/$PLAYER_ID/roles",
                    authorizedStatus = 200,
                ),
                RestEndpoint(
                    "GET /players/{playerId}/roles/search",
                    "GET",
                    "/v1/permissions/players/$PLAYER_ID/roles/search?page=0",
                ),
                RestEndpoint(
                    "GET /players/{playerId}/grants",
                    "GET",
                    "/v1/permissions/players/$PLAYER_ID/grants",
                    authorizedStatus = 200,
                ),
                RestEndpoint(
                    "GET /players/{playerId}/grants/search",
                    "GET",
                    "/v1/permissions/players/$PLAYER_ID/grants/search?page=0",
                ),
                RestEndpoint(
                    "GET /players/{playerId}/effective",
                    "GET",
                    "/v1/permissions/players/invalid/effective",
                ),
                RestEndpoint(
                    "GET /players/{playerId}/effective/search",
                    "GET",
                    "/v1/permissions/players/invalid/effective/search",
                ),
                RestEndpoint(
                    "GET /players/{playerId}/identity",
                    "GET",
                    "/v1/permissions/players/invalid/identity",
                ),
                RestEndpoint(
                    "GET /players/{playerId}/check",
                    "GET",
                    "/v1/permissions/players/invalid/check?permission=grounds.test",
                ),
                RestEndpoint("GET /audit", "GET", "/v1/permissions/audit?from=invalid"),
                RestEndpoint(
                    "GET /identity-sync/status",
                    "GET",
                    "/v1/permissions/identity-sync/status",
                    authorizedStatus = 200,
                ),
                SYNC_SNAPSHOT,
                RestEndpoint(
                    "POST /sync/preview",
                    "POST",
                    "/v1/permissions/sync/preview",
                    SNAPSHOT,
                    authorizedStatus = 200,
                ),
            )

        private val MUTATION_ENDPOINTS =
            listOf(
                RestEndpoint("POST /roles", "POST", "/v1/permissions/roles", "{}"),
                RestEndpoint(
                    "PUT /roles/{roleKey}",
                    "PUT",
                    "/v1/permissions/roles/missing-role",
                    ROLE_BODY,
                    authorizedStatus = 404,
                ),
                RestEndpoint(
                    "DELETE /roles/{roleKey}",
                    "DELETE",
                    "/v1/permissions/roles/missing-role",
                    authorizedStatus = 204,
                ),
                RestEndpoint(
                    "PUT /roles/{roleKey}/inherits/{parentRoleKey}",
                    "PUT",
                    "/v1/permissions/roles/missing-role/inherits/missing-parent",
                    authorizedStatus = 204,
                ),
                RestEndpoint(
                    "DELETE /roles/{roleKey}/inherits/{parentRoleKey}",
                    "DELETE",
                    "/v1/permissions/roles/missing-role/inherits/missing-parent",
                    authorizedStatus = 204,
                ),
                RestEndpoint(
                    "POST /roles/{roleKey}/grants",
                    "POST",
                    "/v1/permissions/roles/missing-role/grants",
                    "{}",
                ),
                RestEndpoint(
                    "PUT /roles/{roleKey}/grants/{grantId}",
                    "PUT",
                    "/v1/permissions/roles/missing-role/grants/$GRANT_ID",
                    "{}",
                ),
                RestEndpoint(
                    "DELETE /roles/{roleKey}/grants/{grantId}",
                    "DELETE",
                    "/v1/permissions/roles/missing-role/grants/$GRANT_ID",
                    authorizedStatus = 204,
                ),
                RestEndpoint(
                    "POST /catalog/custom",
                    "POST",
                    "/v1/permissions/catalog/custom",
                    "{}",
                ),
                RestEndpoint(
                    "PUT /catalog/custom/{permissionKey}",
                    "PUT",
                    "/v1/permissions/catalog/custom/grounds.test",
                    "{}",
                ),
                RestEndpoint(
                    "DELETE /catalog/custom/{permissionKey}",
                    "DELETE",
                    "/v1/permissions/catalog/custom/grounds.test",
                    authorizedStatus = 204,
                ),
                RestEndpoint(
                    "POST /keycloak-groups",
                    "POST",
                    "/v1/permissions/keycloak-groups",
                    "{}",
                ),
                RestEndpoint(
                    "PUT /keycloak-groups/{mappingId}",
                    "PUT",
                    "/v1/permissions/keycloak-groups/$MAPPING_ID",
                    "{}",
                ),
                RestEndpoint(
                    "DELETE /keycloak-groups/{mappingId}",
                    "DELETE",
                    "/v1/permissions/keycloak-groups/$MAPPING_ID",
                    authorizedStatus = 204,
                ),
                RestEndpoint(
                    "POST /players/{playerId}/roles",
                    "POST",
                    "/v1/permissions/players/$PLAYER_ID/roles",
                    "{}",
                ),
                RestEndpoint(
                    "PUT /players/{playerId}/roles/{grantId}",
                    "PUT",
                    "/v1/permissions/players/$PLAYER_ID/roles/$GRANT_ID",
                    "{}",
                ),
                RestEndpoint(
                    "DELETE /players/{playerId}/roles/{grantId}",
                    "DELETE",
                    "/v1/permissions/players/$PLAYER_ID/roles/$GRANT_ID",
                    authorizedStatus = 204,
                ),
                RestEndpoint(
                    "POST /players/{playerId}/grants",
                    "POST",
                    "/v1/permissions/players/$PLAYER_ID/grants",
                    "{}",
                ),
                RestEndpoint(
                    "PUT /players/{playerId}/grants/{grantId}",
                    "PUT",
                    "/v1/permissions/players/$PLAYER_ID/grants/$GRANT_ID",
                    "{}",
                ),
                RestEndpoint(
                    "DELETE /players/{playerId}/grants/{grantId}",
                    "DELETE",
                    "/v1/permissions/players/$PLAYER_ID/grants/$GRANT_ID",
                    authorizedStatus = 204,
                ),
                RestEndpoint(
                    "POST /identity-sync",
                    "POST",
                    "/v1/permissions/identity-sync",
                    authorizedStatus = 202,
                ),
                RestEndpoint(
                    "POST /players/{playerId}/identity-sync",
                    "POST",
                    "/v1/permissions/players/invalid/identity-sync",
                ),
                RestEndpoint(
                    "POST /sync/import",
                    "POST",
                    "/v1/permissions/sync/import",
                    """{"snapshot":$SNAPSHOT,"expectedTargetFingerprint":"reviewed-target","actions":[]}""",
                    authorizedStatus = 200,
                ),
            )

        @JvmStatic fun readEndpoints() = READ_ENDPOINTS.stream()

        @JvmStatic fun mutationEndpoints() = MUTATION_ENDPOINTS.stream()
    }
}

class PermissionRestAuthorizationTestProfile : QuarkusTestProfile {
    override fun getConfigOverrides(): Map<String, String> =
        mapOf(
            "quarkus.flyway.migrate-at-start" to "false",
            "quarkus.datasource.devservices.enabled" to "false",
            "permissions.auth.allow-test-security-principal" to "true",
            "permissions.instance-environment" to "stage",
        )
}

class SharedProjectForgeTestResource : QuarkusTestResourceLifecycleManager {
    private lateinit var server: HttpServer

    override fun start(): Map<String, String> {
        server = HttpServer.create(InetSocketAddress("localhost", 0), 0)
        server.createContext("/v1/control-center/access/me") { exchange ->
            exchange.respondJson("""{"permissions":[]}""")
        }
        server.createContext("/v1/projects/project-a") { exchange ->
            val projectRole =
                exchange.requestHeaders
                    .getFirst("Authorization")
                    ?.removePrefix("Forge-Test ")
                    ?.takeIf { it in setOf("owner", "editor") }
            if (projectRole == null) {
                exchange.respondJson("{}", 403)
            } else {
                exchange.respondJson("""{"role":"$projectRole"}""")
            }
        }
        server.start()
        return mapOf("permissions.forge.base-url" to "http://localhost:${server.address.port}")
    }

    override fun stop() {
        server.stop(0)
    }

    private fun HttpExchange.respondJson(body: String, statusCode: Int = 200) {
        val response = body.toByteArray(StandardCharsets.UTF_8)
        responseHeaders.add("Content-Type", "application/json")
        sendResponseHeaders(statusCode, response.size.toLong())
        responseBody.use { it.write(response) }
    }
}
