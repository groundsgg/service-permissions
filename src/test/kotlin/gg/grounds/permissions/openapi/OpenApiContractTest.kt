package gg.grounds.permissions.openapi

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import io.restassured.RestAssured.given
import io.restassured.http.ContentType
import jakarta.inject.Inject
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

@QuarkusTest
@QuarkusTestResource(
    value = PermissionsPostgresTestResource::class,
    restrictToAnnotatedClass = true,
)
class OpenApiContractTest {
    @Inject lateinit var objectMapper: ObjectMapper

    @Test
    fun `exports the complete permissions REST contract`() {
        val document = openApiDocument()

        assertThat(document.path("openapi").asText()).startsWith("3.")
        assertThat(document.path("tags").map { it.path("name").asText() })
            .containsExactly("Administration", "Runtime", "Environment sync")
        assertThat(
                document
                    .path("components")
                    .path("securitySchemes")
                    .fieldNames()
                    .asSequence()
                    .toSet()
            )
            .containsExactlyInAnyOrder("portalBearer", "workloadBearer")

        val actualOperations = operations(document)
        assertThat(actualOperations.keys)
            .containsExactlyInAnyOrderElementsOf(EXPECTED_OPERATIONS.keys)

        EXPECTED_OPERATIONS.forEach { (key, expected) ->
            val operation = actualOperations.getValue(key)
            assertThat(operation.path("tags").map(JsonNode::asText))
                .describedAs("tags for %s %s", key.method.uppercase(), key.path)
                .containsExactly(expected.tag)
            assertThat(operation.path("security").any { it.has(expected.securityScheme) })
                .describedAs("security for %s %s", key.method.uppercase(), key.path)
                .isTrue()
            assertThat(operation.path("operationId").asText())
                .describedAs("operationId for %s %s", key.method.uppercase(), key.path)
                .isNotBlank()

            assertParameters(key.path, operation)
            assertRequestBody(key, expected, operation)
            assertResponses(key, expected, operation)
        }

        val operationIds = actualOperations.values.map { it.path("operationId").asText() }
        assertThat(operationIds).doesNotHaveDuplicates()
    }

    @Test
    fun `uses RFC 9457 problem details without exposing internal transports or credentials`() {
        val document = openApiDocument()
        val schemas = document.path("components").path("schemas").fieldNames().asSequence().toSet()
        assertThat(schemas).contains("ProblemDetails")
        assertThat(schemas).doesNotContainAnyElementsOf(GRPC_DERIVED_SCHEMAS)

        val serialized = objectMapper.writeValueAsString(document)
        assertThat(serialized)
            .doesNotContain("cluster.local")
            .doesNotContain("nats://")
            .doesNotContain("postgresql://")
            .doesNotContain("OPENAPI_PUBLISHER_PRIVATE_KEY")
            .doesNotContain("github.token")
            .doesNotContain("password=")
            .doesNotContain("authorization=")
    }

    @Test
    fun `describes every public REST payload schema`() {
        val schemas = openApiDocument().path("components").path("schemas")

        PUBLIC_REST_SCHEMAS.forEach { schemaName ->
            assertThat(schemas.path(schemaName).isMissingNode)
                .describedAs("public schema %s", schemaName)
                .isFalse()
            assertThat(schemas.path(schemaName).path("description").asText())
                .describedAs("description for public schema %s", schemaName)
                .isNotBlank()
        }
    }

    @Test
    fun `marks validation-required query parameters as required`() {
        val operations =
            operations(openApiDocument()).values.associateBy { it.path("operationId").asText() }

        REQUIRED_QUERY_PARAMETERS.forEach { (operationId, parameterName) ->
            val parameter =
                operations.getValue(operationId).path("parameters").first {
                    it.path("name").asText() == parameterName
                }
            assertThat(parameter.path("required").asBoolean())
                .describedAs("required query parameter %s.%s", operationId, parameterName)
                .isTrue()
        }
    }

    @Test
    fun `documents validated request fields as required and non-null`() {
        val document = openApiDocument()
        val schemas = document.path("components").path("schemas")
        REQUIRED_REQUEST_FIELDS.forEach { (schemaName, fields) ->
            val schema = schemas.path(schemaName)
            assertThat(schema.path("required").map(JsonNode::asText))
                .describedAs("required fields for %s", schemaName)
                .containsExactlyInAnyOrderElementsOf(fields)
            fields.forEach { field ->
                assertThat(allowsNull(schema.path("properties").path(field)))
                    .describedAs("nullability of %s.%s", schemaName, field)
                    .isFalse()
            }
        }

        val runtimeManifest = schemas.path("RuntimeManifestRequest")
        assertThat(runtimeManifest.path("required").map(JsonNode::asText))
            .doesNotContain("serverType", "serverId")

        val createCatalogSchema =
            document
                .path("paths")
                .path("/v1/permissions/catalog/custom")
                .path("post")
                .path("requestBody")
                .path("content")
                .path("application/json")
                .path("schema")
        assertThat(createCatalogSchema.path("required").map(JsonNode::asText))
            .contains("key", "label")
    }

    private fun allowsNull(schema: JsonNode): Boolean =
        schema.path("type").let { type ->
            (type.isTextual && type.asText() == "null") ||
                (type.isArray && type.any { it.asText() == "null" })
        } ||
            schema.path("anyOf").any { it.path("type").asText() == "null" } ||
            schema.path("oneOf").any { it.path("type").asText() == "null" }

    private fun assertParameters(path: String, operation: JsonNode) {
        val parameters = operation.path("parameters")
        parameters.forEach { parameter ->
            assertThat(parameter.path("name").asText()).isNotBlank()
            assertThat(parameter.path("in").asText()).isIn("path", "query", "header")
            assertThat(parameter.path("schema").isMissingNode).isFalse()
        }
        PATH_PARAMETER.findAll(path)
            .map { it.groupValues[1] }
            .forEach { parameterName ->
                val parameter = parameters.firstOrNull { it.path("name").asText() == parameterName }
                assertThat(parameter)
                    .describedAs("path parameter %s for %s", parameterName, path)
                    .isNotNull()
                assertThat(parameter!!.path("in").asText()).isEqualTo("path")
                assertThat(parameter.path("required").asBoolean()).isTrue()
            }
    }

    private fun assertRequestBody(
        key: OperationKey,
        expected: ExpectedOperation,
        operation: JsonNode,
    ) {
        if (!expected.requestBody) {
            assertThat(operation.has("requestBody"))
                .describedAs("request body for %s %s", key.method.uppercase(), key.path)
                .isFalse()
            return
        }
        val requestBody = operation.path("requestBody")
        assertThat(requestBody.path("required").asBoolean()).isTrue()
        val schema = requestBody.path("content").path("application/json").path("schema")
        assertThat(schema.isMissingNode || schema.isEmpty)
            .describedAs("request schema for %s %s", key.method.uppercase(), key.path)
            .isFalse()
    }

    private fun assertResponses(
        key: OperationKey,
        expected: ExpectedOperation,
        operation: JsonNode,
    ) {
        val responses = operation.path("responses")
        val expectedStatuses = COMMON_ERRORS + expected.additionalErrors + expected.successCode
        assertThat(responses.fieldNames().asSequence().toSet())
            .describedAs("responses for %s %s", key.method.uppercase(), key.path)
            .containsExactlyInAnyOrderElementsOf(expectedStatuses)

        val success = responses.path(expected.successCode)
        assertThat(success.path("description").asText()).isNotBlank()
        if (expected.successCode == "204") {
            assertThat(success.has("content")).isFalse()
        } else {
            val schema = success.path("content").path("application/json").path("schema")
            assertThat(schema.isMissingNode || schema.isEmpty)
                .describedAs("success schema for %s %s", key.method.uppercase(), key.path)
                .isFalse()
        }

        (COMMON_ERRORS + expected.additionalErrors).forEach { status ->
            val response = responses.path(status)
            val schema = response.path("content").path("application/problem+json").path("schema")
            assertThat(schema.path("\$ref").asText())
                .describedAs("RFC 9457 schema for %s %s HTTP %s", key.method, key.path, status)
                .endsWith("/ProblemDetails")
        }
    }

    private fun operations(document: JsonNode): Map<OperationKey, JsonNode> = buildMap {
        document.path("paths").properties().forEach { (path, pathItem) ->
            if (path == TEST_ONLY_AUTH_PROBE) return@forEach
            pathItem.properties().forEach { (method, operation) ->
                if (method in HTTP_METHODS) put(OperationKey(path, method), operation)
            }
        }
    }

    private fun openApiDocument(): JsonNode {
        val body =
            given()
                .accept(ContentType.JSON)
                .get("/q/openapi?format=json")
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .extract()
                .asString()
        return objectMapper.readTree(body)
    }

    private data class OperationKey(val path: String, val method: String)

    private data class ExpectedOperation(
        val tag: String,
        val securityScheme: String,
        val successCode: String = "200",
        val requestBody: Boolean = false,
        val additionalErrors: Set<String> = emptySet(),
    )

    private companion object {
        val COMMON_ERRORS = setOf("400", "401", "403", "500", "503")
        val HTTP_METHODS = setOf("get", "post", "put", "delete", "patch")
        const val TEST_ONLY_AUTH_PROBE = "/v1/permissions/runtime/auth-probe"
        val PATH_PARAMETER = Regex("\\{([^}]+)}")
        val GRPC_DERIVED_SCHEMAS =
            setOf(
                "GetPlayerSnapshotRequest",
                "RefreshOnlinePlayersRequest",
                "RefreshOnlinePlayersReply",
                "PlayerPermissionSnapshot",
                "PermissionGrantOrigin",
                "RegisterPermissionManifestRequest",
                "PermissionManifestEntry",
                "RegisterPermissionManifestReply",
            )
        val PUBLIC_REST_SCHEMAS =
            setOf(
                "RoleRequest",
                "RoleResponse",
                "RoleListResponse",
                "GrantRequest",
                "RoleGrantResponse",
                "PlayerRoleGrantRequest",
                "PlayerRoleGrantResponse",
                "PlayerEffectiveRoleResponse",
                "PlayerGrantResponse",
                "KeycloakGroupMappingRequest",
                "KeycloakGroupMappingResponse",
                "CatalogEntryRequest",
                "CatalogEntryResponse",
                "EffectivePermissionResponse",
                "EffectiveGrantResponse",
                "EffectiveRoleAssignmentResponse",
                "PermissionCheckResponse",
                "PlayerIdentityResponse",
                "PlayerSearchItemResponse",
                "PlayerSearchResponse",
                "IdentitySyncStatusResponse",
                "PermissionAuditEventResponse",
                "PermissionAuditPageResponse",
                "SyncDispatchResponse",
                "RuntimePermissionSnapshotResponse",
                "RuntimePermissionGrantDto",
                "PermissionScopeDto",
                "RuntimeRoleMetadataDto",
                "RuntimeManifestRequest",
                "RuntimeManifestPermissionRequest",
            )
        val REQUIRED_QUERY_PARAMETERS =
            mapOf(
                "searchPlayers" to "query",
                "searchExternalPlayer" to "query",
                "checkPlayerPermission" to "permission",
            )
        val REQUIRED_REQUEST_FIELDS =
            mapOf(
                "RoleRequest" to setOf("name"),
                "GrantRequest" to setOf("effect", "permissionPattern"),
                "PlayerRoleGrantRequest" to setOf("roleKey"),
                "KeycloakGroupMappingRequest" to setOf("keycloakGroup", "roleKey"),
                "CatalogEntryRequest" to setOf("label"),
                "RuntimeManifestRequest" to setOf("sourceVersion", "permissions"),
                "RuntimeManifestPermissionRequest" to setOf("key", "label", "supportedScopes"),
            )

        fun operation(
            path: String,
            method: String,
            tag: String = "Administration",
            security: String = "portalBearer",
            success: String = "200",
            body: Boolean = false,
            vararg errors: String,
        ) =
            OperationKey(path, method) to
                ExpectedOperation(tag, security, success, body, errors.toSet())

        val EXPECTED_OPERATIONS =
            mapOf(
                operation("/v1/permissions/roles", "get"),
                operation(
                    "/v1/permissions/roles",
                    "post",
                    success = "201",
                    body = true,
                    errors = arrayOf("409"),
                ),
                operation("/v1/permissions/roles/{roleKey}", "get", errors = arrayOf("404")),
                operation(
                    "/v1/permissions/roles/{roleKey}",
                    "put",
                    body = true,
                    errors = arrayOf("404"),
                ),
                operation("/v1/permissions/roles/{roleKey}", "delete", success = "204"),
                operation(
                    "/v1/permissions/roles/{roleKey}/inherits/{parentRoleKey}",
                    "put",
                    success = "204",
                ),
                operation(
                    "/v1/permissions/roles/{roleKey}/inherits/{parentRoleKey}",
                    "delete",
                    success = "204",
                ),
                operation("/v1/permissions/roles/{roleKey}/grants", "get"),
                operation("/v1/permissions/roles/{roleKey}/grants/search", "get"),
                operation(
                    "/v1/permissions/roles/{roleKey}/grants",
                    "post",
                    success = "201",
                    body = true,
                ),
                operation("/v1/permissions/roles/{roleKey}/grants/{grantId}", "put", body = true),
                operation(
                    "/v1/permissions/roles/{roleKey}/grants/{grantId}",
                    "delete",
                    success = "204",
                ),
                operation("/v1/permissions/catalog", "get"),
                operation("/v1/permissions/catalog/search", "get"),
                operation("/v1/permissions/catalog/custom", "post", success = "201", body = true),
                operation("/v1/permissions/catalog/custom/{permissionKey}", "put", body = true),
                operation(
                    "/v1/permissions/catalog/custom/{permissionKey}",
                    "delete",
                    success = "204",
                ),
                operation("/v1/permissions/players/search", "get"),
                operation(
                    "/v1/permissions/players/external-search",
                    "get",
                    errors = arrayOf("404"),
                ),
                operation("/v1/permissions/players/{playerId}/roles", "get"),
                operation("/v1/permissions/players/{playerId}/roles/search", "get"),
                operation(
                    "/v1/permissions/players/{playerId}/roles",
                    "post",
                    success = "201",
                    body = true,
                ),
                operation("/v1/permissions/players/{playerId}/roles/{grantId}", "put", body = true),
                operation(
                    "/v1/permissions/players/{playerId}/roles/{grantId}",
                    "delete",
                    success = "204",
                ),
                operation("/v1/permissions/players/{playerId}/grants", "get"),
                operation("/v1/permissions/players/{playerId}/grants/search", "get"),
                operation(
                    "/v1/permissions/players/{playerId}/grants",
                    "post",
                    success = "201",
                    body = true,
                ),
                operation(
                    "/v1/permissions/players/{playerId}/grants/{grantId}",
                    "put",
                    body = true,
                ),
                operation(
                    "/v1/permissions/players/{playerId}/grants/{grantId}",
                    "delete",
                    success = "204",
                ),
                operation("/v1/permissions/players/{playerId}/effective", "get"),
                operation("/v1/permissions/players/{playerId}/effective/search", "get"),
                operation("/v1/permissions/players/{playerId}/identity", "get"),
                operation("/v1/permissions/players/{playerId}/check", "get"),
                operation("/v1/permissions/keycloak-groups", "get"),
                operation("/v1/permissions/keycloak-groups/search", "get"),
                operation("/v1/permissions/keycloak-groups", "post", success = "201", body = true),
                operation("/v1/permissions/keycloak-groups/{mappingId}", "put", body = true),
                operation("/v1/permissions/keycloak-groups/{mappingId}", "delete", success = "204"),
                operation("/v1/permissions/audit", "get"),
                operation("/v1/permissions/identity-sync/status", "get"),
                operation("/v1/permissions/identity-sync", "post", success = "202"),
                operation(
                    "/v1/permissions/players/{playerId}/identity-sync",
                    "post",
                    success = "202",
                    errors = arrayOf("404"),
                ),
                operation("/v1/permissions/sync/snapshot", "get", tag = "Environment sync"),
                operation(
                    "/v1/permissions/sync/preview",
                    "post",
                    tag = "Environment sync",
                    body = true,
                    errors = arrayOf("409"),
                ),
                operation(
                    "/v1/permissions/sync/import",
                    "post",
                    tag = "Environment sync",
                    body = true,
                    errors = arrayOf("409"),
                ),
                operation(
                    "/v1/permissions/runtime/players/{playerId}/snapshot",
                    "get",
                    tag = "Runtime",
                    security = "workloadBearer",
                ),
                operation(
                    "/v1/permissions/runtime/catalog/manifests/{source}",
                    "put",
                    tag = "Runtime",
                    security = "workloadBearer",
                    success = "204",
                    body = true,
                    errors = arrayOf("409"),
                ),
            )
    }
}
