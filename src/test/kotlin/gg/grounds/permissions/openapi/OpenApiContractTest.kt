package gg.grounds.permissions.openapi

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import gg.grounds.permissions.persistence.PermissionsPostgresTestResource
import io.quarkus.test.common.QuarkusTestResource
import io.quarkus.test.junit.QuarkusTest
import io.restassured.RestAssured.given
import io.restassured.http.ContentType
import jakarta.inject.Inject
import java.util.ArrayDeque
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
    fun `serves health and OpenAPI over the HTTP runtime`() {
        val healthStatus = given().get("/q/health").then().extract().statusCode()
        assertThat(healthStatus).isIn(200, 503)
        given().accept(ContentType.JSON).get("/q/openapi?format=json").then().statusCode(200)
    }

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
    fun `describes every schema and enum reachable from public REST operations`() {
        val document = openApiDocument()
        val schemas = document.path("components").path("schemas")
        val reachableSchemas = reachableSchemaNames(document)

        assertThat(reachableSchemas)
            .contains(
                "GlobalPermissionSnapshot",
                "PermissionSyncImportRequest",
                "PermissionSyncMetadataRecord",
                "PermissionSyncPreviewResponse",
                "SyncAction",
                "SyncCatalogEntry",
                "SyncChange",
                "SyncChangeKind",
                "SyncEntityType",
                "SyncInheritance",
                "SyncKeycloakMapping",
                "SyncPlayerGrant",
                "SyncRole",
                "SyncRoleGrant",
            )
        reachableSchemas.forEach { schemaName ->
            assertThat(schemas.path(schemaName).isMissingNode)
                .describedAs("reachable schema %s", schemaName)
                .isFalse()
            assertThat(schemas.path(schemaName).path("description").asText())
                .describedAs("description for reachable schema %s", schemaName)
                .isNotBlank()
        }
    }

    @Test
    fun `documents runtime and administration validation constraints`() {
        val document = openApiDocument()
        val schemas = document.path("components").path("schemas")

        assertStringConstraint(schemas, "RoleRequest", "name", minLength = 1, pattern = "\\S")
        assertStringConstraint(
            schemas,
            "GrantRequest",
            "permissionPattern",
            minLength = 1,
            pattern = PERMISSION_PATTERN,
        )
        assertStringConstraint(
            schemas,
            "PlayerRoleGrantRequest",
            "roleKey",
            minLength = 1,
            pattern = KEY_PATTERN,
        )
        assertStringConstraint(
            schemas,
            "KeycloakGroupMappingRequest",
            "keycloakGroup",
            minLength = 1,
            pattern = "\\S",
        )
        assertStringConstraint(
            schemas,
            "KeycloakGroupMappingRequest",
            "roleKey",
            minLength = 1,
            pattern = KEY_PATTERN,
        )
        assertStringConstraint(
            schemas,
            "CatalogEntryRequest",
            "label",
            minLength = 1,
            pattern = "\\S",
        )
        assertThat(
                schemas
                    .path("CatalogEntryRequest")
                    .path("properties")
                    .path("supportedScopes")
                    .path("minItems")
                    .asInt()
            )
            .isEqualTo(1)

        assertStringConstraint(
            schemas,
            "RuntimeManifestRequest",
            "sourceVersion",
            minLength = 1,
            pattern = "\\S",
        )
        listOf("serverType", "serverId").forEach { field ->
            assertStringConstraint(
                schemas,
                "RuntimeManifestRequest",
                field,
                minLength = 1,
                pattern = "\\S",
            )
            assertThat(
                    allowsNull(
                        schemas.path("RuntimeManifestRequest").path("properties").path(field)
                    )
                )
                .isTrue()
        }
        assertThat(
                schemas
                    .path("RuntimeManifestRequest")
                    .path("properties")
                    .path("permissions")
                    .has("minItems")
            )
            .isFalse()
        assertStringConstraint(
            schemas,
            "RuntimeManifestPermissionRequest",
            "key",
            minLength = 1,
            pattern = KEY_PATTERN,
        )
        assertStringConstraint(
            schemas,
            "RuntimeManifestPermissionRequest",
            "label",
            minLength = 1,
            pattern = "\\S",
        )
        assertThat(
                schemas
                    .path("RuntimeManifestPermissionRequest")
                    .path("properties")
                    .path("supportedScopes")
                    .path("minItems")
                    .asInt()
            )
            .isEqualTo(1)

        assertStringConstraint(
            schemas,
            "GlobalPermissionSnapshot",
            "snapshotId",
            minLength = 1,
            pattern = "\\S",
        )
        listOf("playerGrants", "playerRoleGrants").forEach { field ->
            assertThat(
                    schemas
                        .path("GlobalPermissionSnapshot")
                        .path("properties")
                        .path(field)
                        .path("maxItems")
                        .asInt(-1)
                )
                .isZero()
        }
        assertStringConstraint(
            schemas,
            "PermissionSyncImportRequest",
            "expectedTargetFingerprint",
            minLength = 1,
            pattern = "\\S",
        )

        assertThat(schemas.path("RuntimeManifestRequest").path("description").asText())
            .contains(
                "an empty permissions list clears the source",
                "permission keys must be unique",
                "source must not appear in the body",
            )
        assertThat(schemas.path("GrantRequest").path("description").asText())
            .contains("scopeValue must be absent for GLOBAL", "required for all other scopes")
        assertThat(schemas.path("PermissionSyncImportRequest").path("description").asText())
            .contains(
                "entityType and technicalKey pair must be unique",
                "match the previewed change",
            )
    }

    @Test
    fun `documents validated parameter bounds patterns and enums`() {
        val operationById =
            operations(openApiDocument()).values.associateBy { it.path("operationId").asText() }

        operationById.values
            .flatMap { it.path("parameters").toList() }
            .forEach { parameter ->
                val schema = parameter.path("schema")
                when (parameter.path("name").asText()) {
                    "page" -> assertThat(schema.path("minimum").asInt()).isEqualTo(1)
                    "perPage" -> {
                        assertThat(schema.path("minimum").asInt()).isEqualTo(1)
                        assertThat(schema.path("maximum").asInt()).isEqualTo(100)
                    }
                    "sortDirection" ->
                        assertThat(schema.path("enum").map(JsonNode::asText))
                            .containsExactly("asc", "desc")
                }
            }

        SORT_BY_VALUES.forEach { (operationId, values) ->
            assertThat(
                    parameter(operationById, operationId, "sortBy")
                        .path("schema")
                        .path("enum")
                        .map(JsonNode::asText)
                )
                .containsExactlyElementsOf(values)
        }
        assertThat(
                parameter(operationById, "searchEffectivePlayerPermissions", "effect")
                    .path("schema")
                    .path("enum")
                    .map(JsonNode::asText)
            )
            .containsExactly("ALL", "ALLOW", "DENY")

        assertThat(
                parameter(operationById, "searchPlayers", "query")
                    .path("schema")
                    .path("minLength")
                    .asInt()
            )
            .isEqualTo(2)
        assertThat(
                parameter(operationById, "searchExternalPlayer", "query")
                    .path("schema")
                    .path("pattern")
                    .asText()
            )
            .isEqualTo(MINECRAFT_USERNAME_PATTERN)
        assertThat(
                parameter(operationById, "checkPlayerPermission", "permission")
                    .path("schema")
                    .path("pattern")
                    .asText()
            )
            .isEqualTo(KEY_PATTERN)

        operationById.values
            .flatMap { it.path("parameters").toList() }
            .forEach { parameter ->
                val name = parameter.path("name").asText()
                val schema = parameter.path("schema")
                when (name) {
                    "playerId",
                    "grantId",
                    "mappingId" ->
                        assertThat(schema.path("format").asText())
                            .describedAs("UUID format for parameter %s", name)
                            .isEqualTo("uuid")
                    "roleKey",
                    "parentRoleKey",
                    "permissionKey" ->
                        assertThat(schema.path("pattern").asText())
                            .describedAs("key pattern for parameter %s", name)
                            .isEqualTo(KEY_PATTERN)
                }
            }
        val source = parameter(operationById, "replaceRuntimePermissionManifest", "source")
        assertThat(source.path("schema").path("minLength").asInt()).isEqualTo(1)
        assertThat(source.path("schema").path("pattern").asText()).isEqualTo("\\S")
    }

    @Test
    fun `uses enum and URI reference schemas with accurate nullability`() {
        val schemas = openApiDocument().path("components").path("schemas")

        ENUM_VALUES.forEach { (schemaName, values) ->
            val schema = schemas.path(schemaName)
            assertThat(schema.path("type").asText()).isEqualTo("string")
            assertThat(schema.path("enum").map(JsonNode::asText)).containsExactlyElementsOf(values)
            assertThat(allowsNull(schema)).isFalse()
        }

        val problem = schemas.path("ProblemDetails").path("properties")
        assertThat(problem.path("type").path("format").asText()).isEqualTo("uri-reference")
        assertThat(problem.path("instance").path("format").asText()).isEqualTo("uri-reference")
    }

    @Test
    fun `marks validation-required query parameters as required`() {
        val operations =
            operations(openApiDocument()).values.associateBy { it.path("operationId").asText() }

        REQUIRED_QUERY_PARAMETERS.forEach { (operationId, expectation) ->
            val parameter =
                operations.getValue(operationId).path("parameters").first {
                    it.path("name").asText() == expectation.name
                }
            assertThat(parameter.path("required").asBoolean())
                .describedAs("required query parameter %s.%s", operationId, expectation.name)
                .isTrue()
            assertThat(allowsNull(parameter.path("schema")))
                .describedAs("nullability of query parameter %s.%s", operationId, expectation.name)
                .isFalse()
            assertThat(parameter.path("description").asText()).isEqualTo(expectation.description)
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
        assertThat(createCatalogSchema.path("properties").has("key")).isTrue()
        assertThat(allowsNull(createCatalogSchema.path("properties").path("key"))).isFalse()

        val updateCatalogSchema =
            document
                .path("paths")
                .path("/v1/permissions/catalog/custom/{permissionKey}")
                .path("put")
                .path("requestBody")
                .path("content")
                .path("application/json")
                .path("schema")
        assertThat(updateCatalogSchema.path("\$ref").asText()).endsWith("/CatalogEntryRequest")
        val updateCatalogComponent = schemas.path("CatalogEntryRequest")
        assertThat(updateCatalogComponent.path("required").map(JsonNode::asText))
            .doesNotContain("key")
        val updateKey = updateCatalogComponent.path("properties").path("key")
        assertThat(allowsNull(updateKey)).isTrue()
        assertThat(updateKey.path("description").asText())
            .isEqualTo(
                "Ignored on update because the permissionKey path parameter is authoritative."
            )
    }

    private fun allowsNull(schema: JsonNode): Boolean =
        schema.path("type").let { type ->
            (type.isTextual && type.asText() == "null") ||
                (type.isArray && type.any { it.asText() == "null" })
        } ||
            schema.path("anyOf").any { it.path("type").asText() == "null" } ||
            schema.path("oneOf").any { it.path("type").asText() == "null" }

    private fun assertStringConstraint(
        schemas: JsonNode,
        schemaName: String,
        field: String,
        minLength: Int,
        pattern: String,
    ) {
        val property = schemas.path(schemaName).path("properties").path(field)
        assertThat(property.path("minLength").asInt())
            .describedAs("minLength of %s.%s", schemaName, field)
            .isEqualTo(minLength)
        assertThat(property.path("pattern").asText())
            .describedAs("pattern of %s.%s", schemaName, field)
            .isEqualTo(pattern)
    }

    private fun parameter(
        operations: Map<String, JsonNode>,
        operationId: String,
        parameterName: String,
    ): JsonNode =
        operations.getValue(operationId).path("parameters").first {
            it.path("name").asText() == parameterName
        }

    private fun reachableSchemaNames(document: JsonNode): Set<String> {
        val schemas = document.path("components").path("schemas")
        val reachable = linkedSetOf<String>()
        val pending = ArrayDeque<String>()
        operations(document).values.forEach { operation ->
            referencedSchemaNames(operation).forEach(pending::addLast)
        }
        while (pending.isNotEmpty()) {
            val schemaName = pending.removeFirst()
            if (!reachable.add(schemaName)) continue
            referencedSchemaNames(schemas.path(schemaName)).forEach(pending::addLast)
        }
        return reachable
    }

    private fun referencedSchemaNames(node: JsonNode): Set<String> = buildSet {
        fun visit(current: JsonNode) {
            if (current.isObject) {
                current
                    .path("\$ref")
                    .asText()
                    .takeIf { it.startsWith(SCHEMA_REFERENCE_PREFIX) }
                    ?.removePrefix(SCHEMA_REFERENCE_PREFIX)
                    ?.let(::add)
                current.properties().forEach { (_, child) -> visit(child) }
            } else if (current.isArray) {
                current.forEach(::visit)
            }
        }
        visit(node)
    }

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
        const val SCHEMA_REFERENCE_PREFIX = "#/components/schemas/"
        const val KEY_PATTERN = "^[a-z0-9._-]+$"
        const val PERMISSION_PATTERN = "^(?:\\*|[a-z0-9._-]+|[a-z0-9._-]+\\.\\*)$"
        const val MINECRAFT_USERNAME_PATTERN = "^[A-Za-z0-9_]{3,16}$"

        val SORT_BY_VALUES =
            mapOf(
                "searchRoleGrants" to
                    listOf("permission", "effect", "scope", "activation", "expiration"),
                "searchPlayerRoles" to listOf("role", "source", "activation", "expiration"),
                "searchPlayerGrants" to
                    listOf("permission", "effect", "scope", "activation", "expiration"),
                "searchEffectivePlayerPermissions" to
                    listOf("permission", "effect", "scope", "source", "activation", "expiration"),
                "searchPermissionCatalog" to listOf("permission", "label", "source", "lastseen"),
                "searchKeycloakGroupMappings" to listOf("group", "role", "activation", "expiration"),
            )

        val ENUM_VALUES =
            mapOf(
                "PermissionEffect" to listOf("ALLOW", "DENY"),
                "PermissionGrantOriginKind" to
                    listOf("DEFAULT_ROLE", "DIRECT_ROLE", "GROUP_MAPPING", "DIRECT_PERMISSION"),
                "PermissionGrantSource" to listOf("ROLE", "PLAYER"),
                "PermissionScopeKind" to listOf("GLOBAL", "ENVIRONMENT", "SERVER_TYPE", "SERVER"),
                "SyncAction" to
                    listOf("IMPORT", "KEEP_PROJECT", "USE_GLOBAL", "REMOVE_PROJECT_ENTRY"),
                "SyncChangeKind" to listOf("IMPORT", "CONFLICT", "PROJECT_ONLY"),
                "SyncEntityType" to
                    listOf("ROLE", "ROLE_GRANT", "INHERITANCE", "CATALOG_ENTRY", "KEYCLOAK_MAPPING"),
            )

        data class RequiredQueryParameter(val name: String, val description: String)

        val REQUIRED_QUERY_PARAMETERS =
            mapOf(
                "searchPlayers" to
                    RequiredQueryParameter(
                        "query",
                        "Minecraft username fragment or complete player UUID to search for.",
                    ),
                "searchExternalPlayer" to
                    RequiredQueryParameter(
                        "query",
                        "Exact Minecraft username to look up outside the local player index.",
                    ),
                "checkPlayerPermission" to
                    RequiredQueryParameter("permission", "Permission key to evaluate."),
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
