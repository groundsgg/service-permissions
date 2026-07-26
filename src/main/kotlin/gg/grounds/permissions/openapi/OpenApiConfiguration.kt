package gg.grounds.permissions.openapi

import io.quarkus.smallrye.openapi.OpenApiFilter
import jakarta.ws.rs.ApplicationPath
import jakarta.ws.rs.core.Application
import org.eclipse.microprofile.openapi.OASFactory
import org.eclipse.microprofile.openapi.OASFilter
import org.eclipse.microprofile.openapi.annotations.OpenAPIDefinition
import org.eclipse.microprofile.openapi.annotations.enums.SecuritySchemeType
import org.eclipse.microprofile.openapi.annotations.info.Info
import org.eclipse.microprofile.openapi.annotations.security.SecurityScheme
import org.eclipse.microprofile.openapi.annotations.tags.Tag
import org.eclipse.microprofile.openapi.models.Operation
import org.eclipse.microprofile.openapi.models.media.Schema.SchemaType
import org.eclipse.microprofile.openapi.models.parameters.Parameter
import org.eclipse.microprofile.openapi.models.responses.APIResponse

@ApplicationPath("/")
@OpenAPIDefinition(
    info =
        Info(
            title = "Permissions API",
            version = "1.0.0",
            description =
                "Internal REST API for permissions administration and workload evaluation.",
        ),
    tags =
        [
            Tag(name = "Administration", description = "Portal permissions administration."),
            Tag(name = "Runtime", description = "Workload permission evaluation and catalog."),
            Tag(
                name = "Environment sync",
                description = "Permission configuration transfer between environments.",
            ),
        ],
)
@SecurityScheme(
    securitySchemeName = "portalBearer",
    type = SecuritySchemeType.HTTP,
    scheme = "bearer",
    bearerFormat = "JWT",
    description = "Portal administrator JWT.",
)
@SecurityScheme(
    securitySchemeName = "workloadBearer",
    type = SecuritySchemeType.HTTP,
    scheme = "bearer",
    bearerFormat = "JWT",
    description = "Workload JWT for service-to-service requests.",
)
class OpenApiConfiguration : Application()

@OpenApiFilter
class PermissionsOpenApiFilter : OASFilter {
    override fun filterOperation(operation: Operation): Operation {
        val operationId = operation.operationId ?: return operation
        val responses = operation.responses ?: OASFactory.createAPIResponses()
        val successCode = successCode(operationId)
        val successResponse =
            responses.getAPIResponse(successCode)
                ?: responses.getAPIResponse("200")
                ?: OASFactory.createAPIResponse().description(successDescription(successCode))

        responses.apiResponses.keys.toList().forEach(responses::removeAPIResponse)
        successResponse.description = successDescription(successCode)
        if (successCode == "204") successResponse.content = null
        responses.addAPIResponse(successCode, successResponse)

        (COMMON_PROBLEM_RESPONSES + additionalProblemResponses(operationId)).forEach {
            (status, description) ->
            responses.addAPIResponse(status, problemResponse(description))
        }
        operation.responses = responses

        operation.parameters.orEmpty().forEach { parameter ->
            parameter.description =
                parameter.description?.takeIf(String::isNotBlank)
                    ?: REQUIRED_QUERY_PARAMETER_DESCRIPTIONS[operationId]?.get(parameter.name)
                    ?: PARAMETER_DESCRIPTIONS[parameter.name]
                    ?: "Request parameter ${parameter.name}."
            val requiredQuery =
                REQUIRED_QUERY_PARAMETERS[operationId]?.contains(parameter.name) == true
            parameter.required = parameter.`in` == Parameter.In.PATH || requiredQuery
            if (requiredQuery) parameter.schema?.removeType(SchemaType.NULL)
        }
        if (operationId == "createCustomCatalogEntry") requireCatalogCreateFields(operation)
        return operation
    }

    override fun filterOpenAPI(openAPI: org.eclipse.microprofile.openapi.models.OpenAPI) {
        openAPI.servers = emptyList()
        val components = openAPI.components ?: OASFactory.createComponents()
        components.addSchema("ProblemDetails", problemDetailsSchema())
        openAPI.components = components
    }

    private fun problemDetailsSchema() =
        OASFactory.createSchema()
            .addType(SchemaType.OBJECT)
            .description("RFC 9457 problem details response.")
            .addProperty("type", stringSchema("uri"))
            .addProperty("title", stringSchema())
            .addProperty(
                "status",
                OASFactory.createSchema().addType(SchemaType.INTEGER).format("int32"),
            )
            .addProperty("detail", stringSchema())
            .addProperty("instance", stringSchema("uri"))
            .addProperty("requestId", stringSchema())
            .addProperty("error", stringSchema())
            .addProperty("reason", stringSchema())
            .required(listOf("type", "title", "status", "detail", "instance", "requestId"))

    private fun stringSchema(format: String? = null) =
        OASFactory.createSchema().addType(SchemaType.STRING).also { it.format = format }

    private fun problemResponse(description: String): APIResponse =
        OASFactory.createAPIResponse()
            .description(description)
            .content(
                OASFactory.createContent()
                    .addMediaType(
                        PROBLEM_JSON,
                        OASFactory.createMediaType()
                            .schema(
                                OASFactory.createSchema().ref("#/components/schemas/ProblemDetails")
                            ),
                    )
            )

    private fun requireCatalogCreateFields(operation: Operation) {
        val mediaType = operation.requestBody?.content?.getMediaType(APPLICATION_JSON) ?: return
        val inferredSchema = mediaType.schema ?: return
        mediaType.schema =
            OASFactory.createSchema()
                .addAllOf(inferredSchema)
                .addProperty(
                    "key",
                    stringSchema().description("Permission key for the new catalog entry."),
                )
                .required(listOf("key", "label"))
    }

    private fun successCode(operationId: String): String =
        when (operationId) {
            in CREATED_OPERATIONS -> "201"
            in ACCEPTED_OPERATIONS -> "202"
            in NO_CONTENT_OPERATIONS -> "204"
            else -> "200"
        }

    private fun successDescription(status: String): String =
        when (status) {
            "201" -> "Created successfully."
            "202" -> "Accepted for asynchronous processing."
            "204" -> "Completed successfully with no response body."
            else -> "Completed successfully."
        }

    private fun additionalProblemResponses(operationId: String): Map<String, String> = buildMap {
        if (operationId in NOT_FOUND_OPERATIONS) {
            put("404", "The requested resource was not found.")
        }
        if (operationId in CONFLICT_OPERATIONS) {
            put("409", "The request conflicts with the current resource state.")
        }
    }

    private companion object {
        const val PROBLEM_JSON = "application/problem+json"
        const val APPLICATION_JSON = "application/json"

        val COMMON_PROBLEM_RESPONSES =
            linkedMapOf(
                "400" to "The request is invalid.",
                "401" to "Authentication is missing or invalid.",
                "403" to "The authenticated subject is not authorized.",
                "500" to "The request failed because of an internal service error.",
                "503" to "A required service dependency is unavailable.",
            )

        val CREATED_OPERATIONS =
            setOf(
                "createRole",
                "createRoleGrant",
                "createCustomCatalogEntry",
                "createPlayerRoleGrant",
                "createPlayerGrant",
                "createKeycloakGroupMapping",
            )

        val ACCEPTED_OPERATIONS = setOf("synchronizePlayerIdentities", "synchronizePlayerIdentity")

        val NO_CONTENT_OPERATIONS =
            setOf(
                "deleteRole",
                "addRoleInheritance",
                "removeRoleInheritance",
                "deleteRoleGrant",
                "deleteCustomCatalogEntry",
                "deletePlayerRoleGrant",
                "deletePlayerGrant",
                "deleteKeycloakGroupMapping",
                "replaceRuntimePermissionManifest",
            )

        val NOT_FOUND_OPERATIONS =
            setOf("getRole", "updateRole", "searchExternalPlayer", "synchronizePlayerIdentity")

        val CONFLICT_OPERATIONS =
            setOf(
                "createRole",
                "previewPermissionSync",
                "importPermissionSync",
                "replaceRuntimePermissionManifest",
            )

        val REQUIRED_QUERY_PARAMETERS =
            mapOf(
                "searchPlayers" to setOf("query"),
                "searchExternalPlayer" to setOf("query"),
                "checkPlayerPermission" to setOf("permission"),
            )

        val REQUIRED_QUERY_PARAMETER_DESCRIPTIONS =
            mapOf(
                "searchPlayers" to
                    mapOf(
                        "query" to
                            "Minecraft username fragment or complete player UUID to search for."
                    ),
                "searchExternalPlayer" to
                    mapOf(
                        "query" to
                            "Exact Minecraft username to look up outside the local player index."
                    ),
                "checkPlayerPermission" to mapOf("permission" to "Permission key to evaluate."),
            )

        val PARAMETER_DESCRIPTIONS =
            mapOf(
                "playerId" to "Minecraft player UUID.",
                "roleKey" to "Stable role key.",
                "parentRoleKey" to "Stable parent role key.",
                "grantId" to "Grant UUID.",
                "mappingId" to "Keycloak group mapping UUID.",
                "permissionKey" to "Catalog permission key.",
                "source" to "Stable runtime manifest source.",
                "query" to "Optional case-insensitive search query.",
                "q" to "Optional audit search query.",
                "page" to "One-based result page.",
                "perPage" to "Number of results per page.",
                "sortBy" to "Field used to order results.",
                "sortDirection" to "Sort direction: asc or desc.",
                "serverType" to "Optional server type scope.",
                "serverId" to "Optional server instance scope.",
                "permission" to "Permission key to evaluate.",
                "environment" to "Optional environment scope.",
                "effect" to "Optional permission effect filter.",
                "action" to "Optional audit action filters.",
                "from" to "Optional inclusive audit start time.",
                "to" to "Optional inclusive audit end time.",
            )
    }
}
