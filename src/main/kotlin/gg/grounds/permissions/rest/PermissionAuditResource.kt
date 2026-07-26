package gg.grounds.permissions.rest

import gg.grounds.permissions.auth.AdminAuthorizationService
import gg.grounds.permissions.persistence.PermissionAuditEventQuery
import gg.grounds.permissions.persistence.PermissionAuditEventRecord
import gg.grounds.permissions.persistence.PermissionRepository
import io.quarkus.security.Authenticated
import io.quarkus.security.identity.SecurityIdentity
import jakarta.inject.Inject
import jakarta.ws.rs.DefaultValue
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import java.time.Instant
import java.time.format.DateTimeParseException
import org.eclipse.microprofile.openapi.annotations.Operation
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement
import org.eclipse.microprofile.openapi.annotations.tags.Tag

@Path("/v1/permissions/audit")
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
@Tag(name = "Administration")
@SecurityRequirement(name = "portalBearer")
class PermissionAuditResource
@Inject
constructor(
    private val repository: PermissionRepository,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {

    @GET
    @Operation(operationId = "listPermissionAuditEvents", summary = "List permission audit events")
    fun list(
        @QueryParam("q") q: String?,
        @QueryParam("action") actions: List<String>?,
        @QueryParam("from") from: String?,
        @QueryParam("to") to: String?,
        @QueryParam("page") @DefaultValue("1") page: Int,
        @QueryParam("perPage") @DefaultValue("25") perPage: Int,
        @Context headers: HttpHeaders,
    ): PermissionAuditPageResponse {
        authorization.requireMinecraftPermissionsView(identity, headers)
        val result =
            repository.listAuditEvents(
                PermissionAuditEventQuery(
                    query = q?.trim().orEmpty(),
                    actions =
                        actions.orEmpty().map(String::trim).filter(String::isNotEmpty).toSet(),
                    from = from?.let(::parseInstant),
                    to = to?.let(::parseInstant),
                    page = page,
                    perPage = perPage,
                )
            )
        return PermissionAuditPageResponse(
            items = result.items.map(PermissionAuditEventRecord::toResponse),
            page = result.page,
            perPage = result.perPage,
            total = result.total,
        )
    }

    private fun parseInstant(value: String): Instant =
        try {
            Instant.parse(value)
        } catch (error: DateTimeParseException) {
            throw IllegalArgumentException("invalid_timestamp", error)
        }
}

fun PermissionAuditEventRecord.toResponse(): PermissionAuditEventResponse =
    PermissionAuditEventResponse(
        id = id,
        actorUserId = actorUserId,
        action = action,
        target = target,
        metadata = metadata,
        createdAt = createdAt,
    )
