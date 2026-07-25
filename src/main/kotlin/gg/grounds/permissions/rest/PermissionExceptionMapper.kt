package gg.grounds.permissions.rest

import gg.grounds.permissions.identity.IdentityProjectionUnavailableException
import gg.grounds.permissions.persistence.CatalogSourceConflictException
import gg.grounds.permissions.persistence.DuplicateRoleKeyException
import gg.grounds.permissions.sync.PermissionSyncConflictException
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.ServiceUnavailableException
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriInfo
import jakarta.ws.rs.ext.ExceptionMapper
import jakarta.ws.rs.ext.Provider
import java.net.URI

private const val PROBLEM_JSON = "application/problem+json"

abstract class PermissionExceptionMapperSupport {
    @Context lateinit var headers: HttpHeaders
    @Context lateinit var uriInfo: UriInfo

    fun problem(
        status: Response.Status,
        detail: String,
        error: String? = null,
        reason: String? = null,
        type: URI = URI.create("about:blank"),
    ): Response =
        Response.status(status)
            .type(MediaType.valueOf(PROBLEM_JSON))
            .entity(
                ProblemDetails(
                    type = type,
                    title = status.reasonPhrase,
                    status = status.statusCode,
                    detail = detail,
                    instance = URI.create(uriInfo.requestUri.rawPath ?: "/"),
                    requestId = RequestIdResolver.resolve(headers),
                    error = error,
                    reason = reason,
                )
            )
            .build()

    protected fun invalidArgumentProblem(exception: IllegalArgumentException): SafeProblem =
        when (exception.message) {
            "role_name_invalid" -> SafeProblem("role_name_invalid", "The role name is invalid.")
            in LEGACY_SAFE_INVALID_REQUESTS ->
                SafeProblem(requireNotNull(exception.message), requireNotNull(exception.message))
            else -> SafeProblem("invalid_request", "The request is invalid.")
        }

    protected fun notFoundProblem(exception: NotFoundException): SafeProblem =
        when (exception.message) {
            "player_already_known" ->
                SafeProblem("player_already_known", "The player is already known.")
            "player_not_found" -> SafeProblem("player_not_found", "The player was not found.")
            "player_identity_not_linked" ->
                SafeProblem("player_identity_not_linked", "The player identity is not linked.")
            else -> SafeProblem("not_found", "The requested resource was not found.")
        }

    protected fun serviceUnavailableProblem(exception: ServiceUnavailableException): SafeProblem =
        when (exception.message) {
            "external_player_lookup_unavailable" ->
                SafeProblem(
                    "external_player_lookup_unavailable",
                    "External player lookup is unavailable.",
                )
            else -> SafeProblem("service_unavailable", "The service is unavailable.")
        }
}

data class SafeProblem(val error: String, val detail: String)

private val LEGACY_SAFE_INVALID_REQUESTS =
    setOf(
        "effect must be one of: ALL, ALLOW, DENY",
        "page must be at least 1",
        "perPage must be between 1 and 100",
        "query must contain at least 2 characters",
        "sortBy must be one of: group, role, expiration",
        "sortBy must be one of: permission, effect, scope, expiration",
        "sortBy must be one of: permission, effect, scope, source, expiration",
        "sortBy must be one of: permission, label, source, lastseen",
        "sortBy must be one of: role, source, expiration",
        "sortDirection must be one of: asc, desc",
    )

@Provider
class IllegalArgumentExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<IllegalArgumentException> {
    override fun toResponse(exception: IllegalArgumentException): Response {
        val safeProblem = invalidArgumentProblem(exception)
        return problem(Response.Status.BAD_REQUEST, safeProblem.detail, safeProblem.error)
    }
}

@Provider
class IllegalStateExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<IllegalStateException> {
    override fun toResponse(exception: IllegalStateException): Response =
        problem(
            Response.Status.BAD_REQUEST,
            "The request cannot be processed in its current state.",
            "invalid_state",
        )
}

@Provider
class IdentityProjectionUnavailableExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<IdentityProjectionUnavailableException> {
    override fun toResponse(exception: IdentityProjectionUnavailableException): Response =
        problem(
            Response.Status.SERVICE_UNAVAILABLE,
            "The player identity projection is unavailable.",
            "identity_projection_unavailable",
        )
}

@Provider
class DuplicateRoleKeyExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<DuplicateRoleKeyException> {
    override fun toResponse(exception: DuplicateRoleKeyException): Response =
        problem(
            Response.Status.CONFLICT,
            "A role with this key already exists.",
            "role_key_conflict",
        )
}

@Provider
class CatalogSourceConflictExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<CatalogSourceConflictException> {
    override fun toResponse(exception: CatalogSourceConflictException): Response =
        problem(
            status = Response.Status.CONFLICT,
            detail = "A permission key is already owned by another catalog source.",
            error = "catalog_source_conflict",
            type = URI.create("/problems/catalog-source-conflict"),
        )
}

@Provider
class PermissionSyncConflictExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<PermissionSyncConflictException> {
    override fun toResponse(exception: PermissionSyncConflictException): Response =
        problem(
            Response.Status.CONFLICT,
            "The permission configuration changed and cannot be synchronized.",
            "permission_sync_conflict",
            exception.reason.wireValue,
        )
}

@Provider
class PermissionNotFoundExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<NotFoundException> {
    override fun toResponse(exception: NotFoundException): Response {
        val safeProblem = notFoundProblem(exception)
        return problem(Response.Status.NOT_FOUND, safeProblem.detail, safeProblem.error)
    }
}

@Provider
class PermissionServiceUnavailableExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<ServiceUnavailableException> {
    override fun toResponse(exception: ServiceUnavailableException): Response {
        val safeProblem = serviceUnavailableProblem(exception)
        return problem(Response.Status.SERVICE_UNAVAILABLE, safeProblem.detail, safeProblem.error)
    }
}
