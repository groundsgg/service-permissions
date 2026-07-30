package gg.grounds.permissions.rest

import gg.grounds.permissions.identity.IdentityProjectionUnavailableException
import gg.grounds.permissions.persistence.CatalogSourceConflictException
import gg.grounds.permissions.persistence.DuplicateRoleKeyException
import gg.grounds.permissions.sync.PermissionSyncConflictException
import io.quarkus.security.AuthenticationFailedException
import jakarta.annotation.Priority
import jakarta.ws.rs.BadRequestException
import jakarta.ws.rs.ForbiddenException
import jakarta.ws.rs.NotAllowedException
import jakarta.ws.rs.NotAuthorizedException
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.NotSupportedException
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.ServiceUnavailableException
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriInfo
import jakarta.ws.rs.ext.ExceptionMapper
import jakarta.ws.rs.ext.Provider
import java.net.URI
import org.jboss.logging.Logger

private const val PROBLEM_JSON = "application/problem+json"

abstract class PermissionExceptionMapperSupport {
    @Context lateinit var headers: HttpHeaders
    @Context lateinit var uriInfo: UriInfo

    fun problem(
        status: Response.StatusType,
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
            "startsAt must be before expiresAt" ->
                SafeProblem("invalid_validity_window", "startsAt must be before expiresAt")
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
        "sortBy must be one of: group, role, activation, expiration",
        "sortBy must be one of: permission, effect, scope, activation, expiration",
        "sortBy must be one of: permission, effect, scope, source, activation, expiration",
        "sortBy must be one of: permission, label, source, lastseen",
        "sortBy must be one of: role, source, activation, expiration",
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

@Provider
class PermissionBadRequestExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<BadRequestException> {
    override fun toResponse(exception: BadRequestException): Response =
        problem(Response.Status.BAD_REQUEST, "The request is invalid.", "invalid_request")
}

@Provider
@Priority(Priorities.USER)
class PermissionNotAuthorizedExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<NotAuthorizedException> {
    override fun toResponse(exception: NotAuthorizedException): Response =
        unauthorizedProblem("authentication_required", "Authentication is required.")
}

@Provider
@Priority(Priorities.USER)
class PermissionUnauthorizedExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<io.quarkus.security.UnauthorizedException> {
    override fun toResponse(exception: io.quarkus.security.UnauthorizedException): Response =
        unauthorizedProblem("authentication_required", "Authentication is required.")
}

@Provider
@Priority(Priorities.USER)
class PermissionAuthenticationFailedExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<AuthenticationFailedException> {
    override fun toResponse(exception: AuthenticationFailedException): Response =
        unauthorizedProblem("authentication_failed", "Authentication failed.")
}

@Provider
class PermissionForbiddenExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<ForbiddenException> {
    override fun toResponse(exception: ForbiddenException): Response =
        problem(
            Response.Status.FORBIDDEN,
            "The authenticated user lacks the required permission.",
            if (exception.message == "missing_permission") "missing_permission" else "access_denied",
        )
}

@Provider
@Priority(Priorities.USER)
class PermissionSecurityForbiddenExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<io.quarkus.security.ForbiddenException> {
    override fun toResponse(exception: io.quarkus.security.ForbiddenException): Response =
        problem(
            Response.Status.FORBIDDEN,
            "The authenticated user lacks the required permission.",
            "access_denied",
        )
}

@Provider
class PermissionNotAllowedExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<NotAllowedException> {
    override fun toResponse(exception: NotAllowedException): Response =
        problem(
            Response.Status.METHOD_NOT_ALLOWED,
            "The HTTP method is not supported for this resource.",
            "method_not_allowed",
        )
}

@Provider
class PermissionNotSupportedExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<NotSupportedException> {
    override fun toResponse(exception: NotSupportedException): Response =
        problem(
            Response.Status.UNSUPPORTED_MEDIA_TYPE,
            "The request media type is not supported.",
            "unsupported_media_type",
        )
}

@Provider
class PermissionWebApplicationExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<WebApplicationException> {
    override fun toResponse(exception: WebApplicationException): Response {
        val status = exception.response.statusInfo
        return when (Response.Status.fromStatusCode(status.statusCode)) {
            Response.Status.BAD_REQUEST ->
                problem(status, "The request is invalid.", "invalid_request")
            Response.Status.UNAUTHORIZED ->
                unauthorizedProblem("authentication_required", "Authentication is required.")
            Response.Status.FORBIDDEN ->
                problem(
                    status,
                    "The authenticated user lacks the required permission.",
                    "access_denied",
                )
            Response.Status.NOT_FOUND ->
                problem(status, "The requested resource was not found.", "not_found")
            Response.Status.METHOD_NOT_ALLOWED ->
                problem(
                    status,
                    "The HTTP method is not supported for this resource.",
                    "method_not_allowed",
                )
            Response.Status.NOT_ACCEPTABLE ->
                problem(
                    status,
                    "The requested response media type is not supported.",
                    "not_acceptable",
                )
            Response.Status.CONFLICT ->
                problem(
                    status,
                    "The request conflicts with the current resource state.",
                    "conflict",
                )
            Response.Status.UNSUPPORTED_MEDIA_TYPE ->
                problem(
                    status,
                    "The request media type is not supported.",
                    "unsupported_media_type",
                )
            Response.Status.SERVICE_UNAVAILABLE ->
                problem(status, "The service is unavailable.", "service_unavailable")
            else -> {
                val safeProblem =
                    when (status.family) {
                        Response.Status.Family.CLIENT_ERROR ->
                            SafeProblem("request_rejected", "The request was rejected.")
                        Response.Status.Family.SERVER_ERROR ->
                            SafeProblem(
                                "internal_server_error",
                                "The request failed because of an internal service error.",
                            )
                        else -> SafeProblem("request_failed", "The request could not be completed.")
                    }
                problem(status, safeProblem.detail, safeProblem.error)
            }
        }
    }
}

@Provider
class PermissionUnexpectedExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<Throwable> {
    override fun toResponse(exception: Throwable): Response {
        val response =
            problem(
                Response.Status.INTERNAL_SERVER_ERROR,
                "The request failed because of an internal service error.",
                "internal_server_error",
            )
        val details = response.entity as ProblemDetails
        LOG.errorf(
            "REST request failed (requestId=%s, instance=%s, exceptionType=%s)",
            details.requestId,
            details.instance,
            exception.javaClass.name,
        )
        return response
    }

    private companion object {
        val LOG: Logger = Logger.getLogger(PermissionUnexpectedExceptionMapper::class.java)
    }
}

private fun PermissionExceptionMapperSupport.unauthorizedProblem(
    error: String,
    detail: String,
): Response =
    Response.fromResponse(problem(Response.Status.UNAUTHORIZED, detail, error))
        .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
        .build()
