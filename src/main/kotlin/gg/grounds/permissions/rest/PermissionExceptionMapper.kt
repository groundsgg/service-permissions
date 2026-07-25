package gg.grounds.permissions.rest

import gg.grounds.permissions.identity.IdentityProjectionUnavailableException
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
    ): Response =
        Response.status(status)
            .type(MediaType.valueOf(PROBLEM_JSON))
            .entity(
                ProblemDetails(
                    type = URI.create("about:blank"),
                    title = status.reasonPhrase,
                    status = status.statusCode,
                    detail = detail,
                    instance = uriInfo.requestUri,
                    requestId = RequestIdResolver.resolve(headers),
                    error = error,
                    reason = reason,
                )
            )
            .build()

    fun humanReadableDetail(value: String?, fallback: String): String =
        value?.replace('_', ' ')?.replaceFirstChar(Char::uppercase) ?: fallback
}

@Provider
class IllegalArgumentExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<IllegalArgumentException> {
    override fun toResponse(exception: IllegalArgumentException): Response {
        val error = exception.message ?: "invalid_request"
        return problem(
            Response.Status.BAD_REQUEST,
            humanReadableDetail(error, "Invalid request"),
            error,
        )
    }
}

@Provider
class IllegalStateExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<IllegalStateException> {
    override fun toResponse(exception: IllegalStateException): Response {
        val error = exception.message ?: "invalid_state"
        return problem(
            Response.Status.BAD_REQUEST,
            humanReadableDetail(error, "Invalid state"),
            error,
        )
    }
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
        val error = exception.message ?: "not_found"
        return problem(
            Response.Status.NOT_FOUND,
            humanReadableDetail(error, "The requested resource was not found."),
            error,
        )
    }
}

@Provider
class PermissionServiceUnavailableExceptionMapper :
    PermissionExceptionMapperSupport(), ExceptionMapper<ServiceUnavailableException> {
    override fun toResponse(exception: ServiceUnavailableException): Response {
        val error = exception.message ?: "service_unavailable"
        return problem(
            Response.Status.SERVICE_UNAVAILABLE,
            humanReadableDetail(error, "Service unavailable"),
            error,
        )
    }
}
