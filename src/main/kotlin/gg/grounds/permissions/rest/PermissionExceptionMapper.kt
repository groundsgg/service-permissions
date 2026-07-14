package gg.grounds.permissions.rest

import gg.grounds.permissions.identity.IdentityProjectionUnavailableException
import gg.grounds.permissions.persistence.DuplicateRoleKeyException
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.ext.ExceptionMapper
import jakarta.ws.rs.ext.Provider

@Provider
class IllegalArgumentExceptionMapper : ExceptionMapper<IllegalArgumentException> {
    override fun toResponse(exception: IllegalArgumentException): Response =
        Response.status(Response.Status.BAD_REQUEST)
            .entity(ErrorResponse(exception.message ?: "invalid request"))
            .build()
}

@Provider
class IllegalStateExceptionMapper : ExceptionMapper<IllegalStateException> {
    override fun toResponse(exception: IllegalStateException): Response =
        Response.status(Response.Status.BAD_REQUEST)
            .entity(ErrorResponse(exception.message ?: "invalid state"))
            .build()
}

@Provider
class IdentityProjectionUnavailableExceptionMapper :
    ExceptionMapper<IdentityProjectionUnavailableException> {
    override fun toResponse(exception: IdentityProjectionUnavailableException): Response =
        Response.status(Response.Status.SERVICE_UNAVAILABLE)
            .entity(ErrorResponse("identity_projection_unavailable"))
            .build()
}

@Provider
class DuplicateRoleKeyExceptionMapper : ExceptionMapper<DuplicateRoleKeyException> {
    override fun toResponse(exception: DuplicateRoleKeyException): Response =
        Response.status(Response.Status.CONFLICT).entity(ErrorResponse("role_key_conflict")).build()
}

@Provider
class PermissionNotFoundExceptionMapper : ExceptionMapper<NotFoundException> {
    override fun toResponse(exception: NotFoundException): Response =
        Response.status(Response.Status.NOT_FOUND)
            .entity(ErrorResponse(exception.message ?: "not found"))
            .build()
}
