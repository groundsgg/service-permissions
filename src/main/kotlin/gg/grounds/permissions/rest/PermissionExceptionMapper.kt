package gg.grounds.permissions.rest

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
class PermissionNotFoundExceptionMapper : ExceptionMapper<NotFoundException> {
    override fun toResponse(exception: NotFoundException): Response =
        Response.status(Response.Status.NOT_FOUND)
            .entity(ErrorResponse(exception.message ?: "not found"))
            .build()
}
