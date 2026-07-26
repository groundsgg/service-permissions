package gg.grounds.permissions.rest

import jakarta.annotation.Priority
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerResponseContext
import jakarta.ws.rs.container.ContainerResponseFilter
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.ext.Provider
import java.net.URI

@Provider
@Priority(Priorities.USER)
class JsonBindingProblemResponseFilter : ContainerResponseFilter {
    override fun filter(
        requestContext: ContainerRequestContext,
        responseContext: ContainerResponseContext,
    ) {
        if (
            responseContext.status != Response.Status.BAD_REQUEST.statusCode ||
                responseContext.entity != null ||
                requestContext.mediaType?.isCompatible(MediaType.APPLICATION_JSON_TYPE) != true
        ) {
            return
        }

        responseContext.entity =
            ProblemDetails(
                type = URI.create("about:blank"),
                title = Response.Status.BAD_REQUEST.reasonPhrase,
                status = Response.Status.BAD_REQUEST.statusCode,
                detail = "The request is invalid.",
                instance = URI.create(requestContext.uriInfo.requestUri.rawPath ?: "/"),
                requestId =
                    RequestIdResolver.resolve(requestContext.getHeaderString("X-Request-ID")),
                error = "invalid_request",
            )
        responseContext.headers.putSingle(
            HttpHeaders.CONTENT_TYPE,
            MediaType.valueOf("application/problem+json"),
        )
    }
}
