package gg.grounds.permissions.auth

import com.fasterxml.jackson.databind.ObjectMapper
import gg.grounds.permissions.rest.ProblemDetails
import gg.grounds.permissions.rest.RequestIdResolver
import io.netty.handler.codec.http.HttpHeaderNames
import io.quarkus.security.AuthenticationCompletionException
import io.quarkus.security.identity.IdentityProviderManager
import io.quarkus.security.identity.SecurityIdentity
import io.quarkus.security.runtime.QuarkusSecurityIdentity
import io.quarkus.vertx.http.runtime.security.ChallengeData
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport
import io.smallrye.mutiny.Uni
import io.smallrye.mutiny.infrastructure.Infrastructure
import io.vertx.core.http.HttpHeaders
import io.vertx.ext.web.RoutingContext
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.net.URI
import java.security.Principal

@ApplicationScoped
class RuntimeBearerAuthenticationMechanism
@Inject
constructor(
    private val authorizer: RuntimeAccessAuthorizer,
    private val objectMapper: ObjectMapper,
) : HttpAuthenticationMechanism {
    internal constructor(authorizer: RuntimeAccessAuthorizer) : this(authorizer, ObjectMapper())

    override fun authenticate(
        context: RoutingContext,
        identityProviderManager: IdentityProviderManager,
    ): Uni<SecurityIdentity> {
        val path = context.request().path() ?: return Uni.createFrom().nullItem()
        if (!isRuntimePath(path)) return Uni.createFrom().nullItem()

        val authorizationHeader = context.request().getHeader(HttpHeaders.AUTHORIZATION)
        val method = context.request().method().name() ?: ""
        return Uni.createFrom()
            .item { authorizer.requireAccess(authorizationHeader, method, path) }
            .map(::securityIdentity)
            .onFailure(RuntimeAccessException::class.java)
            .recoverWithUni { failure ->
                sendFailure(context, path, failure as RuntimeAccessException)
            }
            .runSubscriptionOn(Infrastructure.getDefaultWorkerPool())
    }

    override fun getChallenge(context: RoutingContext): Uni<ChallengeData> =
        Uni.createFrom().item(ChallengeData(401, HttpHeaderNames.WWW_AUTHENTICATE, BEARER_SCHEME))

    override fun getCredentialTransport(context: RoutingContext): Uni<HttpCredentialTransport> =
        Uni.createFrom()
            .item(
                HttpCredentialTransport(HttpCredentialTransport.Type.AUTHORIZATION, BEARER_SCHEME)
            )

    override fun getPriority(): Int = Int.MAX_VALUE

    private fun securityIdentity(identity: RuntimeWorkloadIdentity): SecurityIdentity =
        QuarkusSecurityIdentity.builder().setPrincipal(Principal { identity.username }).build()

    private fun sendFailure(
        context: RoutingContext,
        path: String,
        failure: RuntimeAccessException,
    ): Uni<SecurityIdentity> {
        val problem =
            ProblemDetails(
                type = URI.create("about:blank"),
                title = statusTitle(failure.statusCode),
                status = failure.statusCode,
                detail = failure.publicDetail,
                instance = URI.create(path),
                requestId =
                    RequestIdResolver.resolve(context.request().getHeader(REQUEST_ID_HEADER)),
                error = failure.error,
            )
        context
            .response()
            .setStatusCode(failure.statusCode)
            .putHeader(HttpHeaderNames.CONTENT_TYPE, PROBLEM_JSON)
            .end(objectMapper.writeValueAsString(problem))
        return Uni.createFrom().failure(AuthenticationCompletionException())
    }

    private fun statusTitle(statusCode: Int): String =
        when (statusCode) {
            401 -> "Unauthorized"
            403 -> "Forbidden"
            503 -> "Service Unavailable"
            else -> "Request Failed"
        }

    private fun isRuntimePath(path: String): Boolean =
        path == RUNTIME_ROOT || path.startsWith(RUNTIME_PREFIX)

    private companion object {
        const val BEARER_SCHEME = "Bearer"
        const val PROBLEM_JSON = "application/problem+json"
        const val REQUEST_ID_HEADER = "X-Request-ID"
        const val RUNTIME_ROOT = "/v1/permissions/runtime"
        const val RUNTIME_PREFIX = "$RUNTIME_ROOT/"
    }
}
