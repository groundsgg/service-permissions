package gg.grounds.permissions.identity

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.GET
import jakarta.ws.rs.HeaderParam
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient
import org.eclipse.microprofile.rest.client.inject.RestClient
import org.jboss.resteasy.reactive.RestForm

@RegisterRestClient(configKey = "keycloak-admin")
interface KeycloakAdminRestClient {
    @POST
    @Path("/realms/{realm}/protocol/openid-connect/token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    fun requestToken(
        @PathParam("realm") realm: String,
        @RestForm("grant_type") grantType: String,
        @RestForm("client_id") clientId: String,
        @RestForm("client_secret") clientSecret: String,
    ): KeycloakAccessTokenResponse

    @GET
    @Path("/admin/realms/{realm}/users")
    @Produces(MediaType.APPLICATION_JSON)
    fun listUsers(
        @HeaderParam(HttpHeaders.AUTHORIZATION) authorization: String,
        @PathParam("realm") realm: String,
        @QueryParam("first") first: Int,
        @QueryParam("max") max: Int,
    ): List<KeycloakUserRepresentation>

    @GET
    @Path("/admin/realms/{realm}/users/{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    fun getUser(
        @HeaderParam(HttpHeaders.AUTHORIZATION) authorization: String,
        @PathParam("realm") realm: String,
        @PathParam("userId") userId: String,
    ): KeycloakUserRepresentation

    @GET
    @Path("/admin/realms/{realm}/users/{userId}/groups")
    @Produces(MediaType.APPLICATION_JSON)
    fun listUserGroups(
        @HeaderParam(HttpHeaders.AUTHORIZATION) authorization: String,
        @PathParam("realm") realm: String,
        @PathParam("userId") userId: String,
        @QueryParam("first") first: Int,
        @QueryParam("max") max: Int,
    ): List<KeycloakGroupRepresentation>
}

interface KeycloakAdminClient {
    fun requestToken(
        realm: String,
        grantType: String,
        clientId: String,
        clientSecret: String,
    ): KeycloakAccessTokenResponse

    fun listUsers(
        authorization: String,
        realm: String,
        first: Int,
        max: Int,
    ): List<KeycloakUserRepresentation>

    fun getUser(authorization: String, realm: String, userId: String): KeycloakUserRepresentation

    fun listUserGroups(
        authorization: String,
        realm: String,
        userId: String,
        first: Int,
        max: Int,
    ): List<KeycloakGroupRepresentation>
}

@ApplicationScoped
class QuarkusKeycloakAdminClient
@Inject
constructor(@param:RestClient private val delegate: KeycloakAdminRestClient) : KeycloakAdminClient {
    override fun requestToken(
        realm: String,
        grantType: String,
        clientId: String,
        clientSecret: String,
    ): KeycloakAccessTokenResponse = read {
        delegate.requestToken(realm, grantType, clientId, clientSecret)
    }

    override fun listUsers(
        authorization: String,
        realm: String,
        first: Int,
        max: Int,
    ): List<KeycloakUserRepresentation> = read {
        delegate.listUsers(authorization, realm, first, max)
    }

    override fun getUser(
        authorization: String,
        realm: String,
        userId: String,
    ): KeycloakUserRepresentation = read { delegate.getUser(authorization, realm, userId) }

    override fun listUserGroups(
        authorization: String,
        realm: String,
        userId: String,
        first: Int,
        max: Int,
    ): List<KeycloakGroupRepresentation> = read {
        delegate.listUserGroups(authorization, realm, userId, first, max)
    }

    private fun <T> read(operation: () -> T): T =
        try {
            operation()
        } catch (error: WebApplicationException) {
            throw KeycloakAdminException(error.response.status)
        } catch (_: Exception) {
            throw KeycloakAdminException(null)
        }
}
