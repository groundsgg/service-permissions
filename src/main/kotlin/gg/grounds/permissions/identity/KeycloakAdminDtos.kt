package gg.grounds.permissions.identity

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty

@JsonIgnoreProperties(ignoreUnknown = true)
data class KeycloakAccessTokenResponse(
    @field:JsonProperty("access_token") val accessToken: String,
    @field:JsonProperty("expires_in") val expiresIn: Long,
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class KeycloakUserRepresentation(
    val id: String,
    val attributes: Map<String, List<String>> = emptyMap(),
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class KeycloakGroupRepresentation(val id: String, val path: String)

class KeycloakReadException(message: String) : RuntimeException(message)

class KeycloakAdminException(val statusCode: Int?) :
    RuntimeException("Keycloak admin request failed")
