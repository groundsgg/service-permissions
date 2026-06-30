package gg.grounds.permissions.rest

import gg.grounds.permissions.persistence.KeycloakGroupMappingRecord
import gg.grounds.permissions.persistence.PermissionRepository
import jakarta.inject.Inject
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.PUT
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import java.util.UUID

@Path("/v1/permissions/keycloak-groups")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
class PermissionGroupMappingResource
@Inject
constructor(private val repository: PermissionRepository) {

    @GET
    fun listMappings(): List<KeycloakGroupMappingResponse> =
        repository.listKeycloakGroupMappings().map { it.toResponse() }

    @POST
    fun createMapping(request: KeycloakGroupMappingRequest): Response {
        val mapping = request.toRecord(UUID.randomUUID())
        return Response.status(Response.Status.CREATED)
            .entity(repository.createKeycloakGroupMapping(mapping).toResponse())
            .build()
    }

    @PUT
    @Path("/{mappingId}")
    fun updateMapping(
        @PathParam("mappingId") mappingId: String,
        request: KeycloakGroupMappingRequest,
    ): KeycloakGroupMappingResponse {
        val id = PermissionValidation.uuid(mappingId, "mappingId")
        return repository.updateKeycloakGroupMapping(id, request.toRecord(id)).toResponse()
    }

    @DELETE
    @Path("/{mappingId}")
    fun deleteMapping(@PathParam("mappingId") mappingId: String): Response {
        repository.deleteKeycloakGroupMapping(PermissionValidation.uuid(mappingId, "mappingId"))
        return Response.noContent().build()
    }

    private fun KeycloakGroupMappingRequest.toRecord(id: UUID): KeycloakGroupMappingRecord =
        KeycloakGroupMappingRecord(
            id = id,
            keycloakGroup = PermissionValidation.keycloakGroup(keycloakGroup),
            roleKey = PermissionValidation.roleKey(roleKey),
            expiresAt = expiresAt,
        )
}

fun KeycloakGroupMappingRecord.toResponse(): KeycloakGroupMappingResponse =
    KeycloakGroupMappingResponse(
        id = id,
        keycloakGroup = keycloakGroup,
        roleKey = roleKey,
        expiresAt = expiresAt,
    )
