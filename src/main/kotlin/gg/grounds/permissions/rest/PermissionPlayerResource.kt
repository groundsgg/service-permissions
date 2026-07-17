package gg.grounds.permissions.rest

import gg.grounds.permissions.api.PermissionPolicyRequest
import gg.grounds.permissions.auth.AdminAuthorizationService
import gg.grounds.permissions.domain.EffectivePermissionSnapshot
import gg.grounds.permissions.domain.PermissionGrant
import gg.grounds.permissions.domain.PermissionGrantOriginKind
import gg.grounds.permissions.identity.IdentitySyncReadinessCheck
import gg.grounds.permissions.persistence.PermissionRepository
import gg.grounds.permissions.persistence.PlayerGrantRecord
import gg.grounds.permissions.persistence.PlayerIdentityRepository
import gg.grounds.permissions.persistence.PlayerRoleGrantRecord
import gg.grounds.permissions.policy.PermissionCheckScope
import gg.grounds.permissions.policy.PolicyEngine
import io.quarkus.security.Authenticated
import io.quarkus.security.identity.SecurityIdentity
import jakarta.inject.Inject
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.DefaultValue
import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.PUT
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import java.time.Duration
import java.time.Instant
import java.util.UUID
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.eclipse.microprofile.health.Readiness

@Path("/v1/permissions/players/{playerId}")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
class PermissionPlayerResource
@Inject
constructor(
    private val repository: PermissionRepository,
    private val identityRepository: PlayerIdentityRepository,
    @param:Readiness private val readinessCheck: IdentitySyncReadinessCheck,
    @param:ConfigProperty(name = "permissions.identity-sync.max-staleness")
    private val identityMaxStaleness: Duration,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {

    @GET
    @Path("/roles")
    fun listPlayerRoles(
        @PathParam("playerId") playerId: String,
        @Context headers: HttpHeaders,
    ): List<PlayerRoleGrantResponse> {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        return repository.listPlayerRoleGrantRecords(id).map { it.toResponse() }
    }

    @GET
    @Path("/roles/search")
    fun searchPlayerRoles(
        @PathParam("playerId") playerId: String,
        @QueryParam("query") query: String?,
        @QueryParam("page") @DefaultValue("1") page: Int,
        @QueryParam("perPage") @DefaultValue("20") perPage: Int,
        @QueryParam("sortBy") sortBy: String?,
        @QueryParam("sortDirection") sortDirection: String?,
        @Context headers: HttpHeaders,
    ): PagedResponse<PlayerEffectiveRoleResponse> {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val search =
            PermissionSearchPaging.validate(
                query = query,
                page = page,
                perPage = perPage,
                sortBy = sortBy,
                sortDirection = sortDirection,
                defaultSortBy = "role",
                allowedSortKeys = listOf("role", "source", "expiration"),
            )
        val rows =
            playerRoleRows(id).filter { it.matches(search.query) }.sortedWith(search.comparator())
        return rows.toPagedResponse(search)
    }

    @POST
    @Path("/roles")
    fun createPlayerRole(
        @PathParam("playerId") playerId: String,
        request: PlayerRoleGrantRequest,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val grant =
            PlayerRoleGrantRecord(
                id = UUID.randomUUID(),
                playerId = id,
                roleKey = PermissionValidation.roleKey(request.roleKey),
                expiresAt = request.expiresAt,
            )
        return Response.status(Response.Status.CREATED)
            .entity(repository.createPlayerRoleGrant(grant).toResponse())
            .build()
    }

    @PUT
    @Path("/roles/{grantId}")
    fun updatePlayerRole(
        @PathParam("playerId") playerId: String,
        @PathParam("grantId") grantId: String,
        request: PlayerRoleGrantRequest,
        @Context headers: HttpHeaders,
    ): PlayerRoleGrantResponse {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val parsedGrantId = PermissionValidation.uuid(grantId, "grantId")
        val grant =
            PlayerRoleGrantRecord(
                id = parsedGrantId,
                playerId = id,
                roleKey = PermissionValidation.roleKey(request.roleKey),
                expiresAt = request.expiresAt,
            )
        return repository.updatePlayerRoleGrant(id, parsedGrantId, grant).toResponse()
    }

    @DELETE
    @Path("/roles/{grantId}")
    fun deletePlayerRole(
        @PathParam("playerId") playerId: String,
        @PathParam("grantId") grantId: String,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        repository.deletePlayerRoleGrant(
            playerId = PermissionValidation.uuid(playerId, "playerId"),
            grantId = PermissionValidation.uuid(grantId, "grantId"),
        )
        return Response.noContent().build()
    }

    @GET
    @Path("/grants")
    fun listPlayerGrants(
        @PathParam("playerId") playerId: String,
        @Context headers: HttpHeaders,
    ): List<PlayerGrantResponse> {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        return repository.listPlayerGrantRecords(id).map { it.toResponse() }
    }

    @GET
    @Path("/grants/search")
    fun searchPlayerGrants(
        @PathParam("playerId") playerId: String,
        @QueryParam("query") query: String?,
        @QueryParam("page") @DefaultValue("1") page: Int,
        @QueryParam("perPage") @DefaultValue("20") perPage: Int,
        @QueryParam("sortBy") sortBy: String?,
        @QueryParam("sortDirection") sortDirection: String?,
        @Context headers: HttpHeaders,
    ): PagedResponse<PlayerGrantResponse> {
        requireAdmin(headers)
        val search =
            PermissionSearchPaging.validate(
                query = query,
                page = page,
                perPage = perPage,
                sortBy = sortBy,
                sortDirection = sortDirection,
                defaultSortBy = "permission",
                allowedSortKeys = listOf("permission", "effect", "scope", "expiration"),
            )
        val result =
            repository.searchPlayerGrantRecords(
                playerId = PermissionValidation.uuid(playerId, "playerId"),
                query = search.query,
                page = search.page,
                perPage = search.perPage,
                sortBy = search.sortBy,
                sortDirection = search.sortDirection,
            )
        return PagedResponse(
            result.items.map { it.toResponse() },
            search.page,
            search.perPage,
            result.total,
        )
    }

    @POST
    @Path("/grants")
    fun createPlayerGrant(
        @PathParam("playerId") playerId: String,
        request: GrantRequest,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val grant = request.toPlayerGrantRecord(playerId = id, grantId = UUID.randomUUID())
        return Response.status(Response.Status.CREATED)
            .entity(repository.createPlayerGrant(grant).toResponse())
            .build()
    }

    @PUT
    @Path("/grants/{grantId}")
    fun updatePlayerGrant(
        @PathParam("playerId") playerId: String,
        @PathParam("grantId") grantId: String,
        request: GrantRequest,
        @Context headers: HttpHeaders,
    ): PlayerGrantResponse {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val parsedGrantId = PermissionValidation.uuid(grantId, "grantId")
        return repository
            .updatePlayerGrant(id, parsedGrantId, request.toPlayerGrantRecord(id, parsedGrantId))
            .toResponse()
    }

    @DELETE
    @Path("/grants/{grantId}")
    fun deletePlayerGrant(
        @PathParam("playerId") playerId: String,
        @PathParam("grantId") grantId: String,
        @Context headers: HttpHeaders,
    ): Response {
        requireAdmin(headers)
        repository.deletePlayerGrant(
            playerId = PermissionValidation.uuid(playerId, "playerId"),
            grantId = PermissionValidation.uuid(grantId, "grantId"),
        )
        return Response.noContent().build()
    }

    @GET
    @Path("/effective")
    fun effectivePermissions(
        @PathParam("playerId") playerId: String,
        @QueryParam("serverType") serverType: String?,
        @QueryParam("serverId") serverId: String?,
        @Context headers: HttpHeaders,
    ): EffectivePermissionResponse {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val snapshot = snapshotFor(id, serverType, serverId)
        return EffectivePermissionResponse(
            playerId = snapshot.playerId,
            policyVersion = snapshot.policyVersion,
            roleKeys = snapshot.roleKeys,
            allowPatterns = snapshot.allowPatterns.map { it.toResponse() },
            denyPatterns = snapshot.denyPatterns.map { it.toResponse() },
            roleAssignments =
                snapshot.roleAssignments.map { assignment ->
                    EffectiveRoleAssignmentResponse(
                        roleKey = assignment.roleKey,
                        source = assignment.origin.kind,
                        grantId = assignment.origin.grantId,
                        mappingId = assignment.origin.mappingId,
                        inheritedPath = assignment.origin.inheritedPath,
                        editable =
                            assignment.origin.kind == PermissionGrantOriginKind.DIRECT_ROLE &&
                                assignment.origin.inheritedPath.isEmpty(),
                    )
                },
            refreshAfter = snapshot.refreshAfter,
            expiresAt = snapshot.expiresAt,
        )
    }

    @GET
    @Path("/effective/search")
    fun searchEffectivePermissions(
        @PathParam("playerId") playerId: String,
        @QueryParam("query") query: String?,
        @QueryParam("effect") effect: String?,
        @QueryParam("page") @DefaultValue("1") page: Int,
        @QueryParam("perPage") @DefaultValue("20") perPage: Int,
        @QueryParam("sortBy") sortBy: String?,
        @QueryParam("sortDirection") sortDirection: String?,
        @QueryParam("serverType") serverType: String?,
        @QueryParam("serverId") serverId: String?,
        @Context headers: HttpHeaders,
    ): PagedResponse<EffectiveGrantResponse> {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val search =
            PermissionSearchPaging.validate(
                query = query,
                page = page,
                perPage = perPage,
                sortBy = sortBy,
                sortDirection = sortDirection,
                defaultSortBy = "permission",
                allowedSortKeys = listOf("permission", "effect", "scope", "source", "expiration"),
            )
        val requestedEffect = effect?.trim()?.uppercase()?.takeIf { it.isNotEmpty() } ?: "ALL"
        require(requestedEffect in setOf("ALL", "ALLOW", "DENY")) {
            "effect must be one of: ALL, ALLOW, DENY"
        }
        val snapshot = snapshotFor(id, serverType, serverId)
        val rows =
            (snapshot.allowPatterns + snapshot.denyPatterns)
                .map { it.toResponse() }
                .filter { requestedEffect == "ALL" || it.effect.name == requestedEffect }
                .filter { it.matches(search.query) }
                .sortedWith(search.effectiveComparator())
        return rows.toPagedResponse(search)
    }

    @GET
    @Path("/identity")
    fun identity(
        @PathParam("playerId") playerId: String,
        @Context headers: HttpHeaders,
    ): PlayerIdentityResponse {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val projectedIdentity = identityRepository.findByPlayerId(id)
        val fresh =
            projectedIdentity?.syncedAt?.isBefore(Instant.now().minus(identityMaxStaleness)) ==
                false
        val evaluationSafe =
            !repository.requiresIdentityProjection() || readinessCheck.isIdentityPolicyAvailable()
        return PlayerIdentityResponse(
            playerId = id,
            name = projectedIdentity?.minecraftUsername,
            linked = projectedIdentity != null,
            syncedAt = projectedIdentity?.syncedAt,
            sourceUpdatedAt = projectedIdentity?.sourceUpdatedAt,
            fresh = fresh,
            evaluationSafe = evaluationSafe,
        )
    }

    @GET
    @Path("/check")
    fun checkPermission(
        @PathParam("playerId") playerId: String,
        @QueryParam("permission") permission: String?,
        @QueryParam("serverType") serverType: String?,
        @QueryParam("serverId") serverId: String?,
        @Context headers: HttpHeaders,
    ): PermissionCheckResponse {
        requireAdmin(headers)
        val id = PermissionValidation.uuid(playerId, "playerId")
        val normalizedPermission = PermissionValidation.permissionKey(permission)
        val snapshot = snapshotFor(id, serverType, serverId)
        val decision =
            PolicyEngine.checkPermission(
                snapshot = snapshot,
                permission = normalizedPermission,
                scope = checkScope(serverType, serverId),
            )
        return PermissionCheckResponse(
            playerId = id,
            permission = normalizedPermission,
            allowed = decision.allowed,
            winningGrant = decision.winningGrant?.toResponse(),
        )
    }

    private fun snapshotFor(
        playerId: UUID,
        serverType: String?,
        serverId: String?,
    ): EffectivePermissionSnapshot {
        val input =
            repository.policyFor(
                PermissionPolicyRequest(
                    playerId = playerId,
                    serverType = serverType?.trim().orEmpty(),
                    serverId = serverId?.trim().orEmpty(),
                )
            )
        return PolicyEngine.createSnapshot(playerId = playerId, input = input)
    }

    private fun checkScope(serverType: String?, serverId: String?): PermissionCheckScope {
        val normalizedServerType = serverType?.trim()?.takeIf(String::isNotEmpty)
        val normalizedServerId = serverId?.trim()?.takeIf(String::isNotEmpty)
        return when {
            normalizedServerId != null && normalizedServerType != null ->
                PermissionCheckScope.server(normalizedServerId, normalizedServerType)
            normalizedServerId != null -> PermissionCheckScope.serverOnly(normalizedServerId)
            normalizedServerType != null -> PermissionCheckScope.serverType(normalizedServerType)
            else -> PermissionCheckScope.global()
        }
    }

    private fun PermissionGrant.toResponse(): EffectiveGrantResponse =
        scope.toGrantResponse(effect, pattern, expiresAt, origin)

    private fun playerRoleRows(playerId: UUID): List<PlayerEffectiveRoleResponse> {
        val directGrants = repository.listPlayerRoleGrantRecords(playerId)
        val directGrantsById = directGrants.associateBy { it.id }
        val mappingExpirations =
            repository.listKeycloakGroupMappings().associateBy({ it.id }, { it.expiresAt })
        val roles = repository.listRoles().associateBy { it.key }
        val snapshot = snapshotFor(playerId, null, null)
        val directRows =
            directGrants.map { grant ->
                PlayerEffectiveRoleResponse(
                    id = grant.id.toString(),
                    roleKey = grant.roleKey,
                    roleName = roles[grant.roleKey]?.name ?: grant.roleKey,
                    source = PermissionGrantOriginKind.DIRECT_ROLE,
                    expiresAt = grant.expiresAt,
                    editable = true,
                    directGrant = grant.toResponse(),
                    inherited = false,
                    assignments =
                        snapshot.roleAssignments
                            .filter {
                                it.roleKey == grant.roleKey &&
                                    it.origin.kind == PermissionGrantOriginKind.DIRECT_ROLE &&
                                    it.origin.grantId == grant.id &&
                                    it.origin.inheritedPath.isEmpty()
                            }
                            .map { it.toResponse() },
                )
            }
        val derivedRows =
            snapshot.roleAssignments
                .filterNot { assignment ->
                    assignment.origin.kind == PermissionGrantOriginKind.DIRECT_ROLE &&
                        assignment.origin.inheritedPath.isEmpty() &&
                        assignment.origin.grantId?.let { grantId ->
                            directGrantsById[grantId]?.roleKey == assignment.roleKey
                        } == true
                }
                .groupBy {
                    listOf(
                        it.roleKey,
                        it.origin.kind.name,
                        it.origin.grantId?.toString().orEmpty(),
                        it.origin.mappingId?.toString().orEmpty(),
                    )
                }
                .map { (_, assignments) ->
                    val first = assignments.first()
                    PlayerEffectiveRoleResponse(
                        id =
                            listOf(
                                    first.roleKey,
                                    first.origin.kind.name,
                                    first.origin.grantId?.toString().orEmpty(),
                                    first.origin.mappingId?.toString().orEmpty(),
                                )
                                .joinToString(":"),
                        roleKey = first.roleKey,
                        roleName = roles[first.roleKey]?.name ?: first.roleKey,
                        source = first.origin.kind,
                        expiresAt =
                            first.origin.grantId?.let { directGrantsById[it]?.expiresAt }
                                ?: first.origin.mappingId?.let { mappingExpirations[it] },
                        editable = false,
                        directGrant = null,
                        inherited = assignments.any { it.origin.inheritedPath.isNotEmpty() },
                        assignments = assignments.map { it.toResponse() },
                    )
                }
        return directRows + derivedRows
    }

    private fun gg.grounds.permissions.domain.EffectiveRoleAssignment.toResponse() =
        EffectiveRoleAssignmentResponse(
            roleKey = roleKey,
            source = origin.kind,
            grantId = origin.grantId,
            mappingId = origin.mappingId,
            inheritedPath = origin.inheritedPath,
            editable =
                origin.kind == PermissionGrantOriginKind.DIRECT_ROLE &&
                    origin.inheritedPath.isEmpty(),
        )

    private fun PlayerEffectiveRoleResponse.matches(query: String): Boolean =
        query.isEmpty() ||
            listOf(roleName, roleKey, source.name).any { it.contains(query, ignoreCase = true) }

    private fun EffectiveGrantResponse.matches(query: String): Boolean =
        query.isEmpty() ||
            listOf(
                    permissionPattern,
                    source.name,
                    roleKey.orEmpty(),
                    scopeKind.name,
                    scopeValue.orEmpty(),
                )
                .any { it.contains(query, ignoreCase = true) }

    private fun PermissionSearchParameters.comparator(): Comparator<PlayerEffectiveRoleResponse> =
        Comparator { left, right ->
            val direction = if (sortDirection == "asc") 1 else -1
            val result =
                when (sortBy) {
                    "role" -> left.roleName.compareTo(right.roleName, ignoreCase = true) * direction
                    "source" -> left.source.name.compareTo(right.source.name) * direction
                    "expiration" -> compareNullable(left.expiresAt, right.expiresAt, direction)
                    else -> error("Unsupported sort key (sortBy=$sortBy)")
                }
            if (result != 0) result else left.id.compareTo(right.id)
        }

    private fun PermissionSearchParameters.effectiveComparator():
        Comparator<EffectiveGrantResponse> = Comparator { left, right ->
        val direction = if (sortDirection == "asc") 1 else -1
        val result =
            when (sortBy) {
                "permission" ->
                    left.permissionPattern.compareTo(right.permissionPattern, true) * direction
                "effect" -> left.effect.name.compareTo(right.effect.name) * direction
                "scope" -> {
                    val kindResult = left.scopeKind.name.compareTo(right.scopeKind.name)
                    if (kindResult != 0) {
                        kindResult * direction
                    } else {
                        compareNullable(left.scopeValue, right.scopeValue, direction)
                    }
                }
                "source" -> left.source.name.compareTo(right.source.name) * direction
                "expiration" -> compareNullable(left.expiresAt, right.expiresAt, direction)
                else -> error("Unsupported sort key (sortBy=$sortBy)")
            }
        if (result != 0) result else left.identity().compareTo(right.identity())
    }

    private fun <T : Comparable<T>> compareNullable(left: T?, right: T?, direction: Int): Int =
        when {
            left == null && right == null -> 0
            left == null -> 1
            right == null -> -1
            else -> left.compareTo(right) * direction
        }

    private fun EffectiveGrantResponse.identity(): String =
        listOf(
                source.name,
                grantId?.toString().orEmpty(),
                roleKey.orEmpty(),
                mappingId?.toString().orEmpty(),
                inheritedPath.joinToString("/"),
                permissionPattern,
                effect.name,
                scopeKind.name,
                scopeValue.orEmpty(),
                expiresAt?.toString().orEmpty(),
            )
            .joinToString(":")

    private fun <T> List<T>.toPagedResponse(search: PermissionSearchParameters): PagedResponse<T> {
        val offset = (search.page - 1L) * search.perPage
        return PagedResponse(
            items =
                if (offset >= size.toLong()) {
                    emptyList()
                } else {
                    drop(offset.toInt()).take(search.perPage)
                },
            page = search.page,
            perPage = search.perPage,
            total = size.toLong(),
        )
    }

    private fun requireAdmin(headers: HttpHeaders): String =
        authorization.requireMinecraftPermissionsAdmin(identity, headers)

    private fun GrantRequest.toPlayerGrantRecord(playerId: UUID, grantId: UUID): PlayerGrantRecord =
        PlayerGrantRecord(
            id = grantId,
            playerId = playerId,
            effect = requireNotNull(effect) { "effect must not be null" },
            pattern = PermissionValidation.permissionPattern(permissionPattern),
            scope = PermissionValidation.scope(scopeKind, scopeValue),
            expiresAt = expiresAt,
        )
}

fun PlayerRoleGrantRecord.toResponse(): PlayerRoleGrantResponse =
    PlayerRoleGrantResponse(id = id, playerId = playerId, roleKey = roleKey, expiresAt = expiresAt)

fun PlayerGrantRecord.toResponse(): PlayerGrantResponse =
    PlayerGrantResponse(
        id = id,
        playerId = playerId,
        effect = effect,
        permissionPattern = pattern,
        scopeKind = scope.kind,
        scopeValue = scope.value,
        expiresAt = expiresAt,
    )
