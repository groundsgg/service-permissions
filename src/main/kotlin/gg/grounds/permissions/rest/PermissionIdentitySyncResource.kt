package gg.grounds.permissions.rest

import gg.grounds.permissions.auth.AdminAuthorizationService
import gg.grounds.permissions.identity.IdentitySyncCoordinator
import gg.grounds.permissions.identity.IdentitySyncReadinessCheck
import gg.grounds.permissions.persistence.PlayerIdentityRepository
import io.quarkus.security.Authenticated
import io.quarkus.security.identity.SecurityIdentity
import jakarta.annotation.PreDestroy
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.ws.rs.GET
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import org.eclipse.microprofile.health.Readiness

@Path("/v1/permissions/identity-sync")
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
class PermissionIdentitySyncResource
@Inject
constructor(
    private val identityRepository: PlayerIdentityRepository,
    @param:Readiness private val readinessCheck: IdentitySyncReadinessCheck,
    private val dispatcher: IdentitySyncDispatcher,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {
    @GET
    @Path("/status")
    fun status(@Context headers: HttpHeaders): IdentitySyncStatusResponse {
        authorization.requireMinecraftPermissionsAdmin(identity, headers)
        val state = identityRepository.currentSyncState()
        return IdentitySyncStatusResponse(
            status = state.status.name,
            startedAt = state.startedAt,
            completedAt = state.completedAt,
            lastSuccessAt = state.lastSuccessAt,
            durationMs = state.durationMs,
            playerCount = state.playerCount,
            failureReason = state.failureReason,
            stale = !readinessCheck.isIdentityPolicyAvailable(),
        )
    }

    @POST
    fun synchronize(@Context headers: HttpHeaders): Response {
        authorization.requireMinecraftPermissionsAdmin(identity, headers)
        dispatcher.dispatchAll()
        return Response.accepted(SyncDispatchResponse("RUNNING")).build()
    }
}

@Path("/v1/permissions/players/{playerId}/identity-sync")
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
class PermissionPlayerIdentitySyncResource
@Inject
constructor(
    private val identityRepository: PlayerIdentityRepository,
    private val dispatcher: IdentitySyncDispatcher,
    private val authorization: AdminAuthorizationService,
    private val identity: SecurityIdentity,
) {
    @POST
    fun synchronizePlayer(
        @PathParam("playerId") playerId: String,
        @Context headers: HttpHeaders,
    ): Response {
        authorization.requireMinecraftPermissionsAdmin(identity, headers)
        val parsedPlayerId = PermissionValidation.uuid(playerId, "playerId")
        val projectedIdentity =
            identityRepository.findByPlayerId(parsedPlayerId)
                ?: throw NotFoundException("player_identity_not_linked")
        dispatcher.dispatchPlayer(parsedPlayerId, projectedIdentity.keycloakUserId)
        return Response.accepted(SyncDispatchResponse("RUNNING")).build()
    }
}

data class SyncDispatchResponse(val status: String)

@ApplicationScoped
class IdentitySyncDispatcher @Inject constructor(private val coordinator: IdentitySyncCoordinator) {
    private val executor: ExecutorService = Executors.newVirtualThreadPerTaskExecutor()
    private val fullSyncRunning = AtomicBoolean(false)
    private val runningPlayers = ConcurrentHashMap.newKeySet<UUID>()

    fun dispatchAll(): Boolean {
        if (!fullSyncRunning.compareAndSet(false, true)) {
            return false
        }
        executor.submit {
            try {
                coordinator.synchronizeAll()
            } finally {
                fullSyncRunning.set(false)
            }
        }
        return true
    }

    fun dispatchPlayer(playerId: UUID, keycloakUserId: String): Boolean {
        if (!runningPlayers.add(playerId)) {
            return false
        }
        executor.submit {
            try {
                coordinator.refreshPlayer(keycloakUserId)
            } finally {
                runningPlayers.remove(playerId)
            }
        }
        return true
    }

    @PreDestroy
    fun close() {
        executor.close()
    }
}
