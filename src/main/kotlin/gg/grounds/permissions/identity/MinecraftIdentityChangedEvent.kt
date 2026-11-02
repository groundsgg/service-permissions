package gg.grounds.permissions.identity

import io.quarkus.runtime.annotations.RegisterForReflection

@RegisterForReflection
data class MinecraftIdentityChangedEvent(
    val realmId: String,
    val realmName: String? = null,
    val keycloakUserId: String,
    val reason: String,
)
