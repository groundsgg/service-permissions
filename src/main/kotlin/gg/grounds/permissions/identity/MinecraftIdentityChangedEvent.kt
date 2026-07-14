package gg.grounds.permissions.identity

data class MinecraftIdentityChangedEvent(
    val realmId: String,
    val keycloakUserId: String,
    val reason: String,
)
