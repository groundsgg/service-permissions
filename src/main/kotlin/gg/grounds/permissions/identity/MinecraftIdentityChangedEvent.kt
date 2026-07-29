package gg.grounds.permissions.identity

data class MinecraftIdentityChangedEvent(
    val realmId: String,
    val realmName: String? = null,
    val keycloakUserId: String,
    val reason: String,
)
