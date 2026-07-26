package gg.grounds.permissions.auth

data class RuntimeWorkloadIdentity(
    val username: String,
    val namespace: String,
    val serviceAccount: String,
    val groups: Set<String>,
)
