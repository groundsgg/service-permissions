package gg.grounds.permissions.auth

enum class PermissionInstanceEnvironment(val configValue: String) {
    STAGE("stage"),
    PRODUCTION("prod");

    companion object {
        fun fromConfig(value: String?): PermissionInstanceEnvironment? {
            val configValue = value?.trim().orEmpty()
            if (configValue.isEmpty()) return null

            return entries.singleOrNull { it.configValue == configValue }
                ?: throw IllegalArgumentException("Invalid PERMISSIONS_INSTANCE_ENVIRONMENT value")
        }
    }
}
