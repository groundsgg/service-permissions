package gg.grounds.permissions.openapi

import jakarta.ws.rs.ApplicationPath
import jakarta.ws.rs.core.Application
import org.eclipse.microprofile.openapi.annotations.OpenAPIDefinition
import org.eclipse.microprofile.openapi.annotations.enums.SecuritySchemeType
import org.eclipse.microprofile.openapi.annotations.info.Info
import org.eclipse.microprofile.openapi.annotations.security.SecurityScheme

@ApplicationPath("/")
@OpenAPIDefinition(
    info =
        Info(
            title = "Permissions API",
            version = "1.0.0",
            description =
                "Internal REST API for permissions administration and workload evaluation.",
        )
)
@SecurityScheme(
    securitySchemeName = "portalBearer",
    type = SecuritySchemeType.HTTP,
    scheme = "bearer",
    bearerFormat = "JWT",
    description = "Portal administrator JWT.",
)
@SecurityScheme(
    securitySchemeName = "workloadBearer",
    type = SecuritySchemeType.HTTP,
    scheme = "bearer",
    bearerFormat = "JWT",
    description = "Workload JWT for service-to-service requests.",
)
class OpenApiConfiguration : Application()
