package gg.grounds.permissions.architecture

import java.nio.file.Files
import java.nio.file.Path
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class RestOnlyRuntimeGuardTest {
    private val projectRoot = Path.of("").toAbsolutePath()

    @Test
    fun `excludes obsolete gRPC runtime sources and configuration`() {
        val activePaths =
            listOf(
                projectRoot.resolve("build.gradle.kts"),
                projectRoot.resolve("settings.gradle.kts"),
                projectRoot.resolve("Dockerfile"),
                projectRoot.resolve("src/main/kotlin"),
                projectRoot.resolve("src/main/java"),
                projectRoot.resolve("src/main/resources"),
            )
        val prohibitedReferences =
            listOf(
                "quarkus-grpc",
                "protobuf-kotlin",
                "src/main/proto",
                "PermissionSnapshotGrpcService",
                "PermissionCatalogGrpcService",
                "9000",
            )

        val matches =
            activePaths.flatMap(::regularFiles).flatMap { path ->
                val contents = Files.readString(path)
                prohibitedReferences.filter(contents::contains).map { reference ->
                    "${projectRoot.relativize(path)}: $reference"
                }
            }

        assertThat(projectRoot.resolve("src/main/proto")).doesNotExist()
        assertThat(matches).isEmpty()
        assertThat(
                Files.readString(projectRoot.resolve("src/main/resources/application.properties"))
            )
            .contains("quarkus.http.port=8080")
        assertThat(Files.readString(projectRoot.resolve("Dockerfile"))).contains("EXPOSE 8080")
    }

    @Test
    fun `detects obsolete runtime references in Java sources`() {
        val javaSource = projectRoot.resolve("src/main/java/LegacyGrpcFixture.java")
        Files.createDirectories(javaSource.parent)
        Files.writeString(javaSource, "// quarkus-grpc")

        try {
            val matches =
                activePaths().flatMap(::regularFiles).flatMap { path ->
                    val contents = Files.readString(path)
                    prohibitedReferences().filter(contents::contains).map { reference ->
                        "${projectRoot.relativize(path)}: $reference"
                    }
                }

            assertThat(matches).contains("src/main/java/LegacyGrpcFixture.java: quarkus-grpc")
        } finally {
            Files.deleteIfExists(javaSource)
            Files.deleteIfExists(javaSource.parent)
        }
    }

    private fun activePaths() =
        listOf(
            projectRoot.resolve("build.gradle.kts"),
            projectRoot.resolve("settings.gradle.kts"),
            projectRoot.resolve("Dockerfile"),
            projectRoot.resolve("src/main/kotlin"),
            projectRoot.resolve("src/main/java"),
            projectRoot.resolve("src/main/resources"),
        )

    private fun prohibitedReferences() =
        listOf(
            "quarkus-grpc",
            "protobuf-kotlin",
            "src/main/proto",
            "PermissionSnapshotGrpcService",
            "PermissionCatalogGrpcService",
            "9000",
        )

    private fun regularFiles(path: Path): List<Path> {
        if (!Files.exists(path)) return emptyList()
        if (Files.isRegularFile(path)) return listOf(path)
        return Files.walk(path).use { paths -> paths.filter(Files::isRegularFile).toList() }
    }
}
