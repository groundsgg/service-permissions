package gg.grounds.permissions.architecture

import java.nio.file.Files
import java.nio.file.Path
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class RestOnlyRuntimeGuardTest {
    private val projectRoot = Path.of("").toAbsolutePath()
    @TempDir lateinit var temporaryDirectory: Path

    @Test
    fun `excludes obsolete gRPC runtime sources and configuration`() {
        assertThat(projectRoot.resolve("src/main/proto")).doesNotExist()
        assertThat(restOnlyViolations(projectRoot)).isEmpty()
        assertThat(
                Files.readString(projectRoot.resolve("src/main/resources/application.properties"))
            )
            .contains("quarkus.http.port=8080")
        assertThat(Files.readString(projectRoot.resolve("Dockerfile"))).contains("EXPOSE 8080")
    }

    @Test
    fun `detects obsolete Java references and accepts clean source trees`() {
        val temporaryProjectRoot = temporaryDirectory.resolve("project")
        val javaSource = temporaryProjectRoot.resolve("src/main/java/LegacyGrpcFixture.java")
        Files.createDirectories(javaSource.parent)
        Files.writeString(javaSource, "// quarkus-grpc")

        assertThat(restOnlyViolations(temporaryProjectRoot))
            .contains("src/main/java/LegacyGrpcFixture.java: quarkus-grpc")

        Files.delete(javaSource)

        assertThat(restOnlyViolations(temporaryProjectRoot)).isEmpty()
    }

    private fun restOnlyViolations(root: Path): List<String> =
        activePaths(root).flatMap(::regularFiles).flatMap { path ->
            val contents = Files.readString(path)
            prohibitedReferences().filter(contents::contains).map { reference ->
                "${root.relativize(path)}: $reference"
            }
        }

    private fun activePaths(root: Path) =
        listOf(
            root.resolve("build.gradle.kts"),
            root.resolve("settings.gradle.kts"),
            root.resolve("Dockerfile"),
            root.resolve("src/main/kotlin"),
            root.resolve("src/main/java"),
            root.resolve("src/main/resources"),
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
