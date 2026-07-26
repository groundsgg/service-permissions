package gg.grounds.permissions.openapi

import java.nio.file.Files
import java.nio.file.Path
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class OpenApiWorkflowContractTest {
    private val workflowPath = Path.of(".github/workflows/openapi.yml")

    @Test
    fun `publishes only stable releases or explicit manual dispatches`() {
        assertThat(workflowPath).exists()
        val workflow = Files.readString(workflowPath)

        assertThat(workflow).contains("release:", "types: [published]", "workflow_dispatch:")
        assertThat(workflow).contains("permissions:", "actions: read", "contents: read")
        assertThat(workflow)
            .contains(
                "github.event_name == 'workflow_dispatch' || " +
                    "github.event.release.prerelease == false"
            )
        assertThat(workflow).doesNotContain("pull_request:")
    }

    @Test
    fun `exports exactly one validated snapshot artifact with Java 25`() {
        assertThat(workflowPath).exists()
        val workflow = Files.readString(workflowPath)

        assertThat(workflow).contains("runs-on: arc-dind")
        assertThat(workflow).contains("actions/checkout@v7")
        assertThat(workflow).contains("actions/setup-java@v5", "java-version: \"25\"")
        assertThat(workflow).contains("gradle/actions/setup-gradle@v6")
        assertThat(workflow)
            .contains(
                "name: Validate service",
                "run: ./gradlew spotlessCheck test",
                "name: Generate OpenAPI snapshot",
                "run: ./gradlew generateOpenApiSnapshot",
            )
        assertThat(workflow).doesNotContain("spotlessCheck test generateOpenApiSnapshot")
        assertThat(workflow).contains("actions/upload-artifact@v7")
        assertThat(workflow)
            .contains(
                "name: openapi-snapshot",
                "path: build/api-reference/openapi.json",
                "if-no-files-found: error",
                "retention-days: 1",
            )
        assertThat(Regex("(?m)^\\s+name: openapi-snapshot$").findAll(workflow).count()).isEqualTo(1)
    }

    @Test
    fun `hands the artifact to the permissions API central publisher`() {
        assertThat(workflowPath).exists()
        val workflow = Files.readString(workflowPath)

        assertThat(workflow)
            .contains(
                "needs: export-openapi",
                "uses: groundsgg/.github/.github/workflows/publish-openapi-snapshot.yml@main",
                "artifact_name: openapi-snapshot",
                "service_id: service-permissions",
                "service_title: Permissions API",
                "service_slug: permissions",
                "source_ref: \${{ github.event_name == 'release' && " +
                    "github.event.release.tag_name || github.ref_name }}",
                "source_sha: \${{ github.sha }}",
                "app_private_key: \${{ secrets.OPENAPI_PUBLISHER_PRIVATE_KEY }}",
            )
        assertThat(workflow)
            .doesNotContain("gh pr create", "git push", "repository: groundsgg/api-reference")
    }
}
