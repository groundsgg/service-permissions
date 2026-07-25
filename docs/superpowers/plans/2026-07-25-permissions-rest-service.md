# Permissions REST Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `service-permissions` gRPC runtime surface with an authenticated REST API and publish a complete, deterministic OpenAPI contract.

**Architecture:** One Quarkus deployment serves the existing Portal administration API and the new `/v1/permissions/runtime/**` API on port `8080`. Portal requests keep JWT-based administration authorization; runtime requests use projected Kubernetes ServiceAccount tokens validated through TokenReview and authorized through SubjectAccessReview. Runtime manifests are replaced atomically in PostgreSQL.

**Tech Stack:** Kotlin, Java 25, repository-pinned Quarkus 3.x, Quarkus REST/Jackson, SmallRye OpenAPI, Fabric8 Kubernetes Client, PostgreSQL, Flyway, Micrometer, JUnit 5, RestAssured, Testcontainers

## Global Constraints

- Work in `groundsgg/service-permissions` on a fresh branch from current `origin/main`.
- Remove gRPC, Protobuf generation, the gRPC runtime port, and `RefreshOnlinePlayers`; do not add a compatibility endpoint.
- Serve all HTTP endpoints on port `8080`.
- Runtime paths are exactly `GET /v1/permissions/runtime/players/{playerId}/snapshot` and `PUT /v1/permissions/runtime/catalog/manifests/{source}`.
- Runtime authentication audience is exactly `service-permissions`.
- TokenReview and SubjectAccessReview failures fail closed; dependency failures return `503`, invalid tokens return `401`, and denied access returns `403`.
- Every REST error uses RFC 9457 `application/problem+json` and includes `requestId` without exposing credentials.
- Keep Portal administration behavior and `AdminAuthorizationService` checks unchanged.
- Preserve policy evaluation, `refreshAfter`, `expiresAt`, role metadata, and allow/deny semantics.
- The complete REST surface must appear in one OpenAPI document tagged `Administration`, `Runtime`, and `Environment sync`.
- Follow the repository logging rules: English outcome messages, relevant context, correct level, and no tokens or personal data.
- Run every Gradle command in this plan with escalated permissions. After Kotlin or Gradle changes, always finish with `./gradlew test`, `./gradlew spotlessApply`, and `./gradlew build`.

---

### Task 1: Establish RFC 9457 and OpenAPI foundations

**Files:**
- Modify: `service-permissions/build.gradle.kts`
- Modify: `service-permissions/src/main/resources/application.properties`
- Create: `service-permissions/src/main/kotlin/gg/grounds/permissions/rest/ProblemDetails.kt`
- Replace: `service-permissions/src/main/kotlin/gg/grounds/permissions/rest/PermissionExceptionMapper.kt`
- Modify: `service-permissions/src/main/kotlin/gg/grounds/permissions/rest/PermissionDtos.kt`
- Create: `service-permissions/src/main/kotlin/gg/grounds/permissions/openapi/OpenApiConfiguration.kt`
- Create: `service-permissions/src/test/kotlin/gg/grounds/permissions/rest/ProblemDetailsTest.kt`

**Interfaces:**
- Produces: `ProblemDetails(type, title, status, detail, instance, requestId)` for every later resource and mapper.
- Produces: OpenAPI security schemes named `portalBearer` and `workloadBearer`.

- [ ] **Step 1: Write failing problem-response tests**

```kotlin
@QuarkusTest
class ProblemDetailsTest {
    @Test
    fun `invalid request uses RFC 9457`() {
        given()
            .header("X-Request-ID", "request-123")
            .contentType(ContentType.JSON)
            .body("""{"name":"!!!"}""")
            .post("/v1/permissions/roles")
            .then()
            .statusCode(400)
            .contentType("application/problem+json")
            .body("status", equalTo(400))
            .body("requestId", equalTo("request-123"))
            .body("error", equalTo("role_name_invalid"))
    }
}
```

- [ ] **Step 2: Run the test and verify the old `ErrorResponse` contract fails**

Run: `./gradlew test --tests '*ProblemDetailsTest'`

Expected: FAIL because the current mapper returns `application/json` with `{ "error": ... }`.

- [ ] **Step 3: Add OpenAPI and Kubernetes client dependencies and remove obsolete DTOs**

Add:

```kotlin
implementation("io.quarkus:quarkus-smallrye-openapi")
implementation("io.quarkus:quarkus-kubernetes-client")
implementation("io.quarkus:quarkus-micrometer-registry-prometheus")
testImplementation("org.assertj:assertj-core:3.27.7")
```

Do not remove gRPC dependencies until Task 6, so the branch stays compilable while runtime resources are replaced.

- [ ] **Step 4: Implement the shared problem document**

```kotlin
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ProblemDetails(
    val type: URI,
    val title: String,
    val status: Int,
    val detail: String,
    val instance: URI,
    val requestId: String,
    val error: String? = null,
    val reason: String? = null,
)
```

Add a request-ID resolver that accepts a safe nonblank `X-Request-ID` or generates a UUID. Mappers must set `Content-Type: application/problem+json` explicitly. Preserve existing documented administration machine codes in the optional `error` extension and the permission-sync conflict value in `reason`, so the Portal's current conflict handling remains compatible while human-readable clients use `detail`.

- [ ] **Step 5: Configure deterministic OpenAPI generation**

Add the same build pattern used by `service-moderation`:

```kotlin
tasks.register<Copy>("generateOpenApiSnapshot") {
    group = "documentation"
    dependsOn(tasks.named("quarkusBuild"))
    from(layout.buildDirectory.file("generated/openapi/openapi.json"))
    into(layout.buildDirectory.dir("api-reference"))
    rename { "openapi.json" }
}
```

Set:

```properties
quarkus.http.port=8080
quarkus.smallrye-openapi.info-title=Permissions API
quarkus.smallrye-openapi.info-version=${quarkus.application.version}
quarkus.smallrye-openapi.store-schema-directory=build/generated/openapi
quarkus.smallrye-openapi.store-schema-file-name=openapi
quarkus.smallrye-openapi.auto-add-security=false
quarkus.swagger-ui.enabled=false
quarkus.swagger-ui.always-include=false
```

- [ ] **Step 6: Run the focused tests**

Run: `./gradlew test --tests '*ProblemDetailsTest' --tests '*PermissionRestResourceTest'`

Expected: PASS with the new media type and unchanged successful admin responses.

- [ ] **Step 7: Commit the foundation**

```bash
git add build.gradle.kts src/main/resources/application.properties src/main/kotlin/gg/grounds/permissions/rest src/main/kotlin/gg/grounds/permissions/openapi src/test/kotlin/gg/grounds/permissions/rest/ProblemDetailsTest.kt
git commit -m "feat(api): establish permissions OpenAPI contract"
```

### Task 2: Make manifest replacement atomic and conflict-safe

**Files:**
- Modify: `service-permissions/src/main/kotlin/gg/grounds/permissions/persistence/PermissionRepository.kt`
- Create: `service-permissions/src/main/kotlin/gg/grounds/permissions/persistence/RuntimeManifestRegistration.kt`
- Create: `service-permissions/src/main/kotlin/gg/grounds/permissions/persistence/CatalogSourceConflictException.kt`
- Modify: `service-permissions/src/main/kotlin/gg/grounds/permissions/rest/PermissionExceptionMapper.kt`
- Modify: `service-permissions/src/test/kotlin/gg/grounds/permissions/persistence/PermissionRepositoryTest.kt`

**Interfaces:**
- Produces:

```kotlin
data class RuntimeManifestRegistration(
    val source: String,
    val sourceVersion: String,
    val serverType: String?,
    val serverId: String?,
    val permissions: List<CatalogEntryRecord>,
    val registeredAt: Instant,
)

fun PermissionRepository.replaceRuntimeManifest(registration: RuntimeManifestRegistration)
```

- [ ] **Step 1: Write failing repository tests**

Cover all three behaviors in `PermissionRepositoryTest`:

```kotlin
@Test
fun `runtime manifest replacement removes stale entries from the same source`() { /* arrange two old keys, replace with one, assert one remains */ }

@Test
fun `runtime manifest replacement rejects a key owned by another source without partial writes`() { /* assert CatalogSourceConflictException and unchanged rows */ }

@Test
fun `repeating the same runtime manifest is idempotent`() { /* call twice and assert one catalog state */ }
```

- [ ] **Step 2: Run the repository tests and verify they fail**

Run: `./gradlew test --tests '*PermissionRepositoryTest'`

Expected: FAIL because no atomic replacement operation exists.

- [ ] **Step 3: Implement one transaction boundary**

Within the existing `write(...)` transaction:

1. Lock or query all submitted keys.
2. Throw `CatalogSourceConflictException(permissionKey, existingSource, requestedSource)` when ownership differs.
3. Upsert every submitted entry with `custom = false`.
4. Delete `custom = false AND source = ? AND permission_key <> ALL (?)` entries absent from the new list.
5. Insert one `permission_runtime_registrations` row.

Do not call the existing public `upsertCatalogEntry` from inside the transaction because it opens a separate transaction.

- [ ] **Step 4: Map ownership conflicts to RFC 9457**

Return `409` with a stable type such as `/problems/catalog-source-conflict`; do not expose SQL or stack details.

- [ ] **Step 5: Run repository and mapper tests**

Run: `./gradlew test --tests '*PermissionRepositoryTest' --tests '*ProblemDetailsTest'`

Expected: PASS; the conflict test confirms no partial writes.

- [ ] **Step 6: Commit atomic persistence**

```bash
git add src/main/kotlin/gg/grounds/permissions/persistence src/main/kotlin/gg/grounds/permissions/rest/PermissionExceptionMapper.kt src/test/kotlin/gg/grounds/permissions/persistence/PermissionRepositoryTest.kt
git commit -m "feat(catalog): replace runtime manifests atomically"
```

### Task 3: Authenticate and authorize Kubernetes workloads

**Files:**
- Create: `service-permissions/src/main/kotlin/gg/grounds/permissions/auth/RuntimeWorkloadIdentity.kt`
- Create: `service-permissions/src/main/kotlin/gg/grounds/permissions/auth/KubernetesWorkloadAccessClient.kt`
- Create: `service-permissions/src/main/kotlin/gg/grounds/permissions/auth/RuntimeAccessAuthorizer.kt`
- Create: `service-permissions/src/main/kotlin/gg/grounds/permissions/auth/RuntimeBearerAuthenticationMechanism.kt`
- Create: `service-permissions/src/test/kotlin/gg/grounds/permissions/auth/RuntimeAccessAuthorizerTest.kt`
- Create: `service-permissions/src/test/kotlin/gg/grounds/permissions/auth/RuntimeBearerAuthenticationTest.kt`
- Modify: `service-permissions/src/main/resources/application.properties`
- Modify: `service-permissions/src/test/resources/application.properties`

**Interfaces:**
- Produces:

```kotlin
data class RuntimeWorkloadIdentity(
    val username: String,
    val namespace: String,
    val serviceAccount: String,
    val groups: Set<String>,
)

interface KubernetesWorkloadAccessClient {
    fun authenticate(token: String, audience: String): RuntimeWorkloadIdentity
    fun isAllowed(identity: RuntimeWorkloadIdentity, verb: String, path: String): Boolean
}

interface RuntimeAccessAuthorizer {
    fun requireAccess(authorizationHeader: String?, verb: String, path: String): RuntimeWorkloadIdentity
}
```

- [ ] **Step 1: Write failing TokenReview and SubjectAccessReview tests**

Use a mocked `KubernetesWorkloadAccessClient` to assert:

- missing bearer token -> `401`
- wrong audience or malformed ServiceAccount username -> `401`
- `isAllowed == false` -> `403`
- Kubernetes client exception during either review -> `503`
- exact path and lowercase verb are passed to authorization
- no token appears in logs or exception messages

- [ ] **Step 2: Run the auth tests and verify they fail**

Run: `./gradlew test --tests '*RuntimeAccessAuthorizerTest' --tests '*RuntimeBearerAuthenticationTest'`

Expected: FAIL because the runtime authentication types do not exist.

- [ ] **Step 3: Implement the Kubernetes adapter**

Use the injected Fabric8 `KubernetesClient` to create `authentication.k8s.io/v1 TokenReview` and `authorization.k8s.io/v1 SubjectAccessReview` objects. TokenReview must send only the configured audience. SubjectAccessReview must forward the reviewed username and groups and use:

```kotlin
NonResourceAttributesBuilder()
    .withVerb(verb.lowercase())
    .withPath(path)
    .build()
```

Reject `evaluationError`, `allowed != true`, missing returned audience, and usernames that do not match `system:serviceaccount:<namespace>:<name>`.

- [ ] **Step 4: Add bounded caches without retaining raw tokens**

Use a dedicated cache class. TokenReview entries are keyed by `HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.toByteArray(UTF_8)))`; SubjectAccessReview entries are keyed by reviewed identity plus lowercase verb and exact path. Positive entries expire after at most 60 seconds; negative entries after at most five seconds or are not cached. Never include either key in log output.

- [ ] **Step 5: Bind authentication only to runtime paths**

Implement a Quarkus `HttpAuthenticationMechanism` that returns no credential for non-runtime paths, parses `Authorization: Bearer`, delegates to `RuntimeAccessAuthorizer`, and creates a `SecurityIdentity` with principal name equal to the reviewed ServiceAccount username. Existing SmallRye JWT handling remains responsible for administration paths.

- [ ] **Step 6: Run auth and existing administration authorization tests**

Run: `./gradlew test --tests '*Runtime*Authentication*' --tests '*RuntimeAccessAuthorizerTest' --tests '*PermissionRestAuthorizationTest'`

Expected: PASS; Keycloak-style tests continue to use the existing administration mechanism. Add explicit cross-type cases: a Portal JWT on a runtime path returns `401`, and a projected ServiceAccount token on an administration path returns `401`.

- [ ] **Step 7: Commit workload authentication**

```bash
git add src/main/kotlin/gg/grounds/permissions/auth src/main/resources/application.properties src/test/kotlin/gg/grounds/permissions/auth src/test/resources/application.properties
git commit -m "feat(auth): authorize permissions runtime workloads"
```

### Task 4: Add the runtime REST resources

**Files:**
- Create: `service-permissions/src/main/kotlin/gg/grounds/permissions/rest/runtime/RuntimePermissionDtos.kt`
- Create: `service-permissions/src/main/kotlin/gg/grounds/permissions/rest/runtime/PermissionRuntimeResource.kt`
- Create: `service-permissions/src/main/kotlin/gg/grounds/permissions/metrics/RuntimePermissionMetrics.kt`
- Modify: `service-permissions/src/main/kotlin/gg/grounds/permissions/auth/KubernetesWorkloadAccessClient.kt`
- Modify: `service-permissions/src/main/kotlin/gg/grounds/permissions/auth/RuntimeAccessAuthorizer.kt`
- Create: `service-permissions/src/test/kotlin/gg/grounds/permissions/rest/runtime/PermissionRuntimeResourceTest.kt`
- Create: `service-permissions/src/test/kotlin/gg/grounds/permissions/metrics/RuntimePermissionMetricsTest.kt`
- Reuse: `service-permissions/src/main/kotlin/gg/grounds/permissions/api/PermissionPolicyProvider.kt`

**Interfaces:**
- Consumes: the runtime `SecurityIdentity` established after TokenReview/SAR, `PermissionPolicyProvider.policyFor`, and `PermissionRepository.replaceRuntimeManifest`.
- Produces: the exact REST paths and JSON schema approved in the design spec.

- [ ] **Step 1: Write failing snapshot resource tests**

Test `200`, invalid UUID/context `400`, missing token `401`, denied ServiceAccount `403`, and dependency failure `503`. Assert that the response contains `playerId`, `policyVersion`, `issuedAt`, `refreshAfter`, `expiresAt`, `allowPatterns`, `denyPatterns`, `roleKeys`, and `roleMetadata`, and that no request field or query parameter accepts caller-supplied `keycloakGroups`. A valid player with no assignments must return an empty/default `200` snapshot rather than `404`.

- [ ] **Step 2: Write failing manifest resource tests**

Test:

```kotlin
given().contentType(JSON).body(validManifest).put("/v1/permissions/runtime/catalog/manifests/plugin-chat").then().statusCode(204)
given().contentType(JSON).body(duplicateKeys).put("/v1/permissions/runtime/catalog/manifests/plugin-chat").then().statusCode(400)
given().contentType(JSON).body(validManifest).put("/v1/permissions/runtime/catalog/manifests/forbidden").then().statusCode(403)
```

The valid body contains only `sourceVersion`, optional `serverType`, optional `serverId`, and `permissions[{key,label,description,supportedScopes}]`; reject a duplicated body-level source field rather than accepting two authorities.

- [ ] **Step 3: Run the resource tests and verify they fail**

Run: `./gradlew test --tests '*PermissionRuntimeResourceTest'`

Expected: FAIL with `404` because the paths do not exist.

- [ ] **Step 4: Implement immutable runtime DTOs**

Use domain enum names directly as string values. `PermissionScopeDto.value` and grant/role optional fields remain nullable. Do not accept `keycloakGroups` in any request DTO.

- [ ] **Step 5: Implement snapshot loading**

Normalize optional context, call `PermissionPolicyProvider.policyFor`, create the snapshot through `PolicyEngine`, and map it without changing policy semantics. Log one successful outcome with `requestId`, `playerId`, `serverType`, `serverId`, `policyVersion`, and `roleCount`.

- [ ] **Step 6: Implement manifest replacement**

Validate the complete request before calling the repository. Authorize the exact request path containing `{source}`. Return `Response.noContent().build()` only after the transaction commits.

- [ ] **Step 7: Instrument runtime outcomes**

Use Micrometer timers/counters with bounded tags only. Record runtime request count/status/latency, snapshot computation latency, TokenReview/SAR latency and outcome, auth cache hits, and manifest success/conflict/failure. Never use `playerId`, `requestId`, namespace, ServiceAccount, source, or permission key as metric tags. Add tests that assert metric names and bounded tag values for success, deny, dependency failure, cache hit, and catalog conflict.

- [ ] **Step 8: Run runtime, metrics, and policy tests**

Run: `./gradlew test --tests '*PermissionRuntimeResourceTest' --tests '*RuntimePermissionMetricsTest' --tests '*PolicyEngineTest' --tests '*PermissionRepositoryTest'`

Expected: PASS.

- [ ] **Step 9: Commit the runtime REST surface**

```bash
git add src/main/kotlin/gg/grounds/permissions/rest/runtime src/main/kotlin/gg/grounds/permissions/metrics src/test/kotlin/gg/grounds/permissions/rest/runtime src/test/kotlin/gg/grounds/permissions/metrics
git commit -m "feat(api): expose permissions runtime REST endpoints"
```

### Task 5: Document the complete REST surface and publishing workflow

**Files:**
- Modify: every resource under `service-permissions/src/main/kotlin/gg/grounds/permissions/rest/`
- Modify: DTOs under `service-permissions/src/main/kotlin/gg/grounds/permissions/rest/`
- Modify: `service-permissions/src/main/kotlin/gg/grounds/permissions/openapi/OpenApiConfiguration.kt`
- Create: `service-permissions/src/test/kotlin/gg/grounds/permissions/openapi/OpenApiContractTest.kt`
- Create: `service-permissions/src/test/kotlin/gg/grounds/permissions/openapi/OpenApiWorkflowContractTest.kt`
- Create: `service-permissions/.github/workflows/openapi.yml`

**Interfaces:**
- Produces: `service-permissions/build/api-reference/openapi.json`.
- Produces: central publisher metadata `service_id: service-permissions`, `service_title: Permissions API`, `service_slug: permissions`.

- [ ] **Step 1: Write the failing OpenAPI contract test**

Assert the three tags, both security schemes, every current REST path, the two runtime operations, RFC 9457 media types, unique operation IDs, and absence of gRPC-derived schemas.

- [ ] **Step 2: Run the contract test and capture missing annotations**

Run: `./gradlew test --tests '*OpenApiContractTest'`

Expected: FAIL listing undocumented or underspecified operations.

- [ ] **Step 3: Annotate resources in small groups**

Add MicroProfile OpenAPI annotations in this order, rerunning the contract test after each group:

1. roles and catalog
2. player search and player management
3. group mappings and audit
4. identity sync and permission sync
5. runtime endpoints

Every operation must declare parameters, body schema, success responses, `400`, `401`, `403`, applicable `404`/`409`, and `500`/`503`.

- [ ] **Step 4: Add the publishing workflow**

Copy the proven `service-moderation` structure but use Java `25` and permissions metadata:

```yaml
publish-openapi:
  needs: export-openapi
  uses: groundsgg/.github/.github/workflows/publish-openapi-snapshot.yml@main
  with:
    artifact_name: openapi-snapshot
    service_id: service-permissions
    service_title: Permissions API
    service_slug: permissions
    source_ref: ${{ github.event_name == 'release' && github.event.release.tag_name || github.ref_name }}
    source_sha: ${{ github.sha }}
  secrets:
    app_private_key: ${{ secrets.OPENAPI_PUBLISHER_PRIVATE_KEY }}
```

- [ ] **Step 5: Test the workflow as repository content**

`OpenApiWorkflowContractTest` must assert stable release/manual triggers, Java 25, `./gradlew spotlessCheck test generateOpenApiSnapshot`, one artifact named `openapi-snapshot`, and the central reusable workflow inputs.

- [ ] **Step 6: Generate and inspect the snapshot**

Run: `./gradlew spotlessCheck test generateOpenApiSnapshot`

Expected: `build/api-reference/openapi.json` exists, parses as JSON, contains no internal hostnames or credentials, and includes both security schemes.

- [ ] **Step 7: Commit OpenAPI completion**

```bash
git add src/main/kotlin/gg/grounds/permissions/rest src/main/kotlin/gg/grounds/permissions/openapi src/test/kotlin/gg/grounds/permissions/openapi .github/workflows/openapi.yml
git commit -m "docs(api): publish complete permissions OpenAPI"
```

### Task 6: Remove gRPC and complete service verification

**Files:**
- Delete: `service-permissions/src/main/proto/permissions.proto`
- Delete: `service-permissions/src/main/kotlin/gg/grounds/permissions/api/PermissionSnapshotGrpcService.kt`
- Delete: `service-permissions/src/main/kotlin/gg/grounds/permissions/api/PermissionCatalogGrpcService.kt`
- Delete: `service-permissions/src/test/kotlin/gg/grounds/permissions/api/PermissionSnapshotGrpcServiceTest.kt`
- Modify: `service-permissions/build.gradle.kts`
- Modify: `service-permissions/src/main/resources/application.properties`
- Modify: `service-permissions/Dockerfile` if it exposes port `9000`

**Interfaces:**
- Produces: a REST-only service image listening on `8080`.
- Produces: a breaking release candidate consumed by the plugin and rollout plans.

- [ ] **Step 1: Add a failing repository guard test**

Create a test or Gradle verification task that fails if active source/build files contain `quarkus-grpc`, `protobuf-kotlin`, `src/main/proto`, `PermissionSnapshotGrpcService`, or `PermissionCatalogGrpcService`.

- [ ] **Step 2: Remove gRPC sources and dependencies**

Delete the listed files. Remove `io.quarkus:quarkus-grpc`, `com.google.protobuf:protobuf-kotlin`, the Protobuf Gradle plugin/configuration, and `quarkus.grpc.*` configuration. Keep `PermissionPolicyProvider` as the shared policy adapter used by REST.

- [ ] **Step 3: Verify port and health behavior**

Run the service tests and assert `/q/health` plus `/q/openapi?format=json` respond on `8080`. Confirm no listener is configured on `9000`.

- [ ] **Step 4: Run mandatory Gradle verification**

Run with escalated permissions, in this order:

```bash
./gradlew test
./gradlew spotlessApply
./gradlew build
./gradlew generateOpenApiSnapshot
```

Expected: all commands exit `0`; `git diff --check` is clean.

- [ ] **Step 5: Commit the hardcut**

```bash
git add -A
git commit -m "feat!: remove permissions gRPC runtime"
```

- [ ] **Step 6: Prepare the release handoff**

Open a PR using the shared Grounds PR template. The PR body must call out `PERMISSIONS_GRPC_TARGET` removal, port `9000` to `8080`, the two REST paths, the workload token audience, the central OpenAPI publication, and coordinated rollout/rollback requirements. Do not deploy this service release until the plugin-client, infrastructure, and hardcut-rollout plans have produced compatible artifacts and bundle pins.
