# Permissions REST Plugin Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the duplicated Minestom and Velocity gRPC clients with one shared REST runtime client that reads projected workload tokens, preserves local permission evaluation, and fails safely when the service is unavailable.

**Architecture:** `plugin-permissions:common` owns the HTTP transport, JSON DTO mapping, file-backed token provider, snapshot fallback policy, and manifest retry policy. The Minestom and Velocity modules only adapt lifecycle and platform events to the common client. Snapshot reads have a two-second request timeout and no immediate retry; manifest registration is asynchronous and retries only transient failures.

**Tech Stack:** Kotlin, JDK HTTP client and test HTTP server, Jackson, JUnit 5, Gradle

## Global Constraints

- Work in `groundsgg/plugin-permissions` on a fresh branch from current `origin/main`.
- Delete Protobuf and all gRPC client dependencies; do not retain a compatibility client.
- Read the token from `PERMISSIONS_TOKEN_FILE` for every request. Never cache or log its content.
- Accept `PERMISSIONS_SERVICE_URL` only as an absolute `http` or `https` URI without user info, query, or fragment.
- Send `Authorization: Bearer <token>` and JSON; never put credentials into URLs.
- Snapshot transport timeout is two seconds. Do not immediately retry a failed snapshot request.
- Fall back only to a still-valid cached snapshot. If none exists, fail the login closed.
- Manifest registration must not block server startup. Retry connection errors, `429`, and `5xx` with bounded exponential backoff and jitter; treat `400`, `401`, `403`, and `409` as terminal.
- Keep permission checks local and preserve allow/deny, role metadata, `refreshAfter`, and `expiresAt` semantics.
- Follow the repository logging rules and never log token content or full response bodies.
- Run every Gradle command in this plan with escalated permissions. After code or Gradle changes, always finish with `./gradlew test`, `./gradlew spotlessApply`, and `./gradlew build`.

---

### Task 1: Move runtime configuration and transport contracts into `common`

**Files:**
- Modify: `plugin-permissions/common/build.gradle.kts`
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/PermissionServiceConfig.kt`
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/PermissionSnapshotContext.kt`
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/WorkloadTokenProvider.kt`
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/FileWorkloadTokenProvider.kt`
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/PermissionRuntimeClient.kt`
- Create: `plugin-permissions/common/src/test/kotlin/gg/grounds/permissions/client/PermissionServiceConfigTest.kt`
- Create: `plugin-permissions/common/src/test/kotlin/gg/grounds/permissions/client/FileWorkloadTokenProviderTest.kt`

**Interfaces:**

```kotlin
data class PermissionServiceConfig(
    val serviceUri: URI,
    val tokenFile: Path,
)

fun interface WorkloadTokenProvider {
    fun readToken(): String
}

interface PermissionRuntimeClient {
    fun fetchSnapshot(playerId: UUID, context: PermissionSnapshotContext): PermissionSnapshot
    fun registerManifest(
        manifest: PermissionManifest,
        sourceVersion: String,
        context: PermissionSnapshotContext,
    ): PermissionManifestRegistrationResult
}
```

- [ ] **Step 1: Write failing configuration and token-provider tests**

Cover absolute `http`/`https` URLs, rejection of relative URLs/user info/query/fragment, missing/unreadable/blank token files, and token rotation between two consecutive reads.

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run: `./gradlew :common:test --tests '*PermissionServiceConfigTest' --tests '*FileWorkloadTokenProviderTest'`

Expected: FAIL because the shared configuration and token abstractions do not exist.

- [ ] **Step 3: Replace the gRPC convention in `common`**

Use `gg.grounds.kotlin-conventions`, add Jackson and test dependencies, and retain no Protobuf generation in the module.

- [ ] **Step 4: Implement strict parsing and per-request token reads**

`FileWorkloadTokenProvider.readToken()` must read and trim the configured file on each invocation, reject blank content, and return errors that name only the file path.

- [ ] **Step 5: Run the focused tests**

Run: `./gradlew :common:test --tests '*PermissionServiceConfigTest' --tests '*FileWorkloadTokenProviderTest'`

Expected: PASS.

- [ ] **Step 6: Commit the shared client surface**

```bash
git add common
git commit -m "refactor(client): centralize permissions runtime transport"
```

### Task 2: Implement the REST snapshot client and cache fallback

**Files:**
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/HttpPermissionRuntimeClient.kt`
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/PermissionRuntimeDtos.kt`
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/SnapshotCache.kt`
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/PermissionRuntimeStatus.kt`
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/SnapshotUnavailableException.kt`
- Create: `plugin-permissions/common/src/test/kotlin/gg/grounds/permissions/client/HttpPermissionRuntimeClientTest.kt`
- Create: `plugin-permissions/common/src/test/kotlin/gg/grounds/permissions/client/SnapshotCacheTest.kt`

**Request contract:**

```http
GET /v1/permissions/runtime/players/{playerId}/snapshot?serverType=<type>&serverId=<id>
Authorization: Bearer <projected-token>
Accept: application/json
```

- [ ] **Step 1: Write failing HTTP and cache tests with MockWebServer**

Use the JDK `HttpServer` on a loopback ephemeral port. Assert exact method/path/query/header mapping, `X-Request-ID` generation/propagation, DTO-to-domain conversion, a two-second request timeout, no second request after timeout/connection failure/`5xx`, fallback to an unexpired cached snapshot, and `SnapshotUnavailableException` when no valid snapshot exists. Also assert that `401` and `403` fail closed rather than using a stale snapshot; malformed/incompatible JSON is treated as unavailable and may use only a valid cache entry.

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run: `./gradlew :common:test --tests '*HttpPermissionRuntimeClientTest' --tests '*SnapshotCacheTest'`

Expected: FAIL because no REST transport exists.

- [ ] **Step 3: Implement one JDK `HttpClient` transport**

Use `HttpRequest.timeout(Duration.ofSeconds(2))`, percent-encode path/query values, read the token immediately before building each request, and deserialize successful responses with the shared Jackson mapper.

The response DTO must model `playerId`, `policyVersion`, `issuedAt`, `refreshAfter`, `expiresAt`, `allowPatterns`, `denyPatterns`, `roleKeys`, and `roleMetadata`, including nullable scope values and grant expiration. Reject missing required fields and snapshots whose `playerId` differs from the request.

- [ ] **Step 4: Implement explicit response classification**

- `200`: validate and cache the returned snapshot.
- `401`/`403`: throw an authentication/authorization failure and fail closed.
- `404`: fail closed as missing player state.
- `429`/`5xx`/I/O/timeout: use only a snapshot whose `expiresAt` is still in the future.
- other responses: fail closed with status and request ID only; do not include response bodies in logs.

- [ ] **Step 5: Run common tests**

Run: `./gradlew :common:test`

Expected: PASS with exactly one outbound snapshot request per call.

- [ ] **Step 6: Commit snapshot transport**

```bash
git add common/src
git commit -m "feat(client): fetch permission snapshots over REST"
```

### Task 3: Implement asynchronous manifest registration with bounded retry

**Files:**
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/ManifestRegistration.kt`
- Create: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/ManifestRegistrationScheduler.kt`
- Modify: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/PermissionRuntimeStatus.kt`
- Modify: `plugin-permissions/common/src/main/kotlin/gg/grounds/permissions/client/HttpPermissionRuntimeClient.kt`
- Create: `plugin-permissions/common/src/test/kotlin/gg/grounds/permissions/client/ManifestRegistrationSchedulerTest.kt`
- Modify: `plugin-permissions/common/src/test/kotlin/gg/grounds/permissions/client/HttpPermissionRuntimeClientTest.kt`

**Request contract:**

```http
PUT /v1/permissions/runtime/catalog/manifests/{source}
Authorization: Bearer <projected-token>
Content-Type: application/json

{"sourceVersion":"...","serverType":"...","serverId":"...","permissions":[...]}
```

- [ ] **Step 1: Write failing registration tests**

Assert a successful `204`, source only in the path, no startup-thread blocking, retries for I/O/`429`/`5xx`, no retry for `400`/`401`/`403`/`409`, exponential delay capped at 60 seconds, jitter within the configured range, and cancellation on shutdown.

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run: `./gradlew :common:test --tests '*ManifestRegistrationSchedulerTest' --tests '*HttpPermissionRuntimeClientTest'`

Expected: FAIL because manifest REST registration and scheduling do not exist.

- [ ] **Step 3: Implement deterministic retry policy injection**

Inject `Clock`, delay scheduler, and jitter source so tests use fixed time. Start at one second, double after each transient failure, cap at 60 seconds, and allow only one in-flight registration per source.

Expose immutable status fields/counters for snapshot successes/failures, valid-cache fallback, fail-closed decisions, manifest retries, last manifest success, and terminal manifest failure. Platform status commands read this object; the transport must not own console/UI formatting.

- [ ] **Step 4: Add outcome-oriented logs**

Examples:

```text
Permission manifest registered successfully (source=plugin-permissions, permissionCount=12)
Permission manifest registration failed (source=plugin-permissions, status=409, retryable=false)
Permission manifest registration scheduled (source=plugin-permissions, retryInMs=2000)
```

- [ ] **Step 5: Run common tests**

Run: `./gradlew :common:test`

Expected: PASS without sleeps or timing flakes.

- [ ] **Step 6: Commit registration behavior**

```bash
git add common/src
git commit -m "feat(client): register permission manifests over REST"
```

### Task 4: Adapt Minestom to the shared REST client

**Files:**
- Modify: `plugin-permissions/minestom/build.gradle.kts`
- Modify: `plugin-permissions/minestom/src/main/kotlin/gg/grounds/permissions/minestom/GroundsPermissionsModule.kt`
- Modify: `plugin-permissions/minestom/src/main/kotlin/gg/grounds/permissions/minestom/GroundsPermissionsModuleProvider.kt`
- Delete: `plugin-permissions/minestom/src/main/kotlin/gg/grounds/permissions/minestom/PermissionSnapshotClient.kt`
- Delete: `plugin-permissions/minestom/src/main/kotlin/gg/grounds/permissions/minestom/PermissionCatalogClient.kt`
- Delete duplicated Minestom `PermissionSnapshotContext` if present
- Modify: corresponding tests under `plugin-permissions/minestom/src/test/kotlin`

- [ ] **Step 1: Change Minestom tests to the REST configuration**

Construct the module with `serviceUrl` and `tokenFile`; assert login is denied when neither a REST snapshot nor a valid cache entry exists, cached snapshots remain usable until `expiresAt`, and manifest registration starts asynchronously.

- [ ] **Step 2: Run Minestom tests and confirm they fail**

Run: `./gradlew :minestom:test`

Expected: FAIL while the module still requires `grpcTarget` and duplicated clients.

- [ ] **Step 3: Wire `PERMISSIONS_SERVICE_URL` and `PERMISSIONS_TOKEN_FILE`**

Default neither value silently. The plugin must remain disabled only when permissions integration is explicitly absent; a partially configured integration must fail startup with a precise error naming the missing variable.

- [ ] **Step 4: Replace duplicated clients and gRPC dependencies**

Inject the common `PermissionRuntimeClient`, keep local permission evaluation unchanged, and close the scheduler during module shutdown.

- [ ] **Step 5: Run Minestom tests**

Run: `./gradlew :minestom:test`

Expected: PASS.

- [ ] **Step 6: Commit the Minestom adapter**

```bash
git add minestom
git commit -m "feat(minestom): use permissions REST runtime client"
```

### Task 5: Adapt Velocity to the shared REST client

**Files:**
- Modify: `plugin-permissions/velocity/build.gradle.kts`
- Modify: `plugin-permissions/velocity/src/main/kotlin/gg/grounds/permissions/velocity/GroundsPermissionsPlugin.kt`
- Modify: `plugin-permissions/velocity/src/main/kotlin/gg/grounds/permissions/velocity/PermissionCommandService.kt`
- Delete: `plugin-permissions/velocity/src/main/kotlin/gg/grounds/permissions/velocity/PermissionSnapshotClient.kt`
- Delete: `plugin-permissions/velocity/src/main/kotlin/gg/grounds/permissions/velocity/PermissionCatalogClient.kt`
- Delete duplicated Velocity `PermissionSnapshotContext` if present
- Modify: corresponding tests under `plugin-permissions/velocity/src/test/kotlin`

- [ ] **Step 1: Change Velocity tests to the REST configuration**

Assert the same fail-closed/cache/registration behavior as Minestom and change status output from `grpcTarget` to a credential-free `serviceUrl`. Include the common snapshot counters and last manifest registration state without exposing headers or token-file contents.

- [ ] **Step 2: Run Velocity tests and confirm they fail**

Run: `./gradlew :velocity:test`

Expected: FAIL while Velocity still constructs gRPC clients.

- [ ] **Step 3: Wire the shared client and lifecycle**

Use the common client and scheduler, preserve the current player refresh cadence, and close resources during proxy shutdown.

- [ ] **Step 4: Remove gRPC dependencies and duplicated transport types**

Keep only platform-specific event/listener code in `velocity`.

- [ ] **Step 5: Run Velocity tests**

Run: `./gradlew :velocity:test`

Expected: PASS.

- [ ] **Step 6: Commit the Velocity adapter**

```bash
git add velocity
git commit -m "feat(velocity): use permissions REST runtime client"
```

### Task 6: Lock the client to the released OpenAPI contract

**Files:**
- Create: `plugin-permissions/common/src/test/resources/contracts/service-permissions-openapi.json`
- Create: `plugin-permissions/common/src/test/kotlin/gg/grounds/permissions/client/PermissionOpenApiContractTest.kt`
- Modify: `plugin-permissions/README.md`

- [ ] **Step 1: Copy the exact released service snapshot**

After the service plan has published a release, copy that release's generated `openapi.json` without hand-editing it. Record the service release tag and snapshot checksum in the commit message body.

- [ ] **Step 2: Write a contract test**

Parse the fixture and assert both runtime paths, methods, parameters, `workloadBearer`, success codes (`200` and `204`), problem responses, and every JSON field consumed by `PermissionRuntimeDtos`.

- [ ] **Step 3: Run the contract test**

Run: `./gradlew :common:test --tests '*PermissionOpenApiContractTest'`

Expected: PASS against the released snapshot.

- [ ] **Step 4: Document runtime configuration**

Document both environment variables, the projected token rotation behavior, two-second snapshot timeout, valid-cache fallback, fail-closed login, and asynchronous manifest retry behavior.

- [ ] **Step 5: Commit the contract fixture**

```bash
git add common/src/test README.md
git commit -m "test(client): lock permissions REST contract"
```

### Task 7: Remove all gRPC residue and prepare the release

**Files:**
- Delete: `plugin-permissions/common/src/main/proto/permissions.proto`
- Modify: `plugin-permissions/common/build.gradle.kts`
- Modify: `plugin-permissions/minestom/build.gradle.kts`
- Modify: `plugin-permissions/velocity/build.gradle.kts`
- Modify: repository-wide configuration, examples, and tests containing `grpcTarget` or `PERMISSIONS_GRPC_TARGET`

- [ ] **Step 1: Prove no gRPC or Protobuf references remain**

Run:

```bash
rg -n "grpc|protobuf|PERMISSIONS_GRPC_TARGET|grpcTarget" . --glob '!build/**' --glob '!docs/superpowers/**'
```

Expected: no runtime, build, configuration, or test hits.

- [ ] **Step 2: Run required formatting and verification**

Run with escalated permissions, in this order:

```bash
./gradlew test
./gradlew spotlessApply
./gradlew build
git diff --check
```

Expected: all commands pass; if `spotlessApply` changes files, rerun `./gradlew test` before committing.

- [ ] **Step 3: Commit cleanup**

```bash
git add .
git commit -m "refactor(client): remove permissions gRPC transport"
```

- [ ] **Step 4: Open the release PR**

Use the repository PR template. State that the release is incompatible with pre-REST `service-permissions` and must be rolled out with the infrastructure and bundle plan. Do not merge or publish until the service release exists and the contract fixture matches it.
