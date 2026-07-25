# Permissions REST Hardcut Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Release and deploy the incompatible REST-only permissions stack as one coordinated version unit across the lobby, platform bundle, and Pulumi deployments without running mixed gRPC/REST versions.

**Architecture:** Producers are released before consumers are pinned. The static bundle declares permissions capabilities for each workload, while `grounds-pulumi` deploys the REST service on port `8080`, its private runtime Service, and its Kubernetes review identity. Runtime workloads are stopped before the control-plane replacement and recreated only after the REST service and RBAC are healthy.

**Tech Stack:** Gradle, Kotlin, YAML, TypeScript, Helm, Pulumi, GitHub Actions, Kubernetes

## Global Constraints

- This is a stop-and-replace deployment. Never run old gRPC clients against the REST-only service or new REST clients against the gRPC service.
- Do not guess release versions. Query the completed GitHub releases and pin exact immutable tags only.
- Release order is `service-permissions` -> `plugin-permissions` -> `minestom-lobby` and the `containers` Velocity image -> `grounds-forge` and charts -> `library-platform-bundle` -> `grounds-pulumi` deployment.
- The service deployment, plugin clients, Forge/chart versions, bundle, and Pulumi pins form one incompatible release unit.
- Keep database migrations backward-compatible so a coordinated application rollback remains possible.
- Do not expose `/v1/permissions/runtime/**` through public HTTPRoute/Ingress.
- Initial internal transport is HTTP. HTTPS/mTLS remains tracked in `groundsgg/grounds-pulumi#298` and is not part of this rollout.
- Stop after any failed preflight, health check, auth smoke test, or pin mismatch; do not continue to the next environment.
- Run every Gradle command in this plan with escalated permissions.

---

### Task 1: Migrate and release `minestom-lobby`

**Files:**
- Modify: `minestom-lobby/build.gradle.kts` or version catalog containing `plugin-permissions-minestom`
- Modify: lobby startup/configuration code that gates the permissions module
- Modify: tests that reference `PERMISSIONS_GRPC_TARGET`
- Modify: deployment/runtime documentation containing permissions configuration

- [ ] **Step 1: Write a failing configuration test**

Assert the permissions module is enabled only when both `PERMISSIONS_SERVICE_URL` and `PERMISSIONS_TOKEN_FILE` are present, is absent when neither is present, and fails startup on partial configuration. Remove every assertion involving `PERMISSIONS_GRPC_TARGET`.

- [ ] **Step 2: Run the focused test and confirm it fails**

Run the repository's lobby/module configuration test through Gradle.

Expected: FAIL while startup still checks the gRPC variable.

- [ ] **Step 3: Pin the released REST plugin**

Run:

```bash
gh release view --repo groundsgg/plugin-permissions --json tagName,isLatest
```

Update the dependency only after the release containing the common REST client is published. Verify the selected artifact exists in the configured package registry.

- [ ] **Step 4: Replace the environment gate**

Pass URL and token file into the Minestom module; do not parse or read the token in lobby code.

- [ ] **Step 5: Run required Gradle verification**

Run with escalated permissions:

```bash
./gradlew test
./gradlew spotlessApply
./gradlew build
git diff --check
```

If formatting changes files, rerun tests before committing.

- [ ] **Step 6: Commit, PR, merge, and release**

```bash
git add .
git commit -m "feat(permissions): use REST runtime client"
```

After CI passes and the PR merges, wait for the release workflow and record the exact tag from `gh release view --repo groundsgg/minestom-lobby`.

### Task 2: Rebuild the Velocity container with the REST plugin

**Files:**
- Modify: `containers/velocity/Dockerfile`
- Modify: `containers/velocity/README.md`
- Modify: container build tests/workflow fixtures that assert embedded plugin versions

- [ ] **Step 1: Write a failing build assertion**

Assert `PLUGIN_PERMISSIONS_VERSION` equals the released REST client version and that the resolved `plugin-permissions-velocity` artifact contains no gRPC/Protobuf classes or dependencies.

- [ ] **Step 2: Query and pin the exact plugin release**

Run `gh release view --repo groundsgg/plugin-permissions --json tagName,isLatest`, strip only the repository's established `v` prefix when the Maven coordinate requires it, and update the Docker build argument. Do not change unrelated embedded plugin versions.

- [ ] **Step 3: Build and inspect the Velocity image**

Use the repository's documented BuildKit secret for GitHub Packages and build the `velocity` target. Inspect `/app/plugins` and the runtime dependency catalog to confirm exactly one REST-capable permissions plugin and no old permissions gRPC transport.

- [ ] **Step 4: Document the runtime variables**

Replace gRPC examples with `PERMISSIONS_SERVICE_URL` and `PERMISSIONS_TOKEN_FILE`; explain that the chart/Forge projection owns both values in Kubernetes.

- [ ] **Step 5: Commit, PR, merge, and release**

```bash
git add velocity
git commit -m "feat(velocity): bundle permissions REST client"
```

Wait for the component release, obtain the `velocity-v<version>` tag with `gh release list --repo groundsgg/containers`, and verify the matching immutable `ghcr.io/groundsgg/velocity:<version>` image exists before updating the bundle.

### Task 3: Declare exact workload capabilities in `library-platform-bundle`

**Files:**
- Modify: `library-platform-bundle/bundle.yaml`
- Modify: `library-platform-bundle/scripts/validate-bundle.py`
- Modify: `library-platform-bundle/docs/bundle-reference.md`

**Required declarations:**

- Velocity variants: `snapshot:read` plus `catalog:register` for the sources their installed artifacts actually publish (`plugin-permissions`, `plugin-agones`, and `plugin-chat`).
- Lobby variants: `snapshot:read` only unless their released artifact contains a manifest source; do not invent catalog registration.
- Service component: REST service image and chart values for port `8080`, private runtime Service, explicit Kubernetes API credentials, and TokenReview/SAR RBAC.

- [ ] **Step 1: Inventory released manifest sources**

Inspect the exact released Velocity and lobby artifacts/configuration. Record each `permissions.yml`/manifest source found. The access declaration must be derived from this evidence.

- [ ] **Step 2: Query every released producer tag**

Use `gh release view --repo ... --json tagName,isLatest` for `plugin-permissions`, `minestom-lobby`, `service-permissions`, and `grounds-forge`; use `gh release list --repo groundsgg/containers` for the `velocity-v<version>` component release and the chart repository's component tags for changed charts. Abort if any required REST release/image is missing.

- [ ] **Step 3: Write a failing bundle validation test**

Extend `scripts/validate-bundle.py` to assert all permissions-enabled runtimes have a non-empty access list, no workload contains `PERMISSIONS_GRPC_TARGET`, the permissions component type is `http-service`, the service uses container/service port `8080`, and only catalog publishers declare `catalog:register` sources.

- [ ] **Step 4: Update immutable pins and access declarations**

Remove manual `PERMISSIONS_GRPC_TARGET` values. Let Forge derive `PERMISSIONS_SERVICE_URL` and `PERMISSIONS_TOKEN_FILE` from `services.permissions.access`.

- [ ] **Step 5: Validate the bundle**

Run `python3 scripts/validate-bundle.py`, then use the released Forge preview/render flow for each changed component. Inspect resulting values for exact capabilities, sources, service port, and no public runtime route.

- [ ] **Step 6: Commit and release the bundle**

```bash
git add bundle.yaml scripts/validate-bundle.py docs/bundle-reference.md
git commit -m "feat(permissions): roll out REST runtime bundle"
```

After merge, wait for the release and record the exact bundle tag; do not update Pulumi before it exists.

### Task 4: Update the management deployment in `grounds-pulumi`

**Files:**
- Modify: `grounds-pulumi/management/src/platform/permissions.ts`
- Modify: `grounds-pulumi/management/src/config.ts`
- Modify: `grounds-pulumi/platform/src/platform/grounds-forge.ts`
- Modify: `grounds-pulumi/tests/permissions-management-routing.test.ts`
- Modify: `grounds-pulumi/tests/identity-sync-management.test.ts`
- Create or modify: tests for permissions runtime Service and review RBAC

- [ ] **Step 1: Write failing Pulumi resource tests**

Assert:

- container and both Services target port `8080`;
- public HTTPRoute points only to the admin Service;
- a ClusterIP Service named `service-permissions-runtime` selects the same pods and has no route;
- backend pod uses a dedicated ServiceAccount with `automountServiceAccountToken: false`;
- Kubernetes API token/CA/namespace projection exists;
- ClusterRole permits only `create` on TokenReviews and SubjectAccessReviews;
- ClusterRoleBinding targets only the backend ServiceAccount;
- Forge chart plus permissions image/chart pins equal exact released tags.

- [ ] **Step 2: Run focused tests and confirm they fail**

Run: `npm test`

Expected: FAIL while the management deployment still uses port `9000` and lacks the runtime Service/review RBAC.

- [ ] **Step 3: Consume released pins**

Query GitHub releases again immediately before editing. Update `permissionsImageTag`, permissions chart version, `FORGE_CHART_VERSION`, and bundle reference only to tags verified in Task 2.

- [ ] **Step 4: Render service topology and identity**

Use the chart values established by the infrastructure plan. Preserve the existing admin hostname and Keycloak environment. Ensure runtime auth receives Kubernetes API access without enabling automatic token mounting.

- [ ] **Step 5: Run full Pulumi verification**

```bash
npm test
./node_modules/.bin/tsc --noEmit -p management/tsconfig.json
./node_modules/.bin/tsc --noEmit -p platform/tsconfig.json
git diff --check
```

Expected: PASS; preview/test snapshots show no public runtime route and no port `9000`.

- [ ] **Step 6: Commit and open the deployment PR**

```bash
git add management/src platform/src tests
git commit -m "feat(permissions): deploy REST runtime topology"
```

The PR must list every coordinated release tag and state that application is deferred until the maintenance rollout.

### Task 5: Perform a preflight compatibility audit

- [ ] **Step 1: Verify the GitHub release set**

Record immutable tags and release URLs for the service, plugin, lobby, Velocity runtime/plugin as applicable, Forge, charts, bundle, and Pulumi commit. Confirm every consumer pin resolves.

- [ ] **Step 2: Search every checked-out consumer for obsolete transport**

Run from `/home/lukas/grounds`:

```bash
rg -n "PERMISSIONS_GRPC_TARGET|grpcTarget|service-permissions:9000|permissions.*9000" service-permissions plugin-permissions minestom-lobby grounds-forge charts library-platform-bundle grounds-pulumi
```

Expected: no active build, source, manifest, or deployment hit. Historical design documents may be excluded explicitly.

- [ ] **Step 3: Verify database rollback compatibility**

Review Flyway migrations in the released service. Confirm the previous service image can start against the migrated schema without data loss. If not, stop and add an additive compatibility migration before rollout.

- [ ] **Step 4: Render the complete target state**

Use Forge/bundle render and Pulumi preview for each target environment. Verify exact image/chart tags, Recreate-compatible workload strategy, runtime token audience, non-resource RBAC paths, backend review RBAC, and absence of runtime ingress.

- [ ] **Step 5: Capture rollback pins before mutation**

Record the currently deployed service, Forge, chart, bundle, lobby, and Velocity versions. Rollback must restore this full set together; never roll back one member independently.

### Task 6: Execute the stop-and-replace rollout

- [ ] **Step 1: Stop affected runtime workloads**

Scale down or otherwise stop every Velocity/lobby workload that uses permissions. Confirm no old gRPC client pods remain. Do not delete persistent data.

- [ ] **Step 2: Deploy the permissions control plane**

Apply the merged Pulumi revision containing the released service image/chart, port `8080`, runtime Service, and review RBAC. Wait for deployment readiness and migration completion.

- [ ] **Step 3: Smoke-test service separation and auth**

From an authorized test pod using a projected token:

- admin Service remains reachable on its expected internal/public route;
- runtime Service resolves internally on port `8080`;
- unauthenticated runtime request returns `401`;
- valid token without path permission returns `403`;
- permitted snapshot path reaches application behavior;
- permitted exact manifest source returns `204` with a valid body;
- a different source returns `403`;
- public hostname does not route the runtime path.

- [ ] **Step 4: Deploy the released bundle and recreate runtimes**

Start runtimes only from the new bundle/Forge/chart set. Confirm each pod uses the stable ServiceAccount, dedicated token projection, REST URL, and expected ClusterRole/Binding.

- [ ] **Step 5: Verify functional behavior**

Check one player login/snapshot, one local permission evaluation, catalog registration for every declared source, stale same-source catalog removal, and no cross-source collision. Confirm logs contain request/workload/source context but no tokens.

- [ ] **Step 6: Repeat environment by environment**

Complete all smoke checks in the first non-production environment before applying the same immutable release set to the next environment. Never point stage at a partially upgraded production permission service.

### Task 7: Roll back the complete unit if a gate fails

- [ ] **Step 1: Stop new REST runtime workloads**

Prevent new clients from calling a service version that will be rolled back.

- [ ] **Step 2: Restore all captured pins together**

Restore prior service, Forge, charts, bundle, lobby, and Velocity versions in one coordinated change. Do not down-migrate the database if migrations were additive/backward-compatible.

- [ ] **Step 3: Restore the prior service topology and start old runtimes**

Wait for the old permissions service to be healthy before recreating the old gRPC clients.

- [ ] **Step 4: Re-run old-version smoke checks**

Verify player login, snapshot delivery, local evaluation, and catalog behavior before declaring rollback complete.

- [ ] **Step 5: Preserve failure evidence**

Capture release set, Kubernetes events, request IDs, sanitized service/runtime logs, and the exact failing gate. Do not log or attach projected tokens.
