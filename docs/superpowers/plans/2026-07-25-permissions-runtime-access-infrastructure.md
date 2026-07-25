# Permissions Runtime Access Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Forge and the shared Helm charts render the dedicated permissions REST endpoint, projected workload credentials, and least-privilege Kubernetes authorization declared by a workload manifest.

**Architecture:** A workload opts into permissions capabilities through `services.permissions.access`. Forge resolves those declarations into an internal REST URL, a dedicated projected token with audience `service-permissions`, and path-specific non-resource RBAC. The `grounds-service` chart separately gives the permissions backend the Kubernetes API credential and review permissions it needs for TokenReview and SubjectAccessReview.

**Tech Stack:** TypeScript, Zod, Node test runner, Kubernetes YAML, Helm, ServiceAccount token projection, RBAC

## Global Constraints

- Implement Forge first, then consume its released chart/API shape from the chart and bundle rollout.
- A `services.permissions.version` declaration alone grants no access.
- Supported capabilities are exactly `snapshot:read` and `catalog:register`.
- `snapshot:read` must not accept `resources`.
- `catalog:register` requires a non-empty, unique source list and grants only exact source paths.
- Use a dedicated projected token with audience `service-permissions`, mount path `/var/run/secrets/grounds/permissions-token`, and environment variable `PERMISSIONS_TOKEN_FILE`.
- Set `automountServiceAccountToken: false` on runtime and service workloads.
- Render `PERMISSIONS_SERVICE_URL=http://service-permissions-runtime.<namespace>.svc.cluster.local:8080` only when at least one access capability is granted.
- Authorize non-resource REST paths, not synthetic Kubernetes resources.
- Keep names deterministic and labels sufficient for Forge cleanup.
- Never include a bearer token in rendered status, logs, annotations, or manifests.

---

### Task 1: Add the permissions access model to Forge manifests

**Files:**
- Modify: `grounds-forge/src/buildrunner/manifest.ts`
- Modify: `grounds-forge/src/bundle/types.ts`
- Modify: `grounds-forge/src/bundle/overlay.ts`
- Modify: `grounds-forge/src/devcluster/PlatformBundleProfileReconciler.ts`
- Modify: `grounds-forge/tests/manifest.test.ts`
- Modify: `grounds-forge/tests/bundleOverlay.test.ts`

**Schema:**

```yaml
services:
  permissions:
    version: v1
    access:
      - capability: snapshot:read
      - capability: catalog:register
        resources:
          - plugin-permissions
          - plugin-chat
```

- [ ] **Step 1: Write failing schema tests**

Accept the example above and reject unknown capabilities, duplicate capabilities, `resources` on `snapshot:read`, missing/empty/duplicate resources on `catalog:register`, blank source names, and access without `version: v1`. Assert a service declaration with no `access` remains valid but grants nothing.

- [ ] **Step 2: Run focused tests and confirm they fail**

Run: `npm test -- -t 'permissions access|bundle permissions access'`

Expected: FAIL because the schema has no access model.

- [ ] **Step 3: Add discriminated access types**

Use a Zod discriminated union and infer the TypeScript type from it. Reuse the same type in static bundle components through a `services` property; do not define a second capability vocabulary. Add `http-service` to bundle component types and migrate only the permissions service from the misleading `grpc-service` type.

- [ ] **Step 4: Preserve access through bundle overlay generation**

Ensure `BundleComponent.services` is copied to `ResolvedComponent.services` without widening sources or inventing default capabilities. Add `withPermissionsValues(...)` in `PlatformBundleProfileReconciler` so Helm-installed bundle workloads receive the same validated URL, token settings, and access list as pushed workloads. Extend the existing bundle overlay tests for Velocity, gamemode, empty-access, and the permissions `http-service` component.

- [ ] **Step 5: Run schema and overlay tests**

Run: `npm test -- -t 'permissions access|bundle permissions access'`

Expected: PASS.

- [ ] **Step 6: Commit the manifest model**

```bash
git add src/buildrunner/manifest.ts src/bundle/types.ts tests/manifest.test.ts tests/bundleOverlay.test.ts
git commit -m "feat(manifest): declare permissions runtime access"
```

### Task 2: Resolve permissions declarations to explicit runtime inputs

**Files:**
- Modify: `grounds-forge/src/deploy/serviceResolver.ts`
- Modify: the `RenderInput` type under `grounds-forge/src/workloads/renderer.ts`
- Modify: `grounds-forge/tests/serviceResolver.test.ts`

**Resolved type:**

```ts
type ResolvedService = {
  key: "permissions";
  url: string;
  access: PermissionAccess[];
};
```

- [ ] **Step 1: Write failing resolver tests**

Assert the URL uses scheme `http`, service `service-permissions-runtime`, current namespace, and port `8080`; access stays byte-for-byte equivalent after validation; and no permissions runtime environment is emitted when access is empty.

- [ ] **Step 2: Run the resolver tests and confirm they fail**

Run: `npm test -- -t 'service resolver'`

Expected: FAIL because the current resolver emits `service-permissions:9000` without protocol or access.

- [ ] **Step 3: Make service resolution protocol-aware**

Replace the permissions entry in `KNOWN_PLATFORM_SERVICES` with the runtime Service and return an absolute URL. Keep other service behavior unchanged.

- [ ] **Step 4: Run resolver tests**

Run: `npm test -- -t 'service resolver'`

Expected: PASS.

- [ ] **Step 5: Commit resolver changes**

```bash
git add src/deploy/serviceResolver.ts src/workloads/renderer.ts tests/serviceResolver.test.ts
git commit -m "feat(deploy): resolve permissions REST runtime"
```

### Task 3: Render dedicated token projection and exact non-resource RBAC

**Files:**
- Modify: `grounds-forge/src/workloads/renderer.ts`
- Modify: `grounds-forge/tests/renderer.test.ts`
- Modify: Forge Kubernetes object types used by `RenderOutput`

**Rendered authorization:**

```yaml
rules:
  - nonResourceURLs: ["/v1/permissions/runtime/players/*"]
    verbs: ["get"]
  - nonResourceURLs:
      - "/v1/permissions/runtime/catalog/manifests/plugin-permissions"
      - "/v1/permissions/runtime/catalog/manifests/plugin-chat"
    verbs: ["put"]
```

- [ ] **Step 1: Write failing renderer tests**

Assert:

- dedicated projected volume audience `service-permissions` and a bounded expiration;
- mount path and `PERMISSIONS_TOKEN_FILE` exactly match the contract;
- `PERMISSIONS_SERVICE_URL` is the resolved URL;
- `automountServiceAccountToken: false`;
- snapshot-only, catalog-only, and combined ClusterRole rules;
- exact catalog source paths with sorted/deduplicated resources;
- no token/RBAC/env for an empty access list;
- deterministic ClusterRole and ClusterRoleBinding names that include a hash of namespace/workload identity;
- labels identifying Forge owner, deployment, and cleanup scope.

- [ ] **Step 2: Run renderer tests and confirm they fail**

Run: `npm test -- -t 'permissions token|permissions RBAC'`

Expected: FAIL because `RenderOutput` has no cluster-scoped permissions objects.

- [ ] **Step 3: Extend `RenderOutput`**

Add arrays for `clusterRoles` and `clusterRoleBindings`. Bind each generated ClusterRole to the exact stable workload ServiceAccount in its namespace; never bind `system:serviceaccounts` or a namespace-wide group.

- [ ] **Step 4: Render the token separately from `GROUNDS_TOKEN_FILE`**

Do not reuse the `grounds-services` audience projection. Both projections may coexist when a workload uses both systems.

- [ ] **Step 5: Run renderer tests**

Run: `npm test -- -t 'renderer'`

Expected: PASS with stable snapshots.

- [ ] **Step 6: Commit rendered access controls**

```bash
git add src/workloads/renderer.ts tests/renderer.test.ts
git commit -m "feat(deploy): render permissions workload identity"
```

### Task 4: Apply and clean up cluster-scoped Forge resources

**Files:**
- Modify: `grounds-forge/src/deploy/kubeApply.ts`
- Modify: `grounds-forge/src/workers/DeployWorker.ts`
- Modify: Forge deletion/rollback code that removes rendered Kubernetes objects
- Modify: `grounds-forge/tests/DeployWorker.test.ts`

- [ ] **Step 1: Write failing deployment lifecycle tests**

Assert apply order `ServiceAccount -> ClusterRole -> ClusterRoleBinding -> workload`, cleanup of obsolete cluster RBAC when access is removed, and rollback cleanup after a failed deployment. Assert one workload cannot delete another workload's labeled resources.

- [ ] **Step 2: Run focused tests and confirm they fail**

Run: `npm test -- -t 'ClusterRole|permissions RBAC lifecycle'`

Expected: FAIL because cluster-scoped resources are not applied.

- [ ] **Step 3: Add typed apply/delete operations**

Use server-side apply with the existing field manager and resource labels. Delete only exact names derived from the deployment or list by the deployment's ownership labels; never broad-delete ClusterRoles.

- [ ] **Step 4: Wire deploy and rollback order**

Ensure the ServiceAccount exists before the binding and the binding exists before pods start. On an access update, apply new rules before removing the old uniquely named objects.

- [ ] **Step 5: Run deployment tests**

Run: `npm test -- -t 'DeployWorker|ClusterRole'`

Expected: PASS.

- [ ] **Step 6: Commit lifecycle support**

```bash
git add src/deploy/kubeApply.ts src/workers tests/DeployWorker.test.ts
git commit -m "feat(deploy): manage permissions runtime RBAC"
```

### Task 5: Teach runtime charts to consume Forge's permissions inputs

**Files:**
- Modify: `charts/charts/grounds-velocity/values.yaml`
- Modify: `charts/charts/grounds-velocity/templates/deployment.yaml`
- Create: `charts/charts/grounds-velocity/templates/permissions-clusterrole.yaml`
- Create: `charts/charts/grounds-velocity/templates/permissions-clusterrolebinding.yaml`
- Modify: `charts/charts/grounds-gamemode/values.yaml`
- Modify: `charts/charts/grounds-gamemode/templates/deployment.yaml`
- Modify: `charts/charts/grounds-gamemode/templates/fleet.yaml`
- Create: `charts/charts/grounds-gamemode/templates/serviceaccount.yaml`
- Create: `charts/charts/grounds-gamemode/templates/agones-rolebinding.yaml`
- Create: `charts/charts/grounds-gamemode/templates/permissions-clusterrole.yaml`
- Create: `charts/charts/grounds-gamemode/templates/permissions-clusterrolebinding.yaml`
- Create: `charts/tests/permissions/velocity-values.yaml`
- Create: `charts/tests/permissions/gamemode-deployment-values.yaml`
- Create: `charts/tests/permissions/gamemode-fleet-values.yaml`
- Create: `charts/scripts/test-permissions-runtime.sh`
- Modify: `charts/.github/workflows/ci.yml`

- [ ] **Step 1: Add failing Helm render assertions**

Create a shell contract test that renders the three fixed values files to a temporary directory and asserts a stable ServiceAccount, `automountServiceAccountToken: false`, optional permissions token projection, exact file/URL environment variables, exact snapshot/catalog non-resource RBAC, and preservation of the Agones SDK RoleBinding. Assert default renders contain none of these permissions-specific objects. Add the script to chart CI.

- [ ] **Step 2: Render the current charts and capture the failure**

Run:

```bash
helm lint charts/grounds-velocity
helm lint charts/grounds-gamemode
bash scripts/test-permissions-runtime.sh
```

Expected: the new assertions fail because the values/templates do not exist.

- [ ] **Step 3: Add a shared value shape to both charts**

```yaml
permissions:
  enabled: false
  serviceUrl: ""
  token:
    audience: service-permissions
    expirationSeconds: 3600
    mountPath: /var/run/secrets/grounds/permissions-token
```

Forge supplies the validated access values. The charts render deterministic RBAC from those values without inventing capabilities: `snapshot:read` maps to `get /v1/permissions/runtime/players/*`; each `catalog:register` source maps to one exact `put /v1/permissions/runtime/catalog/manifests/<source>` path. Reject unsupported shapes during Forge validation rather than silently rendering broader access. The test script must use `mktemp -d`, clean it with a trap, and fail on missing or unexpected YAML fragments.

- [ ] **Step 4: Add stable ServiceAccount support to `grounds-gamemode`**

Use the same ServiceAccount for Deployment/Fleet and bind it to `agones-sdk` where required. Do not rely on the namespace default ServiceAccount.

- [ ] **Step 5: Run chart lint and render tests**

Run the commands from Step 2; the script covers disabled, Deployment, and Fleet cases.

Expected: PASS; rendered YAML contains no `PERMISSIONS_GRPC_TARGET`.

- [ ] **Step 6: Commit runtime chart support**

```bash
git add charts/grounds-velocity charts/grounds-gamemode tests/permissions scripts/test-permissions-runtime.sh .github/workflows/ci.yml
git commit -m "feat(charts): mount permissions runtime identity"
```

### Task 6: Give `service-permissions` its runtime Service and Kubernetes review identity

**Files:**
- Modify: `charts/charts/grounds-service/values.yaml`
- Modify: `charts/charts/grounds-service/templates/deployment.yaml`
- Modify: `charts/charts/grounds-service/templates/service.yaml`
- Create: `charts/charts/grounds-service/templates/additional-services.yaml`
- Create: `charts/charts/grounds-service/templates/clusterrole.yaml`
- Create: `charts/charts/grounds-service/templates/clusterrolebinding.yaml`
- Create: `charts/tests/permissions/service-values.yaml`
- Modify: `charts/scripts/test-permissions-runtime.sh`

- [ ] **Step 1: Add failing Helm render assertions**

Extend the shell contract test to assert one deployment on port `8080`, the existing admin Service plus a ClusterIP alias named `service-permissions-runtime`, no runtime ingress, `automountServiceAccountToken: false`, an explicit Kubernetes API credential projection, and backend ClusterRole permissions only for `authentication.k8s.io/tokenreviews create` and `authorization.k8s.io/subjectaccessreviews create`.

- [ ] **Step 2: Run chart lint/render and confirm missing objects**

Run:

```bash
helm lint charts/grounds-service
bash scripts/test-permissions-runtime.sh
```

Expected: new assertions fail.

- [ ] **Step 3: Add generic additional Service support**

The additional Service must select the same pods and expose port `8080`. Keep ingress backends attached only to the primary admin Service; the chart must not create an HTTPRoute for the runtime alias.

- [ ] **Step 4: Project backend Kubernetes API credentials explicitly**

Project the ServiceAccount token plus `kube-root-ca.crt` and namespace at the standard Kubernetes ServiceAccount mount so the Fabric8 client works while automatic mounting stays disabled. This token is for Kubernetes API calls and must not use the runtime audience.

- [ ] **Step 5: Add narrowly scoped review RBAC**

Bind the ClusterRole to only the permissions backend ServiceAccount. Keep this value-gated so other `grounds-service` consumers gain no review permissions.

- [ ] **Step 6: Run lint/render tests**

Run the commands from Step 2 and inspect the rendered YAML for both enabled and default-disabled values.

Expected: PASS with two Services and no public runtime route.

- [ ] **Step 7: Commit backend chart support**

```bash
git add charts/grounds-service tests/permissions/service-values.yaml scripts/test-permissions-runtime.sh
git commit -m "feat(charts): expose authenticated permissions runtime"
```

### Task 7: Verify and release Forge and charts

- [ ] **Step 1: Run the complete Forge suite**

From `grounds-forge`:

```bash
npm test
npm run typecheck
npm run build
git diff --check
```

Expected: all pass.

- [ ] **Step 2: Run complete chart validation**

From `charts`, lint and render every changed chart with default and permissions-enabled fixtures. Confirm `rg -n 'PERMISSIONS_GRPC_TARGET|service-permissions:9000' charts` returns no hit.

- [ ] **Step 3: Open separate PRs**

Use each repository's PR template and explain the hardcut coordination. Merge Forge first, publish its release and chart, then merge/publish the shared chart releases.

- [ ] **Step 4: Record exact released versions**

After automation completes, obtain tags with `gh release view --repo groundsgg/grounds-forge` and `gh release list --repo groundsgg/charts`. Pass those exact tags to the rollout plan; do not predict version numbers in code or documentation.
