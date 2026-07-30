# Permission Grant Start Dates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional scheduled start instants to every expirable permission grant and mapping, with automatic activation and complete Portal administration support.

**Architecture:** Store nullable `starts_at` values beside the existing expiration columns and carry them through REST, sync, audit, and Portal contracts. Keep future records in policy input, filter them in `PolicyEngine`, and shorten snapshot `refreshAfter` to the next applicable activation boundary so runtime clients refresh automatically without a scheduler or plugin contract change.

**Tech Stack:** Kotlin, Quarkus REST/OpenAPI, JDBC/PostgreSQL/Flyway, JUnit/REST Assured/Testcontainers, TypeScript, React, TanStack Query/Table, Kumo, Vitest/Testing Library.

## Global Constraints

- Apply `startsAt` to role grants, player-role grants, direct player grants, and Keycloak group mappings.
- A record is active when `(startsAt == null || startsAt <= now) && (expiresAt == null || now < expiresAt)`.
- Reject `startsAt >= expiresAt` when both boundaries are present.
- Existing nullable records remain immediately active; no backfill is allowed.
- Runtime and Minecraft plugin response contracts remain unchanged.
- Global sync carries start dates for role grants and Keycloak mappings; player-specific records remain project-local.
- Service changes must pass `./gradlew test`, `./gradlew spotlessApply`, and `./gradlew build` with escalated permissions.
- Portal changes must pass `npm run lint`, `npm test`, and `npm run build`.

---

### Task 1: Persist and evaluate temporal validity windows

**Files:**
- Create: `src/main/resources/db/migration/V8__add_permission_grant_start_dates.sql`
- Modify: `src/main/kotlin/gg/grounds/permissions/domain/PermissionModels.kt`
- Modify: `src/main/kotlin/gg/grounds/permissions/policy/PolicyEngine.kt`
- Test: `src/test/kotlin/gg/grounds/permissions/policy/PolicyEngineTest.kt`

**Interfaces:**
- Produces: nullable `startsAt: Instant?` on `PermissionGrant`, `PermissionGrantSpec`, `PlayerRoleGrant`, and `PlayerPermissionGrant.assignmentStartsAt`.
- Produces: policy helpers that exclude not-yet-started records and set `refreshAfter` to the earliest applicable future start.
- Consumed by: repository mapping and REST/sync tasks.

- [ ] **Step 1: Add failing policy tests for validity boundaries**

Add tests equivalent to:

```kotlin
@Test
fun `future direct grants are excluded until their inclusive start and schedule refresh`() {
    val startsAt = now.plusSeconds(90)
    val before = PolicyEngine.createSnapshot(playerId, inputWithDirectGrant(startsAt), now)
    assertFalse(PolicyEngine.hasPermission(before, "fly.use", PermissionCheckScope.global(), now))
    assertEquals(startsAt, before.refreshAfter)

    val atStart = PolicyEngine.createSnapshot(playerId, inputWithDirectGrant(startsAt), startsAt)
    assertTrue(PolicyEngine.hasPermission(atStart, "fly.use", PermissionCheckScope.global(), startsAt))
}
```

Cover direct player permission grants, direct player-role grants, group-mapped roles, and future role permission grants. Add a case proving irrelevant future grants do not shorten another player's refresh boundary.

- [ ] **Step 2: Run the targeted policy tests and verify the expected failures**

Run: `./gradlew test --tests gg.grounds.permissions.policy.PolicyEngineTest`

Expected: compilation or assertions fail because start boundaries do not exist or are not evaluated.

- [ ] **Step 3: Add the migration and domain fields**

Create the migration:

```sql
ALTER TABLE permission_role_grants ADD COLUMN starts_at TIMESTAMPTZ;
ALTER TABLE permission_player_role_grants ADD COLUMN starts_at TIMESTAMPTZ;
ALTER TABLE permission_player_grants ADD COLUMN starts_at TIMESTAMPTZ;
ALTER TABLE permission_keycloak_group_mappings ADD COLUMN starts_at TIMESTAMPTZ;
```

Add `startsAt` to grants/role assignments and `assignmentStartsAt` to `PlayerPermissionGrant` alongside `assignmentExpiresAt`.

- [ ] **Step 4: Implement policy activation and refresh-boundary calculation**

Introduce one shared validity predicate:

```kotlin
private fun isActive(startsAt: Instant?, expiresAt: Instant?, now: Instant): Boolean =
    (startsAt == null || !startsAt.isAfter(now)) &&
        (expiresAt == null || expiresAt.isAfter(now))
```

Filter assignments/grants through it. Collect applicable `startsAt` values strictly after `now` before filtering, then use:

```kotlin
refreshAfter =
    (listOf(input.refreshAfter) + futureActivationBoundaries)
        .minOrNull()
        ?: error("Snapshot refresh candidates must not be empty")
```

Keep expiration calculation limited to active records.

- [ ] **Step 5: Run the policy tests until green**

Run: `./gradlew test --tests gg.grounds.permissions.policy.PolicyEngineTest`

Expected: all `PolicyEngineTest` cases pass.

- [ ] **Step 6: Commit the temporal model**

```bash
git add src/main/resources/db/migration/V8__add_permission_grant_start_dates.sql src/main/kotlin/gg/grounds/permissions/domain/PermissionModels.kt src/main/kotlin/gg/grounds/permissions/policy/PolicyEngine.kt src/test/kotlin/gg/grounds/permissions/policy/PolicyEngineTest.kt
git commit -m "feat(permissions): schedule grant activation"
```

### Task 2: Carry start dates through persistence and REST/OpenAPI

**Files:**
- Modify: `src/main/kotlin/gg/grounds/permissions/persistence/PermissionRepository.kt`
- Modify: `src/main/kotlin/gg/grounds/permissions/rest/PermissionDtos.kt`
- Modify: `src/main/kotlin/gg/grounds/permissions/rest/PermissionValidation.kt`
- Modify: `src/main/kotlin/gg/grounds/permissions/rest/PermissionRoleResource.kt`
- Modify: `src/main/kotlin/gg/grounds/permissions/rest/PermissionPlayerResource.kt`
- Modify: `src/main/kotlin/gg/grounds/permissions/rest/PermissionGroupMappingResource.kt`
- Test: `src/test/kotlin/gg/grounds/permissions/persistence/PermissionRepositoryTest.kt`
- Test: `src/test/kotlin/gg/grounds/permissions/rest/PermissionRestResourceTest.kt`

**Interfaces:**
- Consumes: domain `startsAt` fields from Task 1.
- Produces: `startsAt` on all administration requests/responses and effective administration responses.
- Produces: `PermissionValidation.validityWindow(startsAt, expiresAt)`.

- [ ] **Step 1: Add failing repository and REST tests**

Extend CRUD round-trip fixtures for all four record types with `startsAt = Instant.parse("2029-01-01T00:00:00Z")`. Add REST assertions that create/update/list/search return the same value and that this request is rejected with HTTP 400:

```json
{
  "effect": "ALLOW",
  "permissionPattern": "grounds.command.fly",
  "startsAt": "2031-01-01T00:00:00Z",
  "expiresAt": "2030-01-01T00:00:00Z"
}
```

- [ ] **Step 2: Run targeted persistence and REST tests to verify failure**

Run:

```bash
./gradlew test --tests gg.grounds.permissions.persistence.PermissionRepositoryTest --tests gg.grounds.permissions.rest.PermissionRestResourceTest
```

Expected: compilation or response assertions fail because `startsAt` is absent.

- [ ] **Step 3: Extend records, SQL, row mappers, and policy loading**

Add `startsAt` immediately before `expiresAt` in every record. Update every insert, select, update, search projection, import statement, copy statement, and row mapper for the four affected tables. Map player permission assignments as:

```kotlin
PlayerPermissionGrant(
    playerId = rows.getObject("player_id", UUID::class.java),
    grant = rows.toGrantSpec(),
    assignmentStartsAt = rows.instantOrNull("starts_at"),
    assignmentExpiresAt = rows.instantOrNull("expires_at"),
    grantId = rows.getObject("id", UUID::class.java),
)
```

- [ ] **Step 4: Extend DTOs and central interval validation**

Add optional `startsAt` fields to request/response DTOs. Implement:

```kotlin
fun validityWindow(startsAt: Instant?, expiresAt: Instant?) {
    require(startsAt == null || expiresAt == null || startsAt.isBefore(expiresAt)) {
        "startsAt must be before expiresAt"
    }
}
```

Call it from every create/update conversion before repository mutation.

- [ ] **Step 5: Map effective responses and run targeted tests**

Return `startsAt` in `PlayerEffectiveRoleResponse` and `EffectiveGrantResponse` where their existing `expiresAt` is returned. Run the two targeted test classes until green.

- [ ] **Step 6: Commit persistence and REST support**

```bash
git add src/main/kotlin/gg/grounds/permissions/persistence/PermissionRepository.kt src/main/kotlin/gg/grounds/permissions/rest src/test/kotlin/gg/grounds/permissions/persistence/PermissionRepositoryTest.kt src/test/kotlin/gg/grounds/permissions/rest/PermissionRestResourceTest.kt
git commit -m "feat(api): expose permission grant start dates"
```

### Task 3: Preserve start dates in audit and environment sync

**Files:**
- Modify: `src/main/kotlin/gg/grounds/permissions/sync/PermissionSyncModels.kt`
- Modify: `src/main/kotlin/gg/grounds/permissions/sync/PermissionSnapshotFingerprint.kt`
- Modify: `src/main/kotlin/gg/grounds/permissions/sync/PermissionSyncPolicyProjection.kt`
- Modify: `src/main/kotlin/gg/grounds/permissions/persistence/PermissionRepository.kt`
- Test: `src/test/kotlin/gg/grounds/permissions/sync/PermissionSyncDiffTest.kt`
- Test: `src/test/kotlin/gg/grounds/permissions/rest/PermissionAuditResourceTest.kt`

**Interfaces:**
- Consumes: persisted start values from Task 2.
- Produces: `SyncRoleGrant.startsAt` and `SyncKeycloakMapping.startsAt` as optional schema-version-1 fields.
- Produces: canonical fingerprints and audit JSON that distinguish different start boundaries.

- [ ] **Step 1: Add failing sync and audit tests**

Add tests proving snapshots differing only in `startsAt` produce conflicts/fingerprint changes, imported role grants and mappings retain start values, and create/update audit payloads include:

```json
{"startsAt":"2029-01-01T00:00:00Z"}
```

- [ ] **Step 2: Run targeted tests and verify expected failures**

Run:

```bash
./gradlew test --tests gg.grounds.permissions.sync.PermissionSyncDiffTest --tests gg.grounds.permissions.rest.PermissionAuditResourceTest
```

- [ ] **Step 3: Extend sync models, normalization, fingerprinting, import, and audit payloads**

Add `startsAt` beside `expiresAt` in both transferable models. Include it in canonical JSON before `expiresAt`, repository snapshot mapping, import SQL, and audit serialization. Keep `schemaVersion = 1` because the JSON fields are optional and the coordinated service rollout accepts them.

- [ ] **Step 4: Run targeted tests until green**

Run the sync and audit test classes again and confirm all pass.

- [ ] **Step 5: Commit sync and audit support**

```bash
git add src/main/kotlin/gg/grounds/permissions/sync src/main/kotlin/gg/grounds/permissions/persistence/PermissionRepository.kt src/test/kotlin/gg/grounds/permissions/sync/PermissionSyncDiffTest.kt src/test/kotlin/gg/grounds/permissions/rest/PermissionAuditResourceTest.kt
git commit -m "feat(sync): preserve grant start dates"
```

### Task 4: Add Portal API contracts and validity-field behavior

**Files:**
- Modify: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/lib/api/minecraft-permissions.ts`
- Modify: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/expires-at-field.tsx`
- Test: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/lib/api/minecraft-permissions.test.tsx`
- Test: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/expires-at-field.test.tsx`

**Interfaces:**
- Produces: `startsAt: string | null` on Portal role-grant, player-role, player-grant, effective-grant, and mapping types.
- Produces: mutation inputs that normalize both date fields to ISO strings.
- Produces: `StartsAtField` and `validityIntervalValidationMessage(startsAt, expiresAt)` while preserving `ExpiresAtField` behavior.

- [ ] **Step 1: Create the isolated Portal worktree**

From `/home/lukas/grounds/grounds-portal`, fetch `origin/main` and create branch `feat/grant-start-dates` at `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates`. Run `npm ci`.

- [ ] **Step 2: Add failing API and date-field tests**

Assert mutation bodies include `startsAt` and response fixtures retain it. Add boundary-field tests showing a past start is valid, a malformed start reports `Start is invalid.`, and `startsAt >= expiresAt` reports `Start must be before expiration.`.

- [ ] **Step 3: Run targeted Portal tests to verify failure**

Run:

```bash
npx vitest run src/lib/api/minecraft-permissions.test.tsx src/components/minecraft-permissions/expires-at-field.test.tsx
```

- [ ] **Step 4: Extend API contracts and generalize the date picker**

Use one internal picker implementation with configurable label, validation, and default value. Export wrappers:

```tsx
export function StartsAtField(props: ValidityDateFieldProps) {
  return <ValidityDateField {...props} boundary="start" />;
}

export function ExpiresAtField(props: ValidityDateFieldProps) {
  return <ValidityDateField {...props} boundary="expiration" />;
}
```

Keep expiration's future-only validation; start validation checks only parse validity so active grants remain editable. Normalize both API values with one nullable-instant helper.

- [ ] **Step 5: Run targeted tests until green and commit**

```bash
git add src/lib/api/minecraft-permissions.ts src/lib/api/minecraft-permissions.test.tsx src/components/minecraft-permissions/expires-at-field.tsx src/components/minecraft-permissions/expires-at-field.test.tsx
git commit -m "feat(permissions): support grant start dates"
```

### Task 5: Expose start dates in Portal dialogs and tables

**Files:**
- Modify: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/permission-grant-dialog.tsx`
- Modify: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/players/player-role-grant-dialog.tsx`
- Modify: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/players/player-permission-grant-dialog.tsx`
- Modify: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/minecraft-permissions-admin-page.tsx`
- Modify: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/minecraft-permission-server-tables.tsx`
- Modify: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/players/player-role-grants-table.tsx`
- Modify: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/players/player-permission-grants-table.tsx`
- Modify: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/players/player-effective-access-table.tsx`
- Modify: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/players/player-access-format.tsx`
- Test: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/minecraft-permissions-admin-page.test.tsx`
- Test: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/minecraft-permission-server-tables.test.tsx`
- Test: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/players/player-detail-panel.test.tsx`
- Test: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/players/player-detail-panel.integration.test.tsx`
- Test: `/home/lukas/grounds/.worktrees/grounds-portal-grant-start-dates/src/components/minecraft-permissions/players/minecraft-permissions-players-page.test.tsx`

**Interfaces:**
- Consumes: API types and `StartsAtField` from Task 4.
- Produces: start-date create/edit fields for all four assignment types and sortable start columns in all relevant tables.

- [ ] **Step 1: Add failing dialog and table tests**

For each grant type, open create/edit, select or enter a start, submit, and assert the mutation receives the ISO instant. Add one invalid-window assertion and table assertions for future, past, and null start values.

- [ ] **Step 2: Run the focused component tests and verify failure**

Run the affected component and integration test files with `npx vitest run`.

- [ ] **Step 3: Add start state and interval validation to dialogs**

Initialize edit state with `formatLocalDateTime(new Date(grant.startsAt))`, submit ISO values, and block submission when either field or the interval is invalid. Render fields together so their relationship is visible.

- [ ] **Step 4: Add start formatting and table columns**

Render null starts as `Immediately`, valid timestamps with the existing localized date-time style, and malformed server values as `Invalid start`. Add sortable `start` columns before expiration to role grants, mappings, player roles, direct permissions, and effective permissions.

- [ ] **Step 5: Run focused component tests until green and commit**

```bash
git add src/components/minecraft-permissions
git commit -m "feat(permissions): manage grant start dates"
```

### Task 6: Verify both repositories and review the complete diff

**Files:**
- Verify all modified service and Portal files.
- Update plan checkboxes as each task completes.

**Interfaces:**
- Consumes: all service and Portal deliverables.
- Produces: two clean, independently publishable feature branches.

- [ ] **Step 1: Run complete service verification with escalated permissions**

Run in the service worktree:

```bash
./gradlew test
./gradlew spotlessApply
./gradlew build
```

If Spotless changes files, commit them with the service branch's final implementation commit and rerun test/build.

- [ ] **Step 2: Run complete Portal verification**

Run in the Portal worktree:

```bash
npm run lint
npm test
npm run build
```

- [ ] **Step 3: Review repository state and compatibility**

Confirm `git diff --check`, intentional files only, migration number `V8`, optional REST fields, no runtime/plugin DTO change, and no edits in unrelated dirty checkouts.

- [ ] **Step 4: Commit plan completion metadata**

Mark completed checkboxes and commit the plan update on the service branch:

```bash
git add docs/superpowers/plans/2026-07-30-grant-start-dates.md
git commit -m "docs(permissions): record start date implementation"
```
