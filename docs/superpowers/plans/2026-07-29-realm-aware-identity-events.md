# Realm-aware Identity Events Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver Keycloak identity events that carry both the internal realm ID and realm name so `service-permissions` refreshes matching players and publishes live snapshot invalidations.

**Architecture:** The Keycloak listener remains authoritative for admitting configured internal realm IDs and enriches accepted events with Keycloak's realm name. `service-permissions` keeps accepting legacy ID-only events while matching new events by either ID or name, preserving retained-message and rolling-release compatibility.

**Tech Stack:** Kotlin, Gradle, Keycloak Event Listener SPI, Jackson, Quarkus, JUnit 5, MockK, Mockito Kotlin, NATS JetStream

## Global Constraints

- Keep `realmId` as the internal Keycloak realm identifier.
- Add optional `realmName` without rejecting legacy events that omit it.
- Never admit Keycloak events by realm name inside the listener; configured internal IDs remain the publisher security boundary.
- Preserve explicit JetStream acknowledgement and retry behavior.
- All new or changed logs must follow `<action> <result> (key=value)` and must not contain secrets.
- After code changes in each repository, run `./gradlew test`, `./gradlew spotlessApply`, and `./gradlew build` with escalated permissions.

---

### Task 1: Enrich Keycloak identity events with the realm name

**Files:**
- Modify: `keycloak-permissions-event-listener/src/test/kotlin/gg/grounds/keycloak/permissions/events/PermissionsEventListenerProviderTest.kt`
- Modify: `keycloak-permissions-event-listener/src/test/kotlin/gg/grounds/keycloak/permissions/events/NatsIdentityChangePublisherTest.kt`
- Modify: `keycloak-permissions-event-listener/src/main/kotlin/gg/grounds/keycloak/permissions/events/MinecraftIdentityChangedEvent.kt`
- Modify: `keycloak-permissions-event-listener/src/main/kotlin/gg/grounds/keycloak/permissions/events/PermissionsEventListenerProvider.kt`
- Modify: `keycloak-permissions-event-listener/README.md`

**Interfaces:**
- Consumes: Keycloak `Event.realmId`, `Event.realmName`, `AdminEvent.realmId`, and `AdminEvent.realmName`.
- Produces: `MinecraftIdentityChangedEvent(realmId: String, realmName: String?, keycloakUserId: String, reason: String)` serialized on `minecraft-identity.changed`.

- [ ] **Step 1: Write failing listener contract tests**

Update the provider tests so a committed event with `realmId = "realm-uuid"` and `realmName = "grounds"` must publish both values. Keep the existing colliding-name test and assert it publishes nothing when only the name matches a configured realm ID.

Update the NATS publisher test to construct:

```kotlin
MinecraftIdentityChangedEvent(
    realmId = "realm-uuid",
    realmName = "grounds",
    keycloakUserId = "user-1",
    reason = "identity_refreshed",
)
```

and assert the JSON field set is exactly `realmId`, `realmName`, `keycloakUserId`, and `reason`.

- [ ] **Step 2: Verify the listener tests fail for the missing field**

Run:

```bash
./gradlew test --tests gg.grounds.keycloak.permissions.events.PermissionsEventListenerProviderTest --tests gg.grounds.keycloak.permissions.events.NatsIdentityChangePublisherTest
```

Expected: compilation or assertion failure because `MinecraftIdentityChangedEvent` does not expose `realmName` and emitted JSON contains only three fields.

- [ ] **Step 3: Implement the minimal publisher change**

Add `val realmName: String? = null` to the event DTO. Pass both realm identifiers through `schedule(...)` and `PendingIdentityChanges`; deduplicate by internal realm ID and user ID while retaining the realm name in the pending value. Do not change `matchesRealm`, which must continue checking only `configuredRealmIds` against `realmId`.

Update the README payload example and field description to document both identifiers and the listener's ID-only admission boundary.

- [ ] **Step 4: Verify targeted listener tests pass**

Run the command from Step 2. Expected: both test classes pass.

- [ ] **Step 5: Commit the listener change**

```bash
git add README.md src/main/kotlin/gg/grounds/keycloak/permissions/events/MinecraftIdentityChangedEvent.kt src/main/kotlin/gg/grounds/keycloak/permissions/events/PermissionsEventListenerProvider.kt src/test/kotlin/gg/grounds/keycloak/permissions/events/NatsIdentityChangePublisherTest.kt src/test/kotlin/gg/grounds/keycloak/permissions/events/PermissionsEventListenerProviderTest.kt
git commit -m "fix(events): include realm name in identity changes"
```

### Task 2: Match identity events by realm ID or realm name

**Files:**
- Modify: `service-permissions/src/test/kotlin/gg/grounds/permissions/identity/IdentityChangeConsumerTest.kt`
- Modify: `service-permissions/src/main/kotlin/gg/grounds/permissions/identity/MinecraftIdentityChangedEvent.kt`
- Modify: `service-permissions/src/main/kotlin/gg/grounds/permissions/identity/IdentityChangeConsumer.kt`

**Interfaces:**
- Consumes: JSON identity events with required `realmId`, optional `realmName`, required `keycloakUserId`, and required `reason`.
- Produces: one `IdentitySyncCoordinator.refreshPlayer(keycloakUserId)` call for events whose ID or name matches the configured realm.

- [ ] **Step 1: Write failing consumer compatibility tests**

Add tests proving:

```kotlin
// New publisher: internal ID differs, configured realm name matches.
validPayload(realmId = "realm-uuid", realmName = "grounds")

// Legacy publisher: realmName omitted, configured realm ID matches.
validPayload(realmId = "grounds", realmName = null)

// Neither identifier matches.
validPayload(realmId = "other-id", realmName = "other-name")
```

The first two deliveries must refresh and acknowledge. The third must acknowledge without refresh. Add a present-but-blank `realmName` payload that terminates as invalid input.

- [ ] **Step 2: Verify the consumer tests fail for missing name matching**

Run:

```bash
./gradlew test --tests gg.grounds.permissions.identity.IdentityChangeConsumerTest
```

Expected: compilation failure until `realmName` exists, then the name-match assertion fails until consumer matching is updated.

- [ ] **Step 3: Implement the minimal consumer change**

Add `val realmName: String? = null` to the service DTO. Replace the equality check with a focused predicate that accepts `configuredRealm == event.realmId || configuredRealm == event.realmName`. Extend validation so a non-null `realmName` must be non-blank while omission remains valid.

- [ ] **Step 4: Verify targeted consumer tests pass**

Run the command from Step 2. Expected: all `IdentityChangeConsumerTest` tests pass.

- [ ] **Step 5: Commit the service change and design documents**

```bash
git add src/main/kotlin/gg/grounds/permissions/identity/MinecraftIdentityChangedEvent.kt src/main/kotlin/gg/grounds/permissions/identity/IdentityChangeConsumer.kt src/test/kotlin/gg/grounds/permissions/identity/IdentityChangeConsumerTest.kt docs/superpowers
git commit -m "fix(identity): match events by realm name"
```

### Task 3: Full verification and publication

**Files:**
- Verify all modified files in both worktrees.

**Interfaces:**
- Consumes: the committed publisher and consumer changes from Tasks 1 and 2.
- Produces: two reviewable GitHub branches and pull requests with independently green Gradle builds.

- [ ] **Step 1: Run full Keycloak-listener verification**

```bash
./gradlew test
./gradlew spotlessApply
./gradlew build
git diff --check
```

Expected: all commands succeed and formatting introduces no uncommitted semantic changes.

- [ ] **Step 2: Run full service verification**

Run the same four commands in the service worktree. Expected: all commands succeed.

- [ ] **Step 3: Review repository diffs and commit formatting changes**

Inspect `git status -sb`, `git diff`, and `git diff origin/main...HEAD` in each worktree. Stage only task-owned files. If `spotlessApply` changed tracked files after the task commits, amend or add a focused Conventional Commit.

- [ ] **Step 4: Push both branches and open pull requests**

Push `fix/realm-aware-identity-events` in both repositories. Open PRs describing the live reproduction, the ID/name mismatch, compatibility behavior, test evidence, and required release order: service first or together, listener before final runtime verification.

- [ ] **Step 5: Verify CI and prepare the release chain**

Watch all PR checks. After merge and releases, update the Keycloak container and the `service-permissions` pins in their actual deployment sources, restart affected workloads, and repeat the online-player group-change test without `/permissions user <name> refresh`.
