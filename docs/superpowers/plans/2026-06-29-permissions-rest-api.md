# Permissions REST API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Portal-facing CRUD REST API for Minecraft network permissions in `service-permissions`.

**Architecture:** Add Quarkus REST/Jackson endpoints under `/v1/permissions` backed by JDBC repositories and explicit transactions. The same database-backed policy provider feeds the existing gRPC snapshot service so Portal writes and runtime reads use one source of truth.

**Tech Stack:** Kotlin, Quarkus REST/Jackson, JDBC/PostgreSQL, Flyway, Quarkus tests with RestAssured/Testcontainers, existing policy engine.

---

### Task 1: REST and Test Dependencies

**Files:**
- Modify: `build.gradle.kts`

- [ ] Add `quarkus-rest`, `quarkus-rest-jackson`, `quarkus-jackson`, `quarkus-agroal`, and `io.rest-assured:rest-assured`.
- [ ] Run `./gradlew test` and confirm the existing tests still pass.

### Task 2: Database Repository and Policy Provider

**Files:**
- Create: `src/main/kotlin/gg/grounds/permissions/persistence/PermissionRepository.kt`
- Modify: `src/main/kotlin/gg/grounds/permissions/api/PermissionPolicyProvider.kt`
- Test: `src/test/kotlin/gg/grounds/permissions/persistence/PermissionRepositoryTest.kt`

- [ ] Write failing tests for creating/listing roles, grants, mappings, catalog entries, policy version increments, and effective policy input.
- [ ] Implement JDBC repository methods for roles, inheritance, role grants, player role grants, player grants, Keycloak group mappings, catalog entries, audit events, and policy version.
- [ ] Replace the empty production `PermissionPolicyProvider` with a DB-backed implementation.
- [ ] Run focused repository tests and then `./gradlew test`.

### Task 3: REST DTO Validation

**Files:**
- Create: `src/main/kotlin/gg/grounds/permissions/rest/PermissionDtos.kt`
- Create: `src/main/kotlin/gg/grounds/permissions/rest/PermissionValidation.kt`
- Test: `src/test/kotlin/gg/grounds/permissions/rest/PermissionValidationTest.kt`

- [ ] Write failing tests for invalid role keys, invalid permission patterns, invalid scope/value combinations, blank labels, and invalid UUIDs.
- [ ] Implement DTOs and validation helpers shared by REST resources.
- [ ] Run validation tests.

### Task 4: Role, Inheritance, Grant, and Catalog CRUD

**Files:**
- Create: `src/main/kotlin/gg/grounds/permissions/rest/PermissionRoleResource.kt`
- Create: `src/main/kotlin/gg/grounds/permissions/rest/PermissionCatalogResource.kt`
- Test: `src/test/kotlin/gg/grounds/permissions/rest/PermissionRoleResourceTest.kt`
- Test: `src/test/kotlin/gg/grounds/permissions/rest/PermissionCatalogResourceTest.kt`

- [ ] Write failing REST tests for role create/list/get/update/delete.
- [ ] Write failing REST tests for inheritance add/delete with cycle rejection.
- [ ] Write failing REST tests for role grant create/list/update/delete with temporary grants.
- [ ] Write failing REST tests for catalog list/custom create/update/delete.
- [ ] Implement resources with repository transactions, policy version increments on writes, and audit events.
- [ ] Run focused REST tests.

### Task 5: Player Grants, Keycloak Group Mappings, and Effective Snapshot

**Files:**
- Create: `src/main/kotlin/gg/grounds/permissions/rest/PermissionPlayerResource.kt`
- Create: `src/main/kotlin/gg/grounds/permissions/rest/PermissionGroupMappingResource.kt`
- Test: `src/test/kotlin/gg/grounds/permissions/rest/PermissionPlayerResourceTest.kt`
- Test: `src/test/kotlin/gg/grounds/permissions/rest/PermissionGroupMappingResourceTest.kt`

- [ ] Write failing REST tests for player role grant create/list/delete.
- [ ] Write failing REST tests for player permission grant create/list/update/delete.
- [ ] Write failing REST tests for Keycloak group mapping create/list/update/delete.
- [ ] Write failing REST tests for `GET /v1/permissions/players/{playerId}/effective`.
- [ ] Implement resources and effective snapshot conversion.
- [ ] Run focused REST tests.

### Task 6: Full Verification and PR

**Files:**
- All modified files

- [ ] Run `./gradlew test`.
- [ ] Run `./gradlew spotlessApply`.
- [ ] Run `./gradlew build`.
- [ ] Commit with a Conventional Commit.
- [ ] Push and open a PR.
