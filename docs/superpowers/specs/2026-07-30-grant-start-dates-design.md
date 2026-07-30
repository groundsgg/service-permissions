# Permission Grant Start Dates Design

## Goal

Allow administrators to schedule permission grants and role mappings with an optional start date, in addition to the existing optional expiration date. Scheduled access must become effective automatically at the configured instant without a database job, manual refresh, or server restart.

## Scope

The change applies consistently to every persisted permission assignment that currently supports `expiresAt`:

- permission grants assigned to roles;
- roles assigned directly to players;
- permission grants assigned directly to players; and
- Keycloak group-to-role mappings.

Existing records remain valid and immediately active because their new `startsAt` column is nullable.

## Temporal Semantics

Each assignment has a half-open validity interval:

```text
(startsAt is null or startsAt <= now)
and
(expiresAt is null or now < expiresAt)
```

The start instant is inclusive and the expiration instant is exclusive. When both values are present, write APIs reject `startsAt >= expiresAt` with the existing bad-request error format. A missing start means immediate activation; a missing expiration means no scheduled end.

Administrative list and search APIs return scheduled, active, and expired records. Effective-role, effective-permission, permission-check, and runtime snapshot responses only include records active at the evaluation instant.

## Service Architecture

### Persistence

A forward-only Flyway migration adds nullable `starts_at TIMESTAMPTZ` columns to:

- `permission_role_grants`;
- `permission_player_role_grants`;
- `permission_player_grants`; and
- `permission_keycloak_group_mappings`.

Repository record types, CRUD statements, row mappers, audit payloads, search projections, sync import/export statements, and test fixtures carry `startsAt`. Existing ordering and uniqueness constraints remain unchanged.

### REST and OpenAPI

`GrantRequest`, `PlayerRoleGrantRequest`, and `KeycloakGroupMappingRequest` accept an optional `startsAt`. Their corresponding responses return it. Effective grant and effective role responses also expose the contributing assignment's start where the response represents one concrete temporal source.

One shared validation function enforces the interval relationship for all write endpoints. This prevents the four resource implementations from drifting.

### Policy Evaluation and Runtime Refresh

Domain grant and assignment models carry `startsAt`. The policy engine excludes any grant or assignment whose start lies after `now`, just as it already excludes expired records.

Future assignments still enter the policy input so the engine can calculate the next activation boundary. Snapshot `refreshAfter` becomes the earliest of:

- the repository's normal five-minute refresh time; and
- every `startsAt` later than the evaluation instant that could affect the player.

Only starts from applicable player assignments, group mappings, resolved roles, and their permission grants influence that player's refresh time. Active expiration handling remains unchanged. The existing policy-version invalidation handles create, update, and delete operations; the shortened `refreshAfter` handles passage of time without requiring another event.

Runtime and Minecraft plugin contracts do not gain `startsAt`: they continue receiving only currently effective grants plus the snapshot refresh boundary.

### Global-to-Project Sync

`startsAt` is part of role-grant and Keycloak-mapping sync models, canonical fingerprints, diff comparisons, preview output, and import statements. A difference in only `startsAt` is therefore an update, not an unchanged entity. Player-specific grants are not part of global imports and retain their existing project-local behavior.

## Portal Experience

Portal API types and mutation payloads carry `startsAt` for all four assignment types.

The existing date-time picker behavior is reused through a neutral validity-boundary component rather than duplicating a second bespoke picker. Grant dialogs show optional **Starts** and **Expires** fields together. They accept local date-time input and send ISO-8601 instants. Client validation reports malformed values and rejects a start at or after expiration, while still allowing an already-passed start when editing an active assignment.

Role-grant, player-role, player-permission, effective-access, and Keycloak-mapping tables expose the start instant alongside expiration. Empty values render as immediate activation. Future values make the scheduled state visible without hiding the record.

## Error Handling

- Invalid timestamps continue to be rejected by JSON deserialization as bad requests.
- Invalid intervals return a stable message: `startsAt must be before expiresAt`.
- Portal mutation errors use the existing dialog error surface and preserve the user's entered interval.
- No background scheduler or new operational dependency is introduced.

## Testing

Service tests cover:

- migration and CRUD round trips for all four tables;
- REST request and response fields plus invalid interval rejection;
- start-inclusive and expiration-exclusive policy boundaries;
- exclusion of future direct, role-derived, and group-mapped access;
- `refreshAfter` shortening to the earliest relevant future activation;
- sync fingerprint, diff, preview, and import behavior; and
- audit payload inclusion.

Portal tests cover:

- API normalization and payloads;
- picker parsing and interval validation;
- create and edit dialogs for all four assignment types;
- start-date table rendering; and
- preservation of existing expiration-only behavior.

## Rollout and Compatibility

Deploy the service migration and API before deploying the Portal change. Nullable columns and optional JSON fields make the service update compatible with the existing Portal. The new Portal requires a service version that understands `startsAt`; the release and deployment pins must therefore roll forward service first and Portal second.

No data backfill is required. No plugin release is required.

## Non-goals

- recurring schedules;
- timezone selection separate from the browser-local input and UTC API representation;
- delayed database insertion or deletion;
- notification delivery at activation time; and
- changing the current expiration semantics.
