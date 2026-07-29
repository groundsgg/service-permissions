# Realm-aware identity events

## Problem

The Keycloak event listener publishes the internal Keycloak realm ID in
`minecraft-identity.changed`. `service-permissions` is configured with the realm name because that
name is required for Keycloak Admin API paths. The consumer currently compares those two different
identifiers, acknowledges the event as belonging to another realm, and never refreshes the player
identity or publishes `permissions.snapshot.invalidated`.

## Event contract

`minecraft-identity.changed` retains its existing fields and adds an optional `realmName` field:

```json
{
  "realmId": "internal-keycloak-realm-id",
  "realmName": "grounds",
  "keycloakUserId": "user-id",
  "reason": "group_membership_changed"
}
```

`realmId` remains the authoritative internal Keycloak identifier. `realmName` is the realm name
used by Keycloak API clients and deployment configuration. Keeping both values avoids changing the
meaning of the existing field and supports consumers that know either identifier.

Events without `realmName` remain valid so retained events and older publishers stay compatible.
When present, `realmName` must not be blank.

## Publisher behavior

The Keycloak listener continues filtering events exclusively by configured internal realm IDs. It
adds the realm name supplied by Keycloak to each event after the surrounding Keycloak transaction
commits. Realm names do not participate in the listener's admission check, preserving the existing
protection against an unconfigured realm with a colliding name.

Events from the same realm and user remain deduplicated within one transaction. The deduplication
key stays the internal realm ID plus user ID; the matching realm name is carried in the pending
event data.

## Consumer behavior

`service-permissions` accepts an event when its configured realm matches either `realmId` or
`realmName`. It acknowledges and ignores events that match neither. Accepted events keep the
existing flow: refresh the current Keycloak identity, persist effective projection changes,
publish `permissions.snapshot.invalidated`, and acknowledge only after successful processing.

Invalid JSON, blank required fields, or a present-but-blank `realmName` remains terminal invalid
input. Transient refresh or invalidation publication failures remain negatively acknowledged for
retry.

## Verification and rollout

Both repositories use test-first changes. The listener tests prove the emitted JSON includes both
realm identifiers and that name collisions are still rejected. The service tests prove name-based
acceptance, ID-based backward compatibility, mismatched-realm rejection, and old payload support.

After targeted tests pass, each Gradle repository must pass `./gradlew test`,
`./gradlew spotlessApply`, and `./gradlew build`. The listener and service are released separately;
the service may deploy before the listener because it remains compatible with old events. The new
listener must deploy before live name-based matching can occur. Runtime verification changes a
Keycloak group for an online player and confirms the effective permissions change without running
the manual refresh command.
