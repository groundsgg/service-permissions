CREATE TABLE permission_roles (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    prefix TEXT,
    color TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX permission_roles_single_default
    ON permission_roles (is_default)
    WHERE is_default = TRUE;

CREATE TABLE permission_role_inheritance (
    parent_role_key TEXT NOT NULL REFERENCES permission_roles(key) ON DELETE CASCADE,
    child_role_key TEXT NOT NULL REFERENCES permission_roles(key) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (parent_role_key, child_role_key),
    CHECK (parent_role_key <> child_role_key)
);

CREATE INDEX permission_role_inheritance_child_role_key_idx
    ON permission_role_inheritance (child_role_key);

CREATE TABLE permission_role_grants (
    id UUID PRIMARY KEY,
    role_key TEXT NOT NULL REFERENCES permission_roles(key) ON DELETE CASCADE,
    effect TEXT NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
    permission_pattern TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('GLOBAL', 'SERVER_TYPE', 'SERVER')),
    scope_value TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((scope_kind = 'GLOBAL' AND scope_value IS NULL) OR (scope_kind <> 'GLOBAL' AND scope_value IS NOT NULL))
);

CREATE INDEX permission_role_grants_role_key_idx
    ON permission_role_grants (role_key);

CREATE TABLE permission_player_role_grants (
    id UUID PRIMARY KEY,
    player_id UUID NOT NULL,
    role_key TEXT NOT NULL REFERENCES permission_roles(key) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX permission_player_role_grants_player_id_idx
    ON permission_player_role_grants (player_id);

CREATE INDEX permission_player_role_grants_role_key_idx
    ON permission_player_role_grants (role_key);

CREATE TABLE permission_player_grants (
    id UUID PRIMARY KEY,
    player_id UUID NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
    permission_pattern TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('GLOBAL', 'SERVER_TYPE', 'SERVER')),
    scope_value TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((scope_kind = 'GLOBAL' AND scope_value IS NULL) OR (scope_kind <> 'GLOBAL' AND scope_value IS NOT NULL))
);

CREATE INDEX permission_player_grants_player_id_idx
    ON permission_player_grants (player_id);

CREATE TABLE permission_keycloak_group_mappings (
    id UUID PRIMARY KEY,
    keycloak_group TEXT NOT NULL,
    role_key TEXT NOT NULL REFERENCES permission_roles(key) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (keycloak_group, role_key)
);

CREATE INDEX permission_keycloak_group_mappings_keycloak_group_idx
    ON permission_keycloak_group_mappings (keycloak_group);

CREATE TABLE permission_catalog_entries (
    permission_key TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    source_version TEXT NOT NULL,
    supported_scopes TEXT[] NOT NULL,
    custom BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permission_runtime_registrations (
    id UUID PRIMARY KEY,
    source TEXT NOT NULL,
    source_version TEXT NOT NULL,
    server_type TEXT,
    server_id TEXT,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permission_policy_versions (
    id INTEGER PRIMARY KEY DEFAULT 1,
    version BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (id = 1)
);

INSERT INTO permission_policy_versions (id, version) VALUES (1, 1);

CREATE TABLE permission_audit_events (
    id UUID PRIMARY KEY,
    actor_user_id TEXT,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX permission_audit_events_created_at_desc_idx
    ON permission_audit_events (created_at DESC);
