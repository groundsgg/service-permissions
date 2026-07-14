CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE permission_player_identities (
    player_id UUID PRIMARY KEY,
    keycloak_user_id TEXT UNIQUE NOT NULL,
    minecraft_username TEXT NOT NULL,
    minecraft_username_normalized TEXT NOT NULL,
    synced_at TIMESTAMPTZ NOT NULL,
    source_updated_at TIMESTAMPTZ
);

CREATE INDEX permission_player_identities_username_prefix_idx
    ON permission_player_identities (minecraft_username_normalized text_pattern_ops);
CREATE INDEX permission_player_identities_username_trgm_idx
    ON permission_player_identities USING gin (minecraft_username_normalized gin_trgm_ops);

CREATE TABLE permission_player_keycloak_groups (
    player_id UUID NOT NULL REFERENCES permission_player_identities(player_id) ON DELETE CASCADE,
    keycloak_group_path TEXT NOT NULL,
    PRIMARY KEY (player_id, keycloak_group_path)
);

CREATE INDEX permission_player_keycloak_groups_path_idx
    ON permission_player_keycloak_groups (keycloak_group_path);

CREATE TABLE permission_identity_sync_state (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    status TEXT NOT NULL CHECK (status IN ('IDLE', 'RUNNING', 'FAILED')),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    duration_ms BIGINT,
    player_count BIGINT NOT NULL DEFAULT 0,
    failure_reason TEXT
);

INSERT INTO permission_identity_sync_state (id, status) VALUES (1, 'IDLE');
