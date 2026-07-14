CREATE TABLE permission_player_identity_tombstones (
    keycloak_user_id TEXT PRIMARY KEY,
    deleted_at TIMESTAMPTZ NOT NULL
);
