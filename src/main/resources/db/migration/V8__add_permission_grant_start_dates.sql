ALTER TABLE permission_role_grants
    ADD COLUMN starts_at TIMESTAMPTZ,
    ADD CONSTRAINT permission_role_grants_validity_window
        CHECK (starts_at IS NULL OR expires_at IS NULL OR starts_at < expires_at);

ALTER TABLE permission_player_role_grants
    ADD COLUMN starts_at TIMESTAMPTZ,
    ADD CONSTRAINT permission_player_role_grants_validity_window
        CHECK (starts_at IS NULL OR expires_at IS NULL OR starts_at < expires_at);

ALTER TABLE permission_player_grants
    ADD COLUMN starts_at TIMESTAMPTZ,
    ADD CONSTRAINT permission_player_grants_validity_window
        CHECK (starts_at IS NULL OR expires_at IS NULL OR starts_at < expires_at);

ALTER TABLE permission_keycloak_group_mappings
    ADD COLUMN starts_at TIMESTAMPTZ,
    ADD CONSTRAINT permission_keycloak_group_mappings_validity_window
        CHECK (starts_at IS NULL OR expires_at IS NULL OR starts_at < expires_at);
