ALTER TABLE permission_role_grants ADD COLUMN starts_at TIMESTAMPTZ;
ALTER TABLE permission_player_role_grants ADD COLUMN starts_at TIMESTAMPTZ;
ALTER TABLE permission_player_grants ADD COLUMN starts_at TIMESTAMPTZ;
ALTER TABLE permission_keycloak_group_mappings ADD COLUMN starts_at TIMESTAMPTZ;
