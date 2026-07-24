-- A grant may now be pinned to a deployment environment (`stage`, `prod`) as
-- well as to a server type or a single server. The two scope_kind CHECKs were
-- created inline in V1, so they carry generated names; look them up by
-- definition rather than guessing.
DO $$
DECLARE
    constraint_row record;
BEGIN
    FOR constraint_row IN
        SELECT conrelid::regclass AS table_name, conname
        FROM pg_constraint
        WHERE contype = 'c'
          AND conrelid IN (
              'permission_role_grants'::regclass,
              'permission_player_grants'::regclass
          )
          AND pg_get_constraintdef(oid) LIKE '%scope_kind%'
          AND pg_get_constraintdef(oid) LIKE '%SERVER_TYPE%'
    LOOP
        EXECUTE format(
            'ALTER TABLE %s DROP CONSTRAINT %I',
            constraint_row.table_name,
            constraint_row.conname
        );
    END LOOP;
END $$;

ALTER TABLE permission_role_grants
    ADD CONSTRAINT permission_role_grants_scope_kind_check
    CHECK (scope_kind IN ('GLOBAL', 'ENVIRONMENT', 'SERVER_TYPE', 'SERVER'));

ALTER TABLE permission_player_grants
    ADD CONSTRAINT permission_player_grants_scope_kind_check
    CHECK (scope_kind IN ('GLOBAL', 'ENVIRONMENT', 'SERVER_TYPE', 'SERVER'));
