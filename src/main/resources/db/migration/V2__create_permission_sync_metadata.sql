CREATE TABLE permission_sync_metadata (
    snapshot_id TEXT PRIMARY KEY,
    actor_user_id TEXT NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX permission_sync_metadata_imported_at_desc_idx
    ON permission_sync_metadata (imported_at DESC);
