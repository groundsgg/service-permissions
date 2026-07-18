CREATE INDEX permission_audit_events_action_created_at_desc_idx
    ON permission_audit_events (action, created_at DESC, id DESC);

CREATE INDEX permission_audit_events_actor_created_at_desc_idx
    ON permission_audit_events (actor_user_id, created_at DESC, id DESC);
