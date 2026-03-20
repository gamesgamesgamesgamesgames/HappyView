-- OAuth state for external auth flows (e.g., Steam OpenID)
CREATE TABLE external_auth_state (
    state TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

-- Index for cleanup of expired state
CREATE INDEX idx_external_auth_state_expires ON external_auth_state(expires_at);
