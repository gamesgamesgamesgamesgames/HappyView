CREATE TABLE IF NOT EXISTS space_sync_state (
    id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    member_did TEXT NOT NULL,
    cursor TEXT,
    last_synced_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    UNIQUE(space_id, member_did)
);

CREATE INDEX idx_space_sync_state_space_id ON space_sync_state(space_id);
