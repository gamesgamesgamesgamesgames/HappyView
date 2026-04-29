CREATE TABLE IF NOT EXISTS space_invites (
    id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    access TEXT NOT NULL DEFAULT 'read',
    max_uses INTEGER,
    uses INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_space_invites_space_id ON space_invites(space_id);
