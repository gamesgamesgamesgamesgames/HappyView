CREATE TABLE IF NOT EXISTS space_members (
    id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    member_did TEXT NOT NULL,
    access TEXT NOT NULL DEFAULT 'read',
    is_delegation INTEGER NOT NULL DEFAULT 0,
    granted_by TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(space_id, member_did)
);

CREATE INDEX idx_space_members_did ON space_members(member_did);
CREATE INDEX idx_space_members_space_id ON space_members(space_id);
