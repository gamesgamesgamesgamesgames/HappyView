CREATE TABLE IF NOT EXISTS space_dids (
    id TEXT PRIMARY KEY,
    did TEXT NOT NULL UNIQUE,
    space_id TEXT REFERENCES spaces(id) ON DELETE SET NULL,
    signing_key_enc BLOB NOT NULL,
    rotation_key_enc BLOB NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_space_dids_did ON space_dids(did);
CREATE INDEX idx_space_dids_space_id ON space_dids(space_id);
