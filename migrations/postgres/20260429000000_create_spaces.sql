CREATE TABLE IF NOT EXISTS spaces (
    id TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL,
    type_nsid TEXT NOT NULL,
    skey TEXT NOT NULL,
    display_name TEXT,
    description TEXT,
    access_mode TEXT NOT NULL DEFAULT 'default_allow',
    app_allowlist TEXT,
    app_denylist TEXT,
    managing_app_did TEXT,
    config TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(owner_did, type_nsid, skey)
);

CREATE INDEX idx_spaces_owner_did ON spaces(owner_did);
CREATE INDEX idx_spaces_type_nsid ON spaces(type_nsid);
