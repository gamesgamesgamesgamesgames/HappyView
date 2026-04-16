CREATE TABLE IF NOT EXISTS dpop_sessions (
    id TEXT PRIMARY KEY,
    api_client_id TEXT NOT NULL REFERENCES api_clients(id) ON DELETE CASCADE,
    dpop_key_id TEXT NOT NULL REFERENCES dpop_keys(id) ON DELETE CASCADE,
    user_did TEXT NOT NULL,
    access_token_enc BLOB NOT NULL,
    refresh_token_enc BLOB,
    token_expires_at TEXT,
    scopes TEXT NOT NULL,
    pds_url TEXT,
    issuer TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_dpop_sessions_client_user ON dpop_sessions(api_client_id, user_did);
CREATE INDEX idx_dpop_sessions_dpop_key_id ON dpop_sessions(dpop_key_id);
