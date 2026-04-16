CREATE TABLE IF NOT EXISTS dpop_keys (
    id TEXT PRIMARY KEY,
    provision_id TEXT NOT NULL UNIQUE,
    api_client_id TEXT NOT NULL REFERENCES api_clients(id) ON DELETE CASCADE,
    private_key_enc BLOB NOT NULL,
    jwk_thumbprint TEXT NOT NULL,
    pkce_challenge TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_dpop_keys_api_client_id ON dpop_keys(api_client_id);
CREATE INDEX idx_dpop_keys_provision_id ON dpop_keys(provision_id);
