-- Plugin registry
CREATE TABLE plugins (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL CHECK (source IN ('file', 'url')),
    url TEXT,
    sha256 TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    loaded_at TIMESTAMPTZ,
    api_version TEXT NOT NULL
);

-- Plugin configuration
CREATE TABLE plugin_configs (
    plugin_id TEXT PRIMARY KEY REFERENCES plugins(id) ON DELETE CASCADE,
    config JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- External account tokens (encrypted)
CREATE TABLE external_account_tokens (
    id TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    plugin_id TEXT NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    access_token BYTEA NOT NULL,
    refresh_token BYTEA,
    token_type TEXT,
    scope TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(did, plugin_id)
);

-- Deduplication keys for sync records
CREATE TABLE plugin_dedup_keys (
    plugin_id TEXT NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    did TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    record_uri TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (plugin_id, did, dedup_key)
);

-- KV storage for plugins (scoped per plugin + context)
CREATE TABLE plugin_kv (
    plugin_id TEXT NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    value BYTEA NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (plugin_id, scope, key)
);

-- Index for KV expiration cleanup
CREATE INDEX idx_plugin_kv_expires ON plugin_kv(expires_at) WHERE expires_at IS NOT NULL;

-- Index for token lookup by DID
CREATE INDEX idx_external_tokens_did ON external_account_tokens(did);
