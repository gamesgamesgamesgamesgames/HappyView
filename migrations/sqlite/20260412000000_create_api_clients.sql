CREATE TABLE IF NOT EXISTS api_clients (
    id TEXT PRIMARY KEY,
    client_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    client_id_url TEXT NOT NULL UNIQUE,
    client_uri TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT 'atproto',
    rate_limit_capacity INTEGER,
    rate_limit_refill_rate REAL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
