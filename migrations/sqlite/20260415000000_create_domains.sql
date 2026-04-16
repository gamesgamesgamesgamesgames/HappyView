CREATE TABLE IF NOT EXISTS domains (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    is_primary INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
