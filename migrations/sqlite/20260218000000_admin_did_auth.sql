-- SQLite: Recreate admins table with new schema (dropping name, api_key_hash, adding did)
CREATE TABLE admins_new (
    id TEXT PRIMARY KEY,
    did TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);

DROP TABLE admins;
ALTER TABLE admins_new RENAME TO admins;
