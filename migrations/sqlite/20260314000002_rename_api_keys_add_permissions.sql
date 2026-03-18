-- Rename table
ALTER TABLE admin_api_keys RENAME TO api_keys;

-- Rename column
ALTER TABLE api_keys RENAME COLUMN admin_id TO user_id;

-- SQLite: Recreate table to fix foreign key reference
CREATE TABLE api_keys_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    revoked_at TEXT,
    permissions TEXT NOT NULL DEFAULT '[]'
);

INSERT INTO api_keys_new (id, user_id, name, key_hash, key_prefix, created_at, last_used_at, revoked_at, permissions)
SELECT id, user_id, name, key_hash, key_prefix, created_at, last_used_at, revoked_at,
    '["lexicons:create","lexicons:read","lexicons:delete","network-lexicons:create","network-lexicons:read","network-lexicons:delete","records:read","records:delete","records:delete-collection","script-variables:create","script-variables:read","script-variables:delete","users:create","users:read","users:update","users:delete","api-keys:create","api-keys:read","api-keys:delete","backfill:create","backfill:read","stats:read","events:read"]'
FROM api_keys;

DROP TABLE api_keys;
ALTER TABLE api_keys_new RENAME TO api_keys;

CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
