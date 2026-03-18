CREATE TABLE user_permissions (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission  TEXT NOT NULL,
    granted_at  TEXT NOT NULL DEFAULT (datetime('now')),
    granted_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, permission)
);

-- Backfill: grant all 23 permissions to every existing user
INSERT INTO user_permissions (user_id, permission)
SELECT u.id, p.permission
FROM users u, (
    SELECT 'lexicons:create' AS permission UNION ALL
    SELECT 'lexicons:read' UNION ALL
    SELECT 'lexicons:delete' UNION ALL
    SELECT 'network-lexicons:create' UNION ALL
    SELECT 'network-lexicons:read' UNION ALL
    SELECT 'network-lexicons:delete' UNION ALL
    SELECT 'records:read' UNION ALL
    SELECT 'records:delete' UNION ALL
    SELECT 'records:delete-collection' UNION ALL
    SELECT 'script-variables:create' UNION ALL
    SELECT 'script-variables:read' UNION ALL
    SELECT 'script-variables:delete' UNION ALL
    SELECT 'users:create' UNION ALL
    SELECT 'users:read' UNION ALL
    SELECT 'users:update' UNION ALL
    SELECT 'users:delete' UNION ALL
    SELECT 'api-keys:create' UNION ALL
    SELECT 'api-keys:read' UNION ALL
    SELECT 'api-keys:delete' UNION ALL
    SELECT 'backfill:create' UNION ALL
    SELECT 'backfill:read' UNION ALL
    SELECT 'stats:read' UNION ALL
    SELECT 'events:read'
) AS p;
