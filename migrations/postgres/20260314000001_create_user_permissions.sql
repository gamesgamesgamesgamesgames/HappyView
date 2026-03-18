CREATE TABLE user_permissions (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission  TEXT NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, permission)
);

-- Backfill: grant all 23 permissions to every existing user
INSERT INTO user_permissions (user_id, permission)
SELECT u.id, p.permission
FROM users u
CROSS JOIN (VALUES
    ('lexicons:create'), ('lexicons:read'), ('lexicons:delete'),
    ('network-lexicons:create'), ('network-lexicons:read'), ('network-lexicons:delete'),
    ('records:read'), ('records:delete'), ('records:delete-collection'),
    ('script-variables:create'), ('script-variables:read'), ('script-variables:delete'),
    ('users:create'), ('users:read'), ('users:update'), ('users:delete'),
    ('api-keys:create'), ('api-keys:read'), ('api-keys:delete'),
    ('backfill:create'), ('backfill:read'),
    ('stats:read'),
    ('events:read')
) AS p(permission);
