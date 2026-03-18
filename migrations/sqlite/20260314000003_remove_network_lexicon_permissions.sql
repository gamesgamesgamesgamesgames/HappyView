-- Remove network-lexicons permissions from all users
DELETE FROM user_permissions
WHERE permission IN ('network-lexicons:create', 'network-lexicons:read', 'network-lexicons:delete');

-- Remove from api_keys permissions (stored as JSON array in SQLite)
UPDATE api_keys SET permissions = REPLACE(
    REPLACE(
        REPLACE(permissions, '"network-lexicons:create",', ''),
        '"network-lexicons:read",', ''),
    '"network-lexicons:delete",', '');
