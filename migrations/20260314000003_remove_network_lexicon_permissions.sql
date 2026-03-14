-- Remove network-lexicons permissions from all users; the network-lexicons
-- endpoints now reuse the regular lexicons:* permissions.
DELETE FROM user_permissions
WHERE permission IN ('network-lexicons:create', 'network-lexicons:read', 'network-lexicons:delete');

-- Remove from api_keys permissions array
UPDATE api_keys SET permissions = array_remove(array_remove(array_remove(
    permissions,
    'network-lexicons:create'),
    'network-lexicons:read'),
    'network-lexicons:delete');
