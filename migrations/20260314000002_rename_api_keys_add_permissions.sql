-- Rename table
ALTER TABLE admin_api_keys RENAME TO api_keys;

-- Rename column
ALTER TABLE api_keys RENAME COLUMN admin_id TO user_id;

-- Drop old FK constraint and recreate pointing to users.
-- After migration 1 renamed `admins` to `users`, the FK's confrelid OID
-- follows the rename, so confrelid = 'users'::regclass matches.
-- We also try dropping by expected name as a safety net.
DO $$
DECLARE
    fk_name TEXT;
BEGIN
    SELECT conname INTO fk_name
    FROM pg_constraint
    WHERE conrelid = 'api_keys'::regclass
      AND contype = 'f'
      AND confrelid = 'users'::regclass;

    IF fk_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE api_keys DROP CONSTRAINT %I', fk_name);
    ELSE
        -- Fallback: try the default naming convention
        BEGIN
            ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS admin_api_keys_admin_id_fkey;
        EXCEPTION WHEN undefined_object THEN
            NULL;
        END;
    END IF;
END $$;

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- Add permissions column
ALTER TABLE api_keys ADD COLUMN permissions TEXT[] NOT NULL DEFAULT '{}';

-- Backfill: existing keys get all 23 permissions
UPDATE api_keys SET permissions = ARRAY[
    'lexicons:create', 'lexicons:read', 'lexicons:delete',
    'network-lexicons:create', 'network-lexicons:read', 'network-lexicons:delete',
    'records:read', 'records:delete', 'records:delete-collection',
    'script-variables:create', 'script-variables:read', 'script-variables:delete',
    'users:create', 'users:read', 'users:update', 'users:delete',
    'api-keys:create', 'api-keys:read', 'api-keys:delete',
    'backfill:create', 'backfill:read',
    'stats:read',
    'events:read'
];
