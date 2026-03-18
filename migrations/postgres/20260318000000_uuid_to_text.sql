-- Convert Postgres-specific types to portable types for AnyPool compatibility.
-- The application binds all values as text strings.

-- =========================================================================
-- 1. UUID → TEXT
-- =========================================================================

-- Drop FK constraints that reference UUID columns
ALTER TABLE user_permissions DROP CONSTRAINT IF EXISTS user_permissions_user_id_fkey;
ALTER TABLE user_permissions DROP CONSTRAINT IF EXISTS user_permissions_granted_by_fkey;
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_user_id_fkey;
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS admin_api_keys_admin_id_fkey;

-- users
ALTER TABLE users ALTER COLUMN id TYPE TEXT USING id::text;

-- user_permissions
ALTER TABLE user_permissions ALTER COLUMN user_id TYPE TEXT USING user_id::text;
ALTER TABLE user_permissions ALTER COLUMN granted_by TYPE TEXT USING granted_by::text;

-- api_keys
ALTER TABLE api_keys ALTER COLUMN id TYPE TEXT USING id::text;
ALTER TABLE api_keys ALTER COLUMN user_id TYPE TEXT USING user_id::text;

-- event_logs
ALTER TABLE event_logs ALTER COLUMN id TYPE TEXT USING id::text;

-- backfill_jobs
ALTER TABLE backfill_jobs ALTER COLUMN id TYPE TEXT USING id::text;

-- dead_letter_hooks
ALTER TABLE dead_letter_hooks ALTER COLUMN id TYPE TEXT USING id::text;

-- Re-add FK constraints with TEXT types
ALTER TABLE user_permissions ADD CONSTRAINT user_permissions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_permissions ADD CONSTRAINT user_permissions_granted_by_fkey
    FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- =========================================================================
-- 2. BOOLEAN → INTEGER
-- =========================================================================

-- Convert is_super from BOOLEAN to INTEGER.
ALTER TABLE users ALTER COLUMN is_super DROP DEFAULT;
ALTER TABLE users ALTER COLUMN is_super TYPE INTEGER USING CASE WHEN is_super THEN 1 ELSE 0 END;
ALTER TABLE users ALTER COLUMN is_super SET DEFAULT 0;

-- Convert backfill from BOOLEAN to INTEGER.
ALTER TABLE lexicons ALTER COLUMN backfill DROP DEFAULT;
ALTER TABLE lexicons ALTER COLUMN backfill TYPE INTEGER USING CASE WHEN backfill THEN 1 ELSE 0 END;
ALTER TABLE lexicons ALTER COLUMN backfill SET DEFAULT 1;

-- =========================================================================
-- 3. JSONB → TEXT
-- =========================================================================

ALTER TABLE lexicons ALTER COLUMN lexicon_json TYPE TEXT USING lexicon_json::text;
ALTER TABLE records ALTER COLUMN record TYPE TEXT USING record::text;
ALTER TABLE dead_letter_hooks ALTER COLUMN record TYPE TEXT USING record::text;
ALTER TABLE event_logs ALTER COLUMN detail TYPE TEXT USING detail::text;

-- =========================================================================
-- 4. TIMESTAMPTZ → TEXT
-- =========================================================================

-- users
ALTER TABLE users ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE users ALTER COLUMN created_at TYPE TEXT USING created_at::text;
ALTER TABLE users ALTER COLUMN last_used_at TYPE TEXT USING last_used_at::text;

-- user_permissions
ALTER TABLE user_permissions ALTER COLUMN granted_at DROP DEFAULT;
ALTER TABLE user_permissions ALTER COLUMN granted_at TYPE TEXT USING granted_at::text;

-- api_keys
ALTER TABLE api_keys ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE api_keys ALTER COLUMN created_at TYPE TEXT USING created_at::text;
ALTER TABLE api_keys ALTER COLUMN last_used_at TYPE TEXT USING last_used_at::text;
ALTER TABLE api_keys ALTER COLUMN revoked_at TYPE TEXT USING revoked_at::text;

-- event_logs
ALTER TABLE event_logs ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE event_logs ALTER COLUMN created_at TYPE TEXT USING created_at::text;

-- backfill_jobs
ALTER TABLE backfill_jobs ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE backfill_jobs ALTER COLUMN created_at TYPE TEXT USING created_at::text;
ALTER TABLE backfill_jobs ALTER COLUMN started_at TYPE TEXT USING started_at::text;
ALTER TABLE backfill_jobs ALTER COLUMN completed_at TYPE TEXT USING completed_at::text;

-- dead_letter_hooks
ALTER TABLE dead_letter_hooks ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE dead_letter_hooks ALTER COLUMN created_at TYPE TEXT USING created_at::text;

-- lexicons
ALTER TABLE lexicons ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE lexicons ALTER COLUMN created_at TYPE TEXT USING created_at::text;
ALTER TABLE lexicons ALTER COLUMN updated_at TYPE TEXT USING updated_at::text;
ALTER TABLE lexicons ALTER COLUMN last_fetched_at TYPE TEXT USING last_fetched_at::text;

-- records
ALTER TABLE records ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE records ALTER COLUMN created_at TYPE TEXT USING created_at::text;
ALTER TABLE records ALTER COLUMN indexed_at TYPE TEXT USING indexed_at::text;

-- labels
ALTER TABLE labels ALTER COLUMN cts TYPE TEXT USING cts::text;
ALTER TABLE labels ALTER COLUMN exp TYPE TEXT USING exp::text;

-- labeler_subscriptions
ALTER TABLE labeler_subscriptions ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE labeler_subscriptions ALTER COLUMN created_at TYPE TEXT USING created_at::text;
ALTER TABLE labeler_subscriptions ALTER COLUMN updated_at TYPE TEXT USING updated_at::text;

-- rate_limits
ALTER TABLE rate_limits ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE rate_limits ALTER COLUMN created_at TYPE TEXT USING created_at::text;
ALTER TABLE rate_limits ALTER COLUMN updated_at TYPE TEXT USING updated_at::text;

-- rate_limit_allowlist
ALTER TABLE rate_limit_allowlist ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE rate_limit_allowlist ALTER COLUMN created_at TYPE TEXT USING created_at::text;

-- script_variables
ALTER TABLE script_variables ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE script_variables ALTER COLUMN created_at TYPE TEXT USING created_at::text;
ALTER TABLE script_variables ALTER COLUMN updated_at TYPE TEXT USING updated_at::text;

-- =========================================================================
-- 5. ARRAY → TEXT (stored as JSON array string)
-- =========================================================================

ALTER TABLE api_keys ALTER COLUMN permissions TYPE TEXT USING array_to_json(permissions)::text;
