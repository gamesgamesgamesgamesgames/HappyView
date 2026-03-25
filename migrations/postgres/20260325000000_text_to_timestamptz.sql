-- Restore TIMESTAMPTZ columns that were converted to TEXT by uuid_to_text.
-- The stored RFC 3339 strings are valid TIMESTAMPTZ literals, so the cast is safe.

-- users
ALTER TABLE users ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;
ALTER TABLE users ALTER COLUMN last_used_at TYPE TIMESTAMPTZ USING last_used_at::timestamptz;

-- user_permissions
ALTER TABLE user_permissions ALTER COLUMN granted_at TYPE TIMESTAMPTZ USING granted_at::timestamptz;

-- api_keys
ALTER TABLE api_keys ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;
ALTER TABLE api_keys ALTER COLUMN last_used_at TYPE TIMESTAMPTZ USING last_used_at::timestamptz;
ALTER TABLE api_keys ALTER COLUMN revoked_at TYPE TIMESTAMPTZ USING revoked_at::timestamptz;

-- event_logs
ALTER TABLE event_logs ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;

-- backfill_jobs
ALTER TABLE backfill_jobs ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;
ALTER TABLE backfill_jobs ALTER COLUMN started_at TYPE TIMESTAMPTZ USING started_at::timestamptz;
ALTER TABLE backfill_jobs ALTER COLUMN completed_at TYPE TIMESTAMPTZ USING completed_at::timestamptz;

-- dead_letter_hooks
ALTER TABLE dead_letter_hooks ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;

-- lexicons
ALTER TABLE lexicons ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;
ALTER TABLE lexicons ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at::timestamptz;
ALTER TABLE lexicons ALTER COLUMN last_fetched_at TYPE TIMESTAMPTZ USING last_fetched_at::timestamptz;

-- records
ALTER TABLE records ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;
ALTER TABLE records ALTER COLUMN indexed_at TYPE TIMESTAMPTZ USING indexed_at::timestamptz;

-- labels
ALTER TABLE labels ALTER COLUMN cts TYPE TIMESTAMPTZ USING cts::timestamptz;
ALTER TABLE labels ALTER COLUMN exp TYPE TIMESTAMPTZ USING exp::timestamptz;

-- labeler_subscriptions
ALTER TABLE labeler_subscriptions ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;
ALTER TABLE labeler_subscriptions ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at::timestamptz;

-- rate_limits
ALTER TABLE rate_limits ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;
ALTER TABLE rate_limits ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at::timestamptz;

-- rate_limit_allowlist
ALTER TABLE rate_limit_allowlist ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;

-- script_variables
ALTER TABLE script_variables ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;
ALTER TABLE script_variables ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at::timestamptz;
