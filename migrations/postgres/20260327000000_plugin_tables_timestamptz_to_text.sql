-- Fix plugin tables to use TEXT instead of TIMESTAMPTZ.
-- sqlx's AnyPool does not support native Postgres TIMESTAMPTZ, so all
-- timestamp columns must be TEXT with RFC 3339 strings.

-- external_account_tokens
ALTER TABLE external_account_tokens
    ALTER COLUMN expires_at TYPE TEXT USING expires_at::text,
    ALTER COLUMN created_at TYPE TEXT USING created_at::text,
    ALTER COLUMN updated_at TYPE TEXT USING updated_at::text;

ALTER TABLE external_account_tokens
    ALTER COLUMN created_at SET DEFAULT '',
    ALTER COLUMN updated_at SET DEFAULT '';

-- external_auth_state
ALTER TABLE external_auth_state
    ALTER COLUMN created_at TYPE TEXT USING created_at::text,
    ALTER COLUMN expires_at TYPE TEXT USING expires_at::text;

ALTER TABLE external_auth_state
    ALTER COLUMN created_at SET DEFAULT '';
