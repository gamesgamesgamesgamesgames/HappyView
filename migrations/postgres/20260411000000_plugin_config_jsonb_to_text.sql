-- Convert plugin_configs.config from JSONB to TEXT for cross-database consistency.
ALTER TABLE plugin_configs ALTER COLUMN config TYPE TEXT USING config::TEXT;

-- Fix remaining TIMESTAMPTZ columns in plugin tables that were missed by
-- 20260327000000_plugin_tables_timestamptz_to_text.sql.
-- sqlx's AnyPool does not support native Postgres TIMESTAMPTZ.

ALTER TABLE plugin_configs
    ALTER COLUMN updated_at TYPE TEXT USING updated_at::text;
ALTER TABLE plugin_configs
    ALTER COLUMN updated_at SET DEFAULT '';

ALTER TABLE plugins
    ALTER COLUMN loaded_at TYPE TEXT USING loaded_at::text;

ALTER TABLE plugin_dedup_keys
    ALTER COLUMN updated_at TYPE TEXT USING updated_at::text;
ALTER TABLE plugin_dedup_keys
    ALTER COLUMN updated_at SET DEFAULT '';

ALTER TABLE plugin_kv
    ALTER COLUMN expires_at TYPE TEXT USING expires_at::text,
    ALTER COLUMN created_at TYPE TEXT USING created_at::text;
ALTER TABLE plugin_kv
    ALTER COLUMN created_at SET DEFAULT '';
