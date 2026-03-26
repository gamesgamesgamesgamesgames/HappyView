-- No-op migration.
--
-- sqlx's AnyPool driver does not support native Postgres TIMESTAMPTZ or JSONB
-- types, so all columns must remain TEXT. Lua scripts use explicit casts
-- (e.g. col::timestamptz, col::jsonb) in queries where needed.
--
-- This migration was originally intended to restore native types but was
-- reverted after discovering the AnyPool limitation.
SELECT 1;
