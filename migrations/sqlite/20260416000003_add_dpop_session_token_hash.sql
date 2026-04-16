ALTER TABLE dpop_sessions ADD COLUMN access_token_hash TEXT;
CREATE INDEX IF NOT EXISTS idx_dpop_sessions_token_hash ON dpop_sessions (api_client_id, access_token_hash);
