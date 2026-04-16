ALTER TABLE api_clients ADD COLUMN client_type TEXT NOT NULL DEFAULT 'confidential';
ALTER TABLE api_clients ADD COLUMN allowed_origins TEXT;
