ALTER TABLE api_clients ADD COLUMN parent_client_id TEXT REFERENCES api_clients(id) ON DELETE CASCADE;
ALTER TABLE api_clients ADD COLUMN owner_did TEXT;

CREATE INDEX idx_api_clients_parent_id ON api_clients(parent_client_id);
CREATE INDEX idx_api_clients_owner_did ON api_clients(owner_did);
