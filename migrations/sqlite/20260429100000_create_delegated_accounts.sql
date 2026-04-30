CREATE TABLE IF NOT EXISTS delegated_accounts (
    account_did TEXT PRIMARY KEY,
    linked_by TEXT NOT NULL,
    api_client_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
