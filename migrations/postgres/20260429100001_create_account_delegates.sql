CREATE TABLE IF NOT EXISTS account_delegates (
    account_did TEXT NOT NULL REFERENCES delegated_accounts(account_did) ON DELETE CASCADE,
    user_did TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    granted_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (account_did, user_did)
);
