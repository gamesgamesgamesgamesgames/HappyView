CREATE TABLE labeler_subscriptions (
    did        TEXT PRIMARY KEY,
    cursor     INTEGER,
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
