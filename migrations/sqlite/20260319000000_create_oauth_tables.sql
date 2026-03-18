CREATE TABLE oauth_sessions (
    did TEXT PRIMARY KEY,
    session_data TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE oauth_state (
    state_key TEXT PRIMARY KEY,
    state_data TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
