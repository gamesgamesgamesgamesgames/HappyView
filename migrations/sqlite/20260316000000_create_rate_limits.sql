CREATE TABLE rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT UNIQUE,
    capacity INTEGER NOT NULL,
    refill_rate REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed global default: 100 token capacity, refills at 2/sec
INSERT INTO rate_limits (method, capacity, refill_rate) VALUES (NULL, 100, 2.0);

-- Global enabled flag
CREATE TABLE rate_limit_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO rate_limit_settings (key, value) VALUES ('enabled', 'true');

-- IP/CIDR allowlist: exempt IPs from rate limiting
CREATE TABLE rate_limit_allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
