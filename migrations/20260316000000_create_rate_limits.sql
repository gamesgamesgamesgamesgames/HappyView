CREATE TABLE rate_limits (
    id SERIAL PRIMARY KEY,
    method TEXT UNIQUE,          -- NULL = global default, otherwise XRPC method NSID
    capacity INTEGER NOT NULL,   -- max tokens in bucket
    refill_rate REAL NOT NULL,   -- tokens added per second
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed global default: 100 token capacity, refills at 2/sec
INSERT INTO rate_limits (method, capacity, refill_rate) VALUES (NULL, 100, 2.0);

-- Global enabled flag
CREATE TABLE rate_limit_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO rate_limit_settings (key, value) VALUES ('enabled', 'true');

-- IP/CIDR allowlist: exempt IPs from rate limiting
CREATE TABLE rate_limit_allowlist (
    id SERIAL PRIMARY KEY,
    cidr TEXT NOT NULL UNIQUE,   -- IP or CIDR, e.g. '10.0.0.0/8' or '203.0.113.5/32'
    note TEXT,                   -- human-readable reason for the exemption
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
