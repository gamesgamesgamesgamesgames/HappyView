CREATE TABLE IF NOT EXISTS backfill_jobs (
    id TEXT PRIMARY KEY,
    collection TEXT,
    did TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    total_repos INTEGER DEFAULT 0,
    processed_repos INTEGER DEFAULT 0,
    total_records INTEGER DEFAULT 0,
    error TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
