CREATE TABLE IF NOT EXISTS backfill_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection TEXT,
    did TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    total_repos INT DEFAULT 0,
    processed_repos INT DEFAULT 0,
    total_records INT DEFAULT 0,
    error TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
