CREATE TABLE IF NOT EXISTS network_lexicons (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nsid TEXT NOT NULL UNIQUE,
    authority_did TEXT NOT NULL,
    target_collection TEXT,
    last_fetched_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
