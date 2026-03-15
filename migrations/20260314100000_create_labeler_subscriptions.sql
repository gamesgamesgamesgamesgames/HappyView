CREATE TABLE labeler_subscriptions (
    did        TEXT PRIMARY KEY,
    cursor     BIGINT,
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
