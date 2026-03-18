CREATE TABLE dead_letter_hooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lexicon_id TEXT NOT NULL,
    uri TEXT NOT NULL,
    did TEXT NOT NULL,
    collection TEXT NOT NULL,
    rkey TEXT NOT NULL,
    action TEXT NOT NULL,
    record JSONB,
    error TEXT NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dead_letter_hooks_collection ON dead_letter_hooks (collection);
CREATE INDEX idx_dead_letter_hooks_created_at ON dead_letter_hooks (created_at);
