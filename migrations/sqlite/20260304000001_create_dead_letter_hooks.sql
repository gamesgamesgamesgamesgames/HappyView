CREATE TABLE dead_letter_hooks (
    id TEXT PRIMARY KEY,
    lexicon_id TEXT NOT NULL,
    uri TEXT NOT NULL,
    did TEXT NOT NULL,
    collection TEXT NOT NULL,
    rkey TEXT NOT NULL,
    action TEXT NOT NULL,
    record TEXT,
    error TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_dead_letter_hooks_collection ON dead_letter_hooks (collection);
CREATE INDEX idx_dead_letter_hooks_created_at ON dead_letter_hooks (created_at);
