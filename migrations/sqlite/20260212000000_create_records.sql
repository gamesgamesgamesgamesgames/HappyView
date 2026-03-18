CREATE TABLE IF NOT EXISTS records (
    uri        TEXT PRIMARY KEY,
    did        TEXT NOT NULL,
    collection TEXT NOT NULL,
    rkey       TEXT NOT NULL,
    record     TEXT NOT NULL,
    cid        TEXT NOT NULL,
    indexed_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_records_did_collection ON records (did, collection);
CREATE INDEX IF NOT EXISTS idx_records_collection ON records (collection);
