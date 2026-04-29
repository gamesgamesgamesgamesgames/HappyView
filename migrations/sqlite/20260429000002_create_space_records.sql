CREATE TABLE IF NOT EXISTS space_records (
    uri TEXT PRIMARY KEY,
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    author_did TEXT NOT NULL,
    collection TEXT NOT NULL,
    rkey TEXT NOT NULL,
    record TEXT NOT NULL,
    cid TEXT NOT NULL,
    indexed_at TEXT NOT NULL
);

CREATE INDEX idx_space_records_space_id ON space_records(space_id);
CREATE INDEX idx_space_records_author ON space_records(author_did);
CREATE INDEX idx_space_records_collection ON space_records(space_id, collection);
