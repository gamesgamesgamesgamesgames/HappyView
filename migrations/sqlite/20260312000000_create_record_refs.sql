CREATE TABLE IF NOT EXISTS record_refs (
    source_uri TEXT NOT NULL REFERENCES records(uri) ON DELETE CASCADE,
    target_uri TEXT NOT NULL,
    collection TEXT NOT NULL,
    PRIMARY KEY (source_uri, target_uri)
);

CREATE INDEX IF NOT EXISTS idx_record_refs_target ON record_refs (target_uri, collection);
CREATE INDEX IF NOT EXISTS idx_records_created_at_uri ON records (created_at DESC, uri DESC);
