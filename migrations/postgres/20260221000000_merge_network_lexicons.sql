-- Merge network_lexicons metadata into the lexicons table.
ALTER TABLE lexicons ADD COLUMN source TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE lexicons ADD COLUMN authority_did TEXT;
ALTER TABLE lexicons ADD COLUMN last_fetched_at TIMESTAMPTZ;

UPDATE lexicons
SET source = 'network',
    authority_did = nl.authority_did,
    last_fetched_at = nl.last_fetched_at
FROM network_lexicons nl
WHERE lexicons.id = nl.nsid;

DROP TABLE network_lexicons;
