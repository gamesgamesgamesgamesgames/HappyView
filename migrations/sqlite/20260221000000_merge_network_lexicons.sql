-- Merge network_lexicons metadata into the lexicons table.
ALTER TABLE lexicons ADD COLUMN source TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE lexicons ADD COLUMN authority_did TEXT;
ALTER TABLE lexicons ADD COLUMN last_fetched_at TEXT;

-- SQLite doesn't support UPDATE ... FROM, so use a correlated subquery
UPDATE lexicons
SET source = 'network',
    authority_did = (SELECT authority_did FROM network_lexicons WHERE network_lexicons.nsid = lexicons.id),
    last_fetched_at = (SELECT last_fetched_at FROM network_lexicons WHERE network_lexicons.nsid = lexicons.id)
WHERE id IN (SELECT nsid FROM network_lexicons);

DROP TABLE network_lexicons;
