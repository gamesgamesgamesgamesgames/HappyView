CREATE TABLE IF NOT EXISTS lexicons (
    id           TEXT PRIMARY KEY,
    revision     INTEGER NOT NULL DEFAULT 1,
    lexicon_json TEXT NOT NULL,
    backfill     INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
