CREATE TABLE IF NOT EXISTS lexicons (
    id           TEXT PRIMARY KEY,
    revision     INT NOT NULL DEFAULT 1,
    lexicon_json JSONB NOT NULL,
    backfill     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
