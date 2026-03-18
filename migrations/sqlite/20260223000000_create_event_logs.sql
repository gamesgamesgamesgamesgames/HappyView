CREATE TABLE event_logs (
    id          TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info',
    actor_did   TEXT,
    subject     TEXT,
    detail      TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_event_logs_event_type ON event_logs (event_type);
CREATE INDEX idx_event_logs_severity ON event_logs (severity);
CREATE INDEX idx_event_logs_created_at ON event_logs (created_at);
