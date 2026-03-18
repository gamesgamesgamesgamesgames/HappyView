ALTER TABLE records ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'));
