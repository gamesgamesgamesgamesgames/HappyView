ALTER TABLE dead_letter_hooks ADD COLUMN resolved_at TIMESTAMPTZ;
CREATE INDEX idx_dead_letter_hooks_resolved_at ON dead_letter_hooks (resolved_at);
