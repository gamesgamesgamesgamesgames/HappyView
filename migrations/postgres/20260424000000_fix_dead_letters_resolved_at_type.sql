ALTER TABLE dead_letter_hooks ALTER COLUMN resolved_at TYPE TEXT USING resolved_at::text;
