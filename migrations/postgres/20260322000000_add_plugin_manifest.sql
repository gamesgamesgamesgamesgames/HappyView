-- Add manifest column to store full plugin manifest JSON
ALTER TABLE plugins ADD COLUMN manifest TEXT;
