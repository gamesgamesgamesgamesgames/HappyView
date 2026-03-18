-- Rename table
ALTER TABLE admins RENAME TO users;

-- Add is_super column
ALTER TABLE users ADD COLUMN is_super INTEGER NOT NULL DEFAULT 0;

-- Set earliest admin as super user
UPDATE users SET is_super = 1
WHERE created_at = (SELECT MIN(created_at) FROM users);
