-- Rename table
ALTER TABLE admins RENAME TO users;

-- Add is_super column
ALTER TABLE users ADD COLUMN is_super BOOLEAN NOT NULL DEFAULT FALSE;

-- Set earliest admin as super user
UPDATE users SET is_super = TRUE
WHERE created_at = (SELECT MIN(created_at) FROM users);
