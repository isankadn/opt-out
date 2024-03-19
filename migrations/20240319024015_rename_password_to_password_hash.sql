-- Rename the password column to password_hash
ALTER TABLE users RENAME COLUMN password TO password_hash;