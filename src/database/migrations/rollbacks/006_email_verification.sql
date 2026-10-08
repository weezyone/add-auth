-- Rollback for 006_email_verification.sql.
-- Note: does not un-grandfather users (email_verified stays as it is).
DROP TABLE IF EXISTS email_verification_tokens;
ALTER TABLE users ALTER COLUMN email_verified DROP NOT NULL;
ALTER TABLE users DROP COLUMN IF EXISTS email_verified_at;
