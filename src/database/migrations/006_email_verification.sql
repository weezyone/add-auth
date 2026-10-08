-- Email verification (PAU-18): password logins are refused until the address
-- is verified.

-- When the address was verified (link clicked, or OAuth sign-up/link with a
-- provider-verified email). NULL for unverified users AND for grandfathered
-- users (see below), which keeps grandfathered rows identifiable.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMP WITH TIME ZONE;

-- GRANDFATHERING (a product decision; reversible): verification did not exist
-- before this migration, so no existing account could have verified. Mark every
-- existing account as verified so nobody already registered is locked out.
--
-- To reverse later (force existing password users to verify):
--   UPDATE users SET email_verified = FALSE
--   WHERE email_verified AND email_verified_at IS NULL AND password_hash IS NOT NULL;
-- (they can then use POST /api/auth/resend-verification).
UPDATE users SET email_verified = TRUE WHERE email_verified IS DISTINCT FROM TRUE;

ALTER TABLE users ALTER COLUMN email_verified SET DEFAULT FALSE;
ALTER TABLE users ALTER COLUMN email_verified SET NOT NULL;

-- One row per issued link. Only a SHA-256 of the token is stored.
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_expires_at ON email_verification_tokens(expires_at);

COMMENT ON TABLE email_verification_tokens IS 'Single-use email verification links (hashed)';
COMMENT ON COLUMN email_verification_tokens.token_hash IS 'SHA-256 hex of the token sent by email; the token itself is never stored';
COMMENT ON COLUMN email_verification_tokens.used_at IS 'Set when the token is consumed, or when superseded by a newer token';
COMMENT ON COLUMN users.email_verified_at IS 'When the email was verified; NULL with email_verified = TRUE means grandfathered by migration 006';
