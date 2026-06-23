-- =============================================================================
-- Wissely D1 Migration
-- Updates existing databases to match the current production backend.
-- Run once:
-- wrangler d1 execute wissely-db --file=migration.sql
-- =============================================================================

ALTER TABLE users
ADD COLUMN paddle_customer_id TEXT;

CREATE INDEX IF NOT EXISTS idx_users_paddle_customer_id
ON users(paddle_customer_id);

CREATE INDEX IF NOT EXISTS idx_users_paddle_subscription_id
ON users(paddle_subscription_id);

CREATE INDEX IF NOT EXISTS idx_users_email_verification_token
ON users(email_verification_token);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
ON sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
ON sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_password_resets_user_id
ON password_resets(user_id);
