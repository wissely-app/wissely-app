-- =============================================================================
-- Wissely D1 Schema — Fresh Installation
-- Use this file when creating a brand-new database.
-- Run: wrangler d1 execute wissely-db --file=schema.sql
-- =============================================================================

-- ── users ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                           TEXT    NOT NULL PRIMARY KEY,
  email                        TEXT    NOT NULL UNIQUE,
  password_hash                TEXT    NOT NULL,
  password_salt                TEXT    NOT NULL,
  plan                         TEXT    NOT NULL DEFAULT 'trial',
  analyses_used                INTEGER NOT NULL DEFAULT 0,
  analyses_limit               INTEGER NOT NULL DEFAULT 20,
  trial_end                    TEXT,
  created_at                   TEXT    NOT NULL,

  -- Paddle billing (populated by webhook events)
  paddle_customer_id           TEXT,
  paddle_subscription_id       TEXT,
  subscription_status          TEXT             DEFAULT 'none',

  -- Email verification
  email_verified               INTEGER NOT NULL DEFAULT 0,
  email_verification_token     TEXT,
  email_verification_expires   TEXT
);

-- ── sessions ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT NOT NULL PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL
);

-- ── password_resets ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS password_resets (
  token      TEXT NOT NULL PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- ── Indexes ───────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_sessions_user_id
  ON sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
  ON sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_password_resets_user_id
  ON password_resets(user_id);

CREATE INDEX IF NOT EXISTS idx_users_paddle_customer_id
  ON users(paddle_customer_id);

CREATE INDEX IF NOT EXISTS idx_users_paddle_subscription_id
  ON users(paddle_subscription_id);

CREATE INDEX IF NOT EXISTS idx_users_email_verification_token
  ON users(email_verification_token);
