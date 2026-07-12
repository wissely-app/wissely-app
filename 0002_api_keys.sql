-- Wissely — API Access migration
-- Adds support for Pro-plan API keys (Authorization: Bearer <key>).
-- Safe to re-run: every statement uses IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS api_keys (
  id           TEXT PRIMARY KEY,          -- crypto.randomUUID()
  user_id      TEXT NOT NULL,
  name         TEXT NOT NULL,
  key_hash     TEXT NOT NULL UNIQUE,      -- SHA-256 hex digest of the raw key — raw key is never stored
  key_prefix   TEXT NOT NULL,             -- e.g. "wsk_live_AbCd1234" — safe to display, identifies the key
  created_at   TEXT NOT NULL,
  last_used_at TEXT,                      -- NULL until the key's first successful authenticated request
  revoked_at   TEXT,                      -- NULL = active. Revocation is a soft-delete (row is retained)
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id  ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
