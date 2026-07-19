-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 005: Add session_token_store table for pkg/session.Store (Issue #2775).
--
-- This table backs DatabaseSessionTokenStore, the Postgres implementation of
-- pkg/session.Store used by session.Manager in cluster mode.  It is distinct from
-- the `sessions` table (which backs business.SessionStore / DatabaseSessionStore).
--
-- Key design decisions:
--   - token_hash is the SHA-256 hex of the bearer token; the raw token is never stored.
--   - Multiple rows may share session_id (current + prior-token grace slot after Renew).
--   - hash_expires_at: NULL means the hash is the current active token; a non-NULL value
--     is set by StampGraceExpiry and marks the absolute time after which the prior-token
--     grace slot expires and the hash is rejected.
--   - DELETE removes all rows for a session_id, making revocation visible to all nodes.
--
-- RLS policy mirrors the `sessions` table:
--   SELECT: permissive when app.current_tenant is unset (auth-path lookups), filtered when set.
--   INSERT: tenant must be set in transaction (Set() calls setTenantLocal).
--   UPDATE/DELETE: unrestricted — keyed by globally-unique token_hash or session_id.

CREATE TABLE IF NOT EXISTS session_token_store (
    token_hash          TEXT NOT NULL PRIMARY KEY,
    session_id          TEXT NOT NULL,
    principal_id        TEXT NOT NULL,
    connection_name     TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    issued_at           TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity       TIMESTAMP WITH TIME ZONE NOT NULL,
    absolute_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    hash_expires_at     TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_session_token_store_session_id    ON session_token_store(session_id);
CREATE INDEX IF NOT EXISTS idx_session_token_store_tenant_id     ON session_token_store(tenant_id);
CREATE INDEX IF NOT EXISTS idx_session_token_store_hash_expires  ON session_token_store(hash_expires_at);
CREATE INDEX IF NOT EXISTS idx_session_token_store_abs_expires   ON session_token_store(absolute_expires_at);

ALTER TABLE session_token_store ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_token_store FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_read   ON session_token_store;
DROP POLICY IF EXISTS rls_write  ON session_token_store;
DROP POLICY IF EXISTS rls_update ON session_token_store;
DROP POLICY IF EXISTS rls_delete ON session_token_store;

-- SELECT: permissive when no tenant context (validation lookups from any node), filtered when set.
CREATE POLICY rls_read ON session_token_store FOR SELECT USING (
    current_setting('app.current_tenant', true) = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);

-- INSERT: tenant must be set in the transaction before inserting.
CREATE POLICY rls_write ON session_token_store FOR INSERT WITH CHECK (
    tenant_id = current_setting('app.current_tenant', true)
);

-- UPDATE/DELETE: unrestricted at DB level; keyed by globally-unique token_hash / session_id.
CREATE POLICY rls_update ON session_token_store FOR UPDATE USING (TRUE);
CREATE POLICY rls_delete ON session_token_store FOR DELETE USING (TRUE);
