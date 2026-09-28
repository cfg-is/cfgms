-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 004: Add sessions, steward_records, command_records, and command_transitions tables
-- with Row-Level Security for multi-tenant isolation.
--
-- RLS read policy: permissive when app.current_tenant is not set (empty string), strict when set.
--   USING: current_setting('app.current_tenant', true) = '' OR tenant_id = current_setting(...)
-- RLS write policy: always requires the tenant to be set -- an unset tenant is an error
-- condition (matches no row), never a wildcard. INSERT and UPDATE/DELETE all carry a
-- tenant predicate (Issue #4321); UPDATE additionally refuses to move a row to a
-- different tenant via WITH CHECK, except on steward_records, where WITH CHECK (TRUE)
-- is a deliberate, documented exception for UpdateStewardTenant (see that table's policy
-- comment below).
--   INSERT WITH CHECK / UPDATE USING / DELETE USING: tenant_id = current_setting('app.current_tenant', true)
--
-- The Go store layer is responsible for calling set_config('app.current_tenant', $tenantID, true)
-- inside each transaction so these policies enforce correctly.  The application DB role must NOT
-- have the privilege to SET app.is_admin = true.

-- ── sessions ─────────────────────────────────────────────────────────────────
-- session_id_hash is the HMAC-SHA256 hex of the bearer token; the plaintext token is never stored.
CREATE TABLE IF NOT EXISTS sessions (
    session_id_hash  TEXT NOT NULL PRIMARY KEY,
    user_id          TEXT NOT NULL,
    tenant_id        TEXT NOT NULL,
    session_type     TEXT NOT NULL,
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity    TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at       TIMESTAMP WITH TIME ZONE NOT NULL,
    status           TEXT NOT NULL,
    persistent       BOOLEAN NOT NULL DEFAULT TRUE,
    client_info      JSONB NOT NULL DEFAULT '{}',
    metadata         JSONB NOT NULL DEFAULT '{}',
    session_data     JSONB NOT NULL DEFAULT '{}',
    security_context JSONB NOT NULL DEFAULT '{}',
    compliance_flags JSONB NOT NULL DEFAULT '[]',
    created_by       TEXT NOT NULL DEFAULT '',
    modified_at      TIMESTAMP WITH TIME ZONE,
    modified_by      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id    ON sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id      ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status       ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at   ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_user  ON sessions(tenant_id, user_id);

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON sessions;
DROP POLICY IF EXISTS rls_read   ON sessions;
DROP POLICY IF EXISTS rls_write  ON sessions;
DROP POLICY IF EXISTS rls_update ON sessions;
DROP POLICY IF EXISTS rls_delete ON sessions;

-- SELECT: permissive when no tenant context (auth lookups), filtered when context is set.
CREATE POLICY rls_read ON sessions FOR SELECT USING (
    current_setting('app.current_tenant', true) = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);

-- INSERT: tenant must be set in the transaction before inserting.
CREATE POLICY rls_write ON sessions FOR INSERT WITH CHECK (
    tenant_id = current_setting('app.current_tenant', true)
);

-- UPDATE/DELETE (Issue #4321): the target row must belong to the caller's current
-- tenant, and an UPDATE may not move a row to a different tenant -- an unset
-- tenant matches nothing (fail closed), not every row.
CREATE POLICY rls_update ON sessions FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
CREATE POLICY rls_delete ON sessions FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true));

-- ── steward_records ───────────────────────────────────────────────────────────
-- Append-only fleet registry; deregistered records are retained for audit.
CREATE TABLE IF NOT EXISTS steward_records (
    id                   TEXT NOT NULL PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    hostname             TEXT NOT NULL DEFAULT '',
    platform             TEXT NOT NULL DEFAULT '',
    arch                 TEXT NOT NULL DEFAULT '',
    version              TEXT NOT NULL DEFAULT '',
    ip_address           TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL,
    registered_at        TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen            TIMESTAMP WITH TIME ZONE NOT NULL,
    last_heartbeat_at    TIMESTAMP WITH TIME ZONE,
    device_id            TEXT NOT NULL DEFAULT '',
    identity_key_pub     BYTEA,
    key_protection_level TEXT NOT NULL DEFAULT '',
    last_provenance_json TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_steward_records_tenant_id   ON steward_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_steward_records_status      ON steward_records(status);
CREATE INDEX IF NOT EXISTS idx_steward_records_device_id   ON steward_records(device_id);
CREATE INDEX IF NOT EXISTS idx_steward_records_last_seen   ON steward_records(last_seen);

ALTER TABLE steward_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE steward_records FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON steward_records;
DROP POLICY IF EXISTS rls_read   ON steward_records;
DROP POLICY IF EXISTS rls_write  ON steward_records;
DROP POLICY IF EXISTS rls_update ON steward_records;
DROP POLICY IF EXISTS rls_delete ON steward_records;

-- SELECT: permissive when no tenant context (fleet management), filtered when context is set.
CREATE POLICY rls_read ON steward_records FOR SELECT USING (
    current_setting('app.current_tenant', true) = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);

-- INSERT: tenant must be set in the transaction before inserting.
CREATE POLICY rls_write ON steward_records FOR INSERT WITH CHECK (
    tenant_id = current_setting('app.current_tenant', true)
);

-- UPDATE (Issue #4321): the target row must belong to the caller's current tenant --
-- an unset tenant matches nothing (fail closed), not every row. WITH CHECK is
-- deliberately TRUE, not tenant-scoped: UpdateStewardTenant (steward_store.go) is a
-- real product feature that moves a steward to a different tenant, gated at the
-- Go/API layer (handlers_stewards.go's handleMoveSteward requires a root caller or
-- a scoped admin whose scope covers both tenants). USING and WITH CHECK read the
-- same current_setting('app.current_tenant') value within one statement, so a
-- tenant-scoped WITH CHECK here would make that move impossible for any caller.
CREATE POLICY rls_update ON steward_records FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (TRUE);
CREATE POLICY rls_delete ON steward_records FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true));

-- ── command_records ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS command_records (
    id            TEXT NOT NULL PRIMARY KEY,
    type          TEXT NOT NULL,
    steward_id    TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    payload       JSONB NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL,
    issued_at     TIMESTAMP WITH TIME ZONE NOT NULL,
    started_at    TIMESTAMP WITH TIME ZONE,
    completed_at  TIMESTAMP WITH TIME ZONE,
    result        JSONB NOT NULL DEFAULT '{}',
    error_message TEXT NOT NULL DEFAULT '',
    issued_by     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_command_records_tenant_id  ON command_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_command_records_steward_id ON command_records(steward_id);
CREATE INDEX IF NOT EXISTS idx_command_records_status     ON command_records(status);
CREATE INDEX IF NOT EXISTS idx_command_records_issued_at  ON command_records(issued_at);
CREATE INDEX IF NOT EXISTS idx_command_records_issued_by  ON command_records(issued_by);

ALTER TABLE command_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE command_records FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON command_records;
DROP POLICY IF EXISTS rls_read   ON command_records;
DROP POLICY IF EXISTS rls_write  ON command_records;
DROP POLICY IF EXISTS rls_update ON command_records;
DROP POLICY IF EXISTS rls_delete ON command_records;

-- SELECT: permissive when no tenant context, filtered when context is set.
CREATE POLICY rls_read ON command_records FOR SELECT USING (
    current_setting('app.current_tenant', true) = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);

-- INSERT: tenant must be set in the transaction before inserting.
CREATE POLICY rls_write ON command_records FOR INSERT WITH CHECK (
    tenant_id = current_setting('app.current_tenant', true)
);

-- UPDATE/DELETE (Issue #4321): the target row must belong to the caller's current
-- tenant, and an UPDATE may not move a row to a different tenant -- an unset
-- tenant matches nothing (fail closed), not every row.
CREATE POLICY rls_update ON command_records FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
CREATE POLICY rls_delete ON command_records FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true));

-- ── command_transitions ───────────────────────────────────────────────────────
-- Immutable audit trail; rows are never updated, only appended and purged together
-- with their parent command_record.
CREATE TABLE IF NOT EXISTS command_transitions (
    id            BIGSERIAL PRIMARY KEY,
    command_id    TEXT NOT NULL,
    status        TEXT NOT NULL,
    timestamp     TIMESTAMP WITH TIME ZONE NOT NULL,
    error_message TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_command_transitions_command_id ON command_transitions(command_id);
