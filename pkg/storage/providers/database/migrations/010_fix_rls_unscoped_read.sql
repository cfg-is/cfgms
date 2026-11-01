-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 010: make the RLS unscoped-read branch NULL-safe (Issue #3478)
--
-- Migrations 004 and 005 state their intent as "permissive when app.current_tenant
-- is not set (empty string), strict when set", and implement the permissive branch as:
--
--     current_setting('app.current_tenant', true) = ''
--
-- `current_setting(<name>, true)` returns NULL — not the empty string — when the
-- setting has never been applied in the session. NULL = '' is NULL, tenant_id = NULL
-- is NULL, and NULL OR NULL is NULL, so the row is filtered out. The permissive
-- branch therefore never fires for a caller that has not set a tenant, and an
-- unscoped read returns zero rows instead of all rows.
--
-- Writes were unaffected in practice because the registration path sets the tenant
-- before inserting, which is why rows appear in these tables while being unreadable
-- by any code path that has no tenant context.
--
-- The failure is connection-state dependent, which is what made it so hard to see:
-- once a connection has set the GUC even transaction-locally, current_setting()
-- returns '' rather than NULL for the rest of that connection's life. A pooled
-- connection that has previously served a tenant-scoped query therefore reads
-- correctly, while a freshly-opened one reads nothing. Measured on PostgreSQL 16
-- with a non-superuser role (superusers bypass RLS entirely, even under FORCE):
--
--     GUC never set (NULL) -> 0 rows      <-- the defect
--     GUC = ''             -> all rows
--     GUC = '<tenant>'     -> that tenant's rows
--
-- After this migration all three cases behave as the original comments describe.
--
-- Tenant isolation is unchanged: the second branch still restricts a scoped caller
-- to its own tenant_id. Only the unscoped branch is corrected, and the direction of
-- the correction is from "sees nothing" to "sees everything", which is the
-- documented intent for callers that legitimately have no tenant context
-- (ControlChannel admission, session lookup by token hash, command dispatch).
--
-- Idempotent: DROP POLICY IF EXISTS + CREATE POLICY, the same pattern migration 004
-- uses. Safe to re-run.
--
-- NOTE: pkg/storage/providers/database/schemas.go creates these same policies in Go
-- for databases provisioned through the provider rather than through this directory.
-- Both were corrected together; keep them in step.

-- ── sessions ─────────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS rls_read ON sessions;
CREATE POLICY rls_read ON sessions FOR SELECT USING (
    coalesce(current_setting('app.current_tenant', true), '') = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);

-- ── steward_records ──────────────────────────────────────────────────────────
DROP POLICY IF EXISTS rls_read ON steward_records;
CREATE POLICY rls_read ON steward_records FOR SELECT USING (
    coalesce(current_setting('app.current_tenant', true), '') = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);

-- ── command_records ──────────────────────────────────────────────────────────
DROP POLICY IF EXISTS rls_read ON command_records;
CREATE POLICY rls_read ON command_records FOR SELECT USING (
    coalesce(current_setting('app.current_tenant', true), '') = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);

-- ── session_token_store ──────────────────────────────────────────────────────
-- Created by migration 005 with the same defect.
DROP POLICY IF EXISTS rls_read ON session_token_store;
CREATE POLICY rls_read ON session_token_store FOR SELECT USING (
    coalesce(current_setting('app.current_tenant', true), '') = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);

-- command_transitions is deliberately absent: it carries no tenant_id column
-- (it is keyed by command_id and inherits isolation from command_records), so it
-- has no RLS policies to correct.
--
-- 003_enable_rls.sql is also deliberately absent: its policies use the strict form
-- `tenant_id = current_setting('app.current_tenant', true)` with no permissive
-- branch, so they carry no NULL-comparison defect. A caller with no tenant context
-- reads nothing from those tables by design.
