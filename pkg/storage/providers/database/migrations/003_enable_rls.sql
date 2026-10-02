-- M-TENANT-1: PostgreSQL Row-Level Security for Tenant Isolation
-- This migration enables RLS on all multi-tenant tables

-- Enable RLS on RBAC tables
ALTER TABLE IF EXISTS rbac_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS rbac_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS rbac_role_assignments ENABLE ROW LEVEL SECURITY;

-- Issue #4321: without FORCE, RLS policies do not apply to the table owner, so a
-- connection using the owning role bypasses tenant_isolation_policy and
-- admin_override_policy entirely. rbac_subjects/rbac_role_assignments have no
-- admin_override_policy and are out of this story's scope; rbac_roles gets FORCE
-- to match the sessions/steward_records/command_records/session_token_store
-- tables added by migration 004, which already declare it.
ALTER TABLE IF EXISTS rbac_roles FORCE ROW LEVEL SECURITY;

-- Enable RLS on configuration tables
ALTER TABLE IF EXISTS configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS steward_registrations ENABLE ROW LEVEL SECURITY;

-- Enable RLS on audit tables
ALTER TABLE IF EXISTS audit_events ENABLE ROW LEVEL SECURITY;

-- Enable RLS on workflow tables
ALTER TABLE IF EXISTS workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS workflow_executions ENABLE ROW LEVEL SECURITY;

-- M-TENANT-1: Create RLS policy for rbac_roles
DROP POLICY IF EXISTS tenant_isolation_policy ON rbac_roles;
CREATE POLICY tenant_isolation_policy ON rbac_roles
	USING (
		-- System roles bypass tenant check
		is_system_role = true
		OR
		-- Regular roles enforce tenant boundary
		tenant_id = current_setting('app.current_tenant', true)
	)
	WITH CHECK (
		is_system_role = true
		OR
		tenant_id = current_setting('app.current_tenant', true)
	);

-- M-TENANT-1: Create RLS policy for rbac_subjects
DROP POLICY IF EXISTS tenant_isolation_policy ON rbac_subjects;
CREATE POLICY tenant_isolation_policy ON rbac_subjects
	USING (tenant_id = current_setting('app.current_tenant', true))
	WITH CHECK (tenant_id = current_setting('app.current_tenant', true));

-- M-TENANT-1: Create RLS policy for rbac_role_assignments
DROP POLICY IF EXISTS tenant_isolation_policy ON rbac_role_assignments;
CREATE POLICY tenant_isolation_policy ON rbac_role_assignments
	USING (tenant_id = current_setting('app.current_tenant', true))
	WITH CHECK (tenant_id = current_setting('app.current_tenant', true));

-- M-TENANT-1: Create RLS policy for audit_events (read-only for regular users)
DROP POLICY IF EXISTS tenant_isolation_policy ON audit_events;
CREATE POLICY tenant_isolation_policy ON audit_events
	FOR SELECT
	USING (tenant_id = current_setting('app.current_tenant', true));

-- M-TENANT-1: Create indexes for RLS performance
CREATE INDEX IF NOT EXISTS idx_rbac_roles_tenant ON rbac_roles(tenant_id)
	WHERE tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_rbac_subjects_tenant ON rbac_subjects(tenant_id);

CREATE INDEX IF NOT EXISTS idx_rbac_role_assignments_tenant ON rbac_role_assignments(tenant_id);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant ON audit_events(tenant_id);

-- Issue #4321: the admin override was originally gated on a custom placeholder GUC
-- (app.is_admin) constrained by `REVOKE SET ON PARAMETER app.is_admin FROM PUBLIC`.
-- The merge queue's real-Postgres run proved that ineffective: an ordinary,
-- freshly-created non-superuser role could still `SELECT set_config('app.is_admin',
-- 'true', false)` after the REVOKE and satisfy the predicate for the rest of its
-- session (see rls_policy_test.go's TestRLSAdminOverride_RBACRoles history --
-- ApplicationRoleCannotSetIsAdmin failed against real Postgres 15 despite the
-- REVOKE). A session-settable GUC is the wrong primitive to gate a security
-- predicate on regardless of ACL support for it: it is settable, by name, by
-- anyone who can open a connection, and the parameter-privilege system is not a
-- well-trodden enough corner of Postgres to trust for this. Role membership is:
-- an ordinary role can never make itself a member of another role, so gating the
-- override on membership in a dedicated role that nobody is granted by default is
-- enforced by Postgres's core privilege system, not by a GUC-specific ACL feature.
DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cfgms_rls_admin_override') THEN
		CREATE ROLE cfgms_rls_admin_override NOLOGIN;
	END IF;
END
$$;

-- M-TENANT-1: Admin override policy for system maintenance. A connection assumes
-- the override only via `SET ROLE cfgms_rls_admin_override` (which itself requires
-- Postgres to have already granted that role to the connection's login role) or by
-- being directly granted membership; the ordinary application role is granted
-- neither, so it can never satisfy pg_has_role() for this role no matter what it
-- sets on its own session.
DROP POLICY IF EXISTS admin_override_policy ON rbac_roles;
CREATE POLICY admin_override_policy ON rbac_roles
	USING (pg_has_role(current_user, 'cfgms_rls_admin_override', 'MEMBER'))
	WITH CHECK (pg_has_role(current_user, 'cfgms_rls_admin_override', 'MEMBER'));
