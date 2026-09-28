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

-- M-TENANT-1: Admin override policy for system maintenance
DROP POLICY IF EXISTS admin_override_policy ON rbac_roles;
CREATE POLICY admin_override_policy ON rbac_roles
	USING (current_setting('app.is_admin', true)::boolean = true)
	WITH CHECK (current_setting('app.is_admin', true)::boolean = true);

-- Issue #4321: the admin-override predicate above is only as safe as the claim,
-- already made in the RLS write-policy comments, that the application database
-- role cannot set app.is_admin itself. That claim was never enforced: a custom
-- (placeholder) GUC like app.is_admin has no built-in restriction on who may SET
-- it -- any connected role, including the ordinary application role, could run
-- `SELECT set_config('app.is_admin', 'true', false)` and satisfy the predicate
-- for the rest of that connection's life. This REVOKE is what actually
-- constrains admin_override_policy from an open bypass to one only a role
-- explicitly granted SET on this parameter can trigger. PostgreSQL 15+ supports
-- GRANT/REVOKE ON PARAMETER for exactly this class of custom RLS-driving GUC,
-- including parameters -- like this one -- that no extension has registered.
REVOKE SET ON PARAMETER app.is_admin FROM PUBLIC;
