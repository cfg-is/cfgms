-- M-TENANT-1: PostgreSQL Row-Level Security for Tenant Isolation
-- This migration enables RLS on all multi-tenant tables

-- Enable RLS on RBAC tables
ALTER TABLE IF EXISTS rbac_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS rbac_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS rbac_role_assignments ENABLE ROW LEVEL SECURITY;

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
