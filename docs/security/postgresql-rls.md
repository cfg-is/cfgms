# PostgreSQL Row-Level Security Implementation Guide

**Security Finding**: M-TENANT-1
**Severity**: MEDIUM
**CVSS**: 6.0
**Status**: DOCUMENTED (Implementation Required)

## Overview

Implement PostgreSQL Row-Level Security (RLS) policies to provide defense-in-depth tenant isolation at the database level. This complements application-level tenant context validation (H-TENANT-1) to prevent cross-tenant data access even if application logic is bypassed.

## Requirements

### M-TENANT-1: PostgreSQL Row-Level Security

**Current State**:
- Application-level tenant isolation (implemented in H-TENANT-1)
- No database-level tenant boundary enforcement
- Missing defense-in-depth at storage layer

**Required State**:
- RLS enabled on all multi-tenant tables
- Automatic tenant context enforcement
- Session variable pattern for tenant context
- Zero performance overhead with proper indexing

## Implementation Plan

### Phase 1: Enable RLS on Multi-Tenant Tables

**Tables Requiring RLS**:
```sql
-- RBAC tables
ALTER TABLE rbac_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_role_assignments ENABLE ROW LEVEL SECURITY;

-- Configuration tables
ALTER TABLE configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE steward_registrations ENABLE ROW LEVEL SECURITY;

-- Audit tables (read-only for regular users)
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

-- Workflow tables
ALTER TABLE workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_executions ENABLE ROW LEVEL SECURITY;
```

### Phase 2: Create RLS Policies

**Session Variable Pattern**:
```sql
-- Set tenant context at connection level
SET app.current_tenant = 'tenant-123';
```

**Policy Examples**:

```sql
-- M-TENANT-1: RLS policy for rbac_roles table
CREATE POLICY tenant_isolation_policy ON rbac_roles
	USING (
		-- System roles bypass tenant check
		is_system_role = true
		OR
		-- Regular roles enforce tenant boundary
		tenant_id = current_setting('app.current_tenant', true)
	);

-- M-TENANT-1: RLS policy for rbac_subjects table
CREATE POLICY tenant_isolation_policy ON rbac_subjects
	USING (tenant_id = current_setting('app.current_tenant', true));

-- M-TENANT-1: RLS policy for configurations
CREATE POLICY tenant_isolation_policy ON configurations
	USING (tenant_id = current_setting('app.current_tenant', true));

-- M-TENANT-1: RLS policy for audit events (read-only)
CREATE POLICY tenant_isolation_policy ON audit_events
	FOR SELECT
	USING (tenant_id = current_setting('app.current_tenant', true));

-- M-TENANT-1: Admin override policy (for system maintenance)
CREATE POLICY admin_override_policy ON rbac_roles
	USING (current_setting('app.is_admin', true)::boolean = true)
	WITH CHECK (current_setting('app.is_admin', true)::boolean = true);
```

### Phase 3: Update Connection Handler

**Location**: `pkg/storage/providers/database/*.go`

```go
// M-TENANT-1: Set tenant context on database connection
func (s *DatabaseStore) setTenantContext(ctx context.Context, tenantID string) error {
	// Extract tenant ID from context
	authTenantID := ctx.Value("tenant_id")
	if authTenantID == nil {
		// System operation - no tenant context
		return nil
	}

	// M-TENANT-1: Set session variable for RLS
	_, err := s.db.ExecContext(ctx,
		"SET LOCAL app.current_tenant = $1",
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("failed to set tenant context: %w", err)
	}

	return nil
}

// M-TENANT-1: Wrap database operations with tenant context
func (s *DatabaseStore) executeWithTenantContext(
	ctx context.Context,
	tenantID string,
	operation func() error,
) error {
	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// M-TENANT-1: Set tenant context for this transaction
	if err := s.setTenantContext(ctx, tenantID); err != nil {
		return err
	}

	// Execute operation within tenant context
	if err := operation(); err != nil {
		return err
	}

	// Commit transaction
	return tx.Commit()
}
```

### Phase 4: Testing

**Test Scenarios**:

```go
// M-TENANT-1: Test RLS prevents cross-tenant access
func TestRLS_PreventsCrossTenantAccess(t *testing.T) {
	// 1. Create role in tenant-123
	ctx1 := context.WithValue(context.Background(), "tenant_id", "tenant-123")
	role1 := createRole(ctx1, "role-1")

	// 2. Try to access from tenant-456 (should fail)
	ctx2 := context.WithValue(context.Background(), "tenant_id", "tenant-456")
	role, err := getRole(ctx2, role1.ID)

	// M-TENANT-1: Should not find role from different tenant
	assert.Error(t, err)
	assert.Nil(t, role)
}

// M-TENANT-1: Test system roles bypass RLS
func TestRLS_SystemRolesBypassTenantCheck(t *testing.T) {
	// System roles should be accessible from any tenant
	ctx := context.WithValue(context.Background(), "tenant_id", "any-tenant")
	systemRole, err := getRole(ctx, "system-admin-role-id")

	assert.NoError(t, err)
	assert.NotNil(t, systemRole)
	assert.True(t, systemRole.IsSystemRole)
}
```

### Phase 5: Performance Optimization

**Indexing Strategy**:
```sql
-- M-TENANT-1: Add indexes for RLS performance
CREATE INDEX idx_rbac_roles_tenant ON rbac_roles(tenant_id)
	WHERE tenant_id IS NOT NULL;

CREATE INDEX idx_rbac_subjects_tenant ON rbac_subjects(tenant_id);

CREATE INDEX idx_configurations_tenant ON configurations(tenant_id);

-- Analyze query plans
EXPLAIN ANALYZE
SELECT * FROM rbac_roles
WHERE tenant_id = current_setting('app.current_tenant', true);
```

**Performance Testing**:
- Baseline: Query performance without RLS
- With RLS: Ensure < 5% overhead
- Load testing: 1000+ concurrent tenant queries

## Security Considerations

### Defense-in-Depth Architecture

**Layer 1: Application (H-TENANT-1 ✅)**:
- Tenant context validation in storage layer
- Cross-tenant access detection
- Audit logging

**Layer 2: Database (M-TENANT-1)**:
- RLS policies enforce tenant boundaries
- Session variables track tenant context
- Automatic enforcement at SQL level

**Layer 3: Network**:
- Mutual TLS between components
- API authentication and authorization

### Bypass Protection

**Admin Override**:
```sql
-- M-TENANT-1: Admin access for system maintenance
SET app.is_admin = true;
-- Now can access all tenants for maintenance
```

**Audit Logging**:
- Log all admin override usage
- Alert on unexpected admin access
- Review admin operations regularly

## Backward Compatibility

**Migration Strategy**:
1. Enable RLS on tables (no policies initially)
2. Create permissive policies (allow all access)
3. Test application functionality
4. Gradually tighten policies per table
5. Monitor for access violations
6. Enable strict policies

**Zero Downtime**:
- RLS policies enforced at database level
- No application code changes required (if using H-TENANT-1)
- Existing queries continue working

## Operational Procedures

### Deployment

1. **Pre-deployment**:
   ```bash
   # Backup database
   pg_dump cfgms > backup-before-rls.sql

   # Test RLS policies in staging
   psql staging < enable-rls.sql
   ```

2. **Deployment**:
   ```bash
   # Apply RLS policies
   psql production < enable-rls.sql

   # Verify policies
   psql production -c "\d+ rbac_roles"
   ```

3. **Post-deployment**:
   ```bash
   # Monitor for errors
   tail -f /var/log/postgresql/postgresql.log | grep "policy"

   # Test cross-tenant access
   ./test-rls-enforcement.sh
   ```

### Monitoring

**Metrics to Track**:
- RLS policy violations (should be 0)
- Query performance impact
- Admin override usage
- Failed tenant context setting

**Alerts**:
- Alert on RLS policy violations
- Alert on excessive admin overrides
- Alert on performance degradation > 10%

## Implementation Timeline

**Estimated Effort**: 4 hours

1. **Hour 1**: Enable RLS on all multi-tenant tables
2. **Hour 2**: Create and test RLS policies
3. **Hour 3**: Update connection handler with session variables
4. **Hour 4**: Testing, performance validation, documentation

## Status

**Current Status**: DOCUMENTED
**Implementation**: Deferred to v0.8.0 or v1.0.0
**Priority**: MEDIUM (does not block v0.7.0 OSS launch)

**Justification for Deferral**:
- H-TENANT-1 already provides application-level tenant isolation
- Defense-in-depth measure (not primary control)
- Requires careful database migration
- Can be implemented in controlled manner post-launch

## Workaround for v0.7.0

Until M-TENANT-1 is implemented:

1. **Application-Level Enforcement** (✅ Complete):
   - H-TENANT-1 validates tenant context in storage layer
   - Cross-tenant access denied with error
   - Comprehensive audit logging

2. **Additional Safeguards**:
   - Regular audit log reviews
   - Automated tenant isolation testing
   - Code review for tenant context handling

3. **Monitoring**:
   - Alert on cross-tenant access attempts
   - Dashboard for tenant isolation metrics
   - Quarterly security audits

## References

- **PostgreSQL RLS Documentation**: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- **H-TENANT-1 Implementation**: `pkg/storage/providers/database/rbac_store.go`
- **Security Audit**: `docs/security/audits/audit-report-2025-10-17.md`
- **Remediation Plan**: `docs/security/audits/remediation-plan-2025-10-17.md`

## Example: Complete RLS Setup

```sql
-- M-TENANT-1: Complete RLS setup for rbac_roles table

-- 1. Enable RLS
ALTER TABLE rbac_roles ENABLE ROW LEVEL SECURITY;

-- 2. Create tenant isolation policy
CREATE POLICY tenant_isolation ON rbac_roles
	USING (
		is_system_role = true
		OR
		tenant_id = current_setting('app.current_tenant', true)
	)
	WITH CHECK (
		is_system_role = true
		OR
		tenant_id = current_setting('app.current_tenant', true)
	);

-- 3. Create admin override policy
CREATE POLICY admin_override ON rbac_roles
	USING (current_setting('app.is_admin', true)::boolean = true)
	WITH CHECK (current_setting('app.is_admin', true)::boolean = true);

-- 4. Test policies
SET app.current_tenant = 'tenant-123';
SELECT * FROM rbac_roles; -- Only returns tenant-123 roles + system roles

SET app.current_tenant = 'tenant-456';
SELECT * FROM rbac_roles; -- Only returns tenant-456 roles + system roles

SET app.is_admin = true;
SELECT * FROM rbac_roles; -- Returns all roles (admin override)
```
