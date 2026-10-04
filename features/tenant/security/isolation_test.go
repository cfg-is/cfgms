// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package security

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestIsIPInRange(t *testing.T) {
	engine := &TenantIsolationEngine{}

	tests := []struct {
		name      string
		ip        string
		cidrRange string
		want      bool
	}{
		// Match-all wildcard
		{"all-match cidr 0.0.0.0/0 with arbitrary IP", "1.2.3.4", "0.0.0.0/0", true},
		{"all-match cidr 0.0.0.0/0 with another IP", "255.255.255.255", "0.0.0.0/0", true},

		// /24 network
		{"192.168.1.0/24 matches host in range", "192.168.1.5", "192.168.1.0/24", true},
		{"192.168.1.0/24 rejects host outside range", "192.168.2.5", "192.168.1.0/24", false},

		// /8 network
		{"10.0.0.0/8 matches highest host", "10.255.255.255", "10.0.0.0/8", true},
		{"10.0.0.0/8 rejects 11.0.0.0", "11.0.0.0", "10.0.0.0/8", false},

		// /12 network (172.16.0.0 – 172.31.255.255)
		{"172.16.0.0/12 matches lower bound", "172.16.0.1", "172.16.0.0/12", true},
		{"172.16.0.0/12 matches upper bound", "172.31.255.255", "172.16.0.0/12", true},
		{"172.16.0.0/12 rejects address just above range", "172.32.0.0", "172.16.0.0/12", false},

		// /16 network
		{"10.0.0.0/16 matches host in range", "10.0.0.1", "10.0.0.0/16", true},
		{"10.0.0.0/16 rejects 10.1.0.0", "10.1.0.0", "10.0.0.0/16", false},

		// IPv6 /32 network
		{"2001:db8::/32 matches address in range", "2001:db8:1::1", "2001:db8::/32", true},
		{"2001:db8::/32 rejects address outside range", "2001:db9::1", "2001:db8::/32", false},

		// Invalid inputs — must return false, no panic
		{"invalid CIDR returns false", "192.168.1.1", "not-a-cidr", false},
		{"invalid IP returns false", "not-an-ip", "192.168.1.0/24", false},
		{"empty IP returns false", "", "192.168.1.0/24", false},
		{"empty CIDR returns false", "192.168.1.1", "", false},
		{"both empty returns false", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.isIPInRange(tt.ip, tt.cidrRange)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestIsAccessLevelSufficient_ZeroValueOrdersBelowEveryRealLevel asserts the
// invariant ValidateTenantAccess's cap depends on: the zero value of
// CrossTenantLevel (what a map lookup returns for a subject tenant absent from
// CrossTenantAccess.AccessLevels) must never be sufficient for any real,
// access-granting level. If this ever regresses, a missing map entry would
// silently grant access instead of denying it.
func TestIsAccessLevelSufficient_ZeroValueOrdersBelowEveryRealLevel(t *testing.T) {
	engine := &TenantIsolationEngine{}

	var zeroValue CrossTenantLevel // simulates a missing AccessLevels map entry

	for _, requested := range []CrossTenantLevel{
		CrossTenantLevelRead,
		CrossTenantLevelWrite,
		CrossTenantLevelFull,
		CrossTenantLevelDelegate,
	} {
		assert.False(t, engine.isAccessLevelSufficient(zeroValue, requested),
			"zero-value access level must not be sufficient for %s", requested)
	}

	// A request for CrossTenantLevelNone (no access) is the only level a
	// zero-value cap is sufficient for, since both order to 0.
	assert.True(t, engine.isAccessLevelSufficient(zeroValue, CrossTenantLevelNone))
}

// newTestTenantIsolationEngine builds a TenantIsolationEngine backed by real
// storage and a real audit.Manager, mirroring the pattern used by
// enhanced_multi_tenant_security_test.go and integration_cross_tenant_isolation_test.go.
// It also returns the tenant.Manager so callers can create the tenants an
// isolation rule references (CreateIsolationRule requires the target tenant
// to already exist).
// testRootTenantID is the conventional name of the root tenant these tests seed;
// the root is identified by position, never by this name (Issue #4542).
const testRootTenantID = "root"

func newTestTenantIsolationEngine(t *testing.T) (*TenantIsolationEngine, *tenant.Manager) {
	t.Helper()
	storageManager := pkgtesting.SetupTestStorage(t)
	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, nil)
	// The deployment root (the single tenant with no parent, Issue #4542); test
	// tenants are created beneath it.
	_, err := tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ID: testRootTenantID})
	require.NoError(t, err)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "tenant-isolation-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = auditMgr.Stop(ctx)
	})

	return NewTenantIsolationEngine(tenantManager, auditMgr), tenantManager
}

// TestValidateTenantAccess_SubjectMissingFromAccessLevelsIsDenied is the
// [REQUIRED TEST] for Issue #4347's fail-open defect: a subject tenant that
// appears in a target's CrossTenantAccess.AllowedTenants list, but has no
// entry in CrossTenantAccess.AccessLevels, must be denied — including for a
// read-level request, the lowest real access level and the only level the
// controller's authentication middleware currently ever requests
// (features/controller/api/middleware.go). Before the fix, the `exists`
// branch in ValidateTenantAccess skipped the cap entirely for a missing
// entry and fell through to granting access; this test fails against that
// code.
func TestValidateTenantAccess_SubjectMissingFromAccessLevelsIsDenied(t *testing.T) {
	ctx := context.Background()
	engine, tenantManager := newTestTenantIsolationEngine(t)

	_, err := tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "subject-tenant", ParentID: testRootTenantID})
	require.NoError(t, err)
	_, err = tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "target-tenant", ParentID: testRootTenantID})
	require.NoError(t, err)

	rule := &IsolationRule{
		TenantID:        "target-tenant",
		ComplianceLevel: ComplianceLevelBasic,
		DataResidency:   DataResidencyRule{RequireEncryption: false},
		CrossTenantAccess: CrossTenantRule{
			AllowCrossTenantAccess: true,
			AllowedTenants:         []string{"subject-tenant"},
			// Deliberately no AccessLevels entry for "subject-tenant".
		},
	}
	require.NoError(t, engine.CreateIsolationRule(ctx, rule))

	response, err := engine.ValidateTenantAccess(ctx, &TenantAccessRequest{
		SubjectID:       "user-1",
		SubjectTenantID: "subject-tenant",
		TargetTenantID:  "target-tenant",
		ResourceID:      "some-resource",
		AccessLevel:     CrossTenantLevelRead,
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.False(t, response.Granted,
		"a subject tenant present in AllowedTenants but absent from AccessLevels must be denied, not fail open")
}
