// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/migrate"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newInternalOSSManager builds a real OSS (flatfile+sqlite) StorageManager under
// a per-test temp directory. The tests in this file need package-internal access
// to the export/import helpers, so they cannot use the storage_test helpers.
func newInternalOSSManager(t *testing.T) *interfaces.StorageManager {
	t.Helper()
	dir := t.TempDir()
	mgr, err := interfaces.CreateOSSStorageManager(dir+"/flatfile", dir+"/cfgms.db")
	require.NoError(t, err, "create OSS storage manager")
	t.Cleanup(func() { assert.NoError(t, mgr.Close(), "close OSS storage manager") })
	return mgr
}

// recordIndex returns the position of id among the records of the given kind,
// or -1 when it is absent.
func recordIndex(recs []migrate.Record, kind, id string) int {
	pos := -1
	i := 0
	for _, r := range recs {
		if r.Kind != kind {
			continue
		}
		if r.ID == id {
			pos = i
		}
		i++
	}
	return pos
}

// TestExportTenants_EmitsParentsBeforeChildren exercises the sortParentFirst call
// on the tenant export path with a real multi-level hierarchy. The SQLite tenant
// store lists by created_at DESC, so a hierarchy created root-first is returned
// leaf-first — importing in that order would violate the destination's
// cfgms_tenants_parent_id_fkey.
func TestExportTenants_EmitsParentsBeforeChildren(t *testing.T) {
	ctx := context.Background()
	mgr := newInternalOSSManager(t)

	ts := mgr.GetTenantStore()
	if ts == nil {
		t.Fatal("tenant store must be available")
	}
	if err := ts.Initialize(ctx); err != nil {
		t.Fatalf("initialize tenant store: %v", err)
	}
	for _, tenant := range []*business.TenantData{
		{ID: "hier-root", Name: "root"},
		{ID: "hier-child", Name: "child", ParentID: "hier-root"},
		{ID: "hier-leaf", Name: "leaf", ParentID: "hier-child"},
	} {
		tenant.Status = business.TenantStatusActive
		tenant.CreatedAt = time.Now()
		tenant.UpdatedAt = time.Now()
		if err := ts.CreateTenant(ctx, tenant); err != nil {
			t.Fatalf("create tenant %s: %v", tenant.ID, err)
		}
		// Distinct created_at values so the store's ordering is deterministic.
		time.Sleep(2 * time.Millisecond)
	}

	// The unsorted store order must be leaf-first, otherwise this test would
	// pass even if sortParentFirst were removed.
	raw, err := ts.ListTenants(ctx, &business.TenantFilter{})
	if err != nil {
		t.Fatalf("list tenants: %v", err)
	}
	if len(raw) != 3 || raw[0].ID != "hier-leaf" {
		t.Fatalf("expected the store to return leaf-first, got %v", tenantIDs(raw))
	}

	recs, ids, err := exportTenants(ctx, mgr)
	if err != nil {
		t.Fatalf("exportTenants: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3 tenant IDs, got %v", ids)
	}
	root := recordIndex(recs, kindTenant, "hier-root")
	child := recordIndex(recs, kindTenant, "hier-child")
	leaf := recordIndex(recs, kindTenant, "hier-leaf")
	if root == -1 || child == -1 || leaf == -1 {
		t.Fatalf("expected all three tenants in the export, got %v", ids)
	}
	if root >= child || child >= leaf {
		t.Fatalf("expected parent-first order, got root=%d child=%d leaf=%d", root, child, leaf)
	}
}

func tenantIDs(tenants []*business.TenantData) []string {
	out := make([]string, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, t.ID)
	}
	return out
}

// TestExportRBAC_EmitsParentRolesBeforeChildren exercises the sortParentFirst
// call on the RBAC role export path. The SQLite RBAC store lists roles ordered
// by name, so the names below are chosen to return children before parents —
// the order that violates rbac_roles_parent_role_id_fkey on import.
func TestExportRBAC_EmitsParentRolesBeforeChildren(t *testing.T) {
	ctx := context.Background()
	mgr := newInternalOSSManager(t)

	rbac := mgr.GetRBACStore()
	if rbac == nil {
		t.Fatal("RBAC store must be available")
	}
	if err := rbac.Initialize(ctx); err != nil {
		t.Fatalf("initialize RBAC store: %v", err)
	}
	for _, role := range []*common.Role{
		{Id: "role-hier-root", Name: "zzz-root"},
		{Id: "role-hier-child", Name: "mmm-child", ParentRoleId: "role-hier-root"},
		{Id: "role-hier-leaf", Name: "aaa-leaf", ParentRoleId: "role-hier-child"},
	} {
		if err := rbac.StoreRole(ctx, role); err != nil {
			t.Fatalf("store role %s: %v", role.Id, err)
		}
	}

	// The unsorted store order must be leaf-first for this to be a real guard.
	rawRoles, err := rbac.ListRoles(ctx, "")
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(rawRoles) != 3 || rawRoles[0].Id != "role-hier-leaf" {
		t.Fatalf("expected the store to return leaf-first, got %v", roleIDs(rawRoles))
	}

	recs, err := exportRBAC(ctx, mgr)
	if err != nil {
		t.Fatalf("exportRBAC: %v", err)
	}
	root := recordIndex(recs, kindRBACRole, "role-hier-root")
	child := recordIndex(recs, kindRBACRole, "role-hier-child")
	leaf := recordIndex(recs, kindRBACRole, "role-hier-leaf")
	if root == -1 || child == -1 || leaf == -1 {
		t.Fatalf("expected all three roles in the export, got root=%d child=%d leaf=%d", root, child, leaf)
	}
	if root >= child || child >= leaf {
		t.Fatalf("expected parent-first order, got root=%d child=%d leaf=%d", root, child, leaf)
	}
}

func roleIDs(roles []*common.Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.Id)
	}
	return out
}

// TestExportRBAC_RoleParentCycleFails verifies that a role graph whose parent
// chain cannot be resolved fails the export with the sortParentFirst guard
// rather than looping forever. A cycle can only reach the exporter from a
// backend that does not enforce the self-referential FK, which is exactly the
// SQLite source used here.
func TestExportRBAC_RoleParentCycleFails(t *testing.T) {
	ctx := context.Background()
	mgr := newInternalOSSManager(t)

	rbac := mgr.GetRBACStore()
	if err := rbac.Initialize(ctx); err != nil {
		t.Fatalf("initialize RBAC store: %v", err)
	}
	// Store both halves of the cycle: role-a's parent is role-b and vice versa.
	if err := rbac.StoreRole(ctx, &common.Role{Id: "role-cycle-a", Name: "cycle-a"}); err != nil {
		t.Fatalf("store role-cycle-a: %v", err)
	}
	if err := rbac.StoreRole(ctx, &common.Role{Id: "role-cycle-b", Name: "cycle-b", ParentRoleId: "role-cycle-a"}); err != nil {
		t.Fatalf("store role-cycle-b: %v", err)
	}
	if err := rbac.StoreRole(ctx, &common.Role{Id: "role-cycle-a", Name: "cycle-a", ParentRoleId: "role-cycle-b"}); err != nil {
		t.Fatalf("close the cycle on role-cycle-a: %v", err)
	}

	_, err := exportRBAC(ctx, mgr)
	if err == nil {
		t.Fatal("expected exportRBAC to fail on a role parent cycle")
	}
	if !strings.Contains(err.Error(), "sort RBAC roles") || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected a cycle error naming the RBAC role sort, got %v", err)
	}
}

// TestImportRBACAndClientTenant_MalformedData verifies every RBAC and
// client-tenant import path rejects a corrupt record with a descriptive error
// instead of writing partial state.
func TestImportRBACAndClientTenant_MalformedData(t *testing.T) {
	ctx := context.Background()
	mgr := newInternalOSSManager(t)

	cases := []struct {
		name string
		fn   func(context.Context, *interfaces.StorageManager, migrate.Record) error
		want string
	}{
		{"permission", importRBACPermission, "unmarshal permission"},
		{"role", importRBACRole, "unmarshal role"},
		{"subject", importRBACSubject, "unmarshal subject"},
		{"assignment", importRBACAssignment, "unmarshal role assignment"},
		{"client tenant", importClientTenant, "unmarshal client tenant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn(ctx, mgr, migrate.Record{Kind: "x", ID: "id", Data: []byte("{not json")})
			if err == nil {
				t.Fatal("expected an error for malformed record data")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// TestImportRBAC_StoreWriteFailureIsReported verifies that a destination write
// failure surfaces with the failing record's ID rather than being swallowed or
// masked by a second write attempt. The failure is produced by a real backend:
// the destination's SQLite database is closed before the import runs.
func TestImportRBAC_StoreWriteFailureIsReported(t *testing.T) {
	ctx := context.Background()
	mgr := newInternalOSSManager(t)

	rbac := mgr.GetRBACStore()
	if err := rbac.Initialize(ctx); err != nil {
		t.Fatalf("initialize RBAC store: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("close storage manager: %v", err)
	}

	err := importRBACRole(ctx, mgr, migrate.Record{
		Kind: kindRBACRole,
		ID:   "role-write-fail",
		Data: []byte(`{"id":"role-write-fail","name":"write-fail"}`),
	})
	if err == nil {
		t.Fatal("expected an error when the destination backend is unavailable")
	}
	if !strings.Contains(err.Error(), "role-write-fail") {
		t.Fatalf("expected the error to name the failing role, got %v", err)
	}
}

// TestImportRBACAndClientTenant_StoreUnavailable verifies the import paths fail
// with a clear message when the destination backend does not expose the store,
// rather than panicking on a nil interface.
func TestImportRBACAndClientTenant_StoreUnavailable(t *testing.T) {
	ctx := context.Background()
	// A composite manager with no RBAC and no client-tenant store.
	mgr := interfaces.NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	cases := []struct {
		name string
		fn   func(context.Context, *interfaces.StorageManager, migrate.Record) error
		want string
	}{
		{"permission", importRBACPermission, "RBAC store not available"},
		{"role", importRBACRole, "RBAC store not available"},
		{"subject", importRBACSubject, "RBAC store not available"},
		{"assignment", importRBACAssignment, "RBAC store not available"},
		{"client tenant", importClientTenant, "client tenant store not available"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn(ctx, mgr, migrate.Record{Kind: "x", ID: "id", Data: []byte(`{}`)})
			if err == nil {
				t.Fatal("expected an error when the destination store is absent")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}

	// Export must treat the absent stores as "nothing to migrate", not an error.
	recs, err := exportRBAC(ctx, mgr)
	if err != nil || recs != nil {
		t.Fatalf("exportRBAC with no store: got recs=%v err=%v", recs, err)
	}
	ctRecs, err := exportClientTenants(ctx, mgr)
	if err != nil || ctRecs != nil {
		t.Fatalf("exportClientTenants with no store: got recs=%v err=%v", ctRecs, err)
	}
}
