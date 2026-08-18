// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	cfgpkg "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgmstesting "github.com/cfgis/cfgms/pkg/testing"
)

// newTestTenantManager creates a Manager backed by real SQLite+flatfile storage.
func newTestTenantManager(t *testing.T) *Manager {
	t.Helper()
	storageManager := cfgmstesting.SetupTestStorage(t)
	rbacManager := cfgmstesting.SetupTestRBACManager(t)
	return NewManager(storageManager.GetTenantStore(), rbacManager)
}

func TestManager_CreateTenant(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Test creating a new tenant
	req := &TenantRequest{
		Name:        "Test-Tenant",
		Description: "A test tenant",
		Metadata: map[string]string{
			"owner": "test@example.com",
		},
	}

	tenant, err := manager.CreateTenant(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, tenant.ID)
	assert.Equal(t, "Test-Tenant", tenant.Name)
	assert.Equal(t, "A test tenant", tenant.Description)
	assert.Equal(t, business.TenantStatusActive, tenant.Status)
	assert.Equal(t, "test@example.com", tenant.Metadata["owner"])
	assert.NotZero(t, tenant.CreatedAt)
	assert.NotZero(t, tenant.UpdatedAt)

	// Verify tenant can be retrieved
	retrieved, err := manager.GetTenant(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, retrieved.ID)
	assert.Equal(t, tenant.Name, retrieved.Name)
}

func TestManager_CreateTenant_WithParent(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create parent tenant
	parentReq := &TenantRequest{
		Name: "Parent-Tenant",
	}
	parent, err := manager.CreateTenant(ctx, parentReq)
	require.NoError(t, err)

	// Create child tenant
	childReq := &TenantRequest{
		Name:     "Child-Tenant",
		ParentID: parent.ID,
	}
	child, err := manager.CreateTenant(ctx, childReq)
	require.NoError(t, err)
	assert.Equal(t, parent.ID, child.ParentID)

	// Verify hierarchy
	hierarchy, err := manager.GetTenantHierarchy(ctx, child.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, hierarchy.Depth)
	assert.Contains(t, hierarchy.Path, parent.ID)
	assert.Contains(t, hierarchy.Path, child.ID)

	// Verify parent has child
	children, err := manager.GetChildTenants(ctx, parent.ID)
	require.NoError(t, err)
	assert.Len(t, children, 1)
	assert.Equal(t, child.ID, children[0].ID)
}

func TestManager_CreateTenant_Validation(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Test validation errors
	tests := []struct {
		name string
		req  *TenantRequest
	}{
		{
			name: "empty name",
			req:  &TenantRequest{Name: ""},
		},
		{
			name: "invalid characters",
			req:  &TenantRequest{Name: "test@tenant!"},
		},
		{
			name: "name too long",
			req:  &TenantRequest{Name: string(make([]byte, 65))},
		},
		{
			name: "description too long",
			req:  &TenantRequest{Name: "test", Description: string(make([]byte, 256))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := manager.CreateTenant(ctx, tt.req)
			assert.Error(t, err)
		})
	}
}

func TestManager_ListTenants(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create test tenants
	tenant1, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Tenant1"})
	require.NoError(t, err)

	tenant2, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Tenant2", ParentID: tenant1.ID})
	require.NoError(t, err)

	// List all tenants (real storage starts empty — only tenant1 and tenant2 present)
	tenants, err := manager.ListTenants(ctx, nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(tenants), 2)

	// List tenants with filter
	filter := &business.TenantFilter{ParentID: tenant1.ID}
	filteredTenants, err := manager.ListTenants(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, filteredTenants, 1)
	assert.Equal(t, tenant2.ID, filteredTenants[0].ID)
}

func TestManager_UpdateTenant(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create tenant
	originalReq := &TenantRequest{
		Name:        "Original-Name",
		Description: "Original Description",
	}
	tenant, err := manager.CreateTenant(ctx, originalReq)
	require.NoError(t, err)

	// Update tenant
	updateReq := &TenantRequest{
		Name:        "Updated-Name",
		Description: "Updated Description",
		Metadata: map[string]string{
			"updated": "true",
		},
	}

	updated, err := manager.UpdateTenant(ctx, tenant.ID, updateReq)
	require.NoError(t, err)
	assert.Equal(t, "Updated-Name", updated.Name)
	assert.Equal(t, "Updated Description", updated.Description)
	assert.Equal(t, "true", updated.Metadata["updated"])
	assert.True(t, tenant.CreatedAt.Equal(updated.CreatedAt), "CreatedAt should not change after update")
	// UpdatedAt should be at or after the original (may be equal on fast systems)
	assert.False(t, updated.UpdatedAt.Before(tenant.UpdatedAt))
}

func TestManager_DeleteTenant(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create tenant
	tenant, err := manager.CreateTenant(ctx, &TenantRequest{Name: "ToDelete"})
	require.NoError(t, err)

	// Delete tenant
	err = manager.DeleteTenant(ctx, tenant.ID)
	require.NoError(t, err)

	// Verify tenant was removed (real storage hard-deletes)
	_, err = manager.GetTenant(ctx, tenant.ID)
	require.Error(t, err)
}

func TestManager_DeleteTenant_WithChildren(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create parent and child tenants
	parent, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Parent"})
	require.NoError(t, err)

	_, err = manager.CreateTenant(ctx, &TenantRequest{Name: "Child", ParentID: parent.ID})
	require.NoError(t, err)

	// Try to delete parent - should fail
	err = manager.DeleteTenant(ctx, parent.ID)
	assert.Error(t, err)
	assert.Equal(t, ErrTenantHasChildren, err)
}

func TestManager_IsTenantAncestor(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create hierarchy: grandparent -> parent -> child
	grandparent, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Grandparent"})
	require.NoError(t, err)

	parent, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Parent", ParentID: grandparent.ID})
	require.NoError(t, err)

	child, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Child", ParentID: parent.ID})
	require.NoError(t, err)

	// Test ancestor relationships
	isAncestor, err := manager.IsTenantAncestor(ctx, grandparent.ID, child.ID)
	require.NoError(t, err)
	assert.True(t, isAncestor)

	isAncestor, err = manager.IsTenantAncestor(ctx, parent.ID, child.ID)
	require.NoError(t, err)
	assert.True(t, isAncestor)

	isAncestor, err = manager.IsTenantAncestor(ctx, child.ID, grandparent.ID)
	require.NoError(t, err)
	assert.False(t, isAncestor)

	isAncestor, err = manager.IsTenantAncestor(ctx, child.ID, parent.ID)
	require.NoError(t, err)
	assert.False(t, isAncestor)
}

// setupRealTenantManager creates a Manager backed by real SQLite storage for cascade tests.
func setupRealTenantManager(t *testing.T, rbacManager *rbac.Manager) *Manager {
	t.Helper()
	storageManager := cfgmstesting.SetupTestStorage(t)
	return NewManager(storageManager.GetTenantStore(), rbacManager)
}

func TestDeleteTenant_CascadesRBACCleanup(t *testing.T) {
	rbacManager := cfgmstesting.SetupTestRBACManager(t)
	manager := setupRealTenantManager(t, rbacManager)
	ctx := context.Background()
	// M-AUTH-2: CreateRole requires justification in context
	ctx = rbac.WithSensitiveOperationJustification(ctx, "test: tenant RBAC cleanup cascade")

	// Create a tenant — this also calls CreateTenantDefaultRoles (in-memory only)
	tenant, err := manager.CreateTenant(ctx, &TenantRequest{Name: "RBACCleanupTenant"})
	require.NoError(t, err)
	tenantID := tenant.ID

	// Explicitly create a persisted role and two subjects for this tenant
	role := &common.Role{
		Id:       tenantID + ".custom-role",
		Name:     "Custom Role",
		TenantId: tenantID,
	}
	require.NoError(t, rbacManager.CreateRole(ctx, role))

	for _, s := range []*common.Subject{
		{Id: "user-" + tenantID, Type: common.SubjectType_SUBJECT_TYPE_USER, TenantId: tenantID, IsActive: true},
		{Id: "svc-" + tenantID, Type: common.SubjectType_SUBJECT_TYPE_SERVICE, TenantId: tenantID, IsActive: true},
	} {
		require.NoError(t, rbacManager.CreateSubject(ctx, s))
	}

	// Verify the persisted role and subjects exist before deletion
	_, err = rbacManager.GetRole(ctx, role.Id)
	require.NoError(t, err, "custom role must exist before deletion")

	subjectsBefore, err := rbacManager.ListAllSubjects(ctx, tenantID)
	require.NoError(t, err)
	assert.NotEmpty(t, subjectsBefore, "expected subjects before tenant deletion")

	// Delete the tenant — must cascade RBAC cleanup
	require.NoError(t, manager.DeleteTenant(ctx, tenantID))

	// Persisted role must be gone
	_, err = rbacManager.GetRole(ctx, role.Id)
	assert.Error(t, err, "custom role should not exist after tenant deletion")

	// No subjects must remain for this tenant
	subjectsAfter, err := rbacManager.ListAllSubjects(ctx, tenantID)
	require.NoError(t, err)
	assert.Empty(t, subjectsAfter, "expected no subjects after tenant deletion")

	// No tenant-scoped roles must remain (ListRoles also returns system roles; skip those)
	rolesAfter, err := rbacManager.ListRoles(ctx, tenantID)
	require.NoError(t, err)
	for _, r := range rolesAfter {
		assert.NotEqual(t, tenantID, r.TenantId, "tenant-scoped role should have been deleted: %s", r.Id)
	}
}

func TestDeleteTenant_CascadesRBACCleanup_NilRBACManager(t *testing.T) {
	// Manager with nil rbacManager — must not panic, must succeed
	manager := setupRealTenantManager(t, nil)
	ctx := context.Background()

	tenant, err := manager.CreateTenant(ctx, &TenantRequest{Name: "NoRBACTenant"})
	require.NoError(t, err)

	require.NoError(t, manager.DeleteTenant(ctx, tenant.ID))
}

// TestDeleteTenant_CascadesRBACCleanup_PartialFailureContinues verifies that
// DeleteTenant returns nil even when individual RBAC cascade deletions encounter
// errors. CreateTenant loads default tenant roles into the in-memory RBAC store
// without persisting them to durable storage. The cascade deletes them from
// in-memory but the durable delete fails; the warning is logged and the tenant
// deletion proceeds successfully.
func TestDeleteTenant_CascadesRBACCleanup_PartialFailureContinues(t *testing.T) {
	rbacManager := cfgmstesting.SetupTestRBACManager(t)
	manager := setupRealTenantManager(t, rbacManager)
	ctx := context.Background()

	// CreateTenant triggers CreateTenantDefaultRoles which loads roles into the
	// in-memory store only (not the durable RBAC store). The cascade will
	// encounter "role not found" errors from the durable layer — those must be
	// logged as warnings, not returned as failures.
	tenant, err := manager.CreateTenant(ctx, &TenantRequest{Name: "PartialFailureTenant"})
	require.NoError(t, err)

	// DeleteTenant must return nil despite individual cascade errors
	require.NoError(t, manager.DeleteTenant(ctx, tenant.ID))
}

// recordingInvalidator records every tenant ID passed to InvalidateTenantCache.
type recordingInvalidator struct {
	calls []string
}

func (r *recordingInvalidator) InvalidateTenantCache(id string) {
	r.calls = append(r.calls, id)
}

func TestManager_UpdateTenant_InvalidatesConfigCache(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	tenant, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Cache-Invalidation-Test"})
	require.NoError(t, err)

	inv := &recordingInvalidator{}
	manager.WithConfigRouter(inv)

	updateReq := &TenantRequest{
		Name: tenant.Name,
		Metadata: map[string]string{
			"config_source_type": "controller",
		},
	}
	_, err = manager.UpdateTenant(ctx, tenant.ID, updateReq)
	require.NoError(t, err)

	require.Len(t, inv.calls, 1, "InvalidateTenantCache must be called exactly once after UpdateTenant")
	assert.Equal(t, tenant.ID, inv.calls[0], "InvalidateTenantCache must receive the updated tenant ID")
}

func TestManager_InvalidateConfigCache_CallsRouter(t *testing.T) {
	manager := newTestTenantManager(t)

	inv := &recordingInvalidator{}
	manager.WithConfigRouter(inv)

	manager.InvalidateConfigCache("tenant-to-evict")

	require.Len(t, inv.calls, 1, "InvalidateConfigCache must delegate to the wired router exactly once")
	assert.Equal(t, "tenant-to-evict", inv.calls[0], "router must receive the tenant ID passed to InvalidateConfigCache")
}

func TestManager_InvalidateConfigCache_NoRouterWired_NoError(t *testing.T) {
	// Manager with no router wired must not panic when InvalidateConfigCache is called.
	manager := newTestTenantManager(t)

	require.NotPanics(t, func() {
		manager.InvalidateConfigCache("any-tenant")
	}, "InvalidateConfigCache without a wired router must be a safe no-op")
}

func TestManager_UpdateTenant_NoRouterWired_NoError(t *testing.T) {
	// Manager with no router wired must not panic on UpdateTenant.
	manager := newTestTenantManager(t)
	ctx := context.Background()

	tenant, err := manager.CreateTenant(ctx, &TenantRequest{Name: "No-Router-Tenant"})
	require.NoError(t, err)

	_, err = manager.UpdateTenant(ctx, tenant.ID, &TenantRequest{Name: tenant.Name})
	require.NoError(t, err, "UpdateTenant without a wired router must succeed")
}

// --- Validator and audit coverage ---

// testMountPointValidator is a real test double (not a mock) implementing cfgpkg.MountPointValidator.
type testMountPointValidator struct {
	err error
}

func (v *testMountPointValidator) ValidateMountPoint(_ context.Context, _ *cfgpkg.ConfigSourceInfo, _ secretsiface.SecretStore) error {
	return v.err
}

// TestManager_WithMountPointValidator_BlocksCreateOnFailure verifies that a wired
// validator returning an error causes CreateTenant to return that error when the
// metadata includes a git config source.
func TestManager_WithMountPointValidator_BlocksCreateOnFailure(t *testing.T) {
	manager := newTestTenantManager(t)
	manager.WithMountPointValidator(&testMountPointValidator{
		err: fmt.Errorf("mount point connection test failed: connection refused"),
	}, nil)

	ctx := context.Background()
	_, err := manager.CreateTenant(ctx, &TenantRequest{
		Name: "BlockedTenant",
		Metadata: map[string]string{
			cfgpkg.MetaKeyConfigSourceType: "git",
			cfgpkg.MetaKeyConfigSourceURL:  "https://github.com/example/configs.git",
		},
	})
	require.Error(t, err, "CreateTenant must fail when validator rejects the mount point")
	assert.Contains(t, err.Error(), "config source validation failed")
}

// TestManager_WithMountPointValidator_AllowsCreateOnSuccess verifies that a wired
// validator returning nil allows CreateTenant to succeed for git config sources.
func TestManager_WithMountPointValidator_AllowsCreateOnSuccess(t *testing.T) {
	manager := newTestTenantManager(t)
	manager.WithMountPointValidator(&testMountPointValidator{err: nil}, nil)

	ctx := context.Background()
	td, err := manager.CreateTenant(ctx, &TenantRequest{
		Name: "AllowedTenant",
		Metadata: map[string]string{
			cfgpkg.MetaKeyConfigSourceType: "git",
			cfgpkg.MetaKeyConfigSourceURL:  "https://github.com/example/configs.git",
		},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, td.ID)
}

// TestManager_WithMountPointValidator_BlocksUpdateOnFailure verifies that UpdateTenant
// returns an error when the new metadata includes a git config source that fails validation.
func TestManager_WithMountPointValidator_BlocksUpdateOnFailure(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	td, err := manager.CreateTenant(ctx, &TenantRequest{Name: "UpdateBlockedTenant"})
	require.NoError(t, err)

	manager.WithMountPointValidator(&testMountPointValidator{
		err: fmt.Errorf("mount point connection test failed: connection refused"),
	}, nil)

	_, err = manager.UpdateTenant(ctx, td.ID, &TenantRequest{
		Name: td.Name,
		Metadata: map[string]string{
			cfgpkg.MetaKeyConfigSourceType: "git",
			cfgpkg.MetaKeyConfigSourceURL:  "https://github.com/example/configs.git",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config source validation failed")
}

// TestManager_ResolveConfigSourceAuditAction_AllBranches verifies all four branches of
// resolveConfigSourceAuditAction.
func TestManager_ResolveConfigSourceAuditAction_AllBranches(t *testing.T) {
	m := &Manager{}
	const git = "git"

	tests := []struct {
		name             string
		oldType, newType string
		oldMeta, newMeta map[string]string
		wantAction       string
		wantURL          string
	}{
		{
			name:    "no-git to git emits created",
			oldType: "controller", newType: git,
			oldMeta:    map[string]string{},
			newMeta:    map[string]string{cfgpkg.MetaKeyConfigSourceURL: "https://example.com/repo.git"},
			wantAction: "config_source_created",
			wantURL:    "https://example.com/repo.git",
		},
		{
			name:    "git to no-git emits deleted",
			oldType: git, newType: "controller",
			oldMeta:    map[string]string{cfgpkg.MetaKeyConfigSourceURL: "https://example.com/repo.git"},
			newMeta:    map[string]string{},
			wantAction: "config_source_deleted",
			wantURL:    "https://example.com/repo.git",
		},
		{
			name:    "git to git with URL change emits updated",
			oldType: git, newType: git,
			oldMeta:    map[string]string{cfgpkg.MetaKeyConfigSourceURL: "https://old.example.com/repo.git"},
			newMeta:    map[string]string{cfgpkg.MetaKeyConfigSourceURL: "https://new.example.com/repo.git"},
			wantAction: "config_source_updated",
			wantURL:    "https://new.example.com/repo.git",
		},
		{
			name:    "git to git unchanged emits nothing",
			oldType: git, newType: git,
			oldMeta:    map[string]string{cfgpkg.MetaKeyConfigSourceURL: "https://example.com/repo.git"},
			newMeta:    map[string]string{cfgpkg.MetaKeyConfigSourceURL: "https://example.com/repo.git"},
			wantAction: "",
			wantURL:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			action, url := m.resolveConfigSourceAuditAction(tc.oldType, tc.newType, tc.oldMeta, tc.newMeta)
			assert.Equal(t, tc.wantAction, action)
			assert.Equal(t, tc.wantURL, url)
		})
	}
}

// TestManager_WithAuditManager_RecordsEventOnCreate verifies that a wired audit manager
// durably records a config_source_created event when CreateTenant includes a git config source.
func TestManager_WithAuditManager_RecordsEventOnCreate(t *testing.T) {
	manager := newTestTenantManager(t)
	auditMgr := cfgmstesting.SetupTestAuditManager(t)
	manager.WithAuditManager(auditMgr)

	ctx := context.Background()
	td, err := manager.CreateTenant(ctx, &TenantRequest{
		Name: "AuditedTenant",
		Metadata: map[string]string{
			cfgpkg.MetaKeyConfigSourceType: "git",
			cfgpkg.MetaKeyConfigSourceURL:  "https://github.com/example/configs.git",
		},
	})
	require.NoError(t, err)

	// Flush drains the async audit queue so the event is durable before querying.
	require.NoError(t, auditMgr.Flush(ctx))

	entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
		TenantID: td.ID,
		Actions:  []string{"config_source_created"},
	})
	require.NoError(t, err)
	require.Len(t, entries, 1, "expected exactly one config_source_created audit entry")
	assert.Equal(t, "config_source_created", entries[0].Action)
	assert.Equal(t, td.ID, entries[0].TenantID)
}

// TestSanitizeAuditURL verifies that sanitizeAuditURL redacts userinfo from URLs.
func TestSanitizeAuditURL_RedactsUserinfo(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantSub string // substring that must NOT appear
		wantURL string // expected result (empty = any non-secret value is OK)
	}{
		{
			name:    "plain URL unchanged",
			rawURL:  "https://github.com/example/repo.git",
			wantURL: "https://github.com/example/repo.git",
		},
		{
			name:    "URL with password redacted",
			rawURL:  "https://user:supersecret@github.com/example/repo.git",
			wantSub: "supersecret",
		},
		{
			name:    "URL with token-as-username stripped",
			rawURL:  "https://token@github.com/example/repo.git",
			wantURL: "https://github.com/example/repo.git",
		},
		{
			name:    "empty URL returns empty",
			rawURL:  "",
			wantURL: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeAuditURL(tc.rawURL)
			if tc.wantURL != "" {
				assert.Equal(t, tc.wantURL, got)
			}
			if tc.wantSub != "" {
				assert.NotContains(t, got, tc.wantSub, "sanitizeAuditURL must redact credential from URL")
			}
		})
	}
}

// --- Explicit tenant ID tests (Issue #1848) ---

func TestManager_CreateTenant_WithExplicitID(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	req := &TenantRequest{
		ID:   "team-root",
		Name: "Team-Root",
	}

	td, err := manager.CreateTenant(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "team-root", td.ID, "explicit ID must be preserved exactly as provided")
	assert.Equal(t, "Team-Root", td.Name)

	// Verify the tenant can be retrieved by its exact ID
	retrieved, err := manager.GetTenant(ctx, "team-root")
	require.NoError(t, err)
	assert.Equal(t, "team-root", retrieved.ID)
}

func TestManager_CreateTenant_ExplicitID_DefaultsNameToID(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// When Name is omitted, ID is used as Name
	req := &TenantRequest{
		ID: "agent-test",
	}

	td, err := manager.CreateTenant(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "agent-test", td.ID)
	assert.Equal(t, "agent-test", td.Name, "Name must default to ID when omitted")
}

func TestManager_CreateTenant_ExplicitID_WithParent(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	parent, err := manager.CreateTenant(ctx, &TenantRequest{ID: "team-root"})
	require.NoError(t, err)

	child, err := manager.CreateTenant(ctx, &TenantRequest{
		ID:       "agent-test",
		ParentID: parent.ID,
	})
	require.NoError(t, err)
	assert.Equal(t, "agent-test", child.ID)
	assert.Equal(t, "team-root", child.ParentID)
}

func TestValidateExplicitTenantID_K8sRules(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid lowercase alphanumeric", "teamroot", false},
		{"valid with hyphen", "team-root", false},
		{"valid single char", "a", false},
		{"valid with numbers", "agent-test-123", false},
		{"valid 63 chars", strings.Repeat("a", 63), false},
		{"empty string", "", true},
		{"uppercase letter", "Team-Root", true},
		{"uppercase only", "TEAM", true},
		{"underscore", "team_root", true},
		{"leading hyphen", "-team-root", true},
		{"trailing hyphen", "team-root-", true},
		{"64 chars (too long)", strings.Repeat("a", 64), true},
		{"special char @", "team@root", true},
		{"space", "team root", true},
		{"dot", "team.root", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExplicitTenantID(tt.id)
			if tt.wantErr {
				assert.Error(t, err, "expected error for id=%q", tt.id)
			} else {
				assert.NoError(t, err, "expected no error for id=%q", tt.id)
			}
		})
	}
}

func TestManager_CreateTenant_InvalidExplicitID_ReturnsError(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	_, err := manager.CreateTenant(ctx, &TenantRequest{ID: "Team_Root"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid explicit tenant ID")
}

func TestManager_SuspendTenant(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	td, err := manager.CreateTenant(ctx, &TenantRequest{ID: "suspend-test"})
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusActive, td.Status)

	_, err = manager.SuspendTenant(ctx, "suspend-test")
	require.NoError(t, err)

	suspended, err := manager.GetTenant(ctx, "suspend-test")
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, suspended.Status)
}

func TestManager_SuspendTenant_NotFound(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	_, err := manager.SuspendTenant(ctx, "nonexistent-tenant")
	require.Error(t, err)
}

// TestManager_SuspendTenant_DefaultGuard verifies that SuspendTenant rejects the
// "default" tenant ID, does not call the store, and leaves the tenant's status
// unchanged — matching the guard DeleteTenant already enforces (Issue #3181).
func TestManager_SuspendTenant_DefaultGuard(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create a tenant named "default" so any status change would be observable.
	_, err := manager.CreateTenant(ctx, &TenantRequest{ID: "default"})
	require.NoError(t, err)

	_, suspendErr := manager.SuspendTenant(ctx, "default")
	require.Error(t, suspendErr, "SuspendTenant must return an error for the default tenant")
	require.ErrorIs(t, suspendErr, ErrCannotSuspendDefault)

	// Status must remain Active — the guard must not have mutated the tenant.
	td, err := manager.GetTenant(ctx, "default")
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusActive, td.Status,
		"default tenant status must be unchanged after a rejected suspend")
}

// --- slog capture helpers for observable error-branch coverage ---

// capturedLogRecord is a single slog record captured during a test.
type capturedLogRecord struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

// captureHandler is a real slog.Handler (not a mock) that records every emitted
// record so tests can assert on the fields the tenant Manager logs via the global
// slog logger. The tenant Manager writes to slog directly (no injectable logger),
// so tests install this handler as the default for the duration of the test.
type captureHandler struct {
	mu      sync.Mutex
	records []capturedLogRecord
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	rec := capturedLogRecord{level: r.Level, msg: r.Message, attrs: make(map[string]any)}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, rec)
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// find returns the first captured record whose message equals msg, or nil.
func (h *captureHandler) find(msg string) *capturedLogRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.records {
		if h.records[i].msg == msg {
			return &h.records[i]
		}
	}
	return nil
}

// captureSlog installs a capturing slog handler as the default logger for the
// duration of the test and restores the previous default on cleanup.
func captureSlog(t *testing.T) *captureHandler {
	t.Helper()
	h := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return h
}

// failDeleteTenantStore wraps a real tenant Store but forces DeleteTenant to fail.
// This is a real test double (not a mock framework): CreateTenant and every other
// operation delegate to the embedded real store; only DeleteTenant returns the
// injected error, exercising the rollback-failure branch in CreateTenant.
type failDeleteTenantStore struct {
	Store
	delErr error
}

func (s *failDeleteTenantStore) DeleteTenant(_ context.Context, _ string) error {
	return s.delErr
}

// failBulkRolesRBACStore wraps a real RBACStore but can be toggled to fail
// StoreBulkRoles. It embeds the real store so initialization (which also calls
// StoreBulkRoles for system roles) succeeds while fail is false; flipping fail to
// true afterward makes CreateTenantDefaultRoles fail without touching any other path.
type failBulkRolesRBACStore struct {
	business.RBACStore
	fail bool
}

func (s *failBulkRolesRBACStore) StoreBulkRoles(ctx context.Context, roles []*common.Role) error {
	if s.fail {
		return errors.New("simulated durable RBAC store failure")
	}
	return s.RBACStore.StoreBulkRoles(ctx, roles)
}

// TestManager_CreateTenant_RollbackFailure_LogsOrphanedTenant covers the double-failure
// branch at manager.go:139 — CreateTenantDefaultRoles fails AND the rollback
// store.DeleteTenant also fails, firing the slog.Error path that warns operators about
// an orphaned tenant record. Without this, that production branch had no coverage.
func TestManager_CreateTenant_RollbackFailure_LogsOrphanedTenant(t *testing.T) {
	storageManager := cfgmstesting.SetupTestStorage(t)
	ctx := context.Background()

	// Build a real RBAC manager whose durable store can be made to fail on demand.
	failingRBACStore := &failBulkRolesRBACStore{RBACStore: storageManager.GetRBACStore()}
	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		failingRBACStore,
	)
	require.NoError(t, rbacManager.Initialize(ctx))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	// After successful initialization, arm the failure so tenant default-role
	// creation fails, triggering the rollback path.
	failingRBACStore.fail = true

	// Wrap the real tenant store so the rollback DeleteTenant also fails.
	rollbackErr := errors.New("simulated storage failure during rollback")
	store := &failDeleteTenantStore{Store: storageManager.GetTenantStore(), delErr: rollbackErr}
	manager := NewManager(store, rbacManager)

	capture := captureSlog(t)

	_, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Orphan-Tenant"})
	require.Error(t, err, "CreateTenant must fail when RBAC role creation fails")
	assert.Contains(t, err.Error(), "failed to create tenant RBAC roles",
		"returned error must surface the RBAC failure to the caller")

	rec := capture.find("tenant: failed to roll back tenant after RBAC setup failure; orphaned tenant record left in storage")
	require.NotNil(t, rec, "slog.Error must fire when both RBAC setup and rollback fail")
	assert.Equal(t, slog.LevelError, rec.level, "orphaned-tenant log must be at Error level")

	tenantID, ok := rec.attrs["tenant_id"].(string)
	require.True(t, ok, "log record must include a string tenant_id")
	assert.NotEmpty(t, tenantID)

	// The error is logged as a sanitized string, not a bare error value: the
	// DeleteTenant failure text can embed operator-supplied tenant input, so it
	// goes through logging.SanitizeLogValue before reaching slog (CWE-117).
	rbErr, ok := rec.attrs["rollback_error"].(string)
	require.True(t, ok, "log record must include the rollback error as a sanitized string")
	assert.Equal(t, logging.SanitizeLogValue(rollbackErr.Error()), rbErr,
		"rollback_error must be the sanitized DeleteTenant failure")

	_, ok = rec.attrs["rbac_error"]
	require.True(t, ok, "log record must include the originating RBAC error")
}

// TestManager_RecordConfigSourceEvent_SanitizesTenantIDInLog covers the log-injection
// sanitization at manager.go:376 — a tenantID containing newline/carriage-return
// characters must be stripped to underscores before reaching the slog.Warn call in the
// recordConfigSourceEvent error path, and a clean value must pass through unchanged.
func TestManager_RecordConfigSourceEvent_SanitizesTenantIDInLog(t *testing.T) {
	const warnMsg = "tenant: failed to record config source audit event"

	// A stopped audit manager makes RecordEvent fail synchronously (enqueue returns
	// "audit manager is stopped"), driving recordConfigSourceEvent into its error path.
	auditMgr := cfgmstesting.SetupTestAuditManager(t)
	require.NoError(t, auditMgr.Stop(context.Background()))

	manager := newTestTenantManager(t)
	manager.WithAuditManager(auditMgr)
	ctx := context.Background()

	t.Run("injected control chars are stripped", func(t *testing.T) {
		capture := captureSlog(t)

		manager.recordConfigSourceEvent(ctx, "tenant\n123\rinjected",
			"https://example.com/repo.git", "config_source_updated")

		rec := capture.find(warnMsg)
		require.NotNil(t, rec, "slog.Warn must fire when the audit record cannot be persisted")
		tenantID, ok := rec.attrs["tenant_id"].(string)
		require.True(t, ok, "tenant_id must be a string in the log entry")
		assert.NotContains(t, tenantID, "\n", "logged tenant_id must not contain raw newline")
		assert.NotContains(t, tenantID, "\r", "logged tenant_id must not contain raw carriage-return")
		assert.Equal(t, "tenant_123_injected", tenantID,
			"newline and CR must be replaced with underscore before logging")

		// The audit-store error text can carry caller-tainted input back out, so a
		// bare `"error", err` beside a sanitized ID is still a go/log-injection
		// finding (CWE-117). It must be sanitized as a string.
		logErr, ok := rec.attrs["error"].(string)
		require.True(t, ok, "log record must include the audit-store error as a sanitized string, not a bare error value")
		assert.Equal(t, logging.SanitizeLogValue("audit manager is stopped"), logErr,
			"error must be sanitized via logging.SanitizeLogValue before logging")
	})

	t.Run("clean value passes through unchanged", func(t *testing.T) {
		capture := captureSlog(t)

		manager.recordConfigSourceEvent(ctx, "clean-tenant-456",
			"https://example.com/repo.git", "config_source_updated")

		rec := capture.find(warnMsg)
		require.NotNil(t, rec, "slog.Warn must fire when the audit record cannot be persisted")
		tenantID, ok := rec.attrs["tenant_id"].(string)
		require.True(t, ok, "tenant_id must be a string in the log entry")
		assert.Equal(t, "clean-tenant-456", tenantID, "clean tenant_id must pass through unchanged")
	})
}

// TestManager_RecordTenantLifecycleEvent_SanitizesLogFields covers the log-injection
// sanitization in recordTenantLifecycleEvent's slog.Warn error path — both the
// tenantID and the audit-store error must go through logging.SanitizeLogValue
// before reaching slog (CWE-117), matching the pattern already used at
// manager.go:148-152. A bare `"error", err` next to a sanitized ID is still a
// go/log-injection finding because the error text can carry caller-tainted input.
func TestManager_RecordTenantLifecycleEvent_SanitizesLogFields(t *testing.T) {
	const warnMsg = "tenant: failed to record tenant lifecycle audit event"

	// A stopped audit manager makes RecordEvent fail synchronously, driving
	// recordTenantLifecycleEvent into its error path.
	auditMgr := cfgmstesting.SetupTestAuditManager(t)
	require.NoError(t, auditMgr.Stop(context.Background()))

	manager := newTestTenantManager(t)
	manager.WithAuditManager(auditMgr)
	ctx := context.Background()

	capture := captureSlog(t)

	manager.recordTenantLifecycleEvent(ctx, "tenant\n123\rinjected", "Some Tenant", "tenant_suspended")

	rec := capture.find(warnMsg)
	require.NotNil(t, rec, "slog.Warn must fire when the audit record cannot be persisted")

	tenantID, ok := rec.attrs["tenant_id"].(string)
	require.True(t, ok, "tenant_id must be a string in the log entry")
	assert.NotContains(t, tenantID, "\n", "logged tenant_id must not contain raw newline")
	assert.NotContains(t, tenantID, "\r", "logged tenant_id must not contain raw carriage-return")
	assert.Equal(t, "tenant_123_injected", tenantID,
		"newline and CR must be replaced with underscore before logging")

	logErr, ok := rec.attrs["error"].(string)
	require.True(t, ok, "log record must include the audit-store error as a sanitized string, not a bare error value")
	assert.Equal(t, logging.SanitizeLogValue("audit manager is stopped"), logErr,
		"error must be sanitized via logging.SanitizeLogValue before logging")
}

// --- config_source_credential tenant-ownership coverage ---

// recordingMountPointValidator records every ConfigSourceInfo it is asked to
// validate. It stands in for the credential-consuming sink: the real
// DefaultMountPointValidator resolves CredentialRef against the secret store and
// sends the value to the host in URL, so "this validator was never called" is the
// evidence that a rejected reference is never dereferenced.
type recordingMountPointValidator struct {
	calls []*cfgpkg.ConfigSourceInfo
}

func (v *recordingMountPointValidator) ValidateMountPoint(_ context.Context, info *cfgpkg.ConfigSourceInfo, _ secretsiface.SecretStore) error {
	v.calls = append(v.calls, info)
	return nil
}

// TestManager_UpdateTenant_RejectsForeignCredentialRef proves a tenant cannot
// point its config source at another tenant's secret. The scope check on the API
// side only constrains which tenant row is mutated; without this check the
// metadata written into that row can name any tenant's credential, and the
// mount-point validator would then ship it to the caller-chosen git host.
func TestManager_UpdateTenant_RejectsForeignCredentialRef(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	victim, err := manager.CreateTenant(ctx, &TenantRequest{ID: "victim-tenant", Name: "victim-tenant"})
	require.NoError(t, err)
	attacker, err := manager.CreateTenant(ctx, &TenantRequest{ID: "attacker-tenant", Name: "attacker-tenant"})
	require.NoError(t, err)

	validator := &recordingMountPointValidator{}
	manager.WithMountPointValidator(validator, nil)

	_, err = manager.UpdateTenant(ctx, attacker.ID, &TenantRequest{
		Name: attacker.Name,
		Metadata: map[string]string{
			cfgpkg.MetaKeyConfigSourceType:       "git",
			cfgpkg.MetaKeyConfigSourceURL:        "https://attacker.example/r.git",
			cfgpkg.MetaKeyConfigSourceCredential: victim.ID + "/git-token",
		},
	})
	require.Error(t, err, "a tenant must not be able to reference another tenant's credential")
	assert.Contains(t, err.Error(), "own namespace")
	assert.Empty(t, validator.calls, "the foreign credential must be rejected before the mount point is validated")

	// The rejected metadata must not have been persisted.
	stored, err := manager.GetTenant(ctx, attacker.ID)
	require.NoError(t, err)
	assert.Empty(t, stored.Metadata[cfgpkg.MetaKeyConfigSourceCredential])
}

// TestManager_UpdateTenant_RejectsForeignCredentialRefUnderNonGitType covers the
// two-step variant: metadata is replaced wholesale, so a reference parked under a
// non-git config_source_type would go live the moment the type flips to git.
func TestManager_UpdateTenant_RejectsForeignCredentialRefUnderNonGitType(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	attacker, err := manager.CreateTenant(ctx, &TenantRequest{ID: "parking-tenant", Name: "parking-tenant"})
	require.NoError(t, err)

	_, err = manager.UpdateTenant(ctx, attacker.ID, &TenantRequest{
		Name: attacker.Name,
		Metadata: map[string]string{
			cfgpkg.MetaKeyConfigSourceType:       "controller",
			cfgpkg.MetaKeyConfigSourceCredential: "victim-tenant/git-token",
		},
	})
	require.Error(t, err, "a foreign credential reference must be rejected regardless of config_source_type")
	assert.Contains(t, err.Error(), "own namespace")
}

// TestManager_UpdateTenant_RejectsTraversingCredentialRef proves the ownership
// prefix cannot be satisfied while the secret key escapes the tenant's namespace.
func TestManager_UpdateTenant_RejectsTraversingCredentialRef(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	td, err := manager.CreateTenant(ctx, &TenantRequest{ID: "traversal-tenant", Name: "traversal-tenant"})
	require.NoError(t, err)

	for _, ref := range []string{
		"traversal-tenant/../victim-tenant/git-token",
		"traversal-tenant/..",
		"traversal-tenant",
		"/git-token",
		"traversal-tenant/",
	} {
		_, err = manager.UpdateTenant(ctx, td.ID, &TenantRequest{
			Name: td.Name,
			Metadata: map[string]string{
				cfgpkg.MetaKeyConfigSourceType:       "git",
				cfgpkg.MetaKeyConfigSourceURL:        "https://example.com/r.git",
				cfgpkg.MetaKeyConfigSourceCredential: ref,
			},
		})
		require.Error(t, err, "credential reference %q must be rejected", ref)
		assert.Contains(t, err.Error(), "invalid config source metadata")
	}
}

// TestManager_UpdateTenant_AcceptsOwnCredentialRef verifies the legitimate case
// still works: a tenant referencing a secret in its own namespace.
func TestManager_UpdateTenant_AcceptsOwnCredentialRef(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	td, err := manager.CreateTenant(ctx, &TenantRequest{ID: "self-ref-tenant", Name: "self-ref-tenant"})
	require.NoError(t, err)

	validator := &recordingMountPointValidator{}
	manager.WithMountPointValidator(validator, nil)

	updated, err := manager.UpdateTenant(ctx, td.ID, &TenantRequest{
		Name: td.Name,
		Metadata: map[string]string{
			cfgpkg.MetaKeyConfigSourceType:       "git",
			cfgpkg.MetaKeyConfigSourceURL:        "https://example.com/r.git",
			cfgpkg.MetaKeyConfigSourceCredential: td.ID + "/git-token",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "self-ref-tenant/git-token", updated.Metadata[cfgpkg.MetaKeyConfigSourceCredential])
	require.Len(t, validator.calls, 1, "an in-namespace credential reference must still reach mount point validation")
	assert.Equal(t, "self-ref-tenant/git-token", validator.calls[0].CredentialRef)
}

// TestManager_CreateTenant_RejectsForeignCredentialRef covers the create path,
// which is equally reachable by a tenant-scoped principal provisioning a child.
func TestManager_CreateTenant_RejectsForeignCredentialRef(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	_, err := manager.CreateTenant(ctx, &TenantRequest{
		ID:   "child-tenant",
		Name: "child-tenant",
		Metadata: map[string]string{
			cfgpkg.MetaKeyConfigSourceType:       "git",
			cfgpkg.MetaKeyConfigSourceURL:        "https://attacker.example/r.git",
			cfgpkg.MetaKeyConfigSourceCredential: "victim-tenant/git-token",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "own namespace")

	_, err = manager.GetTenant(ctx, "child-tenant")
	require.Error(t, err, "the rejected tenant must not have been created")
}

// TestManager_CreateTenant_AcceptsOwnCredentialRef verifies a tenant created with
// an explicit ID may reference a secret in its own namespace.
func TestManager_CreateTenant_AcceptsOwnCredentialRef(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	td, err := manager.CreateTenant(ctx, &TenantRequest{
		ID:   "own-cred-tenant",
		Name: "own-cred-tenant",
		Metadata: map[string]string{
			cfgpkg.MetaKeyConfigSourceType:       "git",
			cfgpkg.MetaKeyConfigSourceURL:        "https://example.com/r.git",
			cfgpkg.MetaKeyConfigSourceCredential: "own-cred-tenant/git-token",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "own-cred-tenant/git-token", td.Metadata[cfgpkg.MetaKeyConfigSourceCredential])
}

// --- Cascade suspend/restore tests (ADR-027 Decisions 1-2, Issue #3158) ---

// buildSubtree creates a three-tier hierarchy: root → child → grandchild.
// Returns IDs as (rootID, childID, grandchildID).
func buildSubtree(t *testing.T, manager *Manager) (string, string, string) {
	t.Helper()
	ctx := context.Background()

	root, err := manager.CreateTenant(ctx, &TenantRequest{ID: "cs-root", Name: "cs-root"})
	require.NoError(t, err)
	child, err := manager.CreateTenant(ctx, &TenantRequest{ID: "cs-child", Name: "cs-child", ParentID: root.ID})
	require.NoError(t, err)
	grand, err := manager.CreateTenant(ctx, &TenantRequest{ID: "cs-grand", Name: "cs-grand", ParentID: child.ID})
	require.NoError(t, err)
	return root.ID, child.ID, grand.ID
}

// TestManager_SuspendTenant_DefaultProtected verifies the default-tenant guard is
// preserved after the cascade rewrite.
func TestManager_SuspendTenant_DefaultProtected(t *testing.T) {
	manager := newTestTenantManager(t)
	_, err := manager.SuspendTenant(context.Background(), "default")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCannotSuspendDefault)
}

// TestManager_SuspendTenant_CascadesSubtree verifies Decision 1: suspending the root
// suspends the root (DirectlySuspended) and every descendant (CascadeSuspended).
func TestManager_SuspendTenant_CascadesSubtree(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()
	rootID, childID, grandID := buildSubtree(t, manager)

	result, err := manager.SuspendTenant(ctx, rootID)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, rootID, result.Target)

	// Target: DirectlySuspended, not cascade.
	root, err := manager.GetTenant(ctx, rootID)
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, root.Status)
	assert.True(t, root.DirectlySuspended)
	assert.Nil(t, root.CascadeSuspendedFrom)

	// Child: cascade-suspended from root.
	child, err := manager.GetTenant(ctx, childID)
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, child.Status)
	assert.False(t, child.DirectlySuspended)
	require.NotNil(t, child.CascadeSuspendedFrom)
	assert.Equal(t, rootID, *child.CascadeSuspendedFrom)

	// Grandchild: cascade-suspended from root (the direct target, not its parent).
	grand, err := manager.GetTenant(ctx, grandID)
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, grand.Status)
	assert.False(t, grand.DirectlySuspended)
	require.NotNil(t, grand.CascadeSuspendedFrom)
	assert.Equal(t, rootID, *grand.CascadeSuspendedFrom)

	assert.ElementsMatch(t, []string{childID, grandID}, result.NewlyCascadeSuspended)
	assert.Empty(t, result.AlreadySuspended)
}

// TestManager_SuspendTenant_DualProvenance is a REQUIRED TEST (Issue #3158 AC):
// a tenant that was already DirectlySuspended before an ancestor's cascade suspend
// keeps both flags simultaneously.
func TestManager_SuspendTenant_DualProvenance(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()
	rootID, childID, _ := buildSubtree(t, manager)

	// Independently suspend the child first.
	_, err := manager.SuspendTenant(ctx, childID)
	require.NoError(t, err)

	child, err := manager.GetTenant(ctx, childID)
	require.NoError(t, err)
	assert.True(t, child.DirectlySuspended, "child must be directly suspended")
	assert.Nil(t, child.CascadeSuspendedFrom, "no cascade yet")

	// Now cascade-suspend from the root.
	result, err := manager.SuspendTenant(ctx, rootID)
	require.NoError(t, err)

	// The grandchild's provenance was cs-child before the root cascade; the root is the
	// outermost suspension now, so provenance must be re-pointed at it (a deeper value
	// would let RestoreTenant(cs-child) reactivate it while the root is still suspended).
	grand, err := manager.GetTenant(ctx, "cs-grand")
	require.NoError(t, err)
	require.NotNil(t, grand.CascadeSuspendedFrom)
	assert.Equal(t, rootID, *grand.CascadeSuspendedFrom,
		"the outermost suspended ancestor must own the cascade provenance")

	// Child must now carry BOTH flags.
	child, err = manager.GetTenant(ctx, childID)
	require.NoError(t, err)
	assert.True(t, child.DirectlySuspended, "DirectlySuspended must be preserved")
	require.NotNil(t, child.CascadeSuspendedFrom, "CascadeSuspendedFrom must be set")
	assert.Equal(t, rootID, *child.CascadeSuspendedFrom)
	assert.Equal(t, business.TenantStatusSuspended, child.Status)

	// Result must report child as already-suspended, not newly-cascade-suspended.
	assert.Contains(t, result.AlreadySuspended, childID)
	assert.NotContains(t, result.NewlyCascadeSuspended, childID)
}

// TestManager_SuspendTenant_ProvenancePersistsAcrossRead is a REQUIRED TEST (Issue #3158 AC):
// provenance fields must survive a store round-trip (not just be set on the in-memory struct).
func TestManager_SuspendTenant_ProvenancePersistsAcrossRead(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()
	rootID, childID, _ := buildSubtree(t, manager)

	_, err := manager.SuspendTenant(ctx, rootID)
	require.NoError(t, err)

	// Re-read from storage — not from any in-memory cache.
	root, err := manager.store.GetTenant(ctx, rootID)
	require.NoError(t, err)
	assert.True(t, root.DirectlySuspended, "DirectlySuspended must persist in storage")

	child, err := manager.store.GetTenant(ctx, childID)
	require.NoError(t, err)
	require.NotNil(t, child.CascadeSuspendedFrom, "CascadeSuspendedFrom must persist in storage")
	assert.Equal(t, rootID, *child.CascadeSuspendedFrom)
}

// TestManager_RestoreTenant_LiftsCascadeOnly is a REQUIRED TEST (Issue #3158 AC):
// restoring an ancestor must not restore a descendant that is independently suspended.
func TestManager_RestoreTenant_LiftsCascadeOnly(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()
	rootID, childID, grandID := buildSubtree(t, manager)

	// Independently suspend child, then cascade from root.
	_, err := manager.SuspendTenant(ctx, childID)
	require.NoError(t, err)
	_, err = manager.SuspendTenant(ctx, rootID)
	require.NoError(t, err)

	// Restore root only.
	restoreResult, err := manager.RestoreTenant(ctx, rootID)
	require.NoError(t, err)

	// Root must be active again.
	root, err := manager.GetTenant(ctx, rootID)
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusActive, root.Status)
	assert.False(t, root.DirectlySuspended)

	// Child was independently suspended — must remain suspended.
	child, err := manager.GetTenant(ctx, childID)
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, child.Status, "child independently suspended must stay suspended")
	assert.True(t, child.DirectlySuspended, "DirectlySuspended must remain")
	assert.Nil(t, child.CascadeSuspendedFrom, "cascade flag from root must be cleared")

	// Grandchild: the root cascade is lifted, but its parent (the child) is still
	// independently suspended, so the grandchild must stay suspended with its provenance
	// re-pointed at that surviving suspension. Reactivating it here would leave it active
	// underneath a suspended parent.
	grand, err := manager.GetTenant(ctx, grandID)
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, grand.Status,
		"grandchild must not be reactivated while its parent remains suspended")
	require.NotNil(t, grand.CascadeSuspendedFrom, "grandchild must carry the surviving suspension's provenance")
	assert.Equal(t, childID, *grand.CascadeSuspendedFrom)
	assert.False(t, grand.DirectlySuspended)

	// Restore result must report both as still suspended, for different reasons.
	assert.Contains(t, restoreResult.StillSuspended, childID)
	assert.Contains(t, restoreResult.StillSuspended, grandID)
	assert.NotContains(t, restoreResult.Restored, grandID,
		"a tenant under a still-suspended ancestor must not be reported as restored")

	// Restoring the child afterwards releases the grandchild — the re-pointed provenance
	// must not strand it suspended forever.
	secondRestore, err := manager.RestoreTenant(ctx, childID)
	require.NoError(t, err)
	assert.Contains(t, secondRestore.Restored, grandID)

	grand, err = manager.GetTenant(ctx, grandID)
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusActive, grand.Status)
	assert.Nil(t, grand.CascadeSuspendedFrom)
}

// TestManager_RestoreTenant_NestedSuspendCannotEscapeOuterSuspension is a REQUIRED
// security test: on hierarchy A -> B -> C, suspend(A) then suspend(B) then restore(B)
// must leave C suspended. B is itself still cascade-suspended by A, so an operator
// holding tenant:manage on B (legitimately, inside their own subtree) must not be able
// to reactivate anything underneath the MSP-level suspension of A.
func TestManager_RestoreTenant_NestedSuspendCannotEscapeOuterSuspension(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()
	rootID, childID, grandID := buildSubtree(t, manager)

	_, err := manager.SuspendTenant(ctx, rootID)
	require.NoError(t, err)
	_, err = manager.SuspendTenant(ctx, childID)
	require.NoError(t, err)

	// Suspending the child must not steal the grandchild's provenance from the root.
	grand, err := manager.GetTenant(ctx, grandID)
	require.NoError(t, err)
	require.NotNil(t, grand.CascadeSuspendedFrom)
	assert.Equal(t, rootID, *grand.CascadeSuspendedFrom,
		"the root's cascade provenance must survive a nested suspend of the child")

	restoreResult, err := manager.RestoreTenant(ctx, childID)
	require.NoError(t, err)

	// The child stays suspended: the root's cascade still contains it.
	child, err := manager.GetTenant(ctx, childID)
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, child.Status)
	assert.False(t, child.DirectlySuspended, "the child's own suspension is lifted")
	require.NotNil(t, child.CascadeSuspendedFrom)
	assert.Equal(t, rootID, *child.CascadeSuspendedFrom)

	// The grandchild must remain suspended and must not be reported as restored.
	grand, err = manager.GetTenant(ctx, grandID)
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, grand.Status,
		"restoring a cascade-suspended tenant must not reactivate its subtree")
	require.NotNil(t, grand.CascadeSuspendedFrom)
	assert.Equal(t, rootID, *grand.CascadeSuspendedFrom)
	assert.NotContains(t, restoreResult.Restored, grandID)

	// Only restoring the root — the tenant that imposed the containment — releases the
	// whole subtree.
	rootRestore, err := manager.RestoreTenant(ctx, rootID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{childID, grandID}, rootRestore.Restored)
	for _, id := range []string{rootID, childID, grandID} {
		td, err := manager.GetTenant(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, business.TenantStatusActive, td.Status, "tenant %s must be active", id)
		assert.Nil(t, td.CascadeSuspendedFrom)
		assert.False(t, td.DirectlySuspended)
	}
}

// TestManager_RestoreTenant_DeepSubtreeHeldByIntermediateSuspension covers the other
// ordering: suspend(B) then suspend(A) then restore(A). The child B keeps its own
// DirectlySuspended flag, so the grandchild below it must stay suspended even though the
// cascade it carried (from A) is genuinely lifted.
func TestManager_RestoreTenant_DeepSubtreeHeldByIntermediateSuspension(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()
	rootID, childID, grandID := buildSubtree(t, manager)

	// A fourth tier below the grandchild: containment must reach the whole subtree, not
	// just the first level under the still-suspended ancestor.
	greatGrand, err := manager.CreateTenant(ctx, &TenantRequest{ID: "cs-great", Name: "cs-great", ParentID: grandID})
	require.NoError(t, err)

	_, err = manager.SuspendTenant(ctx, childID)
	require.NoError(t, err)
	_, err = manager.SuspendTenant(ctx, rootID)
	require.NoError(t, err)

	_, err = manager.RestoreTenant(ctx, rootID)
	require.NoError(t, err)

	root, err := manager.GetTenant(ctx, rootID)
	require.NoError(t, err)
	require.Equal(t, business.TenantStatusActive, root.Status)

	for _, id := range []string{childID, grandID, greatGrand.ID} {
		td, err := manager.GetTenant(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, business.TenantStatusSuspended, td.Status,
			"tenant %s must stay suspended under the still-suspended child", id)
	}

	// Provenance below the surviving suspension points at it, so restoring the child
	// releases the rest of the subtree.
	grand, err := manager.GetTenant(ctx, grandID)
	require.NoError(t, err)
	require.NotNil(t, grand.CascadeSuspendedFrom)
	assert.Equal(t, childID, *grand.CascadeSuspendedFrom)

	restoreResult, err := manager.RestoreTenant(ctx, childID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{grandID, greatGrand.ID}, restoreResult.Restored)
	for _, id := range []string{childID, grandID, greatGrand.ID} {
		td, err := manager.GetTenant(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, business.TenantStatusActive, td.Status, "tenant %s must be active", id)
		assert.Nil(t, td.CascadeSuspendedFrom)
	}
}

// TestManager_RestoreTenant_ClearsAllDescendants verifies basic restore: after
// a cascade suspend, restoring the root brings all descendants back to active.
func TestManager_RestoreTenant_ClearsAllDescendants(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()
	rootID, childID, grandID := buildSubtree(t, manager)

	_, err := manager.SuspendTenant(ctx, rootID)
	require.NoError(t, err)

	restoreResult, err := manager.RestoreTenant(ctx, rootID)
	require.NoError(t, err)

	for _, id := range []string{rootID, childID, grandID} {
		td, err := manager.GetTenant(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, business.TenantStatusActive, td.Status, "tenant %s must be active after restore", id)
		assert.False(t, td.DirectlySuspended)
		assert.Nil(t, td.CascadeSuspendedFrom)
	}

	assert.ElementsMatch(t, []string{childID, grandID}, restoreResult.Restored)
	assert.Empty(t, restoreResult.StillSuspended)
}

// TestManager_SuspendTenant_CycleDetected is a REQUIRED TEST (Issue #3158 AC):
// the cascade walk must return an error rather than looping forever if it encounters
// a cycle (data corruption or a future code change relaxing the parent_id invariant).
func TestManager_SuspendTenant_CycleDetected(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create A → B hierarchy.
	a, err := manager.CreateTenant(ctx, &TenantRequest{ID: "cycle-a", Name: "cycle-a"})
	require.NoError(t, err)
	b, err := manager.CreateTenant(ctx, &TenantRequest{ID: "cycle-b", Name: "cycle-b", ParentID: a.ID})
	require.NoError(t, err)

	// Corrupt the hierarchy by setting A's parent to B (A→B, B→A via parent_id).
	// The SQLite schema has no FK enforcement by default, so this is possible
	// through the raw store interface.
	a.ParentID = b.ID
	require.NoError(t, manager.store.UpdateTenant(ctx, a))

	// SuspendTenant must return an error, not loop forever.
	_, err = manager.SuspendTenant(ctx, a.ID)
	require.Error(t, err, "cycle in tenant hierarchy must cause an error, not an infinite loop")
	assert.Contains(t, err.Error(), "cycle")
}

// TestManager_RestoreTenant_CycleDetected is a REQUIRED TEST (Issue #3158 AC):
// the restore walk must also terminate with an error on a cycle.
func TestManager_RestoreTenant_CycleDetected(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	a, err := manager.CreateTenant(ctx, &TenantRequest{ID: "rcycle-a", Name: "rcycle-a"})
	require.NoError(t, err)
	b, err := manager.CreateTenant(ctx, &TenantRequest{ID: "rcycle-b", Name: "rcycle-b", ParentID: a.ID})
	require.NoError(t, err)

	// Corrupt: A.ParentID = B
	a.ParentID = b.ID
	require.NoError(t, manager.store.UpdateTenant(ctx, a))

	_, err = manager.RestoreTenant(ctx, a.ID)
	require.Error(t, err, "cycle in tenant hierarchy must cause an error in RestoreTenant")
	assert.Contains(t, err.Error(), "cycle")
}

// TestManager_SuspendRestore_AuditEvents verifies that both operations emit audit
// events when an audit manager is wired, and that no panic occurs when it is not.
func TestManager_SuspendRestore_AuditEvents(t *testing.T) {
	manager := newTestTenantManager(t)
	auditMgr := cfgmstesting.SetupTestAuditManager(t)
	manager.WithAuditManager(auditMgr)
	ctx := context.Background()

	td, err := manager.CreateTenant(ctx, &TenantRequest{ID: "audit-tenant", Name: "audit-tenant"})
	require.NoError(t, err)

	_, err = manager.SuspendTenant(ctx, td.ID)
	require.NoError(t, err)

	require.NoError(t, auditMgr.Flush(ctx))

	suspended, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
		TenantID: td.ID,
		Actions:  []string{"tenant_suspended"},
	})
	require.NoError(t, err)
	assert.Len(t, suspended, 1, "suspend must record a tenant_suspended audit event")

	_, err = manager.RestoreTenant(ctx, td.ID)
	require.NoError(t, err)

	require.NoError(t, auditMgr.Flush(ctx))

	restored, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
		TenantID: td.ID,
		Actions:  []string{"tenant_restored"},
	})
	require.NoError(t, err)
	assert.Len(t, restored, 1, "restore must record a tenant_restored audit event")
}

// TestManager_SuspendTenant_NoAuditManager_NoPanic verifies that SuspendTenant and
// RestoreTenant are safe no-ops at the audit layer when no audit manager is wired.
func TestManager_SuspendTenant_NoAuditManager_NoPanic(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()
	td, err := manager.CreateTenant(ctx, &TenantRequest{Name: "NoAuditTenant"})
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		_, _ = manager.SuspendTenant(ctx, td.ID)
		_, _ = manager.RestoreTenant(ctx, td.ID)
	})
}
