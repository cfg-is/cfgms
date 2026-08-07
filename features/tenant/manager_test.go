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

	require.NoError(t, manager.SuspendTenant(ctx, "suspend-test"))

	suspended, err := manager.GetTenant(ctx, "suspend-test")
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, suspended.Status)
}

func TestManager_SuspendTenant_NotFound(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	err := manager.SuspendTenant(ctx, "nonexistent-tenant")
	require.Error(t, err)
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
