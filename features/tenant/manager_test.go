package tenant

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	
	// Import storage providers for testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

// setupTestRBACManager creates an RBAC manager with git storage for tenant testing
func setupTestRBACManager(t *testing.T) *rbac.Manager {
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":         "main",
		"auto_init":      true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)
	
	manager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	
	err = manager.Initialize(context.Background())
	require.NoError(t, err)
	
	return manager
}

// mockStore implements Store interface for testing
type mockStore struct {
	mu        sync.RWMutex
	tenants   map[string]*Tenant
	hierarchy map[string]*TenantHierarchy
}

func newMockStore() *mockStore {
	store := &mockStore{
		tenants:   make(map[string]*Tenant),
		hierarchy: make(map[string]*TenantHierarchy),
	}
	
	// Initialize with default tenant
	defaultTenant := &Tenant{
		ID:          "default",
		Name:        "Default Tenant",
		Description: "Default system tenant",
		Status:      TenantStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	store.tenants["default"] = defaultTenant
	store.hierarchy["default"] = &TenantHierarchy{
		TenantID: "default",
		Path:     []string{"default"},
		Depth:    0,
		Children: []string{},
	}
	
	return store
}

func (s *mockStore) CreateTenant(ctx context.Context, t *Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if _, exists := s.tenants[t.ID]; exists {
		return ErrTenantExists
	}
	
	var parentHierarchy *TenantHierarchy
	if t.ParentID != "" {
		parent, exists := s.tenants[t.ParentID]
		if !exists {
			return ErrInvalidParent
		}
		if parent.Status != TenantStatusActive {
			return fmt.Errorf("parent tenant is not active")
		}
		parentHierarchy = s.hierarchy[t.ParentID]
	}
	
	now := time.Now()
	t.CreatedAt = now
	t.UpdatedAt = now
	
	s.tenants[t.ID] = t
	
	hierarchy := &TenantHierarchy{
		TenantID: t.ID,
		Children: []string{},
	}
	
	if parentHierarchy != nil {
		hierarchy.Path = append(parentHierarchy.Path, t.ID)
		hierarchy.Depth = parentHierarchy.Depth + 1
		parentHierarchy.Children = append(parentHierarchy.Children, t.ID)
	} else {
		hierarchy.Path = []string{t.ID}
		hierarchy.Depth = 0
	}
	
	s.hierarchy[t.ID] = hierarchy
	return nil
}

func (s *mockStore) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	t, exists := s.tenants[tenantID]
	if !exists {
		return nil, ErrTenantNotFound
	}
	
	result := *t
	return &result, nil
}

func (s *mockStore) UpdateTenant(ctx context.Context, t *Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	existing, exists := s.tenants[t.ID]
	if !exists {
		return ErrTenantNotFound
	}
	
	t.CreatedAt = existing.CreatedAt
	t.UpdatedAt = time.Now()
	s.tenants[t.ID] = t
	return nil
}

func (s *mockStore) DeleteTenant(ctx context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	t, exists := s.tenants[tenantID]
	if !exists {
		return ErrTenantNotFound
	}
	
	hierarchy := s.hierarchy[tenantID]
	if len(hierarchy.Children) > 0 {
		return ErrTenantHasChildren
	}
	
	if tenantID == "default" {
		return fmt.Errorf("cannot delete default tenant")
	}
	
	t.Status = TenantStatusInactive
	t.UpdatedAt = time.Now()
	return nil
}

func (s *mockStore) ListTenants(ctx context.Context, filter *TenantFilter) ([]*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	var result []*Tenant
	for _, t := range s.tenants {
		if filter != nil {
			if filter.ParentID != "" && t.ParentID != filter.ParentID {
				continue
			}
			if filter.Status != "" && t.Status != filter.Status {
				continue
			}
		}
		
		tenantCopy := *t
		result = append(result, &tenantCopy)
	}
	
	return result, nil
}

func (s *mockStore) GetTenantHierarchy(ctx context.Context, tenantID string) (*TenantHierarchy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	hierarchy, exists := s.hierarchy[tenantID]
	if !exists {
		return nil, ErrTenantNotFound
	}
	
	result := *hierarchy
	result.Children = make([]string, len(hierarchy.Children))
	copy(result.Children, hierarchy.Children)
	result.Path = make([]string, len(hierarchy.Path))
	copy(result.Path, hierarchy.Path)
	
	return &result, nil
}

func (s *mockStore) GetChildTenants(ctx context.Context, parentID string) ([]*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	hierarchy, exists := s.hierarchy[parentID]
	if !exists {
		return nil, ErrTenantNotFound
	}
	
	var children []*Tenant
	for _, childID := range hierarchy.Children {
		if child, exists := s.tenants[childID]; exists {
			childCopy := *child
			children = append(children, &childCopy)
		}
	}
	
	return children, nil
}

func (s *mockStore) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	hierarchy, exists := s.hierarchy[tenantID]
	if !exists {
		return nil, ErrTenantNotFound
	}
	
	path := make([]string, len(hierarchy.Path))
	copy(path, hierarchy.Path)
	return path, nil
}

func (s *mockStore) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	descendantHierarchy, exists := s.hierarchy[descendantID]
	if !exists {
		return false, ErrTenantNotFound
	}
	
	for _, pathTenantID := range descendantHierarchy.Path {
		if pathTenantID == ancestorID {
			return true, nil
		}
	}
	
	return false, nil
}

func TestManager_CreateTenant(t *testing.T) {
	// Setup
	tenantStore := newMockStore()
	rbacManager := setupTestRBACManager(t)
	
	manager := NewManager(tenantStore, rbacManager)
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
	assert.Equal(t, TenantStatusActive, tenant.Status)
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
	// Setup
	tenantStore := newMockStore()
	rbacManager := setupTestRBACManager(t)
	
	manager := NewManager(tenantStore, rbacManager)
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
	// Setup
	tenantStore := newMockStore()
	rbacManager := setupTestRBACManager(t)
	
	manager := NewManager(tenantStore, rbacManager)
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
	// Setup
	tenantStore := newMockStore()
	rbacManager := setupTestRBACManager(t)
	
	manager := NewManager(tenantStore, rbacManager)
	ctx := context.Background()

	// Create test tenants
	tenant1, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Tenant1"})
	require.NoError(t, err)
	
	tenant2, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Tenant2", ParentID: tenant1.ID})
	require.NoError(t, err)

	// List all tenants
	tenants, err := manager.ListTenants(ctx, nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(tenants), 3) // default + tenant1 + tenant2

	// List tenants with filter
	filter := &TenantFilter{ParentID: tenant1.ID}
	filteredTenants, err := manager.ListTenants(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, filteredTenants, 1)
	assert.Equal(t, tenant2.ID, filteredTenants[0].ID)
}

func TestManager_UpdateTenant(t *testing.T) {
	// Setup
	tenantStore := newMockStore()
	rbacManager := setupTestRBACManager(t)
	
	manager := NewManager(tenantStore, rbacManager)
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
	assert.Equal(t, tenant.CreatedAt, updated.CreatedAt)
	assert.True(t, updated.UpdatedAt.After(tenant.UpdatedAt))
}

func TestManager_DeleteTenant(t *testing.T) {
	// Setup
	tenantStore := newMockStore()
	rbacManager := setupTestRBACManager(t)
	
	manager := NewManager(tenantStore, rbacManager)
	ctx := context.Background()

	// Create tenant
	tenant, err := manager.CreateTenant(ctx, &TenantRequest{Name: "ToDelete"})
	require.NoError(t, err)

	// Delete tenant
	err = manager.DeleteTenant(ctx, tenant.ID)
	require.NoError(t, err)

	// Verify tenant is soft deleted
	deleted, err := manager.GetTenant(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Equal(t, TenantStatusInactive, deleted.Status)
}

func TestManager_DeleteTenant_WithChildren(t *testing.T) {
	// Setup
	tenantStore := newMockStore()
	rbacManager := setupTestRBACManager(t)
	
	manager := NewManager(tenantStore, rbacManager)
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
	// Setup
	tenantStore := newMockStore()
	rbacManager := setupTestRBACManager(t)
	
	manager := NewManager(tenantStore, rbacManager)
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