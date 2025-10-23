// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/tenant"
)

// Store implements an in-memory tenant store
type Store struct {
	mu        sync.RWMutex
	tenants   map[string]*tenant.Tenant
	hierarchy map[string]*tenant.TenantHierarchy
}

// NewStore creates a new in-memory tenant store
func NewStore() *Store {
	store := &Store{
		tenants:   make(map[string]*tenant.Tenant),
		hierarchy: make(map[string]*tenant.TenantHierarchy),
	}

	// Initialize with default tenant
	defaultTenant := &tenant.Tenant{
		ID:          "default",
		Name:        "Default Tenant",
		Description: "Default system tenant",
		Status:      tenant.TenantStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	store.tenants["default"] = defaultTenant
	store.hierarchy["default"] = &tenant.TenantHierarchy{
		TenantID: "default",
		Path:     []string{"default"},
		Depth:    0,
		Children: []string{},
	}

	return store
}

// CreateTenant creates a new tenant
func (s *Store) CreateTenant(ctx context.Context, t *tenant.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if tenant already exists
	if _, exists := s.tenants[t.ID]; exists {
		return tenant.ErrTenantExists
	}

	// Validate parent tenant if specified
	var parentHierarchy *tenant.TenantHierarchy
	if t.ParentID != "" {
		parent, exists := s.tenants[t.ParentID]
		if !exists {
			return tenant.ErrInvalidParent
		}
		if parent.Status != tenant.TenantStatusActive {
			return fmt.Errorf("parent tenant is not active")
		}
		parentHierarchy = s.hierarchy[t.ParentID]
	}

	// Set timestamps
	now := time.Now()
	t.CreatedAt = now
	t.UpdatedAt = now

	// Store the tenant
	s.tenants[t.ID] = t

	// Build hierarchy
	hierarchy := &tenant.TenantHierarchy{
		TenantID: t.ID,
		Children: []string{},
	}

	if parentHierarchy != nil {
		// Child tenant
		hierarchy.Path = append(parentHierarchy.Path, t.ID)
		hierarchy.Depth = parentHierarchy.Depth + 1

		// Add to parent's children
		parentHierarchy.Children = append(parentHierarchy.Children, t.ID)
	} else {
		// Root tenant
		hierarchy.Path = []string{t.ID}
		hierarchy.Depth = 0
	}

	s.hierarchy[t.ID] = hierarchy

	return nil
}

// GetTenant retrieves a tenant by ID
func (s *Store) GetTenant(ctx context.Context, tenantID string) (*tenant.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, exists := s.tenants[tenantID]
	if !exists {
		return nil, tenant.ErrTenantNotFound
	}

	// Return a copy to prevent modification
	result := *t
	return &result, nil
}

// UpdateTenant updates an existing tenant
func (s *Store) UpdateTenant(ctx context.Context, t *tenant.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.tenants[t.ID]
	if !exists {
		return tenant.ErrTenantNotFound
	}

	// Preserve creation time
	t.CreatedAt = existing.CreatedAt
	t.UpdatedAt = time.Now()

	// Store updated tenant
	s.tenants[t.ID] = t

	return nil
}

// DeleteTenant deletes a tenant (soft delete by setting status)
func (s *Store) DeleteTenant(ctx context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, exists := s.tenants[tenantID]
	if !exists {
		return tenant.ErrTenantNotFound
	}

	// Check if tenant has children
	hierarchy := s.hierarchy[tenantID]
	if len(hierarchy.Children) > 0 {
		return tenant.ErrTenantHasChildren
	}

	// Cannot delete default tenant
	if tenantID == "default" {
		return fmt.Errorf("cannot delete default tenant")
	}

	// Soft delete by setting status
	t.Status = tenant.TenantStatusInactive
	t.UpdatedAt = time.Now()

	return nil
}

// ListTenants lists tenants with optional filtering
func (s *Store) ListTenants(ctx context.Context, filter *tenant.TenantFilter) ([]*tenant.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*tenant.Tenant

	for _, t := range s.tenants {
		// Apply filters
		if filter != nil {
			if filter.ParentID != "" && t.ParentID != filter.ParentID {
				continue
			}
			if filter.Status != "" && t.Status != filter.Status {
				continue
			}
			if filter.Name != "" && !strings.Contains(strings.ToLower(t.Name), strings.ToLower(filter.Name)) {
				continue
			}
		}

		// Return a copy to prevent modification
		tenantCopy := *t
		result = append(result, &tenantCopy)
	}

	return result, nil
}

// GetTenantHierarchy retrieves the hierarchical structure for a tenant
func (s *Store) GetTenantHierarchy(ctx context.Context, tenantID string) (*tenant.TenantHierarchy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hierarchy, exists := s.hierarchy[tenantID]
	if !exists {
		return nil, tenant.ErrTenantNotFound
	}

	// Return a copy to prevent modification
	result := *hierarchy
	result.Children = make([]string, len(hierarchy.Children))
	copy(result.Children, hierarchy.Children)
	result.Path = make([]string, len(hierarchy.Path))
	copy(result.Path, hierarchy.Path)

	return &result, nil
}

// GetChildTenants returns all direct child tenants
func (s *Store) GetChildTenants(ctx context.Context, parentID string) ([]*tenant.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hierarchy, exists := s.hierarchy[parentID]
	if !exists {
		return nil, tenant.ErrTenantNotFound
	}

	var children []*tenant.Tenant
	for _, childID := range hierarchy.Children {
		if child, exists := s.tenants[childID]; exists {
			// Return a copy to prevent modification
			childCopy := *child
			children = append(children, &childCopy)
		}
	}

	return children, nil
}

// GetTenantPath returns the full path from root to the specified tenant
func (s *Store) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hierarchy, exists := s.hierarchy[tenantID]
	if !exists {
		return nil, tenant.ErrTenantNotFound
	}

	// Return a copy to prevent modification
	path := make([]string, len(hierarchy.Path))
	copy(path, hierarchy.Path)

	return path, nil
}

// IsTenantAncestor checks if one tenant is an ancestor of another
func (s *Store) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	descendantHierarchy, exists := s.hierarchy[descendantID]
	if !exists {
		return false, tenant.ErrTenantNotFound
	}

	// Check if ancestorID is in the descendant's path
	for _, pathTenantID := range descendantHierarchy.Path {
		if pathTenantID == ancestorID {
			return true, nil
		}
	}

	return false, nil
}
