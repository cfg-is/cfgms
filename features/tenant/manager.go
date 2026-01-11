// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/cfgis/cfgms/features/rbac"
)

// Manager handles tenant operations and integrates with RBAC
type Manager struct {
	store       Store
	rbacManager *rbac.Manager
}

// NewManager creates a new tenant manager
func NewManager(store Store, rbacManager *rbac.Manager) *Manager {
	return &Manager{
		store:       store,
		rbacManager: rbacManager,
	}
}

// CreateTenant creates a new tenant with validation and RBAC setup
func (m *Manager) CreateTenant(ctx context.Context, req *TenantRequest) (*Tenant, error) {
	// Validate the request
	if err := m.validateTenantRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Generate tenant ID from name
	tenantID := m.generateTenantID(req.Name)

	// Create tenant object
	tenant := &Tenant{
		ID:          tenantID,
		Name:        req.Name,
		Description: req.Description,
		ParentID:    req.ParentID,
		Metadata:    req.Metadata,
		Status:      TenantStatusActive,
	}

	// Create the tenant in storage
	if err := m.store.CreateTenant(ctx, tenant); err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	// Create default RBAC roles for the tenant (if RBAC is enabled)
	if m.rbacManager != nil {
		if err := m.rbacManager.CreateTenantDefaultRoles(ctx, tenantID); err != nil {
			// Rollback tenant creation if RBAC setup fails
			_ = m.store.DeleteTenant(ctx, tenantID)
			return nil, fmt.Errorf("failed to create tenant RBAC roles: %w", err)
		}
	}

	return tenant, nil
}

// GetTenant retrieves a tenant by ID
func (m *Manager) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	return m.store.GetTenant(ctx, tenantID)
}

// UpdateTenant updates an existing tenant
func (m *Manager) UpdateTenant(ctx context.Context, tenantID string, req *TenantRequest) (*Tenant, error) {
	// Get existing tenant
	existing, err := m.store.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Validate the request
	if err := m.validateTenantRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Update fields
	existing.Name = req.Name
	existing.Description = req.Description
	existing.Metadata = req.Metadata
	// Note: ParentID cannot be changed after creation to maintain hierarchy integrity

	// Update in storage
	if err := m.store.UpdateTenant(ctx, existing); err != nil {
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	return existing, nil
}

// DeleteTenant deletes a tenant
func (m *Manager) DeleteTenant(ctx context.Context, tenantID string) error {
	// Cannot delete default tenant
	if tenantID == "default" {
		return fmt.Errorf("cannot delete default tenant")
	}

	// Check if tenant has child tenants
	children, err := m.store.GetChildTenants(ctx, tenantID)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return ErrTenantHasChildren
	}

	// Delete the tenant (soft delete)
	return m.store.DeleteTenant(ctx, tenantID)
}

// ListTenants lists tenants with optional filtering
func (m *Manager) ListTenants(ctx context.Context, filter *TenantFilter) ([]*Tenant, error) {
	return m.store.ListTenants(ctx, filter)
}

// GetTenantHierarchy retrieves the hierarchical structure for a tenant
func (m *Manager) GetTenantHierarchy(ctx context.Context, tenantID string) (*TenantHierarchy, error) {
	return m.store.GetTenantHierarchy(ctx, tenantID)
}

// GetChildTenants returns all direct child tenants
func (m *Manager) GetChildTenants(ctx context.Context, parentID string) ([]*Tenant, error) {
	return m.store.GetChildTenants(ctx, parentID)
}

// GetTenantPath returns the full path from root to the specified tenant
func (m *Manager) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	return m.store.GetTenantPath(ctx, tenantID)
}

// IsTenantAncestor checks if one tenant is an ancestor of another
func (m *Manager) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	return m.store.IsTenantAncestor(ctx, ancestorID, descendantID)
}

// validateTenantRequest validates a tenant creation/update request
func (m *Manager) validateTenantRequest(req *TenantRequest) error {
	if req.Name == "" {
		return fmt.Errorf("tenant name is required")
	}

	// Validate name format (alphanumeric, hyphens, underscores)
	nameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !nameRegex.MatchString(req.Name) {
		return fmt.Errorf("tenant name must contain only alphanumeric characters, hyphens, and underscores")
	}

	if len(req.Name) > 64 {
		return fmt.Errorf("tenant name must be 64 characters or less")
	}

	if len(req.Description) > 255 {
		return fmt.Errorf("tenant description must be 255 characters or less")
	}

	return nil
}

// generateTenantID generates a tenant ID from the name
func (m *Manager) generateTenantID(name string) string {
	// Convert to lowercase and replace spaces with hyphens
	id := regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(name, "-")
	id = regexp.MustCompile(`-+`).ReplaceAllString(id, "-")
	id = regexp.MustCompile(`^-|-$`).ReplaceAllString(id, "")

	// Add timestamp suffix to ensure uniqueness
	timestamp := time.Now().Unix()
	return fmt.Sprintf("%s-%d", id, timestamp)
}
