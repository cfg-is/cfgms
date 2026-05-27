// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Store defines the interface for tenant data storage
type Store interface {
	// CreateTenant creates a new tenant
	CreateTenant(ctx context.Context, tenant *business.TenantData) error

	// GetTenant retrieves a tenant by ID
	GetTenant(ctx context.Context, tenantID string) (*business.TenantData, error)

	// UpdateTenant updates an existing tenant
	UpdateTenant(ctx context.Context, tenant *business.TenantData) error

	// DeleteTenant deletes a tenant (soft delete by setting status)
	DeleteTenant(ctx context.Context, tenantID string) error

	// ListTenants lists tenants with optional filtering
	ListTenants(ctx context.Context, filter *business.TenantFilter) ([]*business.TenantData, error)

	// GetTenantHierarchy retrieves the hierarchical structure for a tenant
	GetTenantHierarchy(ctx context.Context, tenantID string) (*business.TenantHierarchy, error)

	// GetChildTenants returns all direct child tenants
	GetChildTenants(ctx context.Context, parentID string) ([]*business.TenantData, error)

	// GetTenantPath returns the full path from root to the specified tenant
	GetTenantPath(ctx context.Context, tenantID string) ([]string, error)

	// IsTenantAncestor checks if one tenant is an ancestor of another
	IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error)
}

// NewStorageAdapter wraps a business.TenantStore in tenant.Store.
// Trivial passthrough: business.TenantStore satisfies tenant.Store directly now that
// both interfaces use business.TenantData.
func NewStorageAdapter(store business.TenantStore) Store {
	return store
}

// Common errors
var (
	ErrTenantNotFound    = fmt.Errorf("tenant not found")
	ErrTenantExists      = fmt.Errorf("tenant already exists")
	ErrInvalidParent     = fmt.Errorf("invalid parent tenant")
	ErrCircularReference = fmt.Errorf("circular reference in tenant hierarchy")
	ErrTenantHasChildren = fmt.Errorf("tenant has child tenants")
)
