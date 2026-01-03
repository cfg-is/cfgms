// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package tenant

import (
	"context"
	"fmt"
)

// Store defines the interface for tenant data storage
type Store interface {
	// CreateTenant creates a new tenant
	CreateTenant(ctx context.Context, tenant *Tenant) error

	// GetTenant retrieves a tenant by ID
	GetTenant(ctx context.Context, tenantID string) (*Tenant, error)

	// UpdateTenant updates an existing tenant
	UpdateTenant(ctx context.Context, tenant *Tenant) error

	// DeleteTenant deletes a tenant (soft delete by setting status)
	DeleteTenant(ctx context.Context, tenantID string) error

	// ListTenants lists tenants with optional filtering
	ListTenants(ctx context.Context, filter *TenantFilter) ([]*Tenant, error)

	// GetTenantHierarchy retrieves the hierarchical structure for a tenant
	GetTenantHierarchy(ctx context.Context, tenantID string) (*TenantHierarchy, error)

	// GetChildTenants returns all direct child tenants
	GetChildTenants(ctx context.Context, parentID string) ([]*Tenant, error)

	// GetTenantPath returns the full path from root to the specified tenant
	GetTenantPath(ctx context.Context, tenantID string) ([]string, error)

	// IsTenantAncestor checks if one tenant is an ancestor of another
	IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error)
}

// Common errors
var (
	ErrTenantNotFound    = fmt.Errorf("tenant not found")
	ErrTenantExists      = fmt.Errorf("tenant already exists")
	ErrInvalidParent     = fmt.Errorf("invalid parent tenant")
	ErrCircularReference = fmt.Errorf("circular reference in tenant hierarchy")
	ErrTenantHasChildren = fmt.Errorf("tenant has child tenants")
)
