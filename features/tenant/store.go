// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"fmt"
	"time"

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

	// Pending-deletion pipeline (ADR-027 Decisions 3-4, Issue #3182)
	RequestDeletion(ctx context.Context, pending *business.PendingDeletion) error
	CancelDeletion(ctx context.Context, subtreeRootID string) error
	ApproveDeletion(ctx context.Context, subtreeRootID, approvedBy string, requireDualControl bool, now time.Time) ([]string, error)
	GetPendingDeletion(ctx context.Context, subtreeRootID string) (*business.PendingDeletion, error)
}

// NewStorageAdapter wraps a business.TenantStore in tenant.Store.
// Trivial passthrough: business.TenantStore satisfies tenant.Store directly now that
// both interfaces use business.TenantData.
func NewStorageAdapter(store business.TenantStore) Store {
	return store
}

// Common errors
var (
	// ErrTenantNotFound aliases the storage-layer sentinel rather than declaring a
	// second "tenant is missing" error. Manager passes store errors through
	// untouched, so a caller that matched this value while a provider returned the
	// storage sentinel would never match — the divergence that let a missing-tenant
	// lookup be misclassified as a backend fault.
	ErrTenantNotFound       = business.ErrTenantDoesNotExist
	ErrTenantExists         = business.ErrTenantAlreadyExists
	ErrInvalidParent        = fmt.Errorf("invalid parent tenant")
	ErrCircularReference    = fmt.Errorf("circular reference in tenant hierarchy")
	ErrTenantHasChildren    = fmt.Errorf("tenant has child tenants")
	ErrCannotSuspendDefault = fmt.Errorf("cannot suspend default tenant")

	// Deletion pipeline sentinels (ADR-027 Decisions 3-4, Issue #3182).
	ErrTenantNotFullySuspended = fmt.Errorf("target subtree is not fully suspended")
	ErrPendingDeletionExists   = business.ErrPendingDeletionExists
	ErrPendingDeletionNotFound = business.ErrPendingDeletionNotFound
	ErrHoldNotElapsed          = business.ErrHoldNotElapsed
	ErrMembershipChanged       = business.ErrMembershipChanged
	ErrSameApprover            = business.ErrSameApprover
)
