// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
// (tenants, RBAC, sessions, stewards, commands, registration tokens, audit).
package business

import (
	"context"
	"errors"
	"time"
)

// ErrTenantAlreadyExists is returned by TenantStore.CreateTenant when a tenant
// with the given ID already exists. Handlers must use errors.Is to detect it.
var ErrTenantAlreadyExists = errors.New("tenant already exists")

// ErrTenantDoesNotExist is returned by every TenantStore operation that
// addresses a tenant which has no row: GetTenant, UpdateTenant and
// DeleteTenant. Providers wrap it with %w so the message may carry the tenant
// ID and provider-specific phrasing; callers MUST use errors.Is and MUST NOT
// classify on message text. Matching on a substring silently binds a caller to
// one provider's phrasing — a handler that classifies "tenant not found" would
// treat a missing tenant as a backend fault on any provider that phrases the
// same condition differently, turning the resulting status-code difference into
// a cross-tenant existence oracle.
//
// Named for symmetry with ErrTenantAlreadyExists rather than "NotFound",
// because ErrTenantNotFound in this package is the unrelated
// *ClientTenantValidationError for the M365 client-tenant surface.
var ErrTenantDoesNotExist = errors.New("tenant does not exist")

// TenantStore defines storage interface for CFGMS tenant data persistence
// All tenant modules use this interface - storage provider is chosen by controller
type TenantStore interface {
	// Tenant management
	CreateTenant(ctx context.Context, tenant *TenantData) error
	GetTenant(ctx context.Context, tenantID string) (*TenantData, error)
	UpdateTenant(ctx context.Context, tenant *TenantData) error
	DeleteTenant(ctx context.Context, tenantID string) error
	ListTenants(ctx context.Context, filter *TenantFilter) ([]*TenantData, error)

	// Hierarchy operations
	GetTenantHierarchy(ctx context.Context, tenantID string) (*TenantHierarchy, error)
	GetChildTenants(ctx context.Context, parentID string) ([]*TenantData, error)
	GetTenantPath(ctx context.Context, tenantID string) ([]string, error)
	IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error)

	// Initialize and cleanup
	Initialize(ctx context.Context) error
	Close() error
}

// TenantData represents a tenant in the storage layer
type TenantData struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	ParentID    string            `json:"parent_id,omitempty" yaml:"parent_id,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Status      TenantStatus      `json:"status" yaml:"status"`

	// Suspension provenance (ADR-027 Decision 2). Both can be set simultaneously:
	// a tenant independently suspended that is also cascade-suspended by an ancestor
	// carries both flags so restoring the ancestor only removes the cascade effect.
	DirectlySuspended    bool    `json:"directly_suspended,omitempty" yaml:"directly_suspended,omitempty"`
	CascadeSuspendedFrom *string `json:"cascade_suspended_from,omitempty" yaml:"cascade_suspended_from,omitempty"`

	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusDeleted   TenantStatus = "deleted"
)

// TenantFilter defines filtering criteria for tenant queries
type TenantFilter struct {
	ParentID string       `json:"parent_id,omitempty"`
	Status   TenantStatus `json:"status,omitempty"`
	Name     string       `json:"name,omitempty"`
}

// TenantHierarchy represents the hierarchical structure of a tenant
type TenantHierarchy struct {
	TenantID string   `json:"tenant_id" yaml:"tenant_id"`
	Path     []string `json:"path" yaml:"path"`         // Full path from root to tenant
	Depth    int      `json:"depth" yaml:"depth"`       // Depth in hierarchy (0 = root)
	Children []string `json:"children" yaml:"children"` // Direct child tenant IDs
}
