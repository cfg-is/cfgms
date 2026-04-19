// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
// (tenants, RBAC, sessions, stewards, commands, registration tokens, audit).
package business

import (
	"context"
	"time"
)

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
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" yaml:"updated_at"`
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

// TenantStoreProvider defines how storage providers create tenant stores
type TenantStoreProvider interface {
	CreateTenantStore(config map[string]interface{}) (TenantStore, error)
}
