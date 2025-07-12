package tenant

import (
	"time"
)

// Tenant represents a tenant in the multi-tenant system
type Tenant struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	ParentID    string            `json:"parent_id,omitempty"` // For hierarchical tenants
	Metadata    map[string]string `json:"metadata,omitempty"`
	Status      TenantStatus      `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusInactive  TenantStatus = "inactive"
)

// TenantHierarchy represents the hierarchical relationship between tenants
type TenantHierarchy struct {
	TenantID string   `json:"tenant_id"`
	Path     []string `json:"path"`      // Full path from root to this tenant
	Depth    int      `json:"depth"`     // Depth in hierarchy (0 = root)
	Children []string `json:"children"`  // Direct child tenant IDs
}

// TenantRequest represents a request to create or update a tenant
type TenantRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	ParentID    string            `json:"parent_id,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// TenantFilter represents filters for listing tenants
type TenantFilter struct {
	ParentID string       `json:"parent_id,omitempty"`
	Status   TenantStatus `json:"status,omitempty"`
	Name     string       `json:"name,omitempty"`
}