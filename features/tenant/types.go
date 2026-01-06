// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
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
	Path     []string `json:"path"`     // Full path from root to this tenant
	Depth    int      `json:"depth"`    // Depth in hierarchy (0 = root)
	Children []string `json:"children"` // Direct child tenant IDs
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

// M365TenantMetadata represents Microsoft 365 specific tenant metadata
type M365TenantMetadata struct {
	// Core M365 identifiers
	M365TenantID  string `json:"m365_tenant_id"`
	PrimaryDomain string `json:"primary_domain"`

	// Authentication and access
	TokenExpiresAt     time.Time `json:"token_expires_at"`
	ConsentedAt        time.Time `json:"consented_at"`
	AdminEmail         string    `json:"admin_email,omitempty"`
	GDAPRelationshipID string    `json:"gdap_relationship_id,omitempty"`

	// Health monitoring
	LastHealthCheck time.Time    `json:"last_health_check"`
	HealthStatus    HealthStatus `json:"health_status"`
	HealthDetails   string       `json:"health_details,omitempty"`

	// Organization info from Microsoft Graph
	CountryCode string `json:"country_code,omitempty"`
	TenantType  string `json:"tenant_type,omitempty"` // e.g., "AAD"

	// Discovery metadata
	DiscoveredAt    time.Time `json:"discovered_at"`
	DiscoveryMethod string    `json:"discovery_method"` // "admin_consent", "gdap", "manual"
}

// HealthStatus represents the health status of an M365 tenant
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)
