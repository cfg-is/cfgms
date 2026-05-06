// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package tenant

import (
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Type aliases — redirected to business package to eliminate duplicates (Issue #1275).
// These keep existing callers outside features/tenant/ compiling without modification
// until they are updated in follow-on stories.
type Tenant = business.TenantData
type TenantStatus = business.TenantStatus
type TenantHierarchy = business.TenantHierarchy
type TenantFilter = business.TenantFilter

const (
	TenantStatusActive    = business.TenantStatusActive
	TenantStatusSuspended = business.TenantStatusSuspended
)

// TenantRequest represents a request to create or update a tenant
type TenantRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	ParentID    string            `json:"parent_id,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
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
