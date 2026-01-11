// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"time"
)

// M365ClientTenantStore defines the storage interface for M365 client tenant management
// This interface provides durable storage for OAuth client credentials and admin consent requests
// Story #274: M365 Auth Client Tenant Storage Migration
type M365ClientTenantStore interface {
	// Lifecycle
	Initialize(ctx context.Context) error
	Close() error

	// Client tenant management
	StoreClientTenant(ctx context.Context, client *M365ClientTenant) error
	GetClientTenant(ctx context.Context, tenantID string) (*M365ClientTenant, error)
	GetClientTenantByIdentifier(ctx context.Context, clientIdentifier string) (*M365ClientTenant, error)
	ListClientTenants(ctx context.Context, status M365ClientTenantStatus) ([]*M365ClientTenant, error)
	UpdateClientTenantStatus(ctx context.Context, tenantID string, status M365ClientTenantStatus) error
	DeleteClientTenant(ctx context.Context, tenantID string) error

	// Admin consent request management
	StoreAdminConsentRequest(ctx context.Context, request *M365AdminConsentRequest) error
	GetAdminConsentRequest(ctx context.Context, state string) (*M365AdminConsentRequest, error)
	DeleteAdminConsentRequest(ctx context.Context, state string) error

	// Utility methods
	GetStats(ctx context.Context) (*M365ClientTenantStats, error)
	CleanupExpiredRequests(ctx context.Context) (int, error)
}

// M365ClientTenant represents a client organization that has consented to CFGMS
// OAuth client credentials are stored separately in encrypted form
type M365ClientTenant struct {
	ID               string                 `json:"id"`
	TenantID         string                 `json:"tenant_id"`   // Client's Azure AD tenant ID
	TenantName       string                 `json:"tenant_name"` // Client organization name
	DomainName       string                 `json:"domain_name"` // Primary domain (e.g., client.com)
	AdminEmail       string                 `json:"admin_email"` // Admin who consented
	ConsentedAt      time.Time              `json:"consented_at"`
	Status           M365ClientTenantStatus `json:"status"`
	ClientIdentifier string                 `json:"client_identifier"` // CFGMS internal client ID
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

// M365ClientTenantStatus represents the consent status of a client tenant
type M365ClientTenantStatus string

const (
	M365ClientTenantStatusPending   M365ClientTenantStatus = "pending"   // Admin consent URL generated, awaiting consent
	M365ClientTenantStatusConsented M365ClientTenantStatus = "consented" // Admin has consented
	M365ClientTenantStatusActive    M365ClientTenantStatus = "active"    // Fully configured and operational
	M365ClientTenantStatusSuspended M365ClientTenantStatus = "suspended" // Temporarily disabled
	M365ClientTenantStatusRevoked   M365ClientTenantStatus = "revoked"   // Admin revoked consent
)

// M365AdminConsentRequest represents a request for admin consent from a client
type M365AdminConsentRequest struct {
	ClientIdentifier string                 `json:"client_identifier"` // CFGMS internal client ID
	ClientName       string                 `json:"client_name"`       // Display name for client
	RequestedBy      string                 `json:"requested_by"`      // MSP employee who initiated
	State            string                 `json:"state"`             // OAuth2 state parameter
	ExpiresAt        time.Time              `json:"expires_at"`        // Request expiration
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
}

// M365ClientTenantStats provides statistics about stored M365 client tenant data
type M365ClientTenantStats struct {
	TotalClients           int                            `json:"total_clients"`
	PendingConsentRequests int                            `json:"pending_consent_requests"`
	ClientsByStatus        map[M365ClientTenantStatus]int `json:"clients_by_status"`
	LastUpdated            time.Time                      `json:"last_updated"`
}
