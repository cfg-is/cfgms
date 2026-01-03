// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package interfaces defines global storage contracts used by all CFGMS modules
package interfaces

import (
	"time"
)

// ClientTenantStore defines storage interface for MSP client tenant data
// All modules use this interface - storage provider is chosen by controller
type ClientTenantStore interface {
	// Store and retrieve client tenants
	StoreClientTenant(client *ClientTenant) error
	GetClientTenant(tenantID string) (*ClientTenant, error)
	GetClientTenantByIdentifier(clientIdentifier string) (*ClientTenant, error)
	ListClientTenants(status ClientTenantStatus) ([]*ClientTenant, error)
	UpdateClientTenantStatus(tenantID string, status ClientTenantStatus) error
	DeleteClientTenant(tenantID string) error

	// Admin consent request management
	StoreAdminConsentRequest(request *AdminConsentRequest) error
	GetAdminConsentRequest(state string) (*AdminConsentRequest, error)
	DeleteAdminConsentRequest(state string) error
}

// ClientTenant represents an MSP client organization
type ClientTenant struct {
	ID               string                 `json:"id"`
	TenantID         string                 `json:"tenant_id"`   // Client's Azure AD tenant ID
	TenantName       string                 `json:"tenant_name"` // Client organization name
	DomainName       string                 `json:"domain_name"` // Primary domain (e.g., client.com)
	AdminEmail       string                 `json:"admin_email"` // Admin who consented
	ConsentedAt      time.Time              `json:"consented_at"`
	Status           ClientTenantStatus     `json:"status"`
	ClientIdentifier string                 `json:"client_identifier"` // CFGMS internal client ID
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

// ClientTenantStatus represents the consent status of a client tenant
type ClientTenantStatus string

const (
	ClientTenantStatusPending   ClientTenantStatus = "pending"
	ClientTenantStatusActive    ClientTenantStatus = "active"
	ClientTenantStatusSuspended ClientTenantStatus = "suspended"
	ClientTenantStatusDeleted   ClientTenantStatus = "deleted"
)

// AdminConsentRequest represents a pending admin consent request
type AdminConsentRequest struct {
	ClientIdentifier string                 `json:"client_identifier"` // CFGMS internal client ID
	ClientName       string                 `json:"client_name"`       // Display name for client
	RequestedBy      string                 `json:"requested_by"`      // MSP employee email
	State            string                 `json:"state"`             // OAuth2 state parameter
	ExpiresAt        time.Time              `json:"expires_at"`        // When this request expires
	CreatedAt        time.Time              `json:"created_at"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// ClientTenantValidationError represents validation errors
type ClientTenantValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e *ClientTenantValidationError) Error() string {
	return e.Field + ": " + e.Message
}

// Common client tenant errors
var (
	ErrTenantNotFound  = &ClientTenantValidationError{Field: "tenant_id", Message: "tenant not found", Code: "TENANT_NOT_FOUND"}
	ErrTenantExists    = &ClientTenantValidationError{Field: "tenant_id", Message: "tenant already exists", Code: "TENANT_EXISTS"}
	ErrInvalidTenantID = &ClientTenantValidationError{Field: "tenant_id", Message: "invalid tenant ID", Code: "INVALID_TENANT_ID"}
	ErrInvalidEmail    = &ClientTenantValidationError{Field: "admin_email", Message: "invalid email address", Code: "INVALID_EMAIL"}
	ErrConsentExpired  = &ClientTenantValidationError{Field: "consent", Message: "admin consent has expired", Code: "CONSENT_EXPIRED"}
)
