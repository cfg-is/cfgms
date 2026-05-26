// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
package business

import (
	"context"
	"time"
)

// RegistrationTokenStore defines storage interface for CFGMS registration token persistence
// All registration token modules use this interface - storage provider is chosen by controller
type RegistrationTokenStore interface {
	// Token management
	SaveToken(ctx context.Context, token *RegistrationTokenData) error
	GetToken(ctx context.Context, tokenStr string) (*RegistrationTokenData, error)
	UpdateToken(ctx context.Context, token *RegistrationTokenData) error
	DeleteToken(ctx context.Context, tokenStr string) error
	ListTokens(ctx context.Context, filter *RegistrationTokenFilter) ([]*RegistrationTokenData, error)

	// RotateToken atomically revokes all prior tokens for tenant+group and creates a new one.
	// The controller_url is inherited from an existing active token. Returns the new token.
	// Returns an error if no active tokens exist for the given tenant+group.
	RotateToken(ctx context.Context, tenantID, group string) (*RegistrationTokenData, error)

	// Initialize and cleanup
	Initialize(ctx context.Context) error
	Close() error
}

// RegistrationTokenData represents a registration token in the storage layer
type RegistrationTokenData struct {
	// Token is the unique token string (e.g., "abcdefghijklmnopqrstuvwxyz")
	Token string `json:"token" yaml:"token"`

	// TenantID is the tenant this token belongs to
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// ControllerURL is the transport address for this tenant
	ControllerURL string `json:"controller_url" yaml:"controller_url"`

	// Group is an optional group identifier
	Group string `json:"group,omitempty" yaml:"group,omitempty"`

	// CreatedAt is when the token was created
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`

	// ExpiresAt is when the token expires (nil = never)
	ExpiresAt *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`

	// Revoked indicates if token has been revoked
	Revoked bool `json:"revoked" yaml:"revoked"`

	// RevokedAt is when the token was revoked
	RevokedAt *time.Time `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`
}

// IsValid returns whether the token is currently valid for use.
func (t *RegistrationTokenData) IsValid() bool {
	if t.Revoked {
		return false
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return false
	}
	return true
}

// Revoke marks the token as revoked.
func (t *RegistrationTokenData) Revoke() {
	now := time.Now()
	t.Revoked = true
	t.RevokedAt = &now
}

// RegistrationTokenFilter defines filtering criteria for token queries
type RegistrationTokenFilter struct {
	TenantID string `json:"tenant_id,omitempty"`
	Group    string `json:"group,omitempty"`
	Revoked  *bool  `json:"revoked,omitempty"`
}
