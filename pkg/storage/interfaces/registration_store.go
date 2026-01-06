// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package interfaces defines global storage contracts used by all CFGMS modules
package interfaces

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

	// Initialize and cleanup
	Initialize(ctx context.Context) error
	Close() error
}

// RegistrationTokenData represents a registration token in the storage layer
type RegistrationTokenData struct {
	// Token is the unique token string (e.g., "cfgms_reg_abc123def456")
	Token string `json:"token" yaml:"token"`

	// TenantID is the tenant this token belongs to
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// ControllerURL is the MQTT broker URL for this tenant
	ControllerURL string `json:"controller_url" yaml:"controller_url"`

	// Group is an optional group identifier
	Group string `json:"group,omitempty" yaml:"group,omitempty"`

	// CreatedAt is when the token was created
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`

	// ExpiresAt is when the token expires (nil = never)
	ExpiresAt *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`

	// SingleUse indicates if token can only be used once
	SingleUse bool `json:"single_use" yaml:"single_use"`

	// UsedAt is when the token was first used (nil = unused)
	UsedAt *time.Time `json:"used_at,omitempty" yaml:"used_at,omitempty"`

	// UsedBy is the steward_id that used this token
	UsedBy string `json:"used_by,omitempty" yaml:"used_by,omitempty"`

	// Revoked indicates if token has been revoked
	Revoked bool `json:"revoked" yaml:"revoked"`

	// RevokedAt is when the token was revoked
	RevokedAt *time.Time `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`
}

// IsValid returns whether the token is currently valid for use.
func (t *RegistrationTokenData) IsValid() bool {
	// Check if revoked
	if t.Revoked {
		return false
	}

	// Check if expired
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return false
	}

	// Check if single-use and already used
	if t.SingleUse && t.UsedAt != nil {
		return false
	}

	return true
}

// MarkUsed marks the token as used by a specific steward.
func (t *RegistrationTokenData) MarkUsed(stewardID string) {
	now := time.Now()
	t.UsedAt = &now
	t.UsedBy = stewardID
}

// Revoke marks the token as revoked.
func (t *RegistrationTokenData) Revoke() {
	now := time.Now()
	t.Revoked = true
	t.RevokedAt = &now
}

// RegistrationTokenFilter defines filtering criteria for token queries
type RegistrationTokenFilter struct {
	TenantID  string `json:"tenant_id,omitempty"`
	Group     string `json:"group,omitempty"`
	Revoked   *bool  `json:"revoked,omitempty"`
	SingleUse *bool  `json:"single_use,omitempty"`
	Used      *bool  `json:"used,omitempty"` // Filter by used/unused status
}

// RegistrationTokenStoreProvider defines how storage providers create registration token stores
type RegistrationTokenStoreProvider interface {
	CreateRegistrationTokenStore(config map[string]interface{}) (RegistrationTokenStore, error)
}
