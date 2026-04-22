// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package registration provides registration token management for steward deployment.
//
// This package implements the registration token system that allows stewards to
// auto-register with the controller using short API key-style tokens.
package registration

import "time"

// Token represents a registration token for steward deployment.
type Token struct {
	// Token is the unique token string (e.g., "abcdefghijklmnopqrstuvwxyz")
	Token string `json:"token"`

	// TenantID is the tenant this token belongs to
	TenantID string `json:"tenant_id"`

	// ControllerURL is the transport address for this tenant
	ControllerURL string `json:"controller_url"`

	// Group is an optional group identifier
	Group string `json:"group,omitempty"`

	// CreatedAt is when the token was created
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the token expires (nil = never)
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// SingleUse indicates if token can only be used once
	SingleUse bool `json:"single_use"`

	// UsedAt is when the token was first used (nil = unused)
	UsedAt *time.Time `json:"used_at,omitempty"`

	// UsedBy is the steward_id that used this token
	UsedBy string `json:"used_by,omitempty"`

	// Revoked indicates if token has been revoked
	Revoked bool `json:"revoked"`

	// RevokedAt is when the token was revoked
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// IsValid returns whether the token is currently valid for use.
func (t *Token) IsValid() bool {
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
func (t *Token) MarkUsed(stewardID string) {
	now := time.Now()
	t.UsedAt = &now
	t.UsedBy = stewardID
}

// Revoke marks the token as revoked.
func (t *Token) Revoke() {
	now := time.Now()
	t.Revoked = true
	t.RevokedAt = &now
}

// TokenCreateRequest represents a request to create a registration token.
type TokenCreateRequest struct {
	// TenantID is the tenant this token belongs to
	TenantID string `json:"tenant_id"`

	// ControllerURL is the transport address
	ControllerURL string `json:"controller_url"`

	// Group is an optional group identifier
	Group string `json:"group,omitempty"`

	// ExpiresIn is the duration until token expires (e.g., "24h", "7d", "30d")
	ExpiresIn string `json:"expires_in,omitempty"`

	// SingleUse indicates if token can only be used once
	SingleUse bool `json:"single_use"`
}
