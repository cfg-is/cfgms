// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package registration provides registration token management for steward deployment.
//
// This package implements the registration token system that allows stewards to
// auto-register with the controller using short API key-style tokens.
package registration

import "time"

// Token represents a registration token for steward deployment.
// Newly issued tokens expire after a short default lifetime unless an explicit
// lifetime is provided. Legacy records without ExpiresAt remain readable for
// migration and must be rotated before public exposure.
type Token struct {
	// ID is a stable UUID for this token (Issue #2970 — web UI identifier).
	ID string `json:"id"`

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

	// Revoked indicates if token has been revoked
	Revoked bool `json:"revoked"`

	// RevokedAt is when the token was revoked
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// IsValid returns whether the token is currently valid for use.
func (t *Token) IsValid() bool {
	if t.Revoked {
		return false
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return false
	}
	return true
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
}
