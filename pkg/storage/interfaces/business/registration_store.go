// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
package business

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const registrationTokenHashPrefix = "sha256:"

// RegistrationTokenLookupKey returns a deterministic, non-reversible storage
// key. The short prefix is retained only for operator identification.
func RegistrationTokenLookupKey(token string) string {
	if strings.HasPrefix(token, registrationTokenHashPrefix) {
		return token
	}
	prefix := token
	if len(prefix) > 6 {
		prefix = prefix[:6]
	}
	sum := sha256.Sum256([]byte(token))
	return registrationTokenHashPrefix + prefix + ":" + hex.EncodeToString(sum[:])
}

// RegistrationTokenDisplayPrefix extracts the non-secret operator prefix from
// either a raw token during its mint window or a stored lookup key.
func RegistrationTokenDisplayPrefix(token string) string {
	if strings.HasPrefix(token, registrationTokenHashPrefix) {
		parts := strings.SplitN(token, ":", 3)
		if len(parts) == 3 {
			return parts[1]
		}
	}
	if len(token) > 6 {
		return token[:6]
	}
	return token
}

// RegistrationTokenStore defines storage interface for CFGMS registration token persistence
// All registration token modules use this interface - storage provider is chosen by controller
type RegistrationTokenStore interface {
	// Token management
	SaveToken(ctx context.Context, token *RegistrationTokenData) error
	GetToken(ctx context.Context, tokenStr string) (*RegistrationTokenData, error)
	// GetTokenByID retrieves a token by its stable UUID (Issue #2970).
	// Returns "registration token not found" when absent.
	GetTokenByID(ctx context.Context, id string) (*RegistrationTokenData, error)
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

// RegistrationTokenConsumer is implemented by durable stores that can
// atomically spend a registration token. Public admission requires this
// capability so concurrent claims cannot both succeed.
type RegistrationTokenConsumer interface {
	ConsumeToken(ctx context.Context, tokenStr string) error
}

// ErrRegistrationTokenAlreadyClaimed is returned when a registration token has
// already crossed the REST admission boundary for a different device identity.
var ErrRegistrationTokenAlreadyClaimed = errors.New("registration token already claimed")

// RegistrationTokenClaimer is implemented by durable stores that can reserve a
// valid registration token at the REST certificate-issuance boundary without
// consuming it. The token remains valid for the subsequent mTLS-authenticated
// gRPC registration, where RegistrationTokenConsumer performs final consumption.
type RegistrationTokenClaimer interface {
	// ClaimToken atomically creates a durable claim for tokenStr. It returns true
	// only to the caller that created the claim. A retry with the same claimID
	// returns (false, nil); a different claimant receives
	// ErrRegistrationTokenAlreadyClaimed.
	ClaimToken(ctx context.Context, tokenStr, claimID string) (bool, error)

	// ReleaseTokenClaim removes an exact claim after a failure that occurred
	// before a certificate or pending-registration record was produced.
	ReleaseTokenClaim(ctx context.Context, tokenStr, claimID string) error
}

// RegistrationTokenData represents a registration token in the storage layer
type RegistrationTokenData struct {
	// ID is a stable UUID for this token (Issue #2970 — web UI identifier).
	// Never the secret: the Token field is the credential.
	ID string `json:"id" yaml:"id"`

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
