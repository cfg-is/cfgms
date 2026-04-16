// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines the optional LeasedSecret mixin for vault-class providers.
package interfaces

import (
	"context"
	"time"
)

// LeasedSecret is an optional mixin interface for SecretStore providers that support
// dynamic-secret leasing (e.g., OpenBao, HashiCorp Vault, AWS Secrets Manager
// dynamic credentials).
//
// Callers type-assert to LeasedSecret before calling lease operations:
//
//	if ls, ok := store.(interfaces.LeasedSecret); ok {
//	    secret, lease, err := ls.LeaseSecret(ctx, key, req)
//	}
//
// SOPS and steward providers do NOT implement this interface — they are static-secret
// providers. Only vault-class providers with per-request dynamic credentials implement it.
//
// A provider advertises static support for leasing via ProviderCapabilities.SupportsLeasing;
// LeasedSecret is the runtime-checkable counterpart that callers use to dispatch lease
// operations at call time.
type LeasedSecret interface {
	// LeaseSecret requests a dynamic secret lease from the provider. The returned Lease
	// describes the lease ID, TTL, and expiry. The caller is responsible for renewing or
	// revoking the lease when finished.
	LeaseSecret(ctx context.Context, key string, req *LeaseRequest) (*Secret, *Lease, error)

	// RenewLease extends an active lease by increment. The returned Lease reflects the
	// new TTL and expiry after renewal.
	RenewLease(ctx context.Context, leaseID string, increment time.Duration) (*Lease, error)

	// RevokeLease immediately invalidates a lease. After revocation the dynamic secret
	// associated with the lease is no longer valid.
	RevokeLease(ctx context.Context, leaseID string) error
}

// Lease represents an active dynamic-secret lease returned by a vault-class provider.
// Lease IDs must not be logged in plaintext — use logging.SanitizeLogValue when a lease
// ID appears in a log line.
type Lease struct {
	// ID is the opaque provider-assigned lease identifier.
	ID string `json:"id"`

	// TTL is the remaining lifetime of the lease at the time it was issued or last renewed.
	TTL time.Duration `json:"ttl"`

	// Renewable indicates whether the provider allows RenewLease calls for this lease.
	Renewable bool `json:"renewable"`

	// IssuedAt is the time the lease was created or last renewed.
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is the absolute expiry time. Callers should treat the secret as invalid
	// at or after this time even if no explicit revocation occurred.
	ExpiresAt time.Time `json:"expires_at"`
}

// LeaseRequest carries parameters for a dynamic secret lease creation request.
type LeaseRequest struct {
	// TTL is the requested lease duration. Providers may cap or adjust the TTL according
	// to their own policy. Zero means use the provider default.
	TTL time.Duration `json:"ttl,omitempty"`

	// Renewable requests a renewable lease when true. Providers may ignore this if the
	// secret type does not support renewal.
	Renewable bool `json:"renewable"`

	// Parameters are provider-specific inputs for the dynamic credential generation
	// (e.g., database role, IAM policy ARN). Callers must not embed secret values here.
	Parameters map[string]any `json:"parameters,omitempty"`
}
