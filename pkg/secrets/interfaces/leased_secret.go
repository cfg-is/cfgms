// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines the LeasedSecret mixin for dynamic secret leasing
// M-AUTH-1: Lease-based dynamic secrets for providers that support it (e.g. OpenBao)
package interfaces

import (
	"context"
	"errors"
	"time"
)

// ErrLeaseNotSupported is returned when the requested secret does not support leasing.
// KV v2 static secrets always return this; only dynamic secret engines (database, PKI, etc.)
// produce real leases.
var ErrLeaseNotSupported = errors.New("leased secrets are not supported for this secret type")

// LeasedSecret is an optional mixin implemented by SecretStore providers that support
// dynamic secret leasing (e.g. OpenBao database engine). Callers should type-assert
// a SecretStore to LeasedSecret before calling these methods.
type LeasedSecret interface {
	// LeaseSecret mints a new lease for the named secret.
	// Returns ErrLeaseNotSupported for static KV secrets that cannot be leased.
	LeaseSecret(ctx context.Context, req *LeaseRequest) (*Lease, error)

	// RenewLease extends an active lease by increment duration.
	RenewLease(ctx context.Context, leaseID string, increment time.Duration) (*Lease, error)

	// RevokeLease immediately revokes an active lease.
	RevokeLease(ctx context.Context, leaseID string) error
}

// LeaseRequest describes a request to mint a secret lease.
type LeaseRequest struct {
	// Key is the secret key to lease.
	Key string

	// TenantID scopes the request to a specific tenant.
	TenantID string

	// TTL is the requested lease duration. The server may cap this.
	TTL time.Duration
}

// Lease represents an active secret lease returned by LeaseSecret or RenewLease.
type Lease struct {
	// LeaseID is the unique identifier used for renew/revoke operations.
	LeaseID string

	// Key is the secret key the lease was minted for.
	Key string

	// TenantID is the tenant scope.
	TenantID string

	// TTL is the remaining lease duration as granted by the server.
	TTL time.Duration

	// Renewable indicates whether this lease can be extended via RenewLease.
	Renewable bool

	// IssuedAt is when the lease was minted.
	IssuedAt time.Time

	// ExpiresAt is when the lease will expire if not renewed.
	ExpiresAt time.Time
}
