// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"errors"
)

// ErrSigningKeyNotFound is returned by SigningKeyStore.GetSigningKey when no
// material is stored for the requested serial. It means "absent" and nothing
// else: a store that cannot be read (denied, timed out, unreachable) must
// return a different error so callers fail closed instead of treating an
// outage as a missing identity and bootstrapping a replacement.
var ErrSigningKeyNotFound = errors.New("signing key not found")

// ErrSigningMigrationPending is returned when an operation needs the cluster to
// have completed its move from node-local signing certificates to the shared
// signing identity, and it has not. Rotating while nodes still sign with their
// own local keys would write a key to local disk or move the shared cursor to a
// serial the other nodes cannot resolve.
var ErrSigningMigrationPending = errors.New("cluster signing identity migration pending")

// SigningKeyMaterial is one config-signing certificate together with its
// private key and issuer chain. The three are stored as one record so the
// create-if-absent write is atomic for the pair: a reader never sees a
// certificate without its key.
type SigningKeyMaterial struct {
	// Serial is the certificate serial number the material is keyed by.
	Serial string
	// CertificatePEM is the signing certificate.
	CertificatePEM []byte
	// PrivateKeyPEM is the signing private key. It must never be logged or
	// appear in an error message.
	PrivateKeyPEM []byte
	// IssuerChainPEM is the chain from the certificate's issuer up to the
	// trusted root; empty when the issuing CA is itself the root.
	IssuerChainPEM []byte
}

// SigningKeyStore holds config-signing certificate and key material by serial
// in storage every controller node shares, so all nodes sign with one identity
// and no signing private key is written to node-local disk.
type SigningKeyStore interface {
	// PutSigningKey stores material create-if-absent. Storing the same material
	// again is an idempotent success; different material for an existing serial
	// is an error that names fingerprints only. An existing entry is never
	// replaced.
	PutSigningKey(ctx context.Context, material *SigningKeyMaterial) error

	// GetSigningKey returns the material stored for serial. An absent serial
	// yields ErrSigningKeyNotFound; any read failure yields a different error.
	GetSigningKey(ctx context.Context, serial string) (*SigningKeyMaterial, error)

	// ListSigningSerials returns the serials that have stored material.
	ListSigningSerials(ctx context.Context) ([]string, error)
}

// SigningBootstrapClaimer is implemented by a SigningKeyStore that can arbitrate
// which node generates the cluster's first signing identity. Without a claim,
// nodes starting concurrently on a fresh cluster would each generate a
// certificate and each advance the shared cursor, demoting the first serial to
// "rotating" for no reason.
type SigningBootstrapClaimer interface {
	// ClaimSigningBootstrap atomically claims the right to generate the first
	// signing identity. It reports true for exactly one caller until the
	// claim's time-to-live lapses, so a claimant that crashes cannot block
	// bootstrap forever.
	ClaimSigningBootstrap(ctx context.Context) (bool, error)
}
