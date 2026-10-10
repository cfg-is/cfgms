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

	// PutMigrationSigner stores a node-local signing certificate and key a node
	// has validated, create-if-absent, in the migration namespace. The namespace
	// is a separate key prefix from the shared one so a vault policy can treat it
	// differently, and nothing in it is a signing identity until the cursor names
	// its serial and it is promoted. Same material again is an idempotent
	// success; different material for the same serial is an error naming
	// fingerprints only.
	PutMigrationSigner(ctx context.Context, material *SigningKeyMaterial) error

	// GetMigrationSigner returns the migration-namespace material for serial. An
	// absent serial yields ErrSigningKeyNotFound.
	GetMigrationSigner(ctx context.Context, serial string) (*SigningKeyMaterial, error)

	// ListMigrationSigners returns the serials held in the migration namespace.
	// The order is unspecified and must never influence which serial is elected.
	ListMigrationSigners(ctx context.Context) ([]string, error)
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

// SigningRotationClaimer is implemented by a SigningKeyStore that can serialize
// signing-certificate rotations across controller nodes. The claim must be taken
// before a rotation generates a key: without it two nodes each generate and
// store a key and the loser's cursor transition leaves its key unreferenced.
type SigningRotationClaimer interface {
	// ClaimSigningRotation atomically claims the right to rotate. It reports
	// true for exactly one caller until the claim is released or its
	// time-to-live lapses, so a claimant that crashes cannot block rotation
	// forever.
	ClaimSigningRotation(ctx context.Context) (bool, error)

	// ReleaseSigningRotation drops the rotation claim. Releasing an absent
	// claim is not an error.
	ReleaseSigningRotation(ctx context.Context) error
}
