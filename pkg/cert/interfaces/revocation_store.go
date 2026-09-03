// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package interfaces is pkg/cert's central-provider interface position (see
// CLAUDE.md Central Provider System): pkg/cert.Manager reaches revocation-list
// and signing-cursor state only through the types declared here, never a
// concrete implementation. This package is intentionally near-leaf (no
// dependency on pkg/storage or pkg/cert itself) so both a Postgres-backed
// store (cluster-visible; pkg/storage/providers/database) and pkg/cert's own
// file-backed store (single-node; pkg/cert's NewFileRevocationStore /
// NewFileSigningCursorStore) can implement it without an import cycle —
// pkg/storage/interfaces/business transitively imports pkg/cert already
// (features/config/signature's config-signing path), so the type home could
// not live there without cycling back (Issue #3852).
package interfaces

import (
	"context"
	"time"
)

// RevocationEntry records a revoked certificate serial with metadata. JSON
// tags are load-bearing: pkg/cert's file-backed implementation marshals this
// exact type to preserve today's on-disk revocation.json layout.
type RevocationEntry struct {
	Serial    string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason,omitempty"`
}

// RevocationStore defines durable storage for the certificate revocation
// list. A cluster-visible implementation makes a revocation written by one
// controller node observable by every node sharing the same store, without a
// restart.
type RevocationStore interface {
	// Revoke adds entry to the revocation list. A pre-existing entry for the
	// same serial is left unmodified — the original RevokedAt wins, so a
	// repeated revoke is a no-op rather than an error.
	Revoke(ctx context.Context, entry RevocationEntry) error
	// IsRevoked reports whether serial is currently revoked. Called on every
	// mTLS admin certificate authentication request, so implementations must
	// keep this cheap.
	IsRevoked(ctx context.Context, serial string) (bool, error)
	// ListRevoked returns every revocation entry, for audit and --list output.
	ListRevoked(ctx context.Context) ([]RevocationEntry, error)
}
