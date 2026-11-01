// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines the NonceStore interface for the registration-refresh
// challenge/response nonce (ADR-010 §2). ADR-011 originally deferred a durable
// alternative to the in-process nonce cache; ADR-031's any-node service model
// (Decision 1) means a challenge and its completion can land on different
// controller nodes, so the deferred durable design is now required (Issue #3755).
package business

import (
	"context"
	"time"
)

// NonceStore defines durable storage for the registration-refresh challenge
// nonce so that a challenge issued by one controller node is consumable by any
// node sharing the same store.
type NonceStore interface {
	// PutNonce stores entry under key, expiring it after ttl. A pre-existing
	// entry under the same key is overwritten.
	PutNonce(ctx context.Context, key string, entry []byte, ttl time.Duration) error

	// GetAndConsumeNonce atomically retrieves and deletes the live (non-expired)
	// entry stored under key. The get-then-delete is atomic across concurrent
	// callers — including callers on different controller nodes sharing this
	// store — so a nonce can never be consumed twice. Returns found=false when
	// no live entry exists, whether because none was ever stored, it expired,
	// or it was already consumed.
	GetAndConsumeNonce(ctx context.Context, key string) (entry []byte, found bool, err error)
}
