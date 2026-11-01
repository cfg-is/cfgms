// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session

import "time"

// TokenRecord is an internal type tracking rolling-token state for a single session.
// The Manager maintains at most two TokenRecord entries per session: one for the
// current token and one for the prior token during the GraceWindow after a renewal.
// Neither the current nor the prior raw token is stored; only their SHA-256 hashes.
type TokenRecord struct {
	// Session is the live session this record belongs to.
	Session *Session
	// IsGrace marks this as a prior-token entry (the token has already been rotated).
	// When true, GraceExpiry gives the deadline after which this entry is rejected.
	IsGrace bool
	// GraceExpiry is the absolute time after which this prior-token entry expires.
	// Zero when IsGrace is false.
	GraceExpiry time.Time
}
