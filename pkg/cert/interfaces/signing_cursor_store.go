// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"errors"
	"time"
)

// SigningCertCursor is the lifecycle state for a controller's config-signing
// certificate rotation. JSON tags are load-bearing: pkg/cert's file-backed
// implementation marshals this exact type to preserve today's on-disk
// signing-cursor.json layout.
type SigningCertCursor struct {
	// CurrentSerial is the serial of the active signing certificate.
	CurrentSerial string `json:"current_serial"`
	// RotatingSerial is the serial of the previous signer still accepted
	// during the overlap window. Empty when no rotation is in progress.
	RotatingSerial string `json:"rotating_serial,omitempty"`
	// OverlapWindowDays is the number of days RotatingSerial remains
	// accepted after the rotation.
	OverlapWindowDays int `json:"overlap_window_days"`
	// RotatedAt is when the last rotation occurred.
	RotatedAt time.Time `json:"rotated_at"`
	// RetiredAt records when RotatingSerial was retired. Nil while the
	// overlap window is still open or no rotation has occurred.
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

// ErrSigningRotationInProgress is returned by SigningCursorStore.TransitionCursor
// when a non-forced rotation is requested while a previous rotation's overlap
// window is still open. Callers (e.g. the REST handler) can use errors.Is to
// map this to a 409 Conflict rather than a generic 500.
var ErrSigningRotationInProgress = errors.New("signing rotation already in progress")

// SigningCursorStore defines durable storage for the config-signing
// certificate rotation cursor. A cluster-visible implementation makes
// concurrent rotation attempts from different controller nodes converge on
// one cursor instead of diverging.
type SigningCursorStore interface {
	// LoadCursor returns the current cursor, or nil if no rotation has been
	// initiated yet.
	LoadCursor(ctx context.Context) (*SigningCertCursor, error)

	// TransitionCursor evaluates the in-progress guard (skipped when force is
	// true) and, on success, promotes newSerial to CurrentSerial and demotes
	// the prior CurrentSerial to RotatingSerial, persisting the result. The
	// evaluate-and-persist step is atomic with respect to every other caller
	// of this store — including callers on different controller nodes
	// sharing it — so concurrent transitions always converge on one cursor
	// rather than diverging. Returns ErrSigningRotationInProgress if a
	// rotation is already in progress and force is false.
	TransitionCursor(ctx context.Context, newSerial string, overlapDays int, force bool) (*SigningCertCursor, error)
}
