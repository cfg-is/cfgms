// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Signing certificate lifecycle state machine for cert.Manager.
//
// The cursor tracks which certificate serial is "current" and which (if any) is
// "rotating" during the overlap window. A single JSON sidecar file persists the
// state atomically via temp-rename so that a crash mid-write never leaves a
// half-updated cursor.
package cert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const signingCursorFileName = "signing-cursor.json"

// SigningCertLifecycleState describes the lifecycle phase of a config-signing certificate.
type SigningCertLifecycleState int

const (
	// LifecycleStateCurrent is the sole active signer.
	LifecycleStateCurrent SigningCertLifecycleState = iota
	// LifecycleStateRotating is the previous signer still accepted during the overlap window.
	LifecycleStateRotating
	// LifecycleStateRetired is a signer no longer accepted for verification.
	LifecycleStateRetired
)

// SigningCertCursor is the on-disk JSON state for the config-signing rotation.
// It is written atomically to {basePath}/signing-cursor.json.
// A missing file means no rotation has been initiated.
type SigningCertCursor struct {
	// CurrentSerial is the serial of the active signing certificate.
	CurrentSerial string `json:"current_serial"`
	// RotatingSerial is the serial of the previous signer still accepted during
	// the overlap window. Empty when no rotation is in progress.
	RotatingSerial string `json:"rotating_serial,omitempty"`
	// OverlapWindowDays is the number of days RotatingSerial remains accepted
	// after the rotation. Set at rotate-time (B2a); B1 reads it.
	OverlapWindowDays int `json:"overlap_window_days"`
	// RotatedAt is the wall-clock time when the last rotation occurred.
	RotatedAt time.Time `json:"rotated_at"`
	// RetiredAt records when RotatingSerial was retired (overlap window closed).
	// Nil while the overlap window is still open or when no rotation has occurred.
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

// loadSigningCursor reads the cursor file from basePath.
// Returns (nil, nil) when the file does not exist — no rotation in progress.
func loadSigningCursor(basePath string) (*SigningCertCursor, error) {
	// #nosec G304 — path is controlled: constructed from the cert manager's storage path
	data, err := os.ReadFile(filepath.Join(basePath, signingCursorFileName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read signing cursor: %w", err)
	}

	var cursor SigningCertCursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		return nil, fmt.Errorf("failed to parse signing cursor: %w", err)
	}
	return &cursor, nil
}

// saveSigningCursor writes the cursor to basePath/signing-cursor.json atomically
// via a temp-rename so a crash never leaves a half-written file.
func saveSigningCursor(basePath string, cursor *SigningCertCursor) error {
	data, err := json.MarshalIndent(cursor, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal signing cursor: %w", err)
	}

	filePath := filepath.Join(basePath, signingCursorFileName)
	tmpPath := filePath + ".tmp"

	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write signing cursor: %w", err)
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to finalize signing cursor: %w", err)
	}
	return nil
}

// transitionSigningCursor atomically promotes newSerial to CurrentSerial and
// moves the old CurrentSerial to RotatingSerial. The store's write lock is held
// for the full read-modify-write so concurrent callers are serialised.
//
// Returns an error if RotatingSerial is already set and still within the overlap
// window — a rotation is already in progress and must complete before the next one.
func transitionSigningCursor(store *FileStore, basePath string, newSerial string, overlapDays int) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	cursor, err := loadSigningCursor(basePath)
	if err != nil {
		return fmt.Errorf("failed to load signing cursor: %w", err)
	}

	// Guard: reject if a rotation is already in progress and the overlap window has not expired.
	if cursor != nil && cursor.RotatingSerial != "" {
		overlapDuration := time.Duration(cursor.OverlapWindowDays) * 24 * time.Hour
		if time.Since(cursor.RotatedAt) < overlapDuration {
			return fmt.Errorf(
				"rotation already in progress: rotating serial %q is still within %d-day overlap window (rotated %s ago)",
				cursor.RotatingSerial,
				cursor.OverlapWindowDays,
				time.Since(cursor.RotatedAt).Truncate(time.Second),
			)
		}
	}

	oldCurrent := ""
	if cursor != nil {
		oldCurrent = cursor.CurrentSerial
	}

	next := &SigningCertCursor{
		CurrentSerial:     newSerial,
		OverlapWindowDays: overlapDays,
		RotatedAt:         time.Now().UTC(),
	}
	if oldCurrent != "" {
		next.RotatingSerial = oldCurrent
	}

	return saveSigningCursor(basePath, next)
}
