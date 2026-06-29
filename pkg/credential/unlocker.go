// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package credential defines the CredentialUnlocker interface for pluggable credential access.
//
// Credential access for cfg admin sessions goes through CredentialUnlocker. The default
// implementation (Story #3 of epic #2213) wraps pkg/secrets/providers/steward's platform
// encryptor (DPAPI on Windows, machine-key AES-256-GCM on Linux/macOS). Additional unlock
// methods (OS-native keychain, hardware token, passphrase) slot in additively via the same
// seam without rework.
//
// This package defines contracts only; it imports no crypto/* packages directly.
// See ADR-014 §4 for the rationale.
package credential

import (
	"context"
	"errors"
)

// ErrLocked is returned when the credential exists but is currently locked and cannot be read.
var ErrLocked = errors.New("credential: credential is locked")

// ErrNoUnlocker is returned when no unlocker is configured for the requested connection.
var ErrNoUnlocker = errors.New("credential: no unlocker configured for this connection")

// CredentialUnlocker provides access to the machine-bound encrypted admin credential for a
// named connection. Implementations are selectable per-connection via ConnectionEntry.UnlockMethod
// (default "machine"). The seam is mandatory; there is no code path that reads the credential
// without going through an unlocker.
//
// Unlock returns the raw credential bytes (the mTLS bundle) for a single connect operation.
// The caller is responsible for zeroing the returned slice when done.
//
// Lock re-seals the credential. For the machine-bound default implementation this is a no-op
// (the encrypted file is already sealed at rest); for interactive implementations it discards
// any cached key material.
type CredentialUnlocker interface {
	Unlock(ctx context.Context, name string) ([]byte, error)
	Lock(ctx context.Context, name string) error
}
