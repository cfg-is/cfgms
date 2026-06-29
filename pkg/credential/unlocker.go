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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
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

// ValidateCredentialName rejects names that could cause path traversal or contain
// reserved characters. A name must be a simple filename with no directory components.
func ValidateCredentialName(name string) error {
	if name == "" {
		return errors.New("credential: name must not be empty")
	}
	// Reject bare dot-references that are special in every filesystem.
	if name == "." || name == ".." {
		return fmt.Errorf("credential: name %q is reserved", name)
	}
	// filepath.Base cleans path separators and ".." components; if the result differs
	// from the original, the name contained a traversal attempt.
	if filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("credential: name %q contains invalid path characters", name)
	}
	return nil
}

// NewMachineUnlocker creates a machine-bound CredentialUnlocker backed by the platform
// encryptor (DPAPI on Windows, AES-256-GCM with HKDF on Linux/macOS).
// dir is the credentials directory where <name>.enc files reside; a salt file for key
// derivation is also maintained within dir.
func NewMachineUnlocker(dir string) (CredentialUnlocker, error) {
	enc, err := steward.NewPlatformEncryptor(dir)
	if err != nil {
		return nil, fmt.Errorf("credential: init platform encryptor: %w", err)
	}
	return &machineUnlocker{dir: dir, enc: enc}, nil
}

// machineUnlocker implements CredentialUnlocker using the machine-bound platform encryptor.
// No crypto package is imported directly — all encryption is delegated to
// pkg/secrets/providers/steward.
type machineUnlocker struct {
	dir string
	enc steward.Encryptor
}

// Unlock reads <dir>/<name>.enc, decrypts it with the machine-bound key, and returns
// the plaintext bundle bytes. Returns ErrLocked when the file is missing or decryption fails.
func (m *machineUnlocker) Unlock(_ context.Context, name string) ([]byte, error) {
	if err := ValidateCredentialName(name); err != nil {
		return nil, err
	}
	path := filepath.Join(m.dir, name+".enc")
	// #nosec G304 - path is constructed from the configured credentials directory; name is validated above
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: credential %q not found", ErrLocked, name)
		}
		return nil, fmt.Errorf("credential: read %s.enc: %w", name, err)
	}
	plain, err := m.enc.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt failed for %q: %w", ErrLocked, name, err)
	}
	return plain, nil
}

// Lock is a no-op for the machine-bound implementation: the encrypted file is already sealed
// at rest; there is no in-memory key material to discard.
func (m *machineUnlocker) Lock(_ context.Context, _ string) error {
	return nil
}
