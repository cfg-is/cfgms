// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cfgis/cfgms/pkg/credential"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
)

// credentialStoreUnlockerFn creates the CredentialUnlocker for newCredentialStore.
// Overridable in tests to inject a counting or stub unlocker.
var credentialStoreUnlockerFn = func(dir string) (credential.CredentialUnlocker, error) {
	return credential.NewMachineUnlocker(dir)
}

// credentialsDirFn is overridable in tests to avoid touching real user config directories.
var credentialsDirFn = defaultCredentialsDir

func defaultCredentialsDir() (string, error) {
	configDir, err := userConfigDirFn()
	if err != nil {
		return "", fmt.Errorf("cannot determine user config directory: %w", err)
	}
	return filepath.Join(configDir, "cfgms", "credentials"), nil
}

// CredentialStore manages encrypted-at-rest admin credentials stored under
// os.UserConfigDir()/cfgms/credentials/<name>.enc.
// All cryptographic operations are delegated to pkg/secrets/providers/steward;
// no crypto package is used directly.
type CredentialStore struct {
	dir      string
	enc      steward.Encryptor
	unlocker credential.CredentialUnlocker
}

// newCredentialStore returns a CredentialStore using the default machine-bound unlocker.
// The credentials directory is created at mode 0700 if it does not exist.
func newCredentialStore() (*CredentialStore, error) {
	dir, err := credentialsDirFn()
	if err != nil {
		return nil, err
	}
	// #nosec G301 - 0700: traversable but private to the user
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("cannot create credentials directory: %w", err)
	}
	enc, err := steward.NewPlatformEncryptor(dir)
	if err != nil {
		return nil, fmt.Errorf("credential store: init encryptor: %w", err)
	}
	unlocker, err := credentialStoreUnlockerFn(dir)
	if err != nil {
		return nil, fmt.Errorf("credential store: init unlocker: %w", err)
	}
	return &CredentialStore{dir: dir, enc: enc, unlocker: unlocker}, nil
}

// Store encrypts bundleBytes and writes them to <dir>/<name>.enc (mode 0600).
// No plaintext credential material appears on disk after this call.
func (s *CredentialStore) Store(_ context.Context, name string, bundleBytes []byte) error {
	if err := credential.ValidateCredentialName(name); err != nil {
		return err
	}
	ciphertext, err := s.enc.Encrypt(bundleBytes)
	if err != nil {
		return fmt.Errorf("credential store: encrypt %q: %w", name, err)
	}
	path := filepath.Join(s.dir, name+".enc")
	// #nosec G306 - 0600: owner read/write only; encrypted credential material
	if err := os.WriteFile(path, ciphertext, 0600); err != nil {
		return fmt.Errorf("credential store: write %q: %w", name, err)
	}
	return nil
}

// Load decrypts and returns the credential bytes for the named connection.
// Returns a wrapped credential.ErrLocked on decrypt failure or when the credential is absent.
func (s *CredentialStore) Load(ctx context.Context, name string) ([]byte, error) {
	plain, err := s.unlocker.Unlock(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("credential store: load %q: %w", name, err)
	}
	return plain, nil
}

// Lock discards any in-memory reference to decrypted credential material for name.
// For the default machine-bound unlocker this is a no-op; interactive unlocker
// implementations use this to clear cached key material.
func (s *CredentialStore) Lock(ctx context.Context, name string) error {
	return s.unlocker.Lock(ctx, name)
}
