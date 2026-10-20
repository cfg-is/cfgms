// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"errors"
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
// The credentials directory is made private to the current user before any key material
// (the encryptor's salt) is written to it: mode 0700 on Linux/macOS; on Windows a
// protected DACL for the current user and SYSTEM only (see secureCredentialsDir).
func newCredentialStore() (*CredentialStore, error) {
	dir, err := credentialsDirFn()
	if err != nil {
		return nil, err
	}
	if err := secureCredentialsDir(dir); err != nil {
		return nil, fmt.Errorf("cannot create credentials directory: %w", err)
	}
	enc, err := steward.NewUserEncryptor(dir)
	if err != nil {
		return nil, fmt.Errorf("credential store: init encryptor: %w", err)
	}
	// The encryptor has created or read the salt; it is key material, so it
	// gets the same per-file protection as the credentials.
	if err := secureCredentialFile(filepath.Join(dir, "salt")); err != nil {
		return nil, fmt.Errorf("credential store: secure salt: %w", err)
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
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("credential store: refusing %q: credential path is a symlink", name)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("credential store: stat %q: %w", name, err)
	}
	// Write to a fresh 0600 temp file in the same directory and rename it over the
	// target, so a pre-existing file's mode or owner never carries over.
	tmp, err := os.CreateTemp(s.dir, name+".*.tmp")
	if err != nil {
		return fmt.Errorf("credential store: write %q: %w", name, err)
	}
	tmpPath := tmp.Name()
	_, werr := tmp.Write(ciphertext)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("credential store: write %q: %w", name, errors.Join(werr, cerr))
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("credential store: write %q: %w", name, err)
	}
	if err := secureCredentialFile(path); err != nil {
		return fmt.Errorf("credential store: secure %q: %w", name, err)
	}
	return nil
}

// Load decrypts and returns the credential bytes for the named connection.
// Returns a wrapped credential.ErrLocked on decrypt failure or when the credential is absent,
// including a credential written under an earlier encryption scheme; the message tells the
// admin to store it again.
func (s *CredentialStore) Load(ctx context.Context, name string) ([]byte, error) {
	plain, err := s.unlocker.Unlock(ctx, name)
	if errors.Is(err, credential.ErrLocked) {
		return nil, fmt.Errorf("credential store: load %q: %w (store the credential again with 'cfg connect' or 'cfg credential enroll')", name, err)
	}
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
