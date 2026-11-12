// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
// Returns a wrapped credential.ErrLocked when the credential is absent; the message tells the
// admin to store it again. A credential that exists but cannot be read returns the unlocker's
// specific error unchanged in meaning (older cfg format, different user or machine, or
// corrupt), which already carries its own remedy.
func (s *CredentialStore) Load(ctx context.Context, name string) ([]byte, error) {
	plain, err := s.unlocker.Unlock(ctx, name)
	if errors.Is(err, credential.ErrLocked) && !credential.IsStoreFormatError(err) {
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

// Exists reports whether a credential file for name is present. A symlink at the
// path counts as present, so a caller that checks before Store never treats a
// planted link as a free slot. Store and Delete refuse the link themselves.
func (s *CredentialStore) Exists(_ context.Context, name string) (bool, error) {
	if err := credential.ValidateCredentialName(name); err != nil {
		return false, err
	}
	if _, err := os.Lstat(filepath.Join(s.dir, name+".enc")); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("credential store: stat %q: %w", name, err)
	}
	return false, nil
}

// List returns, sorted, the names of the stored credentials that begin with
// prefix. An empty prefix lists every credential. Only regular <name>.enc files
// are reported: temp files from an interrupted Store, the salt, directories and
// symlinks are skipped. List does not decrypt anything.
func (s *CredentialStore) List(_ context.Context, prefix string) ([]string, error) {
	if prefix != "" && strings.ContainsAny(prefix, "/\\") {
		return nil, fmt.Errorf("credential store: list prefix %q contains invalid path characters", prefix)
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("credential store: list: %w", err)
	}
	names := []string{}
	for _, e := range entries {
		fname := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(fname, ".enc") {
			continue
		}
		name := strings.TrimSuffix(fname, ".enc")
		if !strings.HasPrefix(name, prefix) || credential.ValidateCredentialName(name) != nil {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// Delete removes <dir>/<name>.enc. It refuses a symlink at that path, as Store
// does, and returns an error wrapping os.ErrNotExist when there is no such
// credential.
func (s *CredentialStore) Delete(_ context.Context, name string) error {
	if err := credential.ValidateCredentialName(name); err != nil {
		return err
	}
	path := filepath.Join(s.dir, name+".enc")
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("credential store: delete %q: %w", name, os.ErrNotExist)
	}
	if err != nil {
		return fmt.Errorf("credential store: stat %q: %w", name, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("credential store: refusing %q: credential path is a symlink", name)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("credential store: delete %q: %w", name, err)
	}
	return nil
}
