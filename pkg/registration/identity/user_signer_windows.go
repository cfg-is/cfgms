// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// userKeyNamePrefix namespaces the per-user keys CreateUserKey makes. The full
// name appends a random suffix, so each key has its own name and deleting one
// never touches another.
const userKeyNamePrefix = "cfgms-user-key-"

// userKeySuffixBytes is the size of the random part of a user key name.
const userKeySuffixBytes = 16

// userKeyProviders is the order CreateUserKey tries: the Platform Crypto
// Provider (TPM) first, then the Software Key Storage Provider. Both keep the
// private key inside the provider, where it cannot be read back out.
var userKeyProviders = []string{platformCryptoProvider, softwareKeyStorageProvider}

// ErrUserKeyUnavailable means no platform key provider can hold a user key on
// this host. The caller may fall back to another way of keeping its key.
var ErrUserKeyUnavailable = errors.New("no platform key provider is available")

// ErrUserKeyUnsupported means this OS has no platform user-key support. It is
// never returned on Windows.
var ErrUserKeyUnsupported = errors.New("platform user keys are not supported on this OS")

// UserKeysSupported reports whether CreateUserKey can be used on this OS.
func UserKeysSupported() bool { return true }

// userKeyConfig is the CNG configuration of a user key in provider: a per-user
// key (no NCRYPT_MACHINE_KEY_FLAG) under userKeyNamePrefix.
func userKeyConfig(provider string) cngKeyConfig {
	return cngKeyConfig{provider: provider, keyPrefix: userKeyNamePrefix, machine: false}
}

// validateUserKeyRef checks a provider and key name read back from storage
// before either is passed to CNG.
func validateUserKeyRef(provider, keyName string) error {
	known := false
	for _, p := range userKeyProviders {
		if p == provider {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("unknown key provider %q", provider)
	}
	suffix, ok := strings.CutPrefix(keyName, userKeyNamePrefix)
	if !ok || len(suffix) != 2*userKeySuffixBytes {
		return fmt.Errorf("invalid user key name %q", keyName)
	}
	if _, err := hex.DecodeString(suffix); err != nil || strings.ToLower(suffix) != suffix {
		return fmt.Errorf("invalid user key name %q", keyName)
	}
	return nil
}

// UserKeySigner is a crypto.Signer whose P-256 private key is a persisted,
// non-exportable, sign-only key of the calling user in a CNG key storage
// provider. The private key bytes never exist in this process. Provider and
// key handles are opened per operation and freed before it returns.
//
// No CNG call returns the private key. In the Platform Crypto Provider it never
// leaves the TPM. The Software Key Storage Provider enforces the export policy
// itself and persists the key under the user's DPAPI, so a same-user process
// that decrypts that file directly can recover it. Neither provider stops
// another process running as the same user asking the provider to sign.
type UserKeySigner struct {
	cfg  cngKeyConfig
	name string
	pub  *ecdsa.PublicKey
}

var _ crypto.Signer = (*UserKeySigner)(nil)

// CreateUserKey creates a new user key in the first provider that can hold
// one, proves it signs, and returns its signer. The Platform Crypto Provider is
// passed over for any failure, since a host without a usable TPM fails in
// several ways. The Software Key Storage Provider is the last resort: if it
// cannot be opened the result is ErrUserKeyUnavailable; any other failure there
// is returned as it is. A key that fails its self-test is deleted.
func CreateUserKey() (*UserKeySigner, error) {
	if err := loadNCrypt(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUserKeyUnavailable, err)
	}
	var b [userKeySuffixBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("generate user key name: %w", err)
	}
	name := userKeyNamePrefix + hex.EncodeToString(b[:])

	var passed []error
	for _, provider := range userKeyProviders {
		s, err := createUserKeyIn(provider, name)
		if err == nil {
			return s, nil
		}
		var openErr *providerOpenError
		if provider == platformCryptoProvider || errors.As(err, &openErr) {
			passed = append(passed, err)
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("%w: %w", ErrUserKeyUnavailable, errors.Join(passed...))
}

// providerOpenError is a provider that could not be opened at all.
type providerOpenError struct{ err error }

func (e *providerOpenError) Error() string { return e.err.Error() }
func (e *providerOpenError) Unwrap() error { return e.err }

func createUserKeyIn(provider, name string) (*UserKeySigner, error) {
	c := userKeyConfig(provider)
	prov, err := openProvider(provider)
	if err != nil {
		return nil, &providerOpenError{err: fmt.Errorf("open %s: %w", provider, err)}
	}
	defer freeObject(prov)
	// createLocked creates, self-tests (reopen by name, sign, verify) and, on any
	// failure, deletes the key. The store is only a carrier for that sequence.
	ks := &cngKeyStore{cfg: c}
	ks.mu.Lock()
	pub, err := ks.createLocked(prov, name)
	ks.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("create user key in %s: %w", provider, err)
	}
	return &UserKeySigner{cfg: c, name: name, pub: pub}, nil
}

// OpenUserKey opens the user key keyName in provider, as recorded from an
// earlier CreateUserKey.
func OpenUserKey(provider, keyName string) (*UserKeySigner, error) {
	if err := validateUserKeyRef(provider, keyName); err != nil {
		return nil, err
	}
	c := userKeyConfig(provider)
	prov, err := openProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", provider, err)
	}
	defer freeObject(prov)
	h, err := c.openKey(prov, keyName)
	if isKeyNotFound(err) {
		return nil, fmt.Errorf("user key %s not found in %s", keyName, provider)
	}
	if err != nil {
		return nil, fmt.Errorf("open user key: %w", err)
	}
	defer freeObject(h)
	pub, err := publicKeyOf(h)
	if err != nil {
		return nil, fmt.Errorf("read user key public key: %w", err)
	}
	return &UserKeySigner{cfg: c, name: keyName, pub: pub}, nil
}

// DeleteUserKey deletes the user key keyName from provider. A key that does not
// exist is not an error, and neither is a provider that cannot load or cannot
// hold a key at all: as in removeCNGKeys, there is then nothing to remove. A
// provider or name that is not one CreateUserKey makes is refused.
func DeleteUserKey(provider, keyName string) error {
	if err := validateUserKeyRef(provider, keyName); err != nil {
		return err
	}
	c := userKeyConfig(provider)
	prov, err := openProvider(provider)
	if err != nil {
		return nil
	}
	defer freeObject(prov)
	if err := c.deleteKey(prov, keyName); err != nil && !keyCannotExist(err) {
		return fmt.Errorf("delete user key: %w", err)
	}
	return nil
}

// KeyName is the CNG name of the key, to be recorded for OpenUserKey.
func (s *UserKeySigner) KeyName() string { return s.name }

// Provider is the CNG provider holding the key, to be recorded for OpenUserKey.
func (s *UserKeySigner) Provider() string { return s.cfg.provider }

// Public returns the *ecdsa.PublicKey.
func (s *UserKeySigner) Public() crypto.PublicKey { return s.pub }

// Sign signs a 32-byte SHA-256 digest in the provider and returns ASN.1 DER.
// rand is unused: the provider supplies its own randomness.
func (s *UserKeySigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("user key signs SHA-256 digests only")
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digest))
	}
	prov, err := openProvider(s.cfg.provider)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", s.cfg.provider, err)
	}
	defer freeObject(prov)
	h, err := s.cfg.openKey(prov, s.name)
	if err != nil {
		return nil, fmt.Errorf("open user key: %w", err)
	}
	defer freeObject(h)
	return signDigest(h, digest)
}
