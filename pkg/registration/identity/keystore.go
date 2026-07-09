// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package identity manages the steward's stable Ed25519 device identity keypair
// for the registration-refresh handshake defined in ADR-011.
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	stewardcrypto "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
)

const keyFileName = "device_identity.enc"

// KeyStore abstracts device identity key material storage for the registration-refresh handshake.
type KeyStore interface {
	GenerateOrLoad(ctx context.Context) (ed25519.PublicKey, ed25519.PrivateKey, error)
	DeviceID() string
	Sign(message []byte) ([]byte, error)
}

// FileKeyStore stores the Ed25519 device identity key encrypted at rest.
// The private key is encrypted via the platform encryptor (AES-256-GCM on Linux/macOS,
// DPAPI on Windows) and written to {identityDir}/device_identity.enc with mode 0600.
// The plaintext private key is never written to disk.
type FileKeyStore struct {
	identityDir string
	encryptor   stewardcrypto.Encryptor
	mu          sync.Mutex
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	deviceID    string
}

// NewFileKeyStore creates a FileKeyStore that stores the encrypted device identity key in identityDir.
func NewFileKeyStore(identityDir string) (*FileKeyStore, error) {
	enc, err := stewardcrypto.NewPlatformEncryptor(identityDir)
	if err != nil {
		return nil, fmt.Errorf("create platform encryptor: %w", err)
	}
	return newFileKeyStoreWithEncryptor(identityDir, enc), nil
}

// newFileKeyStoreWithEncryptor creates a FileKeyStore with an explicit encryptor.
// Used in tests to inject a real AES-256-GCM encryptor with a fixed machine ID
// when /etc/machine-id is unavailable in the test environment.
func newFileKeyStoreWithEncryptor(identityDir string, enc stewardcrypto.Encryptor) *FileKeyStore {
	return &FileKeyStore{
		identityDir: identityDir,
		encryptor:   enc,
	}
}

// NewFileKeyStoreForTesting creates a FileKeyStore using a fixed AES-256-GCM encryptor
// seeded with a predictable machine ID, independent of the platform machine ID.
// Intended for use in external test packages where /etc/machine-id may be unavailable.
func NewFileKeyStoreForTesting(identityDir string) (*FileKeyStore, error) {
	enc, err := stewardcrypto.NewEncryptorFromBytes([]byte("cfgms-test-machine-id"), identityDir)
	if err != nil {
		return nil, fmt.Errorf("create test encryptor: %w", err)
	}
	return newFileKeyStoreWithEncryptor(identityDir, enc), nil
}

// GenerateOrLoad loads the existing device identity key or generates and stores a new one on first call.
// The private key is stored encrypted at rest; the plaintext never leaves memory.
func (ks *FileKeyStore) GenerateOrLoad(_ context.Context) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	keyPath := filepath.Join(ks.identityDir, keyFileName)
	data, err := os.ReadFile(keyPath) //#nosec G304 -- path constructed from configured identity directory
	if err == nil {
		plaintext, decErr := ks.encryptor.Decrypt(data)
		if decErr != nil {
			return nil, nil, fmt.Errorf("decrypt device identity key: %w", decErr)
		}
		if len(plaintext) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("device identity key corrupt: expected %d bytes, got %d", ed25519.PrivateKeySize, len(plaintext))
		}
		priv := ed25519.PrivateKey(plaintext)
		pub := priv.Public().(ed25519.PublicKey)
		ks.privateKey = priv
		ks.publicKey = pub
		ks.deviceID = computeDeviceID(pub)
		return pub, priv, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("read device identity key: %w", err)
	}

	pub, priv, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		return nil, nil, fmt.Errorf("generate device identity key: %w", genErr)
	}

	ciphertext, encErr := ks.encryptor.Encrypt([]byte(priv))
	if encErr != nil {
		return nil, nil, fmt.Errorf("encrypt device identity key: %w", encErr)
	}

	if mkErr := os.MkdirAll(ks.identityDir, 0700); mkErr != nil {
		return nil, nil, fmt.Errorf("create identity dir: %w", mkErr)
	}

	tmp := keyPath + ".tmp"
	if writeErr := os.WriteFile(tmp, ciphertext, 0600); writeErr != nil {
		_ = os.Remove(tmp)
		return nil, nil, fmt.Errorf("write device identity key: %w", writeErr)
	}
	if renErr := os.Rename(tmp, keyPath); renErr != nil {
		_ = os.Remove(tmp)
		return nil, nil, fmt.Errorf("commit device identity key: %w", renErr)
	}

	ks.privateKey = priv
	ks.publicKey = pub
	ks.deviceID = computeDeviceID(pub)
	return pub, priv, nil
}

// DeviceID returns the 64-char lowercase hex SHA-256 of the Ed25519 public key.
// Returns empty string if GenerateOrLoad has not been called.
func (ks *FileKeyStore) DeviceID() string {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.deviceID
}

// PublicKey returns the Ed25519 public key.
// Returns nil if GenerateOrLoad has not been called.
func (ks *FileKeyStore) PublicKey() ed25519.PublicKey {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.publicKey
}

// Sign signs message with the device identity private key using Ed25519.
// Returns an error if GenerateOrLoad has not been called.
func (ks *FileKeyStore) Sign(message []byte) ([]byte, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.privateKey == nil {
		return nil, fmt.Errorf("device identity key not loaded: call GenerateOrLoad first")
	}
	return ed25519.Sign(ks.privateKey, message), nil
}

// computeDeviceID returns the 64-char lowercase hex SHA-256 of the Ed25519 public key.
// DeviceID = hex(sha256(publicKeyBytes)) per ADR-011.
func computeDeviceID(pub ed25519.PublicKey) string {
	h := sha256.Sum256([]byte(pub))
	return hex.EncodeToString(h[:])
}
