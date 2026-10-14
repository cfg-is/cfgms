// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package identity manages the steward's stable device identity keypair for the
// registration-refresh handshake defined in ADR-011 and ADR-034. The KeyStore
// interface is algorithm-neutral (ed25519 or ecdsa-p256) and backend-neutral;
// Open selects a backend and falls back to the encrypted-file backend.
package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	stewardcrypto "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
)

const keyFileName = "device_identity.enc"

// Algorithm names the signature algorithm of a device identity key.
type Algorithm string

// ProtectionLevel names where a device identity private key lives.
type ProtectionLevel string

const (
	// AlgorithmEd25519 is the file backend's algorithm; the public key is the raw 32 bytes.
	AlgorithmEd25519 Algorithm = "ed25519"
	// AlgorithmECDSAP256 is the hardware backends' algorithm; the public key is PKIX DER.
	AlgorithmECDSAP256 Algorithm = "ecdsa-p256"
)

const (
	// ProtectionFile is a key encrypted at rest in a file.
	ProtectionFile ProtectionLevel = "file"
	// ProtectionTPM is a key held in a TPM or platform crypto provider.
	ProtectionTPM ProtectionLevel = "tpm"
	// ProtectionSecureEnclave is a key held in a Secure Enclave.
	ProtectionSecureEnclave ProtectionLevel = "secure-enclave"
)

// KeyStore abstracts device identity key storage for the registration-refresh
// handshake. Sign signs wherever the key lives; no method returns private key
// material. ed25519 signs the message itself; ecdsa-p256 signs the 32-byte
// digest passed in and returns ASN.1 DER (ADR-011 Amendment 3).
type KeyStore interface {
	// GenerateOrLoad loads the existing key or creates one on first call.
	GenerateOrLoad(ctx context.Context) (crypto.PublicKey, Algorithm, error)
	// Regenerate replaces the key with a new one (clone re-key, ADR-034 §4).
	Regenerate(ctx context.Context) (crypto.PublicKey, Algorithm, error)
	// RemoveKey deletes the stored key (prepare-image). Removing an absent key is not an error.
	RemoveKey() error
	// Algorithm returns the key's algorithm.
	Algorithm() Algorithm
	// ProtectionLevel returns where the private key lives.
	ProtectionLevel() ProtectionLevel
	// DeviceID returns the lowercase hex SHA-256 identifier, or "" before GenerateOrLoad.
	DeviceID() string
	// PublicKey returns the public key, or nil before GenerateOrLoad.
	PublicKey() crypto.PublicKey
	Sign(message []byte) ([]byte, error)
}

// ComputeDeviceID returns the 64-char lowercase hex DeviceID for pub: SHA-256 of
// the raw 32 bytes for ed25519, SHA-256 of the PKIX DER encoding for ecdsa-p256
// (ADR-011 Amendment 3).
func ComputeDeviceID(alg Algorithm, pub crypto.PublicKey) (string, error) {
	der, err := EncodePublicKeyBytes(alg, pub)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:]), nil
}

// EncodePublicKeyBytes returns the wire bytes of pub: raw for ed25519, PKIX DER for ecdsa-p256.
func EncodePublicKeyBytes(alg Algorithm, pub crypto.PublicKey) ([]byte, error) {
	switch alg {
	case AlgorithmEd25519:
		k, ok := pub.(ed25519.PublicKey)
		if !ok || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("public key is not a valid ed25519 key")
		}
		return []byte(k), nil
	case AlgorithmECDSAP256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k == nil || k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("public key is not a P-256 key")
		}
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, fmt.Errorf("marshal P-256 public key: %w", err)
		}
		return der, nil
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", string(alg))
	}
}

// EncodePublicKey returns the base64 wire encoding of pub for the registration request.
func EncodePublicKey(alg Algorithm, pub crypto.PublicKey) (string, error) {
	b, err := EncodePublicKeyBytes(alg, pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
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
	publicKey   crypto.PublicKey
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
func (ks *FileKeyStore) GenerateOrLoad(_ context.Context) (crypto.PublicKey, Algorithm, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	keyPath := filepath.Join(ks.identityDir, keyFileName)
	data, err := os.ReadFile(keyPath) //#nosec G304 -- path constructed from configured identity directory
	if err == nil {
		plaintext, decErr := ks.encryptor.Decrypt(data)
		if decErr != nil {
			return nil, "", fmt.Errorf("decrypt device identity key: %w", decErr)
		}
		if len(plaintext) != ed25519.PrivateKeySize {
			return nil, "", fmt.Errorf("device identity key corrupt: expected %d bytes, got %d", ed25519.PrivateKeySize, len(plaintext))
		}
		priv := ed25519.PrivateKey(plaintext)
		pub := priv.Public().(ed25519.PublicKey)
		ks.privateKey = priv
		ks.publicKey = pub
		ks.deviceID = ed25519DeviceID(pub)
		return pub, AlgorithmEd25519, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("read device identity key: %w", err)
	}

	return ks.generateAndStoreLocked(keyPath)
}

// Regenerate replaces the stored device identity key with a freshly generated
// one and returns it. The new key is encrypted and written to a temp file and
// renamed over the old key file, so the old key is discarded only once the new
// one is durably in place; a crash leaves either the old key or the new one,
// never neither. The old key is never reused. A steward that has learned its
// identity is a copy of another device calls this so it registers as a new
// device (ADR-034 §4).
func (ks *FileKeyStore) Regenerate(_ context.Context) (crypto.PublicKey, Algorithm, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.generateAndStoreLocked(filepath.Join(ks.identityDir, keyFileName))
}

// generateAndStoreLocked generates a key, writes it encrypted to keyPath
// atomically (replacing any existing file) and makes it current. ks.mu must be held.
func (ks *FileKeyStore) generateAndStoreLocked(keyPath string) (crypto.PublicKey, Algorithm, error) {
	pub, priv, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		return nil, "", fmt.Errorf("generate device identity key: %w", genErr)
	}

	ciphertext, encErr := ks.encryptor.Encrypt([]byte(priv))
	if encErr != nil {
		return nil, "", fmt.Errorf("encrypt device identity key: %w", encErr)
	}

	if mkErr := os.MkdirAll(ks.identityDir, 0700); mkErr != nil {
		return nil, "", fmt.Errorf("create identity dir: %w", mkErr)
	}

	tmp := keyPath + ".tmp"
	if writeErr := os.WriteFile(tmp, ciphertext, 0600); writeErr != nil {
		_ = os.Remove(tmp)
		return nil, "", fmt.Errorf("write device identity key: %w", writeErr)
	}
	if renErr := os.Rename(tmp, keyPath); renErr != nil {
		_ = os.Remove(tmp)
		return nil, "", fmt.Errorf("commit device identity key: %w", renErr)
	}

	ks.privateKey = priv
	ks.publicKey = pub
	ks.deviceID = ed25519DeviceID(pub)
	return pub, AlgorithmEd25519, nil
}

// DeviceID returns the 64-char lowercase hex SHA-256 of the Ed25519 public key.
// Returns empty string if GenerateOrLoad has not been called.
func (ks *FileKeyStore) DeviceID() string {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.deviceID
}

// PublicKey returns the Ed25519 public key (an ed25519.PublicKey).
// Returns nil if GenerateOrLoad has not been called.
func (ks *FileKeyStore) PublicKey() crypto.PublicKey {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.publicKey
}

// Algorithm returns AlgorithmEd25519; the file backend never uses another.
func (ks *FileKeyStore) Algorithm() Algorithm { return AlgorithmEd25519 }

// ProtectionLevel returns ProtectionFile.
func (ks *FileKeyStore) ProtectionLevel() ProtectionLevel { return ProtectionFile }

// RemoveKey deletes the encrypted key file and forgets the in-memory key.
func (ks *FileKeyStore) RemoveKey() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if err := RemoveStoredKey(ks.identityDir); err != nil {
		return err
	}
	ks.privateKey, ks.publicKey, ks.deviceID = nil, nil, ""
	return nil
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

// ed25519DeviceID returns hex(sha256(raw public key)) per ADR-011.
func ed25519DeviceID(pub ed25519.PublicKey) string {
	h := sha256.Sum256([]byte(pub))
	return hex.EncodeToString(h[:])
}

// RemoveStoredKey deletes the encrypted device identity key from dir so the next
// FileKeyStore.GenerateOrLoad on that directory generates a new key and with it
// a new DeviceID. It is the only exported way to name the key file, so the file
// name stays defined in this package. Removing a key that does not exist is not
// an error. The path is removed without following symlinks.
func RemoveStoredKey(dir string) error {
	err := os.Remove(filepath.Join(dir, keyFileName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove device identity key: %w", err)
	}
	return nil
}

// StoredKeyFileName returns the name of the device identity key file inside the
// identity directory, so a dry run can list it without touching it.
func StoredKeyFileName() string { return keyFileName }
