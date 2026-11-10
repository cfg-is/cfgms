// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package steward implements OS-native encrypted secret storage for steward endpoints.
//
// This package provides a SecretProvider that uses platform-specific encryption:
//   - Windows: DPAPI (CryptProtectData/CryptUnprotectData)
//   - Linux: AES-256-GCM with HKDF key derived from /etc/machine-id
//   - macOS: AES-256-GCM with HKDF key derived from IOPlatformUUID
package steward

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
)

// Encryptor provides symmetric encryption and decryption.
// Returned by NewPlatformEncryptor for use outside this package.
type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// NewPlatformEncryptor creates an OS-native encryptor for the given directory.
// On Linux/macOS: AES-256-GCM with HKDF-SHA256 derived from the machine ID.
// On Windows: machine-scope DPAPI (any account on the machine can decrypt).
// The dir is used to persist the HKDF salt (Linux/macOS only).
func NewPlatformEncryptor(dir string) (Encryptor, error) {
	return newPlatformEncryptor(dir)
}

// NewUserEncryptor creates the encryptor for the cfg CLI's admin credential
// store. On Windows it is user-scope DPAPI: only the Windows user who stored a
// credential can decrypt it, and its entropy is derived from the machine's
// MachineGuid and a random salt kept in dir, so a blob copied to another
// machine does not decrypt there. On Linux/macOS it is the same AES-256-GCM
// encryptor as NewPlatformEncryptor (key from the machine ID and the salt in
// dir); the files' 0600 mode in the user's config directory binds it to the user.
// Steward callers keep NewPlatformEncryptor.
//
// Every blob it writes starts with a format-version header (see versionedEncryptor),
// and Decrypt reports ErrLegacyFormat, ErrCorrupt or ErrWrongProtectionScope so a
// caller can tell an older-format store, a damaged file and a store protected for
// another user or machine apart.
func NewUserEncryptor(dir string) (Encryptor, error) {
	inner, err := newUserEncryptor(dir)
	if err != nil {
		return nil, err
	}
	return &versionedEncryptor{inner: inner}, nil
}

// NewEncryptorFromBytes creates an AES-256-GCM encryptor using the supplied machineID bytes
// instead of reading the platform machine ID. Intended for use in tests where
// /etc/machine-id or the platform equivalent is unavailable.
func NewEncryptorFromBytes(machineID []byte, dir string) (Encryptor, error) {
	return newAesGcmEncryptor(machineID, dir)
}

// Errors returned by the Decrypt method of the encryptor from NewUserEncryptor.
// Callers test them with errors.Is. Their messages carry no key material, entropy
// or platform error text.
var (
	// ErrLegacyFormat means the blob has no format header: it was written by an
	// older cfg. It is never migrated or decrypted by a fallback.
	ErrLegacyFormat = errors.New("credential blob was written by an older cfg format")
	// ErrCorrupt means the blob is empty, or has the format header but is
	// truncated, altered or of an unknown version.
	ErrCorrupt = errors.New("credential blob is corrupt or unreadable")
	// ErrWrongProtectionScope means the blob is intact but the platform could not
	// decrypt it: it is protected for a different user or machine. DPAPI cannot
	// tell a wrong user from a wrong machine or salt.
	ErrWrongProtectionScope = errors.New("credential blob is protected for a different user or machine")
)

// Layout of a versioned blob: magic, format version, SHA-256 of the body, body.
// The body is the platform encryptor's ciphertext. The checksum is for
// classification only (a damaged file versus an intact blob protected for someone
// else); it is not a security control and no key material enters the header.
const (
	blobMagic         = "CFGS"
	blobFormatVersion = byte(1)
	blobHeaderSize    = len(blobMagic) + 1 + sha256.Size
)

// versionedEncryptor wraps a platform encryptor with the versioned blob header.
// It is the single header codec for every platform.
type versionedEncryptor struct {
	inner platformEncryptor
}

// Encrypt encrypts plaintext with the platform encryptor and prepends the header.
func (v *versionedEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	body, err := v.inner.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	blob := make([]byte, 0, blobHeaderSize+len(body))
	blob = append(blob, blobMagic...)
	blob = append(blob, blobFormatVersion)
	blob = append(blob, sum[:]...)
	return append(blob, body...), nil
}

// Decrypt classifies the blob before decrypting it; see the sentinel errors.
func (v *versionedEncryptor) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, ErrCorrupt
	}
	if !bytes.HasPrefix(blob, []byte(blobMagic)) {
		return nil, ErrLegacyFormat
	}
	if len(blob) <= blobHeaderSize || blob[len(blobMagic)] != blobFormatVersion {
		return nil, ErrCorrupt
	}
	body := blob[blobHeaderSize:]
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], blob[len(blobMagic)+1:blobHeaderSize]) {
		return nil, ErrCorrupt
	}
	plain, err := v.inner.Decrypt(body)
	if err != nil {
		return nil, ErrWrongProtectionScope
	}
	return plain, nil
}

// platformEncryptor abstracts OS-native encryption for secret storage.
// Each platform provides its own implementation via build tags.
type platformEncryptor interface {
	// Encrypt encrypts plaintext using the platform-specific mechanism.
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	// Decrypt decrypts ciphertext using the platform-specific mechanism.
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
	// Algorithm returns the encryption algorithm name (e.g., "AES-256-GCM", "DPAPI").
	Algorithm() string
}

// hkdfInfo is the application-specific context string for HKDF key derivation.
const hkdfInfo = "cfgms-steward-secrets-v1"

// saltFileName is the name of the salt file used for HKDF key derivation.
const saltFileName = "salt"

// saltSize is the size of the random salt in bytes.
const saltSize = 32

// aesGcmEncryptor implements platformEncryptor using AES-256-GCM with HKDF-derived keys.
// Used on Linux and macOS with platform-specific machine ID sources.
type aesGcmEncryptor struct {
	gcm cipher.AEAD
}

// newAesGcmEncryptor creates an AES-256-GCM encryptor from a machine ID and secrets directory.
// The encryption key is derived using HKDF-SHA256 with:
//   - IKM: machine ID bytes
//   - Salt: random 32 bytes (generated once and stored at {secretsDir}/salt)
//   - Info: "cfgms-steward-secrets-v1"
func newAesGcmEncryptor(machineID []byte, secretsDir string) (*aesGcmEncryptor, error) {
	if len(machineID) == 0 {
		return nil, fmt.Errorf("machine ID cannot be empty")
	}

	// Load or generate salt
	salt, err := loadOrGenerateSalt(secretsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load or generate salt: %w", err)
	}

	// Derive 32-byte key using HKDF-SHA256
	hkdfReader := hkdf.New(sha256.New, machineID, salt, []byte(hkdfInfo))
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &aesGcmEncryptor{gcm: gcm}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a random 12-byte nonce.
// The nonce is prepended to the ciphertext.
func (e *aesGcmEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal appends the ciphertext to nonce, so the result is: nonce || ciphertext || tag
	ciphertext := e.gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts AES-256-GCM ciphertext. Expects nonce prepended to ciphertext.
func (e *aesGcmEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes, got %d", nonceSize, len(ciphertext))
	}

	nonce := ciphertext[:nonceSize]
	encryptedData := ciphertext[nonceSize:]

	plaintext, err := e.gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Algorithm returns the encryption algorithm name.
func (e *aesGcmEncryptor) Algorithm() string {
	return "AES-256-GCM"
}

// loadOrGenerateSalt loads an existing salt file or generates a new one.
// The salt file is stored at {secretsDir}/salt with 0600 permissions.
func loadOrGenerateSalt(secretsDir string) ([]byte, error) {
	saltPath := filepath.Join(secretsDir, saltFileName)

	// Try to read existing salt
	salt, err := os.ReadFile(saltPath) //#nosec G304 -- path is constructed from configured secrets directory
	if err == nil {
		if len(salt) != saltSize {
			// Replacing the salt would make every stored secret unreadable and
			// let a writer of this file choose the key input.
			return nil, fmt.Errorf("salt file %s has invalid length %d (want %d); refusing to replace it", saltPath, len(salt), saltSize)
		}
		return salt, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to read salt file: %w", err)
	}

	// Generate new salt
	salt = make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create secrets directory: %w", err)
	}

	// Write salt file with restrictive permissions
	if err := os.WriteFile(saltPath, salt, 0600); err != nil {
		return nil, fmt.Errorf("failed to write salt file: %w", err)
	}

	return salt, nil
}
