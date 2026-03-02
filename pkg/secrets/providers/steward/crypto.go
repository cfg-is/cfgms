// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package steward implements OS-native encrypted secret storage for steward endpoints.
//
// This package provides a SecretProvider that uses platform-specific encryption:
//   - Windows: DPAPI (CryptProtectData/CryptUnprotectData)
//   - Linux: AES-256-GCM with HKDF key derived from /etc/machine-id
//   - macOS: AES-256-GCM with HKDF key derived from IOPlatformUUID
package steward

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
)

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
	if err == nil && len(salt) == saltSize {
		return salt, nil
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
