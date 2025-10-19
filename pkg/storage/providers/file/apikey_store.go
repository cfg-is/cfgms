// Package file - File-based API key storage with encryption
package file

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// APIKeyStore implements file-based encrypted API key storage
// M-AUTH-1: Persistent storage with encryption at rest
type APIKeyStore struct {
	mu           sync.RWMutex
	storePath    string
	encryptionKey []byte
	keys         map[string]*interfaces.StoredAPIKey // keyHash -> key
	keysById     map[string]*interfaces.StoredAPIKey // id -> key
}

// NewAPIKeyStore creates a new file-based API key store
// M-AUTH-1: Initialize with encryption key
func NewAPIKeyStore(storePath string, encryptionKey []byte) *APIKeyStore {
	return &APIKeyStore{
		storePath:     storePath,
		encryptionKey: encryptionKey,
		keys:          make(map[string]*interfaces.StoredAPIKey),
		keysById:      make(map[string]*interfaces.StoredAPIKey),
	}
}

// Initialize sets up the API key store
func (s *APIKeyStore) Initialize(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure storage directory exists
	dir := filepath.Dir(s.storePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Load existing keys if file exists
	if _, err := os.Stat(s.storePath); err == nil {
		if err := s.loadKeysFromDisk(); err != nil {
			return fmt.Errorf("failed to load existing keys: %w", err)
		}
	}

	return nil
}

// StoreKey persists an API key
// M-AUTH-1: Store with encryption
func (s *APIKeyStore) StoreKey(ctx context.Context, key *interfaces.StoredAPIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store in memory
	s.keys[key.KeyHash] = key
	s.keysById[key.ID] = key

	// Persist to disk
	return s.saveKeysToDisk()
}

// GetKeyByHash retrieves an API key by its hash
func (s *APIKeyStore) GetKeyByHash(ctx context.Context, keyHash string) (*interfaces.StoredAPIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.keys[keyHash]
	if !exists {
		return nil, fmt.Errorf("API key not found")
	}

	return key, nil
}

// GetKeyByID retrieves an API key by ID
func (s *APIKeyStore) GetKeyByID(ctx context.Context, id string) (*interfaces.StoredAPIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.keysById[id]
	if !exists {
		return nil, fmt.Errorf("API key not found")
	}

	return key, nil
}

// ListKeys returns all API keys for a tenant
func (s *APIKeyStore) ListKeys(ctx context.Context, tenantID string) ([]*interfaces.StoredAPIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*interfaces.StoredAPIKey
	for _, key := range s.keys {
		if key.TenantID == tenantID {
			result = append(result, key)
		}
	}

	return result, nil
}

// DeleteKey removes an API key
func (s *APIKeyStore) DeleteKey(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find key by ID
	key, exists := s.keysById[id]
	if !exists {
		return fmt.Errorf("API key not found")
	}

	// Delete from both maps
	delete(s.keys, key.KeyHash)
	delete(s.keysById, id)

	// Persist to disk
	return s.saveKeysToDisk()
}

// UpdateLastUsed updates the last used timestamp
func (s *APIKeyStore) UpdateLastUsed(ctx context.Context, id string, lastUsed time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, exists := s.keysById[id]
	if !exists {
		return fmt.Errorf("API key not found")
	}

	key.LastUsedAt = &lastUsed

	// Persist to disk
	return s.saveKeysToDisk()
}

// Close shuts down the store
func (s *APIKeyStore) Close() error {
	// Final save to disk
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveKeysToDisk()
}

// saveKeysToDisk persists keys to disk with encryption
// M-AUTH-1: Encrypt all keys at rest using AES-256-GCM
func (s *APIKeyStore) saveKeysToDisk() error {
	// Collect all keys
	var allKeys []*interfaces.StoredAPIKey
	for _, key := range s.keys {
		allKeys = append(allKeys, key)
	}

	// Marshal to JSON
	plaintext, err := json.Marshal(allKeys)
	if err != nil {
		return fmt.Errorf("failed to marshal keys: %w", err)
	}

	// Encrypt using AES-256-GCM
	ciphertext, err := s.encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt keys: %w", err)
	}

	// Write to temporary file first
	tmpPath := s.storePath + ".tmp"
	if err := os.WriteFile(tmpPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted keys: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, s.storePath); err != nil {
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return nil
}

// loadKeysFromDisk loads keys from disk and decrypts them
// M-AUTH-1: Decrypt keys from persistent storage
func (s *APIKeyStore) loadKeysFromDisk() error {
	// Read encrypted file
	ciphertext, err := os.ReadFile(s.storePath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted keys: %w", err)
	}

	// Decrypt
	plaintext, err := s.decrypt(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decrypt keys: %w", err)
	}

	// Unmarshal JSON
	var allKeys []*interfaces.StoredAPIKey
	if err := json.Unmarshal(plaintext, &allKeys); err != nil {
		return fmt.Errorf("failed to unmarshal keys: %w", err)
	}

	// Populate maps
	s.keys = make(map[string]*interfaces.StoredAPIKey)
	s.keysById = make(map[string]*interfaces.StoredAPIKey)
	for _, key := range allKeys {
		s.keys[key.KeyHash] = key
		s.keysById[key.ID] = key
	}

	return nil
}

// encrypt encrypts plaintext using AES-256-GCM
// M-AUTH-1: Industry-standard authenticated encryption
func (s *APIKeyStore) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and append nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts ciphertext using AES-256-GCM
func (s *APIKeyStore) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// HashAPIKey creates a SHA-256 hash of an API key
// M-AUTH-1: Hash keys for constant-time lookup without storing plaintext
func HashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", hash)
}
