// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package steward

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// StewardSecretStore implements interfaces.SecretStore using OS-native encryption.
// Secrets are stored as individually encrypted blob files with an encrypted JSON index.
type StewardSecretStore struct {
	secretsDir string
	encryptor  platformEncryptor
	mu         sync.RWMutex
	index      *secretIndex
}

// secretIndex maintains metadata about all stored secrets.
type secretIndex struct {
	Entries map[string]*secretIndexEntry `json:"entries"`
}

// secretIndexEntry holds metadata for a single secret.
type secretIndexEntry struct {
	Key         string            `json:"key"`
	BlobFile    string            `json:"blob_file"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Version     int               `json:"version"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	CreatedBy   string            `json:"created_by"`
	UpdatedBy   string            `json:"updated_by"`
	TenantID    string            `json:"tenant_id"`
	Description string            `json:"description,omitempty"`
}

// indexFileName is the name of the encrypted index file.
const indexFileName = "index.json.enc"

// StoreSecret stores a secret with OS-native encryption.
func (s *StewardSecretStore) StoreSecret(_ context.Context, req *interfaces.SecretRequest) error {
	if req.Key == "" {
		return fmt.Errorf("secret key cannot be empty")
	}
	if len(req.Key) > 256 {
		return fmt.Errorf("secret key exceeds maximum length of 256 characters")
	}
	if len(req.Value) > 1*1024*1024 {
		return fmt.Errorf("secret value exceeds maximum size of 1MB")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Encrypt the secret value
	encrypted, err := s.encryptor.Encrypt([]byte(req.Value))
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Write encrypted blob to file
	blobFile := keyToBlobFile(req.Key)
	blobPath := filepath.Join(s.secretsDir, "blobs", blobFile)
	if err := os.WriteFile(blobPath, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted blob: %w", err)
	}

	// Update or create index entry
	now := time.Now()
	entry, exists := s.index.Entries[req.Key]
	if exists {
		entry.Version++
		entry.UpdatedAt = now
		entry.UpdatedBy = req.CreatedBy
		entry.Metadata = req.Metadata
		entry.Tags = req.Tags
		entry.Description = req.Description
	} else {
		entry = &secretIndexEntry{
			Key:         req.Key,
			BlobFile:    blobFile,
			Metadata:    req.Metadata,
			Tags:        req.Tags,
			Version:     1,
			CreatedAt:   now,
			UpdatedAt:   now,
			CreatedBy:   req.CreatedBy,
			UpdatedBy:   req.CreatedBy,
			TenantID:    req.TenantID,
			Description: req.Description,
		}
	}

	// Set expiration if TTL is specified
	if req.TTL > 0 {
		expiresAt := now.Add(req.TTL)
		entry.ExpiresAt = &expiresAt
	}

	s.index.Entries[req.Key] = entry

	// Persist encrypted index
	if err := s.saveIndex(); err != nil {
		return fmt.Errorf("failed to save index: %w", err)
	}

	return nil
}

// GetSecret retrieves and decrypts a secret.
func (s *StewardSecretStore) GetSecret(_ context.Context, key string) (*interfaces.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.index.Entries[key]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	// Check expiration
	if entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
		return nil, fmt.Errorf("secret expired: %s", key)
	}

	// Read encrypted blob
	blobPath := filepath.Join(s.secretsDir, "blobs", entry.BlobFile)
	encrypted, err := os.ReadFile(blobPath) //#nosec G304 -- path constructed from configured secrets directory
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted blob: %w", err)
	}

	// Decrypt
	plaintext, err := s.encryptor.Decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	return &interfaces.Secret{
		Key:         entry.Key,
		Value:       string(plaintext),
		Metadata:    copyMetadata(entry.Metadata),
		Tags:        copyTags(entry.Tags),
		Version:     entry.Version,
		CreatedAt:   entry.CreatedAt,
		UpdatedAt:   entry.UpdatedAt,
		ExpiresAt:   entry.ExpiresAt,
		CreatedBy:   entry.CreatedBy,
		UpdatedBy:   entry.UpdatedBy,
		TenantID:    entry.TenantID,
		Description: entry.Description,
	}, nil
}

// DeleteSecret removes a secret and its encrypted blob.
func (s *StewardSecretStore) DeleteSecret(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.index.Entries[key]
	if !exists {
		return fmt.Errorf("secret not found: %s", key)
	}

	// Remove blob file
	blobPath := filepath.Join(s.secretsDir, "blobs", entry.BlobFile)
	if err := os.Remove(blobPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete encrypted blob: %w", err)
	}

	// Remove from index
	delete(s.index.Entries, key)

	// Persist index
	if err := s.saveIndex(); err != nil {
		return fmt.Errorf("failed to save index: %w", err)
	}

	return nil
}

// ListSecrets lists secrets matching the filter criteria.
func (s *StewardSecretStore) ListSecrets(_ context.Context, filter *interfaces.SecretFilter) ([]*interfaces.SecretMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*interfaces.SecretMetadata

	for _, entry := range s.index.Entries {
		// Apply filters
		if filter != nil {
			if filter.TenantID != "" && entry.TenantID != filter.TenantID {
				continue
			}
			if filter.KeyPrefix != "" && !strings.HasPrefix(entry.Key, filter.KeyPrefix) {
				continue
			}
			if filter.CreatedBy != "" && entry.CreatedBy != filter.CreatedBy {
				continue
			}
			if !filter.IncludeExpired && entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
				continue
			}
			if !matchTags(entry.Tags, filter.Tags) {
				continue
			}
			if !matchMetadata(entry.Metadata, filter.Metadata) {
				continue
			}
		}

		results = append(results, &interfaces.SecretMetadata{
			Key:         entry.Key,
			Metadata:    copyMetadata(entry.Metadata),
			Tags:        copyTags(entry.Tags),
			Version:     entry.Version,
			CreatedAt:   entry.CreatedAt,
			UpdatedAt:   entry.UpdatedAt,
			ExpiresAt:   entry.ExpiresAt,
			CreatedBy:   entry.CreatedBy,
			UpdatedBy:   entry.UpdatedBy,
			TenantID:    entry.TenantID,
			Description: entry.Description,
		})

		// Apply limit
		if filter != nil && filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}

	return results, nil
}

// GetSecrets retrieves multiple secrets by key.
func (s *StewardSecretStore) GetSecrets(ctx context.Context, keys []string) (map[string]*interfaces.Secret, error) {
	results := make(map[string]*interfaces.Secret)
	for _, key := range keys {
		secret, err := s.GetSecret(ctx, key)
		if err != nil {
			continue // Skip missing/expired secrets
		}
		results[key] = secret
	}
	return results, nil
}

// StoreSecrets stores multiple secrets.
func (s *StewardSecretStore) StoreSecrets(ctx context.Context, secrets map[string]*interfaces.SecretRequest) error {
	for _, req := range secrets {
		if err := s.StoreSecret(ctx, req); err != nil {
			return fmt.Errorf("failed to store secret %s: %w", req.Key, err)
		}
	}
	return nil
}

// GetSecretVersion returns ErrVersioningNotSupported as steward provider does not support versioning.
func (s *StewardSecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*interfaces.Secret, error) {
	return nil, fmt.Errorf("versioning not supported by steward secret provider")
}

// ListSecretVersions returns an empty slice as versioning is not supported.
func (s *StewardSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*interfaces.SecretVersion, error) {
	return []*interfaces.SecretVersion{}, nil
}

// GetSecretMetadata retrieves metadata about a secret without the value.
func (s *StewardSecretStore) GetSecretMetadata(_ context.Context, key string) (*interfaces.SecretMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.index.Entries[key]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	return &interfaces.SecretMetadata{
		Key:         entry.Key,
		Metadata:    copyMetadata(entry.Metadata),
		Tags:        copyTags(entry.Tags),
		Version:     entry.Version,
		CreatedAt:   entry.CreatedAt,
		UpdatedAt:   entry.UpdatedAt,
		ExpiresAt:   entry.ExpiresAt,
		CreatedBy:   entry.CreatedBy,
		UpdatedBy:   entry.UpdatedBy,
		TenantID:    entry.TenantID,
		Description: entry.Description,
	}, nil
}

// UpdateSecretMetadata updates metadata without changing the secret value.
func (s *StewardSecretStore) UpdateSecretMetadata(_ context.Context, key string, metadata map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.index.Entries[key]
	if !exists {
		return fmt.Errorf("secret not found: %s", key)
	}

	if entry.Metadata == nil {
		entry.Metadata = make(map[string]string)
	}
	for k, v := range metadata {
		entry.Metadata[k] = v
	}
	entry.UpdatedAt = time.Now()

	if err := s.saveIndex(); err != nil {
		return fmt.Errorf("failed to save index: %w", err)
	}

	return nil
}

// RotateSecret replaces a secret's value while preserving metadata.
func (s *StewardSecretStore) RotateSecret(ctx context.Context, key string, newValue string) error {
	s.mu.RLock()
	entry, exists := s.index.Entries[key]
	if !exists {
		s.mu.RUnlock()
		return fmt.Errorf("secret not found: %s", key)
	}
	// Copy metadata for the store request
	meta := copyMetadata(entry.Metadata)
	if meta == nil {
		meta = make(map[string]string)
	}
	meta[interfaces.MetadataKeyLastRotated] = time.Now().Format(time.RFC3339)
	tags := copyTags(entry.Tags)
	createdBy := entry.UpdatedBy
	tenantID := entry.TenantID
	description := entry.Description
	s.mu.RUnlock()

	return s.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:         key,
		Value:       newValue,
		Metadata:    meta,
		Tags:        tags,
		CreatedBy:   createdBy,
		TenantID:    tenantID,
		Description: description,
	})
}

// ExpireSecret marks a secret as expired by setting its expiration to now.
func (s *StewardSecretStore) ExpireSecret(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.index.Entries[key]
	if !exists {
		return fmt.Errorf("secret not found: %s", key)
	}

	now := time.Now()
	entry.ExpiresAt = &now
	entry.UpdatedAt = now

	if err := s.saveIndex(); err != nil {
		return fmt.Errorf("failed to save index: %w", err)
	}

	return nil
}

// HealthCheck verifies the store is operational by performing an encrypt/decrypt round trip.
func (s *StewardSecretStore) HealthCheck(_ context.Context) error {
	// Verify encryption round-trip
	testData := []byte("cfgms-health-check")
	encrypted, err := s.encryptor.Encrypt(testData)
	if err != nil {
		return fmt.Errorf("health check encryption failed: %w", err)
	}

	decrypted, err := s.encryptor.Decrypt(encrypted)
	if err != nil {
		return fmt.Errorf("health check decryption failed: %w", err)
	}

	if string(decrypted) != string(testData) {
		return fmt.Errorf("health check round-trip mismatch")
	}

	// Verify directory is accessible
	if _, err := os.Stat(s.secretsDir); err != nil {
		return fmt.Errorf("secrets directory not accessible: %w", err)
	}

	return nil
}

// Close persists the index to disk.
func (s *StewardSecretStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveIndex()
}

// loadIndex loads and decrypts the secret index from disk.
// If no index file exists, creates a new empty index.
func (s *StewardSecretStore) loadIndex() error {
	indexPath := filepath.Join(s.secretsDir, indexFileName)

	data, err := os.ReadFile(indexPath) //#nosec G304 -- path constructed from configured secrets directory
	if err != nil {
		if os.IsNotExist(err) {
			// New store, create empty index
			s.index = &secretIndex{
				Entries: make(map[string]*secretIndexEntry),
			}
			return nil
		}
		return fmt.Errorf("failed to read index file: %w", err)
	}

	// Decrypt index
	plaintext, err := s.encryptor.Decrypt(data)
	if err != nil {
		return fmt.Errorf("failed to decrypt index: %w", err)
	}

	var idx secretIndex
	if err := json.Unmarshal(plaintext, &idx); err != nil {
		return fmt.Errorf("failed to parse index: %w", err)
	}

	if idx.Entries == nil {
		idx.Entries = make(map[string]*secretIndexEntry)
	}

	s.index = &idx
	return nil
}

// saveIndex encrypts and persists the secret index to disk.
func (s *StewardSecretStore) saveIndex() error {
	data, err := json.Marshal(s.index)
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	encrypted, err := s.encryptor.Encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt index: %w", err)
	}

	indexPath := filepath.Join(s.secretsDir, indexFileName)
	if err := os.WriteFile(indexPath, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write index file: %w", err)
	}

	return nil
}

// keyToBlobFile converts a secret key to a blob filename using SHA-256 hash.
func keyToBlobFile(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:]) + ".enc"
}

// copyMetadata creates a defensive copy of a metadata map.
func copyMetadata(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// copyTags creates a defensive copy of a tags slice.
func copyTags(src []string) []string {
	if src == nil {
		return nil
	}
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}

// matchTags checks if entry tags contain all filter tags (AND logic).
func matchTags(entryTags, filterTags []string) bool {
	if len(filterTags) == 0 {
		return true
	}
	tagSet := make(map[string]bool, len(entryTags))
	for _, t := range entryTags {
		tagSet[t] = true
	}
	for _, t := range filterTags {
		if !tagSet[t] {
			return false
		}
	}
	return true
}

// matchMetadata checks if entry metadata contains all filter metadata (AND logic).
func matchMetadata(entryMeta, filterMeta map[string]string) bool {
	if len(filterMeta) == 0 {
		return true
	}
	for k, v := range filterMeta {
		if entryMeta[k] != v {
			return false
		}
	}
	return true
}
