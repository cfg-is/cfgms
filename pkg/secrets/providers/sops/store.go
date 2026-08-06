// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sops implements authenticated envelope-encrypted secret storage.
package sops

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/cache"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	storageif "github.com/cfgis/cfgms/pkg/storage/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// SOPSSecretStoreConfig provides configuration for SOPS secret store
type SOPSSecretStoreConfig struct {
	StorageProvider string                 // Storage provider name (default: "flatfile")
	StorageConfig   map[string]interface{} // Storage provider configuration
	CacheEnabled    bool                   // Enable secret caching
	CacheTTL        int                    // Cache TTL in seconds
	CacheMaxSize    int                    // Maximum cache size
	KeyFile         string                 // External 32-byte or base64-encoded AES key file
}

// SOPSSecretStore stores encrypted ConfigEntry objects in a configured
// ConfigStore. The historical provider name is retained for compatibility.
type SOPSSecretStore struct {
	configStore  cfgconfig.ConfigStore // Underlying config store (backend-agnostic, SOPS-encrypted)
	cache        *cache.Cache          // Secret cache
	config       *SOPSSecretStoreConfig
	providerName string
	aead         cipher.AEAD
}

type encryptedEnvelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// NewSOPSSecretStore creates a new SOPS-based secret store
// M-AUTH-1: Create an envelope-encrypted store backed by the configured
// ConfigStore. The encryption key must be provisioned separately from data.
func NewSOPSSecretStore(config *SOPSSecretStoreConfig) (*SOPSSecretStore, error) {
	if config == nil {
		return nil, fmt.Errorf("secret store config is required")
	}
	key, err := loadExternalKey(config)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize AES-GCM: %w", err)
	}

	// Create ConfigStore using storage provider
	configStore, err := storageif.CreateConfigStoreFromConfig(config.StorageProvider, config.StorageConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create config store: %w", err)
	}

	store := &SOPSSecretStore{
		configStore:  configStore,
		config:       config,
		providerName: config.StorageProvider,
		aead:         aead,
	}

	// Initialize cache if enabled
	if config.CacheEnabled {
		cacheConfig := cache.CacheConfig{
			Name:            "sops-secrets",
			DefaultTTL:      time.Duration(config.CacheTTL) * time.Second,
			MaxRuntimeItems: config.CacheMaxSize,
			CleanupInterval: 5 * time.Minute,
		}
		store.cache = cache.NewCache(cacheConfig)
	}

	return store, nil
}

func loadExternalKey(config *SOPSSecretStoreConfig) ([]byte, error) {
	if strings.TrimSpace(config.KeyFile) == "" {
		return nil, fmt.Errorf("external encryption key file is required")
	}

	keyPath, err := filepath.Abs(config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("resolve encryption key file: %w", err)
	}
	if root, ok := config.StorageConfig["root"].(string); ok && strings.TrimSpace(root) != "" {
		rootPath, rootErr := filepath.Abs(root)
		if rootErr != nil {
			return nil, fmt.Errorf("resolve secret storage root: %w", rootErr)
		}
		rel, relErr := filepath.Rel(rootPath, keyPath)
		if relErr != nil {
			return nil, fmt.Errorf("compare key and storage paths: %w", relErr)
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return nil, fmt.Errorf("encryption key file must be stored separately from secret data")
		}
	}

	info, err := os.Lstat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("stat encryption key file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("encryption key file must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("encryption key file must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("encryption key file permissions must not grant group or other access")
	}

	// #nosec G304 -- keyPath is explicit administrator configuration and has
	// just been lstat-validated as a private regular, non-symlink file.
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read encryption key file: %w", err)
	}
	if len(keyData) != 32 {
		encoded := bytes.TrimSpace(keyData)
		decoded, decodeErr := base64.StdEncoding.DecodeString(string(encoded))
		if decodeErr != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("encryption key file must contain exactly 32 raw bytes or a base64-encoded 32-byte key")
		}
		keyData = decoded
	}
	return keyData, nil
}

func (s *SOPSSecretStore) encrypt(plaintext []byte, tenantID, key string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	aad := []byte(tenantID + "\x00" + key)
	ciphertext := s.aead.Seal(nil, nonce, plaintext, aad)
	return json.Marshal(&encryptedEnvelope{
		Version:    1,
		Algorithm:  "AES-256-GCM",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
}

func (s *SOPSSecretStore) decrypt(encrypted []byte, tenantID, key string) ([]byte, error) {
	var envelope encryptedEnvelope
	if err := json.Unmarshal(encrypted, &envelope); err != nil {
		return nil, fmt.Errorf("secret ciphertext is not a valid encrypted envelope")
	}
	if envelope.Version != 1 || envelope.Algorithm != "AES-256-GCM" {
		return nil, fmt.Errorf("unsupported secret encryption envelope")
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != s.aead.NonceSize() {
		return nil, fmt.Errorf("invalid secret encryption nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid secret ciphertext encoding")
	}
	aad := []byte(tenantID + "\x00" + key)
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("secret ciphertext authentication failed")
	}
	return plaintext, nil
}

// StoreSecret stores a secret
// M-AUTH-1: Stores an authenticated encrypted envelope as ConfigEntry data.
func (s *SOPSSecretStore) StoreSecret(ctx context.Context, req *secretsif.SecretRequest) error {
	// Validate request
	if req == nil {
		return fmt.Errorf("secret request cannot be nil")
	}
	if req.Key == "" {
		return fmt.Errorf("secret key cannot be empty")
	}
	if len(req.Key) > 256 {
		return fmt.Errorf("secret key exceeds 256 character limit")
	}
	if req.TenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}
	if len(req.Value) > 1<<20 {
		return fmt.Errorf("secret value exceeds 1048576 byte limit")
	}

	// Create secret metadata
	secret := &secretsif.Secret{
		Key:         req.Key,
		Value:       req.Value,
		Metadata:    req.Metadata,
		Tags:        req.Tags,
		Version:     1, // Version will be set by ConfigStore
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   req.CreatedBy,
		UpdatedBy:   req.CreatedBy,
		TenantID:    req.TenantID,
		Description: req.Description,
	}

	// Set expiration if TTL is specified
	if req.TTL > 0 {
		expiresAt := time.Now().Add(req.TTL)
		secret.ExpiresAt = &expiresAt
	}

	// Convert secret to JSON for storage
	secretData, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("failed to marshal secret: %w", err)
	}
	encryptedData, err := s.encrypt(secretData, req.TenantID, req.Key)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Store the encrypted envelope as a ConfigEntry.
	configKey := &cfgconfig.ConfigKey{
		TenantID:  req.TenantID,
		Namespace: "secrets", // Use "secrets" namespace for all secrets
		Name:      req.Key,   // Secret key is the config name
		Scope:     "",        // No scope needed for secrets
	}

	configEntry := &cfgconfig.ConfigEntry{
		Key:       configKey,
		Data:      encryptedData,
		Format:    cfgconfig.ConfigFormatJSON, // Secrets are stored as JSON
		CreatedBy: req.CreatedBy,
		UpdatedBy: req.CreatedBy,
		Tags:      append(req.Tags, "secret"), // Add "secret" tag
	}

	// Add secret type metadata if provided
	if secretType, ok := req.Metadata[secretsif.MetadataKeySecretType]; ok {
		configEntry.Tags = append(configEntry.Tags, fmt.Sprintf("type:%s", secretType))
	}

	// Store only the authenticated encrypted envelope in the ConfigStore.
	if err := s.configStore.StoreConfig(ctx, configEntry); err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	// Update cache if enabled
	if s.cache != nil {
		cacheKey := s.getCacheKey(req.TenantID, req.Key)
		cacheTTL := time.Duration(s.config.CacheTTL) * time.Second
		if req.TTL > 0 && req.TTL < cacheTTL {
			cacheTTL = req.TTL // Use shorter TTL if secret expires sooner
		}
		_ = s.cache.Set(cacheKey, secret, cacheTTL)
	}

	return nil
}

// GetSecret retrieves a secret
// M-AUTH-1: Retrieves secret from ConfigStore, automatically decrypted by SOPS
func (s *SOPSSecretStore) GetSecret(ctx context.Context, key string) (*secretsif.Secret, error) {
	return s.getSecretWithTenant(ctx, "", key)
}

// getSecretWithTenant retrieves a secret with explicit tenant ID
func (s *SOPSSecretStore) getSecretWithTenant(ctx context.Context, tenantID, key string) (*secretsif.Secret, error) {
	// Try cache first if enabled
	if s.cache != nil {
		cacheKey := s.getCacheKey(tenantID, key)
		if cached, found := s.cache.Get(cacheKey); found {
			if secret, ok := cached.(*secretsif.Secret); ok {
				// Check expiration
				if !s.isExpired(secret) {
					return secret, nil
				}
				// Secret expired, remove from cache
				s.cache.Delete(cacheKey)
			}
		}
	}

	// Extract tenant ID from key if not provided (format: tenant_id/secret_key)
	if tenantID == "" {
		parts := strings.SplitN(key, "/", 2)
		if len(parts) == 2 {
			tenantID = parts[0]
			key = parts[1]
		} else {
			return nil, fmt.Errorf("secret key must be in format 'tenant_id/key' or tenant ID must be provided")
		}
	}

	// Retrieve from ConfigStore
	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "secrets",
		Name:      key,
	}

	configEntry, err := s.configStore.GetConfig(ctx, configKey)
	if err != nil {
		if err == cfgconfig.ErrConfigNotFound {
			return nil, fmt.Errorf("secret not found: %s: %w", key, secretsif.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("failed to retrieve secret: %w", err)
	}

	plaintext, err := s.decrypt(configEntry.Data, tenantID, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	// Parse the authenticated plaintext only after decryption succeeds.
	var secret secretsif.Secret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret: %w", err)
	}

	// Check expiration
	if s.isExpired(&secret) {
		return nil, fmt.Errorf("secret expired: %s", key)
	}

	// Update cache if enabled
	if s.cache != nil {
		cacheKey := s.getCacheKey(tenantID, key)
		cacheTTL := time.Duration(s.config.CacheTTL) * time.Second
		if secret.ExpiresAt != nil {
			remainingTTL := time.Until(*secret.ExpiresAt)
			if remainingTTL < cacheTTL {
				cacheTTL = remainingTTL
			}
		}
		_ = s.cache.Set(cacheKey, &secret, cacheTTL)
	}

	return &secret, nil
}

// DeleteSecret deletes a secret
// M-AUTH-1: Deletes secret from ConfigStore
func (s *SOPSSecretStore) DeleteSecret(ctx context.Context, key string) error {
	// Extract tenant ID from key (format: tenant_id/secret_key)
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("secret key must be in format 'tenant_id/key'")
	}
	tenantID := parts[0]
	secretKey := parts[1]

	// Delete from ConfigStore
	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "secrets",
		Name:      secretKey,
	}

	if err := s.configStore.DeleteConfig(ctx, configKey); err != nil {
		if err == cfgconfig.ErrConfigNotFound {
			return fmt.Errorf("secret not found: %s", key)
		}
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	// Remove from cache if enabled
	if s.cache != nil {
		cacheKey := s.getCacheKey(tenantID, secretKey)
		s.cache.Delete(cacheKey)
	}

	return nil
}

// ListSecrets lists secrets matching the filter
// M-AUTH-1: Lists secrets from ConfigStore
func (s *SOPSSecretStore) ListSecrets(ctx context.Context, filter *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	// Convert secret filter to config filter
	configFilter := &cfgconfig.ConfigFilter{
		TenantID:  filter.TenantID,
		Namespace: "secrets",
		Tags:      append(filter.Tags, "secret"), // Must have "secret" tag
		Limit:     filter.Limit,
		Offset:    filter.Offset,
	}

	// Note: ConfigStore doesn't have prefix filtering, so we filter after retrieval (see loop below)
	// This is inefficient but works for MVP

	// List configs from ConfigStore
	configs, err := s.configStore.ListConfigs(ctx, configFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Convert to secret metadata
	var metadata []*secretsif.SecretMetadata
	for _, config := range configs {
		if config.Key == nil {
			continue
		}
		plaintext, decryptErr := s.decrypt(config.Data, config.Key.TenantID, config.Key.Name)
		if decryptErr != nil {
			return nil, fmt.Errorf("failed to decrypt secret metadata: %w", decryptErr)
		}
		// Parse secret to get metadata
		var secret secretsif.Secret
		if err := json.Unmarshal(plaintext, &secret); err != nil {
			return nil, fmt.Errorf("failed to unmarshal secret metadata: %w", err)
		}

		// Apply additional filters
		if filter.KeyPrefix != "" && !strings.HasPrefix(secret.Key, filter.KeyPrefix) {
			continue
		}

		if filter.CreatedBy != "" && secret.CreatedBy != filter.CreatedBy {
			continue
		}

		// Skip expired secrets unless IncludeExpired is true
		if !filter.IncludeExpired && s.isExpired(&secret) {
			continue
		}

		// Check metadata filters
		if len(filter.Metadata) > 0 {
			match := true
			for k, v := range filter.Metadata {
				if secret.Metadata[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		metadata = append(metadata, &secretsif.SecretMetadata{
			Key:         secret.Key,
			Metadata:    secret.Metadata,
			Tags:        secret.Tags,
			Version:     secret.Version,
			CreatedAt:   secret.CreatedAt,
			UpdatedAt:   secret.UpdatedAt,
			ExpiresAt:   secret.ExpiresAt,
			CreatedBy:   secret.CreatedBy,
			UpdatedBy:   secret.UpdatedBy,
			TenantID:    secret.TenantID,
			Description: secret.Description,
		})
	}

	return metadata, nil
}

// GetSecrets retrieves multiple secrets
// M-AUTH-1: Bulk secret retrieval
func (s *SOPSSecretStore) GetSecrets(ctx context.Context, keys []string) (map[string]*secretsif.Secret, error) {
	result := make(map[string]*secretsif.Secret)

	for _, key := range keys {
		secret, err := s.GetSecret(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve secret %s: %w", key, err)
		}
		result[key] = secret
	}

	return result, nil
}

// StoreSecrets stores multiple secrets
// M-AUTH-1: Bulk secret storage
func (s *SOPSSecretStore) StoreSecrets(ctx context.Context, secrets map[string]*secretsif.SecretRequest) error {
	for _, req := range secrets {
		if err := s.StoreSecret(ctx, req); err != nil {
			return fmt.Errorf("failed to store secret %s: %w", req.Key, err)
		}
	}
	return nil
}

// GetSecretVersion retrieves a specific version of a secret
// M-AUTH-1: Version retrieval using git history
func (s *SOPSSecretStore) GetSecretVersion(ctx context.Context, key string, version int) (*secretsif.Secret, error) {
	// Extract tenant ID from key
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("secret key must be in format 'tenant_id/key'")
	}
	tenantID := parts[0]
	secretKey := parts[1]

	// Get version from ConfigStore
	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "secrets",
		Name:      secretKey,
	}

	configEntry, err := s.configStore.GetConfigVersion(ctx, configKey, int64(version))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secret version: %w", err)
	}

	plaintext, err := s.decrypt(configEntry.Data, tenantID, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
	}

	// Parse secret from JSON
	var secret secretsif.Secret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret: %w", err)
	}

	return &secret, nil
}

// ListSecretVersions lists all versions of a secret
// M-AUTH-1: Version history using git log
func (s *SOPSSecretStore) ListSecretVersions(ctx context.Context, key string) ([]*secretsif.SecretVersion, error) {
	// Extract tenant ID from key
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("secret key must be in format 'tenant_id/key'")
	}
	tenantID := parts[0]
	secretKey := parts[1]

	// Get version history from ConfigStore
	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "secrets",
		Name:      secretKey,
	}

	history, err := s.configStore.GetConfigHistory(ctx, configKey, 100) // Get last 100 versions
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve version history: %w", err)
	}

	// Convert to secret versions
	var versions []*secretsif.SecretVersion
	for _, config := range history {
		plaintext, decryptErr := s.decrypt(config.Data, tenantID, secretKey)
		if decryptErr != nil {
			return nil, fmt.Errorf("failed to decrypt secret version history: %w", decryptErr)
		}
		// Parse secret to get created info
		var secret secretsif.Secret
		if err := json.Unmarshal(plaintext, &secret); err != nil {
			return nil, fmt.Errorf("failed to unmarshal secret version history: %w", err)
		}

		versions = append(versions, &secretsif.SecretVersion{
			Version:   int(config.Version),
			CreatedAt: config.CreatedAt,
			CreatedBy: config.CreatedBy,
		})
	}

	return versions, nil
}

// GetSecretMetadata retrieves metadata about a secret without the value
// M-AUTH-1: Metadata-only retrieval for listing
func (s *SOPSSecretStore) GetSecretMetadata(ctx context.Context, key string) (*secretsif.SecretMetadata, error) {
	secret, err := s.GetSecret(ctx, key)
	if err != nil {
		return nil, err
	}

	return &secretsif.SecretMetadata{
		Key:         secret.Key,
		Metadata:    secret.Metadata,
		Tags:        secret.Tags,
		Version:     secret.Version,
		CreatedAt:   secret.CreatedAt,
		UpdatedAt:   secret.UpdatedAt,
		ExpiresAt:   secret.ExpiresAt,
		CreatedBy:   secret.CreatedBy,
		UpdatedBy:   secret.UpdatedBy,
		TenantID:    secret.TenantID,
		Description: secret.Description,
	}, nil
}

// UpdateSecretMetadata updates secret metadata without changing the value
// M-AUTH-1: Metadata-only updates
func (s *SOPSSecretStore) UpdateSecretMetadata(ctx context.Context, key string, metadata map[string]string) error {
	// Get current secret
	secret, err := s.GetSecret(ctx, key)
	if err != nil {
		return err
	}

	// Update metadata
	if secret.Metadata == nil {
		secret.Metadata = make(map[string]string)
	}
	for k, v := range metadata {
		secret.Metadata[k] = v
	}
	secret.UpdatedAt = time.Now()

	// Store updated secret
	req := &secretsif.SecretRequest{
		Key:         secret.Key,
		Value:       secret.Value,
		Metadata:    secret.Metadata,
		Tags:        secret.Tags,
		CreatedBy:   secret.UpdatedBy,
		TenantID:    secret.TenantID,
		Description: secret.Description,
	}

	return s.StoreSecret(ctx, req)
}

// RotateSecret rotates a secret with a new value
// M-AUTH-1: Secret rotation with version tracking
func (s *SOPSSecretStore) RotateSecret(ctx context.Context, key string, newValue string) error {
	// Get current secret to preserve metadata
	secret, err := s.GetSecret(ctx, key)
	if err != nil {
		return err
	}

	// Update rotation metadata
	if secret.Metadata == nil {
		secret.Metadata = make(map[string]string)
	}
	secret.Metadata[secretsif.MetadataKeyLastRotated] = time.Now().Format(time.RFC3339)

	// Store rotated secret
	req := &secretsif.SecretRequest{
		Key:         secret.Key,
		Value:       newValue, // New value
		Metadata:    secret.Metadata,
		Tags:        secret.Tags,
		CreatedBy:   secret.UpdatedBy,
		TenantID:    secret.TenantID,
		Description: secret.Description,
	}

	return s.StoreSecret(ctx, req)
}

// ExpireSecret marks a secret as expired
// M-AUTH-1: Immediate secret expiration
func (s *SOPSSecretStore) ExpireSecret(ctx context.Context, key string) error {
	// Design decision: SOPS secrets have no TTL mechanism; expiration is implemented as deletion. Time-based expiry requires a separate scheduled cleanup process.
	return s.DeleteSecret(ctx, key)
}

// HealthCheck checks if the secret store is healthy
// M-AUTH-1: Health monitoring
func (s *SOPSSecretStore) HealthCheck(ctx context.Context) error {
	// Check if ConfigStore is accessible
	// Try to list configs to verify connectivity
	_, err := s.configStore.GetConfigStats(ctx)
	if err != nil {
		return fmt.Errorf("secret store unhealthy: %w", err)
	}
	return nil
}

// Close closes the secret store
// M-AUTH-1: Cleanup resources
func (s *SOPSSecretStore) Close() error {
	// Close cache if enabled
	if s.cache != nil {
		s.cache.Close()
	}
	return nil
}

// Helper methods

// getCacheKey generates a cache key for a secret
func (s *SOPSSecretStore) getCacheKey(tenantID, key string) string {
	return fmt.Sprintf("%s/%s", tenantID, key)
}

// isExpired checks if a secret is expired
func (s *SOPSSecretStore) isExpired(secret *secretsif.Secret) bool {
	if secret.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*secret.ExpiresAt)
}
