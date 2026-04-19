// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sops implements SOPS-based secret store
// M-AUTH-1: SecretStore implementation using git ConfigStore with SOPS encryption
package sops

import (
	"context"
	"encoding/json"
	"fmt"
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
	KMSKeyID        string                 // KMS key ID for encryption (optional)
}

// SOPSSecretStore implements SecretStore using git ConfigStore with SOPS encryption
// M-AUTH-1: Secrets are stored as ConfigEntry objects in git, automatically encrypted by SOPS
type SOPSSecretStore struct {
	configStore  cfgconfig.ConfigStore // Underlying config store (git with SOPS)
	cache        *cache.Cache          // Secret cache
	config       *SOPSSecretStoreConfig
	providerName string
}

// NewSOPSSecretStore creates a new SOPS-based secret store
// M-AUTH-1: Create secret store that leverages existing git+SOPS infrastructure
func NewSOPSSecretStore(config *SOPSSecretStoreConfig) (*SOPSSecretStore, error) {
	// Create ConfigStore using storage provider
	configStore, err := storageif.CreateConfigStoreFromConfig(config.StorageProvider, config.StorageConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create config store: %w", err)
	}

	store := &SOPSSecretStore{
		configStore:  configStore,
		config:       config,
		providerName: config.StorageProvider,
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

// StoreSecret stores a secret
// M-AUTH-1: Stores secret as ConfigEntry, automatically encrypted by SOPS
func (s *SOPSSecretStore) StoreSecret(ctx context.Context, req *secretsif.SecretRequest) error {
	// Validate request
	if req.Key == "" {
		return fmt.Errorf("secret key cannot be empty")
	}
	if req.TenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
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

	// Store as ConfigEntry (will be automatically encrypted by SOPS)
	configKey := &cfgconfig.ConfigKey{
		TenantID:  req.TenantID,
		Namespace: "secrets", // Use "secrets" namespace for all secrets
		Name:      req.Key,   // Secret key is the config name
		Scope:     "",        // No scope needed for secrets
	}

	configEntry := &cfgconfig.ConfigEntry{
		Key:       configKey,
		Data:      secretData,
		Format:    cfgconfig.ConfigFormatJSON, // Secrets are stored as JSON
		CreatedBy: req.CreatedBy,
		UpdatedBy: req.CreatedBy,
		Tags:      append(req.Tags, "secret"), // Add "secret" tag
	}

	// Add secret type metadata if provided
	if secretType, ok := req.Metadata[secretsif.MetadataKeySecretType]; ok {
		configEntry.Tags = append(configEntry.Tags, fmt.Sprintf("type:%s", secretType))
	}

	// Store in ConfigStore (SOPS encryption happens here)
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
			return nil, fmt.Errorf("secret not found: %s", key)
		}
		return nil, fmt.Errorf("failed to retrieve secret: %w", err)
	}

	// Parse secret from JSON (SOPS decryption happens in ConfigStore.GetConfig)
	var secret secretsif.Secret
	if err := json.Unmarshal(configEntry.Data, &secret); err != nil {
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
		// Parse secret to get metadata
		var secret secretsif.Secret
		if err := json.Unmarshal(config.Data, &secret); err != nil {
			continue // Skip invalid secrets
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
			// Skip secrets that don't exist or have errors
			continue
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

	// Parse secret from JSON
	var secret secretsif.Secret
	if err := json.Unmarshal(configEntry.Data, &secret); err != nil {
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
		// Parse secret to get created info
		var secret secretsif.Secret
		if err := json.Unmarshal(config.Data, &secret); err != nil {
			continue
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
	// Just delete the secret (expiration = deletion for now)
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
