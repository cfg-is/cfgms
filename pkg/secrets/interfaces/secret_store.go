// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines the SecretStore interface for CFGMS secrets management
// M-AUTH-1: Core secret storage operations with encryption, versioning, and audit support
package interfaces

import (
	"context"
	"time"
)

// SecretStore defines the interface for storing and retrieving secrets
// All implementations MUST encrypt secrets at rest - no cleartext storage allowed
type SecretStore interface {
	// Core CRUD operations
	StoreSecret(ctx context.Context, req *SecretRequest) error
	GetSecret(ctx context.Context, key string) (*Secret, error)
	DeleteSecret(ctx context.Context, key string) error
	ListSecrets(ctx context.Context, filter *SecretFilter) ([]*SecretMetadata, error)

	// Bulk operations
	GetSecrets(ctx context.Context, keys []string) (map[string]*Secret, error)
	StoreSecrets(ctx context.Context, secrets map[string]*SecretRequest) error

	// Versioning support (if provider supports it)
	GetSecretVersion(ctx context.Context, key string, version int) (*Secret, error)
	ListSecretVersions(ctx context.Context, key string) ([]*SecretVersion, error)

	// Metadata operations
	GetSecretMetadata(ctx context.Context, key string) (*SecretMetadata, error)
	UpdateSecretMetadata(ctx context.Context, key string, metadata map[string]string) error

	// Lifecycle operations
	RotateSecret(ctx context.Context, key string, newValue string) error
	ExpireSecret(ctx context.Context, key string) error

	// Health and status
	HealthCheck(ctx context.Context) error
	Close() error
}

// Secret represents a stored secret with metadata
// M-AUTH-1: All secret values are encrypted by the provider
type Secret struct {
	Key         string            `json:"key"`
	Value       string            `json:"value"` // Decrypted value (providers handle encryption/decryption)
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

// SecretRequest represents a request to store a secret
// M-AUTH-1: Input for secret creation/updates
type SecretRequest struct {
	Key         string            `json:"key"`
	Value       string            `json:"value"` // Plaintext value - provider will encrypt
	Metadata    map[string]string `json:"metadata,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	TTL         time.Duration     `json:"ttl,omitempty"`         // Time-to-live before expiration
	CreatedBy   string            `json:"created_by"`            // User/service creating the secret
	TenantID    string            `json:"tenant_id"`             // Tenant ID for multi-tenancy
	Description string            `json:"description,omitempty"` // Human-readable description
}

// SecretMetadata represents metadata about a secret without the actual value
// M-AUTH-1: Lightweight secret information for listing operations
type SecretMetadata struct {
	Key         string            `json:"key"`
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
	// Policy carries provider-specific access-control and lease-policy parameters as an
	// opaque map. Each provider populates only the fields it understands; all others leave
	// it nil. Callers must not log or expose Policy values — they may contain sensitive
	// policy identifiers. SOPS and steward providers always leave this nil.
	Policy map[string]any `json:"policy,omitempty"`
}

// SecretVersion represents a historical version of a secret
// M-AUTH-1: Support for secret versioning and rollback
type SecretVersion struct {
	Version   int        `json:"version"`
	CreatedAt time.Time  `json:"created_at"`
	CreatedBy string     `json:"created_by"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"` // Soft delete timestamp
}

// SecretFilter defines filtering criteria for listing secrets
// M-AUTH-1: Support for efficient secret discovery
type SecretFilter struct {
	TenantID       string            `json:"tenant_id,omitempty"`       // Filter by tenant
	Tags           []string          `json:"tags,omitempty"`            // Filter by tags (AND logic)
	Metadata       map[string]string `json:"metadata,omitempty"`        // Filter by metadata (AND logic)
	KeyPrefix      string            `json:"key_prefix,omitempty"`      // Filter by key prefix
	CreatedBy      string            `json:"created_by,omitempty"`      // Filter by creator
	IncludeExpired bool              `json:"include_expired,omitempty"` // Include expired secrets in results
	Limit          int               `json:"limit,omitempty"`           // Maximum results to return
	Offset         int               `json:"offset,omitempty"`          // Pagination offset
}

// SecretType defines common secret types for standardization
// M-AUTH-1: Standardized secret type classification
type SecretType string

const (
	SecretTypeAPIKey           SecretType = "api_key"
	SecretTypePassword         SecretType = "password"
	SecretTypeCertificate      SecretType = "certificate"
	SecretTypePrivateKey       SecretType = "private_key"
	SecretTypeToken            SecretType = "token"
	SecretTypeOAuthCredential  SecretType = "oauth_credential"
	SecretTypeConnectionString SecretType = "connection_string"
	SecretTypeEncryptionKey    SecretType = "encryption_key"
	SecretTypeGeneric          SecretType = "generic"
)

// Common metadata keys for standardization
const (
	MetadataKeySecretType     = "secret_type"     // Type of secret (SecretType)
	MetadataKeyService        = "service"         // Service this secret is for
	MetadataKeyEnvironment    = "environment"     // Environment (dev, staging, prod)
	MetadataKeyRotationPolicy = "rotation_policy" // Rotation policy identifier
	MetadataKeyLastRotated    = "last_rotated"    // Last rotation timestamp
	MetadataKeyOwner          = "owner"           // Team/person responsible
)

// SecretStoreConfig provides configuration for secret store creation
// M-AUTH-1: Configuration passed to provider.CreateSecretStore()
type SecretStoreConfig struct {
	// Provider-specific configuration
	Config map[string]interface{} `json:"config"`

	// Cache configuration
	CacheTTL     time.Duration `json:"cache_ttl"`      // How long to cache secrets
	CacheEnabled bool          `json:"cache_enabled"`  // Enable caching
	CacheMaxSize int           `json:"cache_max_size"` // Maximum cache size

	// Security settings
	RequireEncryption bool   `json:"require_encryption"`          // Enforce encryption (should always be true)
	EncryptionKeyID   string `json:"encryption_key_id,omitempty"` // KMS key ID for encryption

	// Default TTL for secrets without explicit expiration
	DefaultTTL time.Duration `json:"default_ttl,omitempty"`
}

// SecretStoreStats provides statistics about secret store usage
// M-AUTH-1: Metrics and monitoring
type SecretStoreStats struct {
	TotalSecrets    int       `json:"total_secrets"`
	ExpiredSecrets  int       `json:"expired_secrets"`
	LastRotation    time.Time `json:"last_rotation,omitempty"`
	CacheHits       int64     `json:"cache_hits"`
	CacheMisses     int64     `json:"cache_misses"`
	ProviderName    string    `json:"provider_name"`
	ProviderVersion string    `json:"provider_version"`
}
