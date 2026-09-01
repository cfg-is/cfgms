// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package interfaces defines the SecretStore interface for CFGMS secrets management
// M-AUTH-1: Core secret storage operations with encryption, versioning, and audit support
package interfaces

import (
	"context"
	"errors"
	"time"
)

// ErrTenantRequired is returned when TenantID is empty in a multi-tenant context.
var ErrTenantRequired = errors.New("TenantID is required for multi-tenant secret operations")

// ErrSecretNotFound is returned when a requested secret key does not exist in the store.
var ErrSecretNotFound = errors.New("secret not found")

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

	// CompareAndSwapSecret atomically stores req at key only if the secret
	// currently stored there has version expectedVersion. Pass expectedVersion
	// 0 to require that no secret currently exists at key (a create-if-absent
	// claim). A version mismatch is reported as ok=false with a nil error, so
	// callers can distinguish "lost the race" from a genuine store failure —
	// err is reserved for infrastructure failures. On success, ok is true and
	// newVersion is the version now stored. This is the primitive multi-writer
	// state transitions (pending -> approved, approved -> collected, revoke,
	// issue-and-rebind) must use instead of a per-process mutex, which provides
	// no protection once a concurrent request can land on a different node
	// (Issue #3775 / ADR-031).
	//
	// An expired secret does not exist. A provider that implements secret expiry
	// must treat a record past its ExpiresAt exactly as it treats an absent one,
	// for every expectedVersion: 0 succeeds against it and takes it over, and any
	// non-zero value fails against it — no reader can obtain a version for an
	// expired record, so a caller presenting one is by definition stale. Every
	// read path already refuses expired records, so the alternative is a record
	// that is invisible to readers yet permanently blocks a create-if-absent claim
	// — which turns a TTL-bounded claim (the renewal claim, #3724) into a
	// permanent lockout when the claiming process crashes before releasing it.
	// newVersion after such a takeover continues the record's own version sequence
	// rather than restarting at 1, so versions stay monotonic per key; callers must
	// use the returned value and never assume expectedVersion+1.
	//
	// Atomicity is only as strong as the backend. Providers whose swap is atomic
	// across controller nodes additionally implement
	// ClusterAtomicCompareAndSwapper; see that interface before relying on this
	// in cluster mode.
	CompareAndSwapSecret(ctx context.Context, key string, expectedVersion int, req *SecretRequest) (newVersion int, ok bool, err error)

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

// ClusterAtomicCompareAndSwapper is implemented by SecretStore instances whose
// CompareAndSwapSecret is atomic across CFGMS controller nodes, not merely within
// one process or one host.
//
// The distinction is not academic. Every caller of CompareAndSwapSecret in the
// controller mints or invalidates a credential on the strength of winning it —
// the approved->collected transition (#3719), enrolment-token spend (#3717),
// CLI-login collect (#3721), account revoke, and the renewal claim (#3724). If
// two nodes can both win, two client certificates are issued for one approval.
//
// This is deliberately a property of the constructed store rather than of the
// provider: the same provider is cluster-atomic or not depending on the backend
// it was configured with (the SOPS provider backed by PostgreSQL has a genuine
// conditional write; backed by a local directory it has a file lock). A store
// that does not implement this interface must be assumed not to be cluster-atomic.
type ClusterAtomicCompareAndSwapper interface {
	CompareAndSwapIsClusterAtomic() bool
}

// CompareAndSwapIsClusterAtomic reports whether store's CompareAndSwapSecret is
// atomic across controller nodes. A store that does not implement
// ClusterAtomicCompareAndSwapper reports false: absence of the claim is not
// evidence for it.
func CompareAndSwapIsClusterAtomic(store SecretStore) bool {
	c, ok := store.(ClusterAtomicCompareAndSwapper)
	return ok && c.CompareAndSwapIsClusterAtomic()
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
	// Policy holds provider-level access policy metadata when available.
	// Populated by providers that expose policy information (e.g. OpenBao mount policies).
	Policy map[string]string `json:"policy,omitempty"`
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
