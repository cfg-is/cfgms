// Package interfaces - API key storage interface for persistent key management
package interfaces

import (
	"context"
	"time"
)

// APIKeyStore provides persistent storage for API keys
// M-AUTH-1: Interface for durable API key storage
type APIKeyStore interface {
	// Initialize sets up the API key store
	Initialize(ctx context.Context) error

	// StoreKey persists an API key (key hash stored, not plaintext)
	StoreKey(ctx context.Context, key *StoredAPIKey) error

	// GetKeyByHash retrieves an API key by its hash
	GetKeyByHash(ctx context.Context, keyHash string) (*StoredAPIKey, error)

	// GetKeyByID retrieves an API key by ID
	GetKeyByID(ctx context.Context, id string) (*StoredAPIKey, error)

	// ListKeys returns all API keys for a tenant
	ListKeys(ctx context.Context, tenantID string) ([]*StoredAPIKey, error)

	// DeleteKey removes an API key
	DeleteKey(ctx context.Context, id string) error

	// UpdateLastUsed updates the last used timestamp
	UpdateLastUsed(ctx context.Context, id string, lastUsed time.Time) error

	// Close shuts down the store
	Close() error
}

// StoredAPIKey represents a persisted API key
// M-AUTH-1: Never stores plaintext keys, only hashes
type StoredAPIKey struct {
	ID          string                 `json:"id"`
	KeyHash     string                 `json:"key_hash"` // SHA-256 hash of actual key
	Name        string                 `json:"name"`
	Permissions []string               `json:"permissions"`
	TenantID    string                 `json:"tenant_id"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time             `json:"last_used_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
