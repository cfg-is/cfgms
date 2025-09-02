// Package interfaces defines global storage contracts used by all CFGMS modules
package interfaces

import (
	"context"
	"time"
)

// ConfigStore defines storage interface for all CFGMS configuration data
// This interface handles human-editable configurations (YAML) and system configurations
type ConfigStore interface {
	// Configuration CRUD operations
	StoreConfig(ctx context.Context, config *ConfigEntry) error
	GetConfig(ctx context.Context, key *ConfigKey) (*ConfigEntry, error)
	DeleteConfig(ctx context.Context, key *ConfigKey) error
	ListConfigs(ctx context.Context, filter *ConfigFilter) ([]*ConfigEntry, error)
	
	// Configuration versioning and history
	GetConfigHistory(ctx context.Context, key *ConfigKey, limit int) ([]*ConfigEntry, error)
	GetConfigVersion(ctx context.Context, key *ConfigKey, version int64) (*ConfigEntry, error)
	
	// Batch operations for performance
	StoreConfigBatch(ctx context.Context, configs []*ConfigEntry) error
	DeleteConfigBatch(ctx context.Context, keys []*ConfigKey) error
	
	// Template and inheritance support
	ResolveConfigWithInheritance(ctx context.Context, key *ConfigKey) (*ConfigEntry, error)
	ValidateConfig(ctx context.Context, config *ConfigEntry) error
	
	// Health and statistics
	GetConfigStats(ctx context.Context) (*ConfigStats, error)
}

// ConfigKey uniquely identifies a configuration entry
type ConfigKey struct {
	TenantID   string `json:"tenant_id"`             // Multi-tenant isolation
	Namespace  string `json:"namespace"`             // Configuration category (templates, certificates, etc.)
	Name       string `json:"name"`                  // Configuration name
	Scope      string `json:"scope,omitempty"`       // Optional scope (device, group, etc.)
}

// String returns a human-readable representation of the config key
func (ck *ConfigKey) String() string {
	if ck.Scope != "" {
		return ck.TenantID + "/" + ck.Namespace + "/" + ck.Name + "@" + ck.Scope
	}
	return ck.TenantID + "/" + ck.Namespace + "/" + ck.Name
}

// ConfigEntry represents a stored configuration with metadata
type ConfigEntry struct {
	Key         *ConfigKey             `json:"key"`
	Data        []byte                 `json:"data"`                   // YAML or JSON data
	Format      ConfigFormat           `json:"format"`                 // YAML or JSON
	Version     int64                  `json:"version"`                // Auto-incrementing version
	Checksum    string                 `json:"checksum"`               // SHA256 of data for integrity
	Metadata    map[string]interface{} `json:"metadata,omitempty"`     // Additional metadata
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   string                 `json:"created_by"`             // User/system that created this
	UpdatedBy   string                 `json:"updated_by"`             // User/system that last updated this
	Tags        []string               `json:"tags,omitempty"`         // Optional tags for organization
	Source      string                 `json:"source,omitempty"`       // Source system/process
}

// ConfigFormat specifies the data format
type ConfigFormat string

const (
	ConfigFormatYAML ConfigFormat = "yaml"
	ConfigFormatJSON ConfigFormat = "json"
)

// ConfigFilter defines criteria for listing configurations
type ConfigFilter struct {
	TenantID   string   `json:"tenant_id,omitempty"`
	Namespace  string   `json:"namespace,omitempty"`
	Names      []string `json:"names,omitempty"`           // Filter by specific names
	Tags       []string `json:"tags,omitempty"`            // Filter by tags
	CreatedBy  string   `json:"created_by,omitempty"`
	UpdatedBy  string   `json:"updated_by,omitempty"`
	
	// Time-based filtering
	CreatedAfter  *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`
	UpdatedAfter  *time.Time `json:"updated_after,omitempty"`
	UpdatedBefore *time.Time `json:"updated_before,omitempty"`
	
	// Pagination
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
	SortBy string `json:"sort_by,omitempty"`    // "created_at", "updated_at", "name", "version"
	Order  string `json:"order,omitempty"`      // "asc", "desc"
}

// ConfigStats provides statistics about stored configurations
type ConfigStats struct {
	TotalConfigs     int64            `json:"total_configs"`
	TotalSize        int64            `json:"total_size"`        // Total storage size in bytes
	ConfigsByTenant  map[string]int64 `json:"configs_by_tenant"`
	ConfigsByFormat  map[string]int64 `json:"configs_by_format"`  // YAML vs JSON counts
	ConfigsByNamespace map[string]int64 `json:"configs_by_namespace"` // Templates, certificates, etc.
	OldestConfig     *time.Time       `json:"oldest_config,omitempty"`
	NewestConfig     *time.Time       `json:"newest_config,omitempty"`
	AverageSize      int64            `json:"average_size"`      // Average config size
	LastUpdated      time.Time        `json:"last_updated"`      // When stats were computed
}

// ConfigValidationError represents validation errors
type ConfigValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e *ConfigValidationError) Error() string {
	return e.Field + ": " + e.Message
}

// Common config validation errors
var (
	ErrConfigNotFound     = &ConfigValidationError{Field: "key", Message: "configuration not found", Code: "CONFIG_NOT_FOUND"}
	ErrConfigExists       = &ConfigValidationError{Field: "key", Message: "configuration already exists", Code: "CONFIG_EXISTS"}
	ErrInvalidFormat      = &ConfigValidationError{Field: "format", Message: "invalid configuration format", Code: "INVALID_FORMAT"}
	ErrInvalidYAML        = &ConfigValidationError{Field: "data", Message: "invalid YAML data", Code: "INVALID_YAML"}
	ErrInvalidJSON        = &ConfigValidationError{Field: "data", Message: "invalid JSON data", Code: "INVALID_JSON"}
	ErrChecksumMismatch   = &ConfigValidationError{Field: "checksum", Message: "checksum validation failed", Code: "CHECKSUM_MISMATCH"}
	ErrTenantRequired     = &ConfigValidationError{Field: "tenant_id", Message: "tenant ID is required", Code: "TENANT_REQUIRED"}
	ErrNamespaceRequired  = &ConfigValidationError{Field: "namespace", Message: "namespace is required", Code: "NAMESPACE_REQUIRED"}
	ErrNameRequired       = &ConfigValidationError{Field: "name", Message: "name is required", Code: "NAME_REQUIRED"}
)