// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines the global directory provider system for CFGMS.
//
// This package implements CFGMS's pluggable infrastructure design paradigm for directory services,
// enabling unified management of Active Directory, Entra ID, and other directory providers from
// a single control plane.
//
// Architecture Pattern: Global Controller Directory Selection
// - Controller-Level Decision: Single directory provider choice affects entire system
// - All Modules Use Same Backend: No per-module directory configuration needed
// - Interface Injection: Modules receive interfaces, never import specific providers
// - Discovery: Providers auto-register via init() functions
// - Simple Configuration: One setting: controller.directory.provider: "hybrid"
//
// Example usage:
//
//	// Business logic imports interfaces only
//	provider, err := interfaces.GetDirectoryProvider("activedirectory")
//
//	// Normalized directory operations
//	user, err := provider.GetUser(ctx, "john.doe@company.com")
//	err = provider.CreateUser(ctx, &DirectoryUser{...})
//
//	// Cross-directory operations
//	err = provider.SyncUser(ctx, sourceUserID, targetProviderName)
package interfaces

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DirectoryProvider defines the unified interface for all directory service providers.
// This interface enables consistent operations across Active Directory, Entra ID, and future providers.
type DirectoryProvider interface {
	// Provider Information
	GetProviderInfo() ProviderInfo

	// Connection Management
	Connect(ctx context.Context, config ProviderConfig) error
	Disconnect(ctx context.Context) error
	IsConnected(ctx context.Context) bool
	HealthCheck(ctx context.Context) (*HealthStatus, error)

	// User Management
	GetUser(ctx context.Context, userID string) (*DirectoryUser, error)
	CreateUser(ctx context.Context, user *DirectoryUser) (*DirectoryUser, error)
	UpdateUser(ctx context.Context, userID string, updates *DirectoryUser) (*DirectoryUser, error)
	DeleteUser(ctx context.Context, userID string) error
	ListUsers(ctx context.Context, filters *SearchFilters) (*UserList, error)

	// Group Management
	GetGroup(ctx context.Context, groupID string) (*DirectoryGroup, error)
	CreateGroup(ctx context.Context, group *DirectoryGroup) (*DirectoryGroup, error)
	UpdateGroup(ctx context.Context, groupID string, updates *DirectoryGroup) (*DirectoryGroup, error)
	DeleteGroup(ctx context.Context, groupID string) error
	ListGroups(ctx context.Context, filters *SearchFilters) (*GroupList, error)

	// Membership Management
	AddUserToGroup(ctx context.Context, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, userID, groupID string) error
	GetUserGroups(ctx context.Context, userID string) ([]DirectoryGroup, error)
	GetGroupMembers(ctx context.Context, groupID string) ([]DirectoryUser, error)

	// Organizational Unit Management (for AD compatibility)
	GetOU(ctx context.Context, ouID string) (*OrganizationalUnit, error)
	CreateOU(ctx context.Context, ou *OrganizationalUnit) (*OrganizationalUnit, error)
	UpdateOU(ctx context.Context, ouID string, updates *OrganizationalUnit) (*OrganizationalUnit, error)
	DeleteOU(ctx context.Context, ouID string) error
	ListOUs(ctx context.Context, filters *SearchFilters) (*OUList, error)

	// Advanced Search Operations
	Search(ctx context.Context, query *DirectoryQuery) (*SearchResults, error)

	// Bulk Operations
	BulkCreateUsers(ctx context.Context, users []*DirectoryUser, options *BulkOptions) (*BulkResult, error)
	BulkUpdateUsers(ctx context.Context, updates []*UserUpdate, options *BulkOptions) (*BulkResult, error)
	BulkDeleteUsers(ctx context.Context, userIDs []string, options *BulkOptions) (*BulkResult, error)

	// Cross-Directory Operations
	SyncUser(ctx context.Context, sourceUserID string, targetProvider DirectoryProvider) error
	SyncGroup(ctx context.Context, sourceGroupID string, targetProvider DirectoryProvider) error

	// Schema and Capabilities
	GetSchema(ctx context.Context) (*DirectorySchema, error)
	GetCapabilities() ProviderCapabilities
	ValidateUser(user *DirectoryUser) error
	ValidateGroup(group *DirectoryGroup) error
}

// DirectoryConnection defines connection pool management interface
type DirectoryConnection interface {
	// Connection lifecycle
	Open(ctx context.Context, config ProviderConfig) error
	Close(ctx context.Context) error
	IsHealthy(ctx context.Context) bool

	// Connection information
	GetConnectionInfo() ConnectionInfo
	GetStatistics() ConnectionStatistics

	// Connection pool management
	Reset(ctx context.Context) error
	RefreshCredentials(ctx context.Context) error
}

// ProviderInfo contains information about a directory provider
type ProviderInfo struct {
	Name           string                `json:"name"`                    // e.g., "activedirectory", "entraid"
	DisplayName    string                `json:"display_name"`            // e.g., "Active Directory"
	Version        string                `json:"version"`                 // Provider version
	Description    string                `json:"description"`             // Provider description
	SupportedTypes []DirectoryObjectType `json:"supported_types"`         // Supported object types
	Capabilities   ProviderCapabilities  `json:"capabilities"`            // What this provider supports
	Configuration  ConfigurationSchema   `json:"configuration"`           // Required configuration
	Documentation  string                `json:"documentation,omitempty"` // Documentation URL
}

// ProviderCapabilities describes what operations a provider supports
type ProviderCapabilities struct {
	// Basic CRUD operations
	SupportsUserManagement  bool `json:"supports_user_management"`
	SupportsGroupManagement bool `json:"supports_group_management"`
	SupportsOUManagement    bool `json:"supports_ou_management"`

	// Advanced features
	SupportsBulkOperations     bool `json:"supports_bulk_operations"`
	SupportsAdvancedSearch     bool `json:"supports_advanced_search"`
	SupportsCrossDirectorySync bool `json:"supports_cross_directory_sync"`
	SupportsRealTimeSync       bool `json:"supports_real_time_sync"`

	// Authentication methods
	SupportedAuthMethods []AuthMethod `json:"supported_auth_methods"`

	// Search capabilities
	MaxSearchResults     int      `json:"max_search_results"`
	SupportedSearchTypes []string `json:"supported_search_types"`

	// Rate limiting
	RateLimitInfo *RateLimitInfo `json:"rate_limit_info,omitempty"`
}

// DirectoryUser represents a normalized user object across all directory providers
type DirectoryUser struct {
	// Core Identity
	ID                string `json:"id"`                         // Unique identifier in source directory
	UserPrincipalName string `json:"user_principal_name"`        // UPN (user@domain.com)
	SAMAccountName    string `json:"sam_account_name,omitempty"` // For AD compatibility
	DisplayName       string `json:"display_name"`               // Full display name

	// Authentication
	AccountEnabled bool       `json:"account_enabled"`           // Is account enabled
	PasswordExpiry *time.Time `json:"password_expiry,omitempty"` // When password expires
	LastLogon      *time.Time `json:"last_logon,omitempty"`      // Last successful logon

	// Contact Information
	EmailAddress string `json:"email_address,omitempty"` // Primary email
	PhoneNumber  string `json:"phone_number,omitempty"`  // Primary phone
	MobilePhone  string `json:"mobile_phone,omitempty"`  // Mobile phone

	// Organizational Information
	Department     string `json:"department,omitempty"`      // Department name
	JobTitle       string `json:"job_title,omitempty"`       // Job title
	Manager        string `json:"manager,omitempty"`         // Manager's ID
	OfficeLocation string `json:"office_location,omitempty"` // Office location
	Company        string `json:"company,omitempty"`         // Company name

	// Directory Structure
	DistinguishedName string   `json:"distinguished_name,omitempty"` // Full DN (for AD)
	OU                string   `json:"ou,omitempty"`                 // Parent OU
	Groups            []string `json:"groups,omitempty"`             // Group memberships

	// Provider-Specific Attributes
	ProviderAttributes map[string]interface{} `json:"provider_attributes,omitempty"`

	// Metadata
	Created  *time.Time `json:"created,omitempty"`  // When created
	Modified *time.Time `json:"modified,omitempty"` // When last modified
	Source   string     `json:"source"`             // Source provider name
}

// DirectoryGroup represents a normalized group object across all directory providers
type DirectoryGroup struct {
	// Core Identity
	ID          string `json:"id"`                    // Unique identifier
	Name        string `json:"name"`                  // Group name
	DisplayName string `json:"display_name"`          // Display name
	Description string `json:"description,omitempty"` // Group description

	// Group Properties
	GroupType  GroupType  `json:"group_type"`            // Security vs Distribution
	GroupScope GroupScope `json:"group_scope,omitempty"` // Domain, Global, Universal

	// Directory Structure
	DistinguishedName string   `json:"distinguished_name,omitempty"` // Full DN (for AD)
	OU                string   `json:"ou,omitempty"`                 // Parent OU
	Members           []string `json:"members,omitempty"`            // Member user IDs

	// Provider-Specific Attributes
	ProviderAttributes map[string]interface{} `json:"provider_attributes,omitempty"`

	// Metadata
	Created  *time.Time `json:"created,omitempty"`  // When created
	Modified *time.Time `json:"modified,omitempty"` // When last modified
	Source   string     `json:"source"`             // Source provider name
}

// OrganizationalUnit represents a normalized OU object (primarily for AD compatibility)
type OrganizationalUnit struct {
	// Core Identity
	ID          string `json:"id"`                    // Unique identifier
	Name        string `json:"name"`                  // OU name
	DisplayName string `json:"display_name"`          // Display name
	Description string `json:"description,omitempty"` // OU description

	// Directory Structure
	DistinguishedName string `json:"distinguished_name"`  // Full DN
	ParentOU          string `json:"parent_ou,omitempty"` // Parent OU ID

	// Provider-Specific Attributes
	ProviderAttributes map[string]interface{} `json:"provider_attributes,omitempty"`

	// Metadata
	Created  *time.Time `json:"created,omitempty"`  // When created
	Modified *time.Time `json:"modified,omitempty"` // When last modified
	Source   string     `json:"source"`             // Source provider name
}

// Supporting Types

// DirectoryObjectType represents the type of directory object
type DirectoryObjectType string

const (
	DirectoryObjectTypeUser  DirectoryObjectType = "user"
	DirectoryObjectTypeGroup DirectoryObjectType = "group"
	DirectoryObjectTypeOU    DirectoryObjectType = "organizational_unit"
)

// GroupType represents the type of group
type GroupType string

const (
	GroupTypeSecurity     GroupType = "security"
	GroupTypeDistribution GroupType = "distribution"
)

// GroupScope represents the scope of a group (AD concept)
type GroupScope string

const (
	GroupScopeDomainLocal GroupScope = "domain_local"
	GroupScopeGlobal      GroupScope = "global"
	GroupScopeUniversal   GroupScope = "universal"
)

// AuthMethod represents supported authentication methods
type AuthMethod string

const (
	AuthMethodKerberos   AuthMethod = "kerberos"
	AuthMethodLDAP       AuthMethod = "ldap"
	AuthMethodOAuth2     AuthMethod = "oauth2"
	AuthMethodClientCert AuthMethod = "client_cert"
	AuthMethodAPIKey     AuthMethod = "api_key"
)

// SearchFilters defines filters for directory searches
type SearchFilters struct {
	// Text search
	Query string `json:"query,omitempty"` // Free text search

	// Object filters
	ObjectTypes []DirectoryObjectType `json:"object_types,omitempty"` // Filter by object type

	// User-specific filters
	Department string `json:"department,omitempty"` // Filter by department
	JobTitle   string `json:"job_title,omitempty"`  // Filter by job title
	Enabled    *bool  `json:"enabled,omitempty"`    // Filter by enabled status

	// OU filters
	OU        string `json:"ou,omitempty"` // Filter by OU
	Recursive bool   `json:"recursive"`    // Search recursively in OUs

	// Pagination
	Offset int `json:"offset"` // Starting offset
	Limit  int `json:"limit"`  // Maximum results

	// Sorting
	SortBy    string `json:"sort_by,omitempty"`    // Field to sort by
	SortOrder string `json:"sort_order,omitempty"` // "asc" or "desc"
}

// DirectoryQuery represents advanced search queries
type DirectoryQuery struct {
	// LDAP-style query string
	Filter string `json:"filter"` // LDAP filter or equivalent

	// Attributes to retrieve
	Attributes []string `json:"attributes,omitempty"` // Specific attributes to return

	// Search base
	SearchBase string `json:"search_base,omitempty"` // Where to start search

	// Search scope
	Scope SearchScope `json:"scope"` // Search scope

	// Search options
	Options map[string]interface{} `json:"options,omitempty"` // Provider-specific options
}

// SearchScope defines the scope of directory searches
type SearchScope string

const (
	SearchScopeBase     SearchScope = "base"      // Search only the base object
	SearchScopeOneLevel SearchScope = "one_level" // Search one level below base
	SearchScopeSubtree  SearchScope = "subtree"   // Search entire subtree
)

// Result Types

// UserList represents a paginated list of users
type UserList struct {
	Users      []DirectoryUser `json:"users"`
	TotalCount int             `json:"total_count"`
	HasMore    bool            `json:"has_more"`
	NextToken  string          `json:"next_token,omitempty"`
}

// GroupList represents a paginated list of groups
type GroupList struct {
	Groups     []DirectoryGroup `json:"groups"`
	TotalCount int              `json:"total_count"`
	HasMore    bool             `json:"has_more"`
	NextToken  string           `json:"next_token,omitempty"`
}

// OUList represents a paginated list of organizational units
type OUList struct {
	OUs        []OrganizationalUnit `json:"ous"`
	TotalCount int                  `json:"total_count"`
	HasMore    bool                 `json:"has_more"`
	NextToken  string               `json:"next_token,omitempty"`
}

// SearchResults represents the results of an advanced search
type SearchResults struct {
	Users      []DirectoryUser      `json:"users,omitempty"`
	Groups     []DirectoryGroup     `json:"groups,omitempty"`
	OUs        []OrganizationalUnit `json:"ous,omitempty"`
	TotalCount int                  `json:"total_count"`
	HasMore    bool                 `json:"has_more"`
	NextToken  string               `json:"next_token,omitempty"`
}

// Bulk Operations

// BulkOptions defines options for bulk operations
type BulkOptions struct {
	BatchSize       int           `json:"batch_size"`         // Items per batch
	ConcurrentBatch int           `json:"concurrent_batches"` // Concurrent batches
	ContinueOnError bool          `json:"continue_on_error"`  // Continue if errors occur
	RetryAttempts   int           `json:"retry_attempts"`     // Retry attempts per item
	RetryDelay      time.Duration `json:"retry_delay"`        // Delay between retries
	BatchTimeout    time.Duration `json:"batch_timeout"`      // Timeout for individual batches
}

// BulkResult represents the result of a bulk operation
type BulkResult struct {
	TotalItems   int              `json:"total_items"`
	SuccessCount int              `json:"success_count"`
	ErrorCount   int              `json:"error_count"`
	Errors       []BulkItemError  `json:"errors,omitempty"`
	Duration     time.Duration    `json:"duration"`
	ItemResults  []BulkItemResult `json:"item_results,omitempty"`
}

// BulkItemError represents an error for a specific item in a bulk operation
type BulkItemError struct {
	ItemIndex int    `json:"item_index"`
	ItemID    string `json:"item_id,omitempty"`
	Error     string `json:"error"`
}

// BulkItemResult represents the result for a specific item in a bulk operation
type BulkItemResult struct {
	ItemIndex int         `json:"item_index"`
	ItemID    string      `json:"item_id,omitempty"`
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// UserUpdate represents an update to a user for bulk operations
type UserUpdate struct {
	UserID  string         `json:"user_id"`
	Updates *DirectoryUser `json:"updates"`
}

// Connection Management

// HealthStatus represents the health status of a directory provider connection
type HealthStatus struct {
	IsHealthy    bool                   `json:"is_healthy"`
	LastCheck    time.Time              `json:"last_check"`
	ResponseTime time.Duration          `json:"response_time"`
	Details      map[string]interface{} `json:"details,omitempty"`
	Errors       []string               `json:"errors,omitempty"`
}

// ConnectionInfo provides information about a directory connection
type ConnectionInfo struct {
	ProviderName   string            `json:"provider_name"`
	ServerAddress  string            `json:"server_address"`
	ConnectedSince time.Time         `json:"connected_since"`
	AuthMethod     AuthMethod        `json:"auth_method"`
	UserContext    string            `json:"user_context,omitempty"`
	Properties     map[string]string `json:"properties,omitempty"`
}

// ConnectionStatistics provides statistics about a directory connection
type ConnectionStatistics struct {
	RequestCount    int64          `json:"request_count"`
	ErrorCount      int64          `json:"error_count"`
	AverageLatency  time.Duration  `json:"average_latency"`
	LastRequestTime time.Time      `json:"last_request_time"`
	ConnectionPool  PoolStatistics `json:"connection_pool,omitempty"`
}

// PoolStatistics provides connection pool statistics
type PoolStatistics struct {
	ActiveConnections int           `json:"active_connections"`
	IdleConnections   int           `json:"idle_connections"`
	MaxConnections    int           `json:"max_connections"`
	RequestCount      int64         `json:"request_count"`
	ErrorCount        int64         `json:"error_count"`
	AverageLatency    time.Duration `json:"average_latency"`
	LastRequestTime   time.Time     `json:"last_request_time"`
}

// Configuration

// ProviderConfig contains configuration for a directory provider
type ProviderConfig struct {
	// Provider identification
	ProviderName string `json:"provider_name"` // Which provider to use

	// Connection settings
	ServerAddress string `json:"server_address"` // Server address/URL
	Port          int    `json:"port,omitempty"` // Port number
	UseTLS        bool   `json:"use_tls"`        // Use TLS/SSL

	// Authentication
	AuthMethod AuthMethod `json:"auth_method"`         // Authentication method
	Username   string     `json:"username,omitempty"`  // Username
	Password   string     `json:"password,omitempty"`  // Password (will be secured)
	ClientID   string     `json:"client_id,omitempty"` // OAuth2 client ID
	TenantID   string     `json:"tenant_id,omitempty"` // Tenant ID (for multi-tenant)

	// Search settings
	SearchBase string `json:"search_base,omitempty"` // Default search base
	PageSize   int    `json:"page_size,omitempty"`   // Default page size

	// Connection pool settings
	MaxConnections    int           `json:"max_connections"`    // Maximum connections
	ConnectionTimeout time.Duration `json:"connection_timeout"` // Connection timeout
	IdleTimeout       time.Duration `json:"idle_timeout"`       // Idle connection timeout

	// Provider-specific configuration
	ProviderConfig map[string]interface{} `json:"provider_config,omitempty"`
}

// ConfigurationSchema describes the configuration requirements for a provider
type ConfigurationSchema struct {
	Required []ConfigField `json:"required"` // Required configuration fields
	Optional []ConfigField `json:"optional"` // Optional configuration fields
}

// ConfigField describes a configuration field
type ConfigField struct {
	Name         string      `json:"name"`                    // Field name
	Type         string      `json:"type"`                    // Data type
	Description  string      `json:"description"`             // Field description
	DefaultValue interface{} `json:"default_value,omitempty"` // Default value
	ValidValues  []string    `json:"valid_values,omitempty"`  // Valid values (for enums)
	Required     bool        `json:"required"`                // Is field required
}

// DirectorySchema describes the schema supported by a directory provider
type DirectorySchema struct {
	UserSchema  ObjectSchema `json:"user_schema"`         // User object schema
	GroupSchema ObjectSchema `json:"group_schema"`        // Group object schema
	OUSchema    ObjectSchema `json:"ou_schema,omitempty"` // OU schema (if supported)
}

// ObjectSchema describes the schema for a directory object type
type ObjectSchema struct {
	ObjectType       DirectoryObjectType `json:"object_type"`
	RequiredFields   []SchemaField       `json:"required_fields"`
	OptionalFields   []SchemaField       `json:"optional_fields"`
	ReadOnlyFields   []SchemaField       `json:"read_only_fields"`
	SearchableFields []SchemaField       `json:"searchable_fields"`
}

// SchemaField describes a field in a directory object schema
type SchemaField struct {
	Name        string `json:"name"`                 // Field name
	Type        string `json:"type"`                 // Data type
	Description string `json:"description"`          // Field description
	MaxLength   int    `json:"max_length,omitempty"` // Maximum length (for strings)
	Format      string `json:"format,omitempty"`     // Format constraints
	Validation  string `json:"validation,omitempty"` // Validation rules
}

// Rate Limiting

// RateLimitInfo describes rate limiting for a provider
type RateLimitInfo struct {
	RequestsPerSecond int    `json:"requests_per_second"` // Max requests per second
	RequestsPerMinute int    `json:"requests_per_minute"` // Max requests per minute
	RequestsPerHour   int    `json:"requests_per_hour"`   // Max requests per hour
	BurstSize         int    `json:"burst_size"`          // Burst request allowance
	BackoffStrategy   string `json:"backoff_strategy"`    // Backoff strategy
}

// Global Provider Registry (following CFGMS storage provider pattern)

var (
	globalRegistry = &providerRegistry{
		providers: make(map[string]DirectoryProvider),
	}
)

type providerRegistry struct {
	providers map[string]DirectoryProvider
	mutex     sync.RWMutex
}

// RegisterDirectoryProvider registers a directory provider (called from provider init() functions)
func RegisterDirectoryProvider(provider DirectoryProvider) {
	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()

	info := provider.GetProviderInfo()
	globalRegistry.providers[info.Name] = provider
}

// GetDirectoryProvider retrieves a registered provider by name
func GetDirectoryProvider(name string) (DirectoryProvider, error) {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	provider, exists := globalRegistry.providers[name]
	if !exists {
		return nil, fmt.Errorf("directory provider '%s' not found", name)
	}

	return provider, nil
}

// GetAvailableDirectoryProviders returns all providers that are currently available
func GetAvailableDirectoryProviders() map[string]DirectoryProvider {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	available := make(map[string]DirectoryProvider)
	for name, provider := range globalRegistry.providers {
		// Test basic connectivity/health
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if provider.IsConnected(ctx) {
			available[name] = provider
		}
		cancel()
	}

	return available
}

// ListDirectoryProviders returns information about all registered providers
func ListDirectoryProviders() []ProviderInfo {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	var providers []ProviderInfo
	for _, provider := range globalRegistry.providers {
		providers = append(providers, provider.GetProviderInfo())
	}

	return providers
}

// CreateDirectoryProviderFromConfig creates a configured directory provider
// This is the main entry point used by the controller
func CreateDirectoryProviderFromConfig(providerName string, config ProviderConfig) (DirectoryProvider, error) {
	provider, err := GetDirectoryProvider(providerName)
	if err != nil {
		// Provide helpful error with available options
		available := GetAvailableDirectoryProviders()
		var availableNames []string
		for name := range available {
			availableNames = append(availableNames, name)
		}
		return nil, fmt.Errorf("directory provider '%s' not available. Available providers: %v", providerName, availableNames)
	}

	// Connect to the directory service
	ctx, cancel := context.WithTimeout(context.Background(), config.ConnectionTimeout)
	defer cancel()

	if err := provider.Connect(ctx, config); err != nil {
		return nil, fmt.Errorf("failed to connect to directory provider '%s': %w", providerName, err)
	}

	return provider, nil
}
