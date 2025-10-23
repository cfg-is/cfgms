// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package directory provides a unified directory service abstraction for the CFGMS controller.
//
// This package follows CFGMS's architectural pattern where the controller provides a unified
// interface and modules contain the specific implementations. The directory service acts as
// a facade over different directory providers (Active Directory, Entra ID, etc.) while
// maintaining clear separation of concerns.
//
// Architecture:
// - Controller: Contains unified DirectoryService interface
// - Modules: Implement directory-specific operations (activedirectory, entra_user, etc.)
// - Workflow Engine: Routes directory operations to appropriate modules
package directory

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/pkg/directory/types"
)

// Service defines the unified directory interface available to the controller.
// This interface abstracts away the complexity of different directory providers
// and presents a consistent API for directory operations.
type Service interface {
	// Provider Management
	GetAvailableProviders() []ProviderInfo
	GetProvider(name string) (Provider, error)
	SetDefaultProvider(name string) error
	GetDefaultProvider() (Provider, error)

	// User Operations (delegated to appropriate provider/module)
	GetUser(ctx context.Context, providerName, userID string) (*types.DirectoryUser, error)
	CreateUser(ctx context.Context, providerName string, user *types.DirectoryUser) (*types.DirectoryUser, error)
	UpdateUser(ctx context.Context, providerName, userID string, updates *types.DirectoryUser) (*types.DirectoryUser, error)
	DeleteUser(ctx context.Context, providerName, userID string) error
	SearchUsers(ctx context.Context, providerName string, query *SearchQuery) ([]*types.DirectoryUser, error)

	// Group Operations (delegated to appropriate provider/module)
	GetGroup(ctx context.Context, providerName, groupID string) (*types.DirectoryGroup, error)
	CreateGroup(ctx context.Context, providerName string, group *types.DirectoryGroup) (*types.DirectoryGroup, error)
	UpdateGroup(ctx context.Context, providerName, groupID string, updates *types.DirectoryGroup) (*types.DirectoryGroup, error)
	DeleteGroup(ctx context.Context, providerName, groupID string) error
	SearchGroups(ctx context.Context, providerName string, query *SearchQuery) ([]*types.DirectoryGroup, error)

	// Membership Operations
	AddUserToGroup(ctx context.Context, providerName, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, providerName, userID, groupID string) error
	GetUserGroups(ctx context.Context, providerName, userID string) ([]*types.DirectoryGroup, error)
	GetGroupMembers(ctx context.Context, providerName, groupID string) ([]*types.DirectoryUser, error)

	// Organizational Structure (AD-specific concepts with graceful degradation)
	GetOU(ctx context.Context, providerName, ouID string) (*OrganizationalUnit, error)
	CreateOU(ctx context.Context, providerName string, ou *OrganizationalUnit) (*OrganizationalUnit, error)
	UpdateOU(ctx context.Context, providerName, ouID string, updates *OrganizationalUnit) (*OrganizationalUnit, error)
	DeleteOU(ctx context.Context, providerName, ouID string) error
	ListOUs(ctx context.Context, providerName string) ([]*OrganizationalUnit, error)

	// Administrative Units (Entra ID-specific with graceful degradation)
	GetAdminUnit(ctx context.Context, providerName, unitID string) (*AdministrativeUnit, error)
	CreateAdminUnit(ctx context.Context, providerName string, unit *AdministrativeUnit) (*AdministrativeUnit, error)
	UpdateAdminUnit(ctx context.Context, providerName, unitID string, updates *AdministrativeUnit) (*AdministrativeUnit, error)
	DeleteAdminUnit(ctx context.Context, providerName, unitID string) error
	ListAdminUnits(ctx context.Context, providerName string) ([]*AdministrativeUnit, error)

	// Cross-Provider Operations
	SyncUser(ctx context.Context, sourceProvider, targetProvider, userID string) error
	SyncGroup(ctx context.Context, sourceProvider, targetProvider, groupID string) error
	CompareDirectories(ctx context.Context, provider1, provider2 string) (*DirectoryComparison, error)

	// Health and Statistics
	GetProviderHealth(ctx context.Context, providerName string) (*ProviderHealth, error)
	GetProviderStatistics(ctx context.Context, providerName string) (*ProviderStatistics, error)
}

// Provider represents a directory provider that the controller can work with.
// Providers are implemented by modules (activedirectory, entra_user, etc.)
type Provider interface {
	// Metadata
	Name() string
	DisplayName() string
	Description() string
	Capabilities() ProviderCapabilities

	// Connection Management
	Connect(ctx context.Context, config ProviderConfig) error
	Disconnect(ctx context.Context) error
	IsConnected() bool
	HealthCheck(ctx context.Context) (*ProviderHealth, error)

	// Core Operations (modules implement these based on their capabilities)
	GetUser(ctx context.Context, userID string) (*types.DirectoryUser, error)
	CreateUser(ctx context.Context, user *types.DirectoryUser) (*types.DirectoryUser, error)
	UpdateUser(ctx context.Context, userID string, updates *types.DirectoryUser) (*types.DirectoryUser, error)
	DeleteUser(ctx context.Context, userID string) error
	SearchUsers(ctx context.Context, query *SearchQuery) ([]*types.DirectoryUser, error)

	GetGroup(ctx context.Context, groupID string) (*types.DirectoryGroup, error)
	CreateGroup(ctx context.Context, group *types.DirectoryGroup) (*types.DirectoryGroup, error)
	UpdateGroup(ctx context.Context, groupID string, updates *types.DirectoryGroup) (*types.DirectoryGroup, error)
	DeleteGroup(ctx context.Context, groupID string) error
	SearchGroups(ctx context.Context, query *SearchQuery) ([]*types.DirectoryGroup, error)

	// Membership
	AddUserToGroup(ctx context.Context, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, userID, groupID string) error
	GetUserGroups(ctx context.Context, userID string) ([]*types.DirectoryGroup, error)
	GetGroupMembers(ctx context.Context, groupID string) ([]*types.DirectoryUser, error)

	// Optional: Organizational Structure (implement if supported)
	SupportsOUs() bool
	GetOU(ctx context.Context, ouID string) (*OrganizationalUnit, error)
	CreateOU(ctx context.Context, ou *OrganizationalUnit) (*OrganizationalUnit, error)
	UpdateOU(ctx context.Context, ouID string, updates *OrganizationalUnit) (*OrganizationalUnit, error)
	DeleteOU(ctx context.Context, ouID string) error
	ListOUs(ctx context.Context) ([]*OrganizationalUnit, error)

	// Optional: Administrative Units (implement if supported)
	SupportsAdminUnits() bool
	GetAdminUnit(ctx context.Context, unitID string) (*AdministrativeUnit, error)
	CreateAdminUnit(ctx context.Context, unit *AdministrativeUnit) (*AdministrativeUnit, error)
	UpdateAdminUnit(ctx context.Context, unitID string, updates *AdministrativeUnit) (*AdministrativeUnit, error)
	DeleteAdminUnit(ctx context.Context, unitID string) error
	ListAdminUnits(ctx context.Context) ([]*AdministrativeUnit, error)
}

// Supporting Types

// ProviderInfo contains metadata about a directory provider
type ProviderInfo struct {
	Name         string               `json:"name"`         // e.g., "activedirectory", "entraid"
	DisplayName  string               `json:"display_name"` // e.g., "Active Directory"
	Description  string               `json:"description"`  // Provider description
	Capabilities ProviderCapabilities `json:"capabilities"` // What this provider supports
	ModuleName   string               `json:"module_name"`  // Which module implements this provider
	Version      string               `json:"version"`      // Provider version
}

// ProviderCapabilities describes what operations a provider supports
type ProviderCapabilities struct {
	// Core operations
	UserManagement  bool `json:"user_management"`
	GroupManagement bool `json:"group_management"`

	// Advanced features
	AdvancedSearch    bool `json:"advanced_search"`
	BulkOperations    bool `json:"bulk_operations"`
	RealTimeSync      bool `json:"real_time_sync"`
	CrossDirectoryOps bool `json:"cross_directory_ops"`

	// Provider-specific features
	OUSupport        bool `json:"ou_support"`         // Active Directory OUs
	AdminUnitSupport bool `json:"admin_unit_support"` // Entra ID Administrative Units

	// Authentication
	SupportedAuthMethods []string `json:"supported_auth_methods"`

	// Limits
	MaxSearchResults int            `json:"max_search_results"`
	RateLimit        *RateLimitInfo `json:"rate_limit,omitempty"`
}

// SearchQuery represents a directory search query
type SearchQuery struct {
	// Basic search
	Query  string `json:"query"`  // Free text search
	Filter string `json:"filter"` // Advanced filter (LDAP-style or OData)

	// Object type filter
	ObjectType ObjectType `json:"object_type"` // Users, Groups, OUs, etc.

	// Scoping
	SearchBase string      `json:"search_base,omitempty"` // OU/container to search in
	Scope      SearchScope `json:"scope"`                 // Base, OneLevel, Subtree

	// Results
	Attributes []string `json:"attributes,omitempty"` // Specific attributes to return
	Limit      int      `json:"limit"`                // Maximum results
	Offset     int      `json:"offset"`               // Pagination offset
	Sort       string   `json:"sort,omitempty"`       // Sort field and direction
}

// ObjectType represents the type of directory object
type ObjectType string

const (
	ObjectTypeUser      ObjectType = "user"
	ObjectTypeGroup     ObjectType = "group"
	ObjectTypeOU        ObjectType = "organizational_unit"
	ObjectTypeAdminUnit ObjectType = "administrative_unit"
	ObjectTypeAll       ObjectType = "all"
)

// SearchScope defines the scope of directory searches
type SearchScope string

const (
	SearchScopeBase     SearchScope = "base"      // Search only the base object
	SearchScopeOneLevel SearchScope = "one_level" // Search one level below base
	SearchScopeSubtree  SearchScope = "subtree"   // Search entire subtree
)

// OrganizationalUnit represents an Active Directory OU (with graceful degradation for other providers)
type OrganizationalUnit struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	DisplayName       string    `json:"display_name"`
	Description       string    `json:"description,omitempty"`
	DistinguishedName string    `json:"distinguished_name"`
	ParentOU          string    `json:"parent_ou,omitempty"`
	Created           time.Time `json:"created,omitempty"`
	Modified          time.Time `json:"modified,omitempty"`
	Source            string    `json:"source"`
}

// AdministrativeUnit represents an Entra ID Administrative Unit (with graceful degradation)
type AdministrativeUnit struct {
	ID                            string    `json:"id"`
	DisplayName                   string    `json:"display_name"`
	Description                   string    `json:"description,omitempty"`
	Visibility                    string    `json:"visibility,omitempty"`                       // Public, HiddenMembership
	MembershipType                string    `json:"membership_type,omitempty"`                  // Assigned, Dynamic
	MembershipRule                string    `json:"membership_rule,omitempty"`                  // Dynamic membership rule
	MembershipRuleProcessingState string    `json:"membership_rule_processing_state,omitempty"` // On, Paused
	Created                       time.Time `json:"created,omitempty"`
	Modified                      time.Time `json:"modified,omitempty"`
	Source                        string    `json:"source"`
}

// ProviderConfig contains configuration for a directory provider
type ProviderConfig struct {
	ProviderName string                 `json:"provider_name"`
	Settings     map[string]interface{} `json:"settings"`    // Provider-specific settings
	Credentials  map[string]string      `json:"credentials"` // Authentication credentials
	Options      map[string]interface{} `json:"options"`     // Optional configuration
}

// ProviderHealth represents the health status of a directory provider
type ProviderHealth struct {
	IsHealthy    bool                   `json:"is_healthy"`
	LastCheck    time.Time              `json:"last_check"`
	ResponseTime time.Duration          `json:"response_time"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
	Capabilities ProviderCapabilities   `json:"capabilities"`
}

// ProviderStatistics contains statistics about provider usage
type ProviderStatistics struct {
	TotalUsers      int64         `json:"total_users"`
	TotalGroups     int64         `json:"total_groups"`
	TotalOUs        int64         `json:"total_ous"`
	TotalAdminUnits int64         `json:"total_admin_units"`
	RequestCount    int64         `json:"request_count"`
	ErrorCount      int64         `json:"error_count"`
	AverageLatency  time.Duration `json:"average_latency"`
	LastSyncTime    time.Time     `json:"last_sync_time,omitempty"`
}

// DirectoryComparison represents the result of comparing two directories
type DirectoryComparison struct {
	Provider1        string                     `json:"provider1"`
	Provider2        string                     `json:"provider2"`
	ComparisonTime   time.Time                  `json:"comparison_time"`
	UserDifferences  []ObjectDifference         `json:"user_differences,omitempty"`
	GroupDifferences []ObjectDifference         `json:"group_differences,omitempty"`
	Summary          DirectoryComparisonSummary `json:"summary"`
}

// ObjectDifference represents a difference between directory objects
type ObjectDifference struct {
	ObjectType ObjectType `json:"object_type"`
	ObjectID   string     `json:"object_id"`
	Action     string     `json:"action"` // "create", "update", "delete"
	Field      string     `json:"field,omitempty"`
	OldValue   string     `json:"old_value,omitempty"`
	NewValue   string     `json:"new_value,omitempty"`
}

// DirectoryComparisonSummary provides a summary of directory differences
type DirectoryComparisonSummary struct {
	TotalDifferences int `json:"total_differences"`
	UsersToCreate    int `json:"users_to_create"`
	UsersToUpdate    int `json:"users_to_update"`
	UsersToDelete    int `json:"users_to_delete"`
	GroupsToCreate   int `json:"groups_to_create"`
	GroupsToUpdate   int `json:"groups_to_update"`
	GroupsToDelete   int `json:"groups_to_delete"`
}

// RateLimitInfo describes rate limiting for a provider
type RateLimitInfo struct {
	RequestsPerSecond int    `json:"requests_per_second"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	BurstSize         int    `json:"burst_size"`
	BackoffStrategy   string `json:"backoff_strategy"`
}
