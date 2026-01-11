// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package dna - DirectoryDNA Collector Implementation
//
// This file implements the DirectoryDNA collector that treats directory objects
// (users, groups, OUs) as individual DNA-enabled entities for comprehensive
// drift detection and change monitoring in hybrid identity environments.

package dna

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// DefaultDirectoryDNACollector is the default implementation of DirectoryDNACollector.
//
// This collector integrates with directory providers to collect DNA from directory objects,
// following CFGMS patterns for real component testing and comprehensive functionality.
type DefaultDirectoryDNACollector struct {
	provider interfaces.DirectoryProvider
	logger   logging.Logger

	// Configuration
	config *CollectorConfig

	// State management
	mutex sync.RWMutex
	stats *CollectionStats

	// Caching for performance
	providerInfo interfaces.ProviderInfo
	capabilities DirectoryCollectionCapabilities
}

// CollectorConfig defines configuration for the directory DNA collector.
type CollectorConfig struct {
	// Collection Settings
	BatchSize         int           `json:"batch_size"`         // Objects per batch
	CollectionTimeout time.Duration `json:"collection_timeout"` // Timeout per collection
	RetryAttempts     int           `json:"retry_attempts"`     // Number of retries
	RetryDelay        time.Duration `json:"retry_delay"`        // Delay between retries

	// Filtering
	IncludeUsers     bool     `json:"include_users"`               // Collect user DNA
	IncludeGroups    bool     `json:"include_groups"`              // Collect group DNA
	IncludeOUs       bool     `json:"include_ous"`                 // Collect OU DNA
	ExcludedOUs      []string `json:"excluded_ous,omitempty"`      // OUs to skip
	AttributeFilters []string `json:"attribute_filters,omitempty"` // Attributes to include

	// Performance
	MaxConcurrency  int           `json:"max_concurrency"`  // Max concurrent collections
	CacheTTL        time.Duration `json:"cache_ttl"`        // Cache time-to-live
	EnableProfiling bool          `json:"enable_profiling"` // Enable performance profiling

	// Multi-tenancy
	TenantID      string            `json:"tenant_id,omitempty"`      // Tenant identifier
	TenantContext map[string]string `json:"tenant_context,omitempty"` // Additional tenant context
}

// CollectionStats provides statistics about DNA collection performance.
type CollectionStats struct {
	// Collection Metrics
	TotalCollections      int64 `json:"total_collections"`
	SuccessfulCollections int64 `json:"successful_collections"`
	FailedCollections     int64 `json:"failed_collections"`

	// Performance Metrics
	AverageCollectionTime time.Duration `json:"avg_collection_time"`
	LastCollectionTime    time.Duration `json:"last_collection_time"`
	TotalCollectionTime   time.Duration `json:"total_collection_time"`

	// Object Metrics
	UsersCollected         int64 `json:"users_collected"`
	GroupsCollected        int64 `json:"groups_collected"`
	OUsCollected           int64 `json:"ous_collected"`
	RelationshipsCollected int64 `json:"relationships_collected"`

	// Error Metrics
	LastError        string    `json:"last_error,omitempty"`
	ErrorCount       int64     `json:"error_count"`
	LastCollectionAt time.Time `json:"last_collection_at"`

	// Health Metrics
	HealthStatus    string    `json:"health_status"`
	LastHealthCheck time.Time `json:"last_health_check"`
}

// NewDirectoryDNACollector creates a new directory DNA collector.
//
// This follows CFGMS patterns by accepting interfaces and real components for testing.
func NewDirectoryDNACollector(provider interfaces.DirectoryProvider, logger logging.Logger) *DefaultDirectoryDNACollector {
	return &DefaultDirectoryDNACollector{
		provider: provider,
		logger:   logger,
		config:   getDefaultCollectorConfig(),
		stats: &CollectionStats{
			HealthStatus:    "unknown",
			LastHealthCheck: time.Now(),
		},
	}
}

// NewDirectoryDNACollectorWithConfig creates a collector with custom configuration.
func NewDirectoryDNACollectorWithConfig(provider interfaces.DirectoryProvider, logger logging.Logger, config *CollectorConfig) *DefaultDirectoryDNACollector {
	collector := NewDirectoryDNACollector(provider, logger)
	collector.config = config
	return collector
}

// getDefaultCollectorConfig returns the default collector configuration.
func getDefaultCollectorConfig() *CollectorConfig {
	return &CollectorConfig{
		BatchSize:         100,
		CollectionTimeout: 30 * time.Second,
		RetryAttempts:     3,
		RetryDelay:        time.Second,
		IncludeUsers:      true,
		IncludeGroups:     true,
		IncludeOUs:        true,
		MaxConcurrency:    5,
		CacheTTL:          5 * time.Minute,
		EnableProfiling:   false,
	}
}

// Individual Object Collection Methods

// CollectUserDNA collects DNA for a specific user.
func (c *DefaultDirectoryDNACollector) CollectUserDNA(ctx context.Context, userID string) (*DirectoryDNA, error) {
	startTime := time.Now()
	c.logger.Debug("Collecting user DNA", "user_id", userID)

	// Get user from provider
	user, err := c.provider.GetUser(ctx, userID)
	if err != nil {
		c.recordError("failed to get user", err)
		return nil, fmt.Errorf("failed to get user %s: %w", userID, err)
	}

	// Collect relationships
	relationships, err := c.CollectRelationships(ctx, userID)
	if err != nil {
		c.logger.Warn("Failed to collect user relationships", "user_id", userID, "error", err)
		// Continue without relationships rather than failing completely
	}

	// Generate DNA
	dna, err := c.generateUserDNA(user, relationships)
	if err != nil {
		c.recordError("failed to generate user DNA", err)
		return nil, fmt.Errorf("failed to generate DNA for user %s: %w", userID, err)
	}

	// Update statistics
	c.mutex.Lock()
	c.stats.UsersCollected++
	c.stats.LastCollectionTime = time.Since(startTime)
	c.stats.TotalCollections++
	c.stats.SuccessfulCollections++
	c.mutex.Unlock()

	c.logger.Debug("User DNA collected successfully",
		"user_id", userID,
		"dna_id", dna.ID,
		"attributes", len(dna.Attributes),
		"duration", time.Since(startTime))

	return dna, nil
}

// CollectGroupDNA collects DNA for a specific group.
func (c *DefaultDirectoryDNACollector) CollectGroupDNA(ctx context.Context, groupID string) (*DirectoryDNA, error) {
	startTime := time.Now()
	c.logger.Debug("Collecting group DNA", "group_id", groupID)

	// Get group from provider
	group, err := c.provider.GetGroup(ctx, groupID)
	if err != nil {
		c.recordError("failed to get group", err)
		return nil, fmt.Errorf("failed to get group %s: %w", groupID, err)
	}

	// Collect relationships (members)
	relationships, err := c.CollectRelationships(ctx, groupID)
	if err != nil {
		c.logger.Warn("Failed to collect group relationships", "group_id", groupID, "error", err)
		// Continue without relationships rather than failing completely
	}

	// Generate DNA
	dna, err := c.generateGroupDNA(group, relationships)
	if err != nil {
		c.recordError("failed to generate group DNA", err)
		return nil, fmt.Errorf("failed to generate DNA for group %s: %w", groupID, err)
	}

	// Update statistics
	c.mutex.Lock()
	c.stats.GroupsCollected++
	c.stats.LastCollectionTime = time.Since(startTime)
	c.stats.TotalCollections++
	c.stats.SuccessfulCollections++
	c.mutex.Unlock()

	c.logger.Debug("Group DNA collected successfully",
		"group_id", groupID,
		"dna_id", dna.ID,
		"attributes", len(dna.Attributes),
		"duration", time.Since(startTime))

	return dna, nil
}

// CollectOUDNA collects DNA for a specific organizational unit.
func (c *DefaultDirectoryDNACollector) CollectOUDNA(ctx context.Context, ouID string) (*DirectoryDNA, error) {
	startTime := time.Now()
	c.logger.Debug("Collecting OU DNA", "ou_id", ouID)

	// Get OU from provider
	ou, err := c.provider.GetOU(ctx, ouID)
	if err != nil {
		c.recordError("failed to get OU", err)
		return nil, fmt.Errorf("failed to get OU %s: %w", ouID, err)
	}

	// Collect relationships (parent/child OUs, contained objects)
	relationships, err := c.CollectRelationships(ctx, ouID)
	if err != nil {
		c.logger.Warn("Failed to collect OU relationships", "ou_id", ouID, "error", err)
		// Continue without relationships rather than failing completely
	}

	// Generate DNA
	dna, err := c.generateOUDNA(ou, relationships)
	if err != nil {
		c.recordError("failed to generate OU DNA", err)
		return nil, fmt.Errorf("failed to generate DNA for OU %s: %w", ouID, err)
	}

	// Update statistics
	c.mutex.Lock()
	c.stats.OUsCollected++
	c.stats.LastCollectionTime = time.Since(startTime)
	c.stats.TotalCollections++
	c.stats.SuccessfulCollections++
	c.mutex.Unlock()

	c.logger.Debug("OU DNA collected successfully",
		"ou_id", ouID,
		"dna_id", dna.ID,
		"attributes", len(dna.Attributes),
		"duration", time.Since(startTime))

	return dna, nil
}

// Bulk Collection Methods

// CollectAllUsers collects DNA for all users matching the given filters.
func (c *DefaultDirectoryDNACollector) CollectAllUsers(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error) {
	if !c.config.IncludeUsers {
		return nil, nil
	}

	startTime := time.Now()
	c.logger.Info("Collecting DNA for all users")

	// Set up filters if not provided, but don't set limit for "collect all"
	if filters == nil {
		filters = &interfaces.SearchFilters{}
	}
	// Note: We intentionally don't set a default limit for CollectAllUsers
	// to allow collecting all users when no limit is specified

	var allDNA []*DirectoryDNA
	var totalUsers int

	for {
		// Get users from provider
		userList, err := c.provider.ListUsers(ctx, filters)
		if err != nil {
			c.recordError("failed to list users", err)
			return nil, fmt.Errorf("failed to list users: %w", err)
		}

		if len(userList.Users) == 0 {
			break
		}

		// Collect DNA for this batch
		batchDNA, err := c.collectUserBatchDNA(ctx, userList.Users)
		if err != nil {
			c.recordError("failed to collect user batch DNA", err)
			return nil, fmt.Errorf("failed to collect user batch DNA: %w", err)
		}

		allDNA = append(allDNA, batchDNA...)
		totalUsers += len(userList.Users)

		// Check if we have more users
		if !userList.HasMore {
			break
		}

		// Update offset for next page
		filters.Offset += len(userList.Users)
	}

	c.logger.Info("Completed user DNA collection",
		"total_users", totalUsers,
		"total_dna_records", len(allDNA),
		"duration", time.Since(startTime))

	return allDNA, nil
}

// CollectAllGroups collects DNA for all groups matching the given filters.
func (c *DefaultDirectoryDNACollector) CollectAllGroups(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error) {
	if !c.config.IncludeGroups {
		return nil, nil
	}

	startTime := time.Now()
	c.logger.Info("Collecting DNA for all groups")

	// Set up filters if not provided, but don't set limit for "collect all"
	if filters == nil {
		filters = &interfaces.SearchFilters{}
	}
	// Note: We intentionally don't set a default limit for CollectAllGroups
	// to allow collecting all groups when no limit is specified

	var allDNA []*DirectoryDNA
	var totalGroups int

	for {
		// Get groups from provider
		groupList, err := c.provider.ListGroups(ctx, filters)
		if err != nil {
			c.recordError("failed to list groups", err)
			return nil, fmt.Errorf("failed to list groups: %w", err)
		}

		if len(groupList.Groups) == 0 {
			break
		}

		// Collect DNA for this batch
		batchDNA, err := c.collectGroupBatchDNA(ctx, groupList.Groups)
		if err != nil {
			c.recordError("failed to collect group batch DNA", err)
			return nil, fmt.Errorf("failed to collect group batch DNA: %w", err)
		}

		allDNA = append(allDNA, batchDNA...)
		totalGroups += len(groupList.Groups)

		// Check if we have more groups
		if !groupList.HasMore {
			break
		}

		// Update offset for next page
		filters.Offset += len(groupList.Groups)
	}

	c.logger.Info("Completed group DNA collection",
		"total_groups", totalGroups,
		"total_dna_records", len(allDNA),
		"duration", time.Since(startTime))

	return allDNA, nil
}

// CollectAllOUs collects DNA for all organizational units matching the given filters.
func (c *DefaultDirectoryDNACollector) CollectAllOUs(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error) {
	if !c.config.IncludeOUs {
		return nil, nil
	}

	startTime := time.Now()
	c.logger.Info("Collecting DNA for all OUs")

	// Set up filters if not provided, but don't set limit for "collect all"
	if filters == nil {
		filters = &interfaces.SearchFilters{}
	}
	// Note: We intentionally don't set a default limit for CollectAllOUs
	// to allow collecting all OUs when no limit is specified

	var allDNA []*DirectoryDNA
	var totalOUs int

	for {
		// Get OUs from provider
		ouList, err := c.provider.ListOUs(ctx, filters)
		if err != nil {
			c.recordError("failed to list OUs", err)
			return nil, fmt.Errorf("failed to list OUs: %w", err)
		}

		if len(ouList.OUs) == 0 {
			break
		}

		// Collect DNA for this batch
		batchDNA, err := c.collectOUBatchDNA(ctx, ouList.OUs)
		if err != nil {
			c.recordError("failed to collect OU batch DNA", err)
			return nil, fmt.Errorf("failed to collect OU batch DNA: %w", err)
		}

		allDNA = append(allDNA, batchDNA...)
		totalOUs += len(ouList.OUs)

		// Check if we have more OUs
		if !ouList.HasMore {
			break
		}

		// Update offset for next page
		filters.Offset += len(ouList.OUs)
	}

	c.logger.Info("Completed OU DNA collection",
		"total_ous", totalOUs,
		"total_dna_records", len(allDNA),
		"duration", time.Since(startTime))

	return allDNA, nil
}

// CollectAll collects DNA for all directory objects (users, groups, OUs).
func (c *DefaultDirectoryDNACollector) CollectAll(ctx context.Context) ([]*DirectoryDNA, error) {
	startTime := time.Now()
	c.logger.Info("Collecting DNA for all directory objects")

	var allDNA []*DirectoryDNA
	var errors []error

	// Collect user DNA
	if c.config.IncludeUsers {
		userDNA, err := c.CollectAllUsers(ctx, nil)
		if err != nil {
			errors = append(errors, fmt.Errorf("user collection failed: %w", err))
		} else {
			allDNA = append(allDNA, userDNA...)
		}
	}

	// Collect group DNA
	if c.config.IncludeGroups {
		groupDNA, err := c.CollectAllGroups(ctx, nil)
		if err != nil {
			errors = append(errors, fmt.Errorf("group collection failed: %w", err))
		} else {
			allDNA = append(allDNA, groupDNA...)
		}
	}

	// Collect OU DNA
	if c.config.IncludeOUs {
		ouDNA, err := c.CollectAllOUs(ctx, nil)
		if err != nil {
			errors = append(errors, fmt.Errorf("OU collection failed: %w", err))
		} else {
			allDNA = append(allDNA, ouDNA...)
		}
	}

	// Update final statistics
	c.mutex.Lock()
	c.stats.LastCollectionAt = time.Now()
	c.stats.TotalCollectionTime += time.Since(startTime)
	if len(errors) > 0 {
		c.stats.FailedCollections++
		c.stats.LastError = fmt.Sprintf("partial collection failed: %v", errors)
	}
	c.mutex.Unlock()

	// Log results
	duration := time.Since(startTime)
	if len(errors) > 0 {
		c.logger.Warn("Completed directory DNA collection with errors",
			"total_objects", len(allDNA),
			"errors", len(errors),
			"duration", duration)
		// Return partial results with error details
		return allDNA, fmt.Errorf("collection completed with %d errors: %v", len(errors), errors)
	}

	c.logger.Info("Completed directory DNA collection successfully",
		"total_objects", len(allDNA),
		"users", c.stats.UsersCollected,
		"groups", c.stats.GroupsCollected,
		"ous", c.stats.OUsCollected,
		"duration", duration)

	return allDNA, nil
}

// DNA Generation Methods

// generateUserDNA creates a DirectoryDNA record for a user.
func (c *DefaultDirectoryDNACollector) generateUserDNA(user *interfaces.DirectoryUser, relationships *DirectoryRelationships) (*DirectoryDNA, error) {
	attributes := make(map[string]string)

	// Core identity attributes
	attributes["user_principal_name"] = user.UserPrincipalName
	attributes["sam_account_name"] = user.SAMAccountName
	attributes["display_name"] = user.DisplayName
	attributes["account_enabled"] = strconv.FormatBool(user.AccountEnabled)

	// Contact information
	if user.EmailAddress != "" {
		attributes["email_address"] = user.EmailAddress
	}
	if user.PhoneNumber != "" {
		attributes["phone_number"] = user.PhoneNumber
	}
	if user.MobilePhone != "" {
		attributes["mobile_phone"] = user.MobilePhone
	}

	// Organizational information
	if user.Department != "" {
		attributes["department"] = user.Department
	}
	if user.JobTitle != "" {
		attributes["job_title"] = user.JobTitle
	}
	if user.Manager != "" {
		attributes["manager"] = user.Manager
	}
	if user.OfficeLocation != "" {
		attributes["office_location"] = user.OfficeLocation
	}
	if user.Company != "" {
		attributes["company"] = user.Company
	}

	// Directory structure
	if user.DistinguishedName != "" {
		attributes["distinguished_name"] = user.DistinguishedName
	}
	if user.OU != "" {
		attributes["ou"] = user.OU
	}

	// Group memberships
	if len(user.Groups) > 0 {
		attributes["group_count"] = strconv.Itoa(len(user.Groups))
		attributes["groups"] = strings.Join(user.Groups, ",")
	}

	// Authentication attributes
	if user.PasswordExpiry != nil {
		attributes["password_expiry"] = user.PasswordExpiry.Format(time.RFC3339)
	}
	if user.LastLogon != nil {
		attributes["last_logon"] = user.LastLogon.Format(time.RFC3339)
	}

	// Provider-specific attributes
	for key, value := range user.ProviderAttributes {
		if strValue, ok := value.(string); ok {
			attributes[fmt.Sprintf("provider_%s", key)] = strValue
		}
	}

	// Metadata attributes
	attributes["object_type"] = string(interfaces.DirectoryObjectTypeUser)
	attributes["provider"] = c.provider.GetProviderInfo().Name
	if c.config.TenantID != "" {
		attributes["tenant_id"] = c.config.TenantID
	}
	attributes["collected_at"] = time.Now().Format(time.RFC3339)

	// Generate DNA ID from stable identifiers
	dnaID := c.generateDNAID(user.ID, interfaces.DirectoryObjectTypeUser, attributes)

	// Create DirectoryDNA record
	now := time.Now()
	dna := &DirectoryDNA{
		ObjectID:    user.ID,
		ObjectType:  interfaces.DirectoryObjectTypeUser,
		ID:          dnaID,
		Attributes:  attributes,
		LastUpdated: &now,

		// Directory-specific metadata
		Provider:          c.provider.GetProviderInfo().Name,
		TenantID:          c.config.TenantID,
		DistinguishedName: user.DistinguishedName,

		// Object state
		ObjectState: &DirectoryObjectState{
			User:           user,
			CollectedAt:    now,
			CollectionTime: 0, // Will be set by caller
		},

		// Relationships
		Relationships: c.extractRelationshipIDs(relationships),

		// DNA framework compatibility
		AttributeCount: func() int32 {
			count := len(attributes)
			if count > math.MaxInt32 {
				return math.MaxInt32
			}
			return int32(count)
		}(),
		SyncFingerprint: c.generateSyncFingerprint(dnaID, attributes),

		// Change tracking
		ChangeCount: 0, // Will be updated during drift detection
	}

	return dna, nil
}

// generateGroupDNA creates a DirectoryDNA record for a group.
func (c *DefaultDirectoryDNACollector) generateGroupDNA(group *interfaces.DirectoryGroup, relationships *DirectoryRelationships) (*DirectoryDNA, error) {
	attributes := make(map[string]string)

	// Core identity attributes
	attributes["name"] = group.Name
	attributes["display_name"] = group.DisplayName
	attributes["group_type"] = string(group.GroupType)
	attributes["group_scope"] = string(group.GroupScope)

	// Description
	if group.Description != "" {
		attributes["description"] = group.Description
	}

	// Email address (for distribution groups) - check provider attributes
	if emailAddr, exists := group.ProviderAttributes["email_address"]; exists {
		if emailStr, ok := emailAddr.(string); ok && emailStr != "" {
			attributes["email_address"] = emailStr
		}
	}

	// Directory structure
	if group.DistinguishedName != "" {
		attributes["distinguished_name"] = group.DistinguishedName
	}
	if group.OU != "" {
		attributes["ou"] = group.OU
	}

	// Members
	if len(group.Members) > 0 {
		attributes["member_count"] = strconv.Itoa(len(group.Members))
		attributes["members"] = strings.Join(group.Members, ",")
	}

	// Provider-specific attributes
	for key, value := range group.ProviderAttributes {
		if strValue, ok := value.(string); ok {
			attributes[fmt.Sprintf("provider_%s", key)] = strValue
		}
	}

	// Metadata attributes
	attributes["object_type"] = string(interfaces.DirectoryObjectTypeGroup)
	attributes["provider"] = c.provider.GetProviderInfo().Name
	if c.config.TenantID != "" {
		attributes["tenant_id"] = c.config.TenantID
	}
	attributes["collected_at"] = time.Now().Format(time.RFC3339)

	// Generate DNA ID from stable identifiers
	dnaID := c.generateDNAID(group.ID, interfaces.DirectoryObjectTypeGroup, attributes)

	// Create DirectoryDNA record
	now := time.Now()
	dna := &DirectoryDNA{
		ObjectID:    group.ID,
		ObjectType:  interfaces.DirectoryObjectTypeGroup,
		ID:          dnaID,
		Attributes:  attributes,
		LastUpdated: &now,

		// Directory-specific metadata
		Provider:          c.provider.GetProviderInfo().Name,
		TenantID:          c.config.TenantID,
		DistinguishedName: group.DistinguishedName,

		// Object state
		ObjectState: &DirectoryObjectState{
			Group:          group,
			CollectedAt:    now,
			CollectionTime: 0, // Will be set by caller
		},

		// Relationships
		Relationships: c.extractRelationshipIDs(relationships),

		// DNA framework compatibility
		AttributeCount: func() int32 {
			count := len(attributes)
			if count > math.MaxInt32 {
				return math.MaxInt32
			}
			return int32(count)
		}(),
		SyncFingerprint: c.generateSyncFingerprint(dnaID, attributes),

		// Change tracking
		ChangeCount: 0, // Will be updated during drift detection
	}

	return dna, nil
}

// generateOUDNA creates a DirectoryDNA record for an organizational unit.
func (c *DefaultDirectoryDNACollector) generateOUDNA(ou *interfaces.OrganizationalUnit, relationships *DirectoryRelationships) (*DirectoryDNA, error) {
	attributes := make(map[string]string)

	// Core identity attributes
	attributes["name"] = ou.Name
	attributes["display_name"] = ou.DisplayName

	// Description
	if ou.Description != "" {
		attributes["description"] = ou.Description
	}

	// Directory structure
	attributes["distinguished_name"] = ou.DistinguishedName
	if ou.ParentOU != "" {
		attributes["parent_ou"] = ou.ParentOU
	}

	// Provider-specific attributes
	for key, value := range ou.ProviderAttributes {
		if strValue, ok := value.(string); ok {
			attributes[fmt.Sprintf("provider_%s", key)] = strValue
		}
	}

	// Metadata attributes
	attributes["object_type"] = string(interfaces.DirectoryObjectTypeOU)
	attributes["provider"] = c.provider.GetProviderInfo().Name
	if c.config.TenantID != "" {
		attributes["tenant_id"] = c.config.TenantID
	}
	attributes["collected_at"] = time.Now().Format(time.RFC3339)

	// Generate DNA ID from stable identifiers
	dnaID := c.generateDNAID(ou.ID, interfaces.DirectoryObjectTypeOU, attributes)

	// Create DirectoryDNA record
	now := time.Now()
	dna := &DirectoryDNA{
		ObjectID:    ou.ID,
		ObjectType:  interfaces.DirectoryObjectTypeOU,
		ID:          dnaID,
		Attributes:  attributes,
		LastUpdated: &now,

		// Directory-specific metadata
		Provider:          c.provider.GetProviderInfo().Name,
		TenantID:          c.config.TenantID,
		DistinguishedName: ou.DistinguishedName,

		// Object state
		ObjectState: &DirectoryObjectState{
			OU:             ou,
			CollectedAt:    now,
			CollectionTime: 0, // Will be set by caller
		},

		// Relationships
		Relationships: c.extractRelationshipIDs(relationships),

		// DNA framework compatibility
		AttributeCount: func() int32 {
			count := len(attributes)
			if count > math.MaxInt32 {
				return math.MaxInt32
			}
			return int32(count)
		}(),
		SyncFingerprint: c.generateSyncFingerprint(dnaID, attributes),

		// Change tracking
		ChangeCount: 0, // Will be updated during drift detection
	}

	return dna, nil
}

// Helper Methods

// generateDNAID creates a stable DNA identifier for directory objects.
func (c *DefaultDirectoryDNACollector) generateDNAID(objectID string, objectType interfaces.DirectoryObjectType, attributes map[string]string) string {
	// Use stable identifiers to generate DNA ID
	var identifiers []string

	// Primary identifier
	identifiers = append(identifiers, objectID)
	identifiers = append(identifiers, string(objectType))
	identifiers = append(identifiers, c.provider.GetProviderInfo().Name)

	// Add distinguished name if available (most stable for AD)
	if dn := attributes["distinguished_name"]; dn != "" {
		identifiers = append(identifiers, dn)
	}

	// Add tenant context
	if c.config.TenantID != "" {
		identifiers = append(identifiers, c.config.TenantID)
	}

	// Generate SHA256 hash of identifiers
	data := strings.Join(identifiers, "|")
	hash := sha256.Sum256([]byte(data))

	// Return first 16 characters of hex encoding with prefix
	return fmt.Sprintf("dir_%x", hash[:8])
}

// generateSyncFingerprint creates a fingerprint for sync verification.
func (c *DefaultDirectoryDNACollector) generateSyncFingerprint(dnaID string, attributes map[string]string) string {
	// Combine stable elements for sync verification
	elements := []string{
		dnaID,
		strconv.Itoa(len(attributes)),
		c.provider.GetProviderInfo().Name,
	}

	// Generate SHA256 hash
	data := strings.Join(elements, "|")
	hash := sha256.Sum256([]byte(data))

	// Return first 12 characters for compact representation
	return fmt.Sprintf("%x", hash[:6])
}

// extractRelationshipIDs extracts relationship IDs from DirectoryRelationships.
func (c *DefaultDirectoryDNACollector) extractRelationshipIDs(relationships *DirectoryRelationships) []string {
	if relationships == nil {
		return nil
	}

	var relationshipIDs []string

	// Add all related object IDs
	relationshipIDs = append(relationshipIDs, relationships.MemberOf...)
	relationshipIDs = append(relationshipIDs, relationships.Members...)
	relationshipIDs = append(relationshipIDs, relationships.ChildOUs...)
	relationshipIDs = append(relationshipIDs, relationships.UsersInOU...)
	relationshipIDs = append(relationshipIDs, relationships.GroupsInOU...)
	relationshipIDs = append(relationshipIDs, relationships.DirectReports...)

	if relationships.ParentOU != "" {
		relationshipIDs = append(relationshipIDs, relationships.ParentOU)
	}
	if relationships.Manager != "" {
		relationshipIDs = append(relationshipIDs, relationships.Manager)
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var unique []string
	for _, id := range relationshipIDs {
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}

	return unique
}

// recordError records an error in the collection statistics.
func (c *DefaultDirectoryDNACollector) recordError(operation string, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.stats.ErrorCount++
	c.stats.LastError = fmt.Sprintf("%s: %v", operation, err)
	c.stats.FailedCollections++

	c.logger.Error("Directory DNA collection error",
		"operation", operation,
		"error", err,
		"total_errors", c.stats.ErrorCount)
}

// GetProviderInfo returns information about the directory provider.
func (c *DefaultDirectoryDNACollector) GetProviderInfo() interfaces.ProviderInfo {
	if c.providerInfo.Name == "" {
		c.providerInfo = c.provider.GetProviderInfo()
	}
	return c.providerInfo
}

// GetCollectionCapabilities returns the collection capabilities.
func (c *DefaultDirectoryDNACollector) GetCollectionCapabilities() DirectoryCollectionCapabilities {
	if c.capabilities.MaxBatchSize == 0 {
		// Build capabilities based on provider capabilities
		providerCaps := c.provider.GetCapabilities()

		c.capabilities = DirectoryCollectionCapabilities{
			SupportsUsers:         providerCaps.SupportsUserManagement,
			SupportsGroups:        providerCaps.SupportsGroupManagement,
			SupportsOUs:           providerCaps.SupportsOUManagement,
			SupportsRelationships: true,          // Always supported through our collector
			SupportsPermissions:   true,          // Always supported through our collector
			SupportedAttributes:   []string{"*"}, // Support all attributes
			MaxBatchSize:          c.config.BatchSize,
			CollectionInterval:    c.config.CacheTTL,
		}
	}
	return c.capabilities
}

// GetCollectionStats returns current collection statistics.
func (c *DefaultDirectoryDNACollector) GetCollectionStats() *CollectionStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Return a copy to prevent race conditions
	statsCopy := *c.stats
	return &statsCopy
}

// SetCollectorConfig updates the collector configuration.
func (c *DefaultDirectoryDNACollector) SetCollectorConfig(config *CollectorConfig) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.config = config
}

// GetCollectorConfig returns the current collector configuration.
func (c *DefaultDirectoryDNACollector) GetCollectorConfig() *CollectorConfig {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Return a copy to prevent race conditions
	configCopy := *c.config
	return &configCopy
}

// Hierarchical Collection Methods

// CollectDomainDNA collects DNA for the entire directory domain.
//
// This method captures domain-level configuration, policies, and organizational
// structure for comprehensive domain drift detection and change monitoring.
func (c *DefaultDirectoryDNACollector) CollectDomainDNA(ctx context.Context) (*DomainDNA, error) {
	startTime := time.Now()
	c.logger.Info("Collecting domain DNA")

	providerInfo := c.provider.GetProviderInfo()

	// Generate domain DNA ID
	domainID := c.generateDomainDNAID(providerInfo.Name)

	// Collect domain-level statistics
	userStats, _ := c.provider.ListUsers(ctx, &interfaces.SearchFilters{Limit: 1})
	groupStats, _ := c.provider.ListGroups(ctx, &interfaces.SearchFilters{Limit: 1})
	ouStats, _ := c.provider.ListOUs(ctx, &interfaces.SearchFilters{Limit: 1})

	// Build domain attributes
	attributes := make(map[string]string)
	attributes["domain_name"] = providerInfo.Name
	attributes["provider_display_name"] = providerInfo.DisplayName
	attributes["provider_version"] = providerInfo.Version
	attributes["total_users"] = fmt.Sprintf("%d", userStats.TotalCount)
	attributes["total_groups"] = fmt.Sprintf("%d", groupStats.TotalCount)
	attributes["total_ous"] = fmt.Sprintf("%d", ouStats.TotalCount)
	attributes["collection_time"] = time.Since(startTime).String()

	if c.config.TenantID != "" {
		attributes["tenant_id"] = c.config.TenantID
	}

	// Get OU hierarchy for root containers
	hierarchy, err := c.CollectOUHierarchy(ctx)
	var rootContainers []string
	if err == nil {
		if hierarchy.RootOU != "" {
			rootContainers = append(rootContainers, hierarchy.RootOU)
		}
		// Find all root-level OUs
		for ouID, node := range hierarchy.Hierarchy {
			if node.ParentID == "" && ouID != hierarchy.RootOU {
				rootContainers = append(rootContainers, ouID)
			}
		}
	}

	// Create domain DNA record
	now := time.Now()
	domainDNA := &DomainDNA{
		DomainName:     providerInfo.Name,
		DomainID:       domainID,
		ID:             domainID,
		Attributes:     attributes,
		LastUpdated:    &now,
		RootContainers: rootContainers,
		TotalOUs:       ouStats.TotalCount,
		TotalUsers:     userStats.TotalCount,
		TotalGroups:    groupStats.TotalCount,
		Provider:       providerInfo.Name,
		TenantID:       c.config.TenantID,
		CollectedAt:    now,
		AttributeCount: func() int32 {
			count := len(attributes)
			if count > math.MaxInt32 {
				return math.MaxInt32
			}
			return int32(count)
		}(),
		SyncFingerprint: c.generateSyncFingerprint(domainID, attributes),
	}

	// Try to collect domain policies (provider-specific)
	if capabilities := c.provider.GetCapabilities(); capabilities.SupportsGroupManagement {
		// This would be enhanced with provider-specific policy collection
		domainDNA.DomainPolicies = make(map[string]interface{})
		domainDNA.SecuritySettings = make(map[string]interface{})
		domainDNA.PasswordPolicy = make(map[string]interface{})
	}

	c.logger.Info("Domain DNA collected successfully",
		"domain_name", domainDNA.DomainName,
		"total_objects", domainDNA.TotalUsers+domainDNA.TotalGroups+domainDNA.TotalOUs,
		"collection_time", time.Since(startTime))

	return domainDNA, nil
}

// CollectHierarchicalDNA collects DNA for a complete organizational hierarchy.
//
// This method captures the complete hierarchical structure starting from a root OU,
// including all child objects and their relationships for comprehensive drift detection.
func (c *DefaultDirectoryDNACollector) CollectHierarchicalDNA(ctx context.Context, rootOU string) (*HierarchicalDNA, error) {
	startTime := time.Now()
	c.logger.Info("Collecting hierarchical DNA", "root_ou", rootOU)

	// Generate hierarchy DNA ID
	hierarchyID := c.generateHierarchyDNAID(rootOU)

	// Collect OU hierarchy
	ouHierarchy, err := c.CollectOUHierarchy(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect OU hierarchy: %w", err)
	}

	// Filter hierarchy to include only descendants of rootOU
	filteredHierarchy := c.filterHierarchyFromRoot(ouHierarchy, rootOU)

	// Collect all objects in the hierarchy
	var allObjects []*DirectoryDNA
	objectsByType := make(map[interfaces.DirectoryObjectType][]*DirectoryDNA)
	var allRelationships []*DirectoryRelationships

	// Collect DNA for all OUs in the hierarchy
	for ouID := range filteredHierarchy.Hierarchy {
		if ouDNA, err := c.CollectOUDNA(ctx, ouID); err == nil {
			allObjects = append(allObjects, ouDNA)
			objectsByType[interfaces.DirectoryObjectTypeOU] = append(
				objectsByType[interfaces.DirectoryObjectTypeOU], ouDNA)
		}

		if relationships, err := c.CollectRelationships(ctx, ouID); err == nil {
			allRelationships = append(allRelationships, relationships)
		}
	}

	// Collect all users in the hierarchy
	for ouID, node := range filteredHierarchy.Hierarchy {
		if len(node.Children) > 0 || ouID == rootOU {
			// Collect users in this OU
			userFilters := &interfaces.SearchFilters{OU: ouID, Limit: 1000}
			userList, err := c.provider.ListUsers(ctx, userFilters)
			if err == nil {
				for _, user := range userList.Users {
					if userDNA, err := c.CollectUserDNA(ctx, user.ID); err == nil {
						allObjects = append(allObjects, userDNA)
						objectsByType[interfaces.DirectoryObjectTypeUser] = append(
							objectsByType[interfaces.DirectoryObjectTypeUser], userDNA)
					}

					if relationships, err := c.CollectRelationships(ctx, user.ID); err == nil {
						allRelationships = append(allRelationships, relationships)
					}
				}
			}

			// Collect groups in this OU
			groupFilters := &interfaces.SearchFilters{OU: ouID, Limit: 1000}
			groupList, err := c.provider.ListGroups(ctx, groupFilters)
			if err == nil {
				for _, group := range groupList.Groups {
					if groupDNA, err := c.CollectGroupDNA(ctx, group.ID); err == nil {
						allObjects = append(allObjects, groupDNA)
						objectsByType[interfaces.DirectoryObjectTypeGroup] = append(
							objectsByType[interfaces.DirectoryObjectTypeGroup], groupDNA)
					}

					if relationships, err := c.CollectRelationships(ctx, group.ID); err == nil {
						allRelationships = append(allRelationships, relationships)
					}
				}
			}
		}
	}

	// Collect group memberships
	allMemberships, err := c.CollectGroupMemberships(ctx)
	if err != nil {
		c.logger.Warn("Failed to collect group memberships for hierarchy", "root_ou", rootOU, "error", err)
	}

	// Calculate hierarchy statistics
	leafNodes := 0
	for _, node := range filteredHierarchy.Hierarchy {
		if len(node.Children) == 0 {
			leafNodes++
		}
	}

	// Build hierarchy attributes
	attributes := make(map[string]string)
	attributes["root_ou"] = rootOU
	attributes["max_depth"] = fmt.Sprintf("%d", filteredHierarchy.Depth)
	attributes["total_nodes"] = fmt.Sprintf("%d", len(filteredHierarchy.Hierarchy))
	attributes["leaf_nodes"] = fmt.Sprintf("%d", leafNodes)
	attributes["total_objects"] = fmt.Sprintf("%d", len(allObjects))
	attributes["total_users"] = fmt.Sprintf("%d", len(objectsByType[interfaces.DirectoryObjectTypeUser]))
	attributes["total_groups"] = fmt.Sprintf("%d", len(objectsByType[interfaces.DirectoryObjectTypeGroup]))
	attributes["total_ous"] = fmt.Sprintf("%d", len(objectsByType[interfaces.DirectoryObjectTypeOU]))
	attributes["total_relationships"] = fmt.Sprintf("%d", len(allRelationships))
	attributes["collection_time"] = time.Since(startTime).String()
	attributes["provider"] = c.provider.GetProviderInfo().Name

	if c.config.TenantID != "" {
		attributes["tenant_id"] = c.config.TenantID
	}

	// Create hierarchical DNA record
	now := time.Now()
	hierarchicalDNA := &HierarchicalDNA{
		RootOU:           rootOU,
		HierarchyID:      hierarchyID,
		ID:               hierarchyID,
		Attributes:       attributes,
		LastUpdated:      &now,
		Structure:        filteredHierarchy,
		AllObjects:       allObjects,
		ObjectsByType:    objectsByType,
		MaxDepth:         filteredHierarchy.Depth,
		TotalNodes:       len(filteredHierarchy.Hierarchy),
		LeafNodes:        leafNodes,
		AllRelationships: allRelationships,
		AllMemberships:   allMemberships,
		Provider:         c.provider.GetProviderInfo().Name,
		TenantID:         c.config.TenantID,
		CollectedAt:      now,
		CollectionTime:   time.Since(startTime),
		AttributeCount: func() int32 {
			count := len(attributes)
			if count > math.MaxInt32 {
				return math.MaxInt32
			}
			return int32(count)
		}(),
		SyncFingerprint: c.generateSyncFingerprint(hierarchyID, attributes),
	}

	c.logger.Info("Hierarchical DNA collected successfully",
		"root_ou", rootOU,
		"hierarchy_id", hierarchyID,
		"total_objects", len(allObjects),
		"max_depth", filteredHierarchy.Depth,
		"collection_time", time.Since(startTime))

	return hierarchicalDNA, nil
}

// Helper methods for domain and hierarchical collection

// generateDomainDNAID generates a unique DNA ID for a domain.
func (c *DefaultDirectoryDNACollector) generateDomainDNAID(domainName string) string {
	identifiers := []string{
		"domain",
		domainName,
		c.provider.GetProviderInfo().Name,
	}

	if c.config.TenantID != "" {
		identifiers = append(identifiers, c.config.TenantID)
	}

	data := strings.Join(identifiers, "|")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("domain_%x", hash[:8])
}

// generateHierarchyDNAID generates a unique DNA ID for a hierarchy.
func (c *DefaultDirectoryDNACollector) generateHierarchyDNAID(rootOU string) string {
	identifiers := []string{
		"hierarchy",
		rootOU,
		c.provider.GetProviderInfo().Name,
	}

	if c.config.TenantID != "" {
		identifiers = append(identifiers, c.config.TenantID)
	}

	data := strings.Join(identifiers, "|")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("hierarchy_%x", hash[:8])
}

// filterHierarchyFromRoot filters OU hierarchy to include only descendants of rootOU.
func (c *DefaultDirectoryDNACollector) filterHierarchyFromRoot(hierarchy *OUHierarchy, rootOU string) *OUHierarchy {
	if hierarchy == nil {
		return nil
	}

	// Start with the root OU
	filteredHierarchy := &OUHierarchy{
		RootOU:      rootOU,
		Hierarchy:   make(map[string]*OUNode),
		CollectedAt: hierarchy.CollectedAt,
		Provider:    hierarchy.Provider,
		TenantID:    hierarchy.TenantID,
	}

	// Check if rootOU exists in the hierarchy
	rootNode, exists := hierarchy.Hierarchy[rootOU]
	if !exists {
		c.logger.Warn("Root OU not found in hierarchy", "root_ou", rootOU)
		return filteredHierarchy
	}

	// Add root node
	filteredHierarchy.Hierarchy[rootOU] = rootNode

	// Recursively add all descendants
	c.addDescendantsToHierarchy(hierarchy, filteredHierarchy, rootOU)

	// Calculate final statistics
	maxDepth := 0
	for _, node := range filteredHierarchy.Hierarchy {
		if node.Depth > maxDepth {
			maxDepth = node.Depth
		}
	}

	filteredHierarchy.Depth = maxDepth
	filteredHierarchy.TotalOUs = len(filteredHierarchy.Hierarchy)

	return filteredHierarchy
}

// addDescendantsToHierarchy recursively adds descendants to filtered hierarchy.
func (c *DefaultDirectoryDNACollector) addDescendantsToHierarchy(source *OUHierarchy, target *OUHierarchy, parentOU string) {
	parentNode, exists := source.Hierarchy[parentOU]
	if !exists {
		return
	}

	// Add all children
	for _, childOU := range parentNode.Children {
		if childNode, exists := source.Hierarchy[childOU]; exists {
			target.Hierarchy[childOU] = childNode
			// Recursively add grandchildren
			c.addDescendantsToHierarchy(source, target, childOU)
		}
	}
}
