// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package directory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/directory/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// DirectoryService implements the unified directory service for the controller.
// It acts as a facade over different directory providers implemented in modules.
type DirectoryService struct {
	mu sync.RWMutex

	// Registry of available directory providers
	providers map[string]Provider

	// Default provider name
	defaultProvider string

	// Logger
	logger logging.Logger

	// Module integration (will be set by controller)
	moduleRegistry ModuleRegistry
}

// ModuleRegistry defines how the directory service integrates with CFGMS modules
type ModuleRegistry interface {
	// GetModule returns a module by name
	GetModule(name string) (interface{}, error)

	// ListModules returns all available modules
	ListModules() []string

	// ExecuteModuleOperation executes an operation on a module
	ExecuteModuleOperation(ctx context.Context, moduleName, operation string, params map[string]interface{}) (interface{}, error)
}

// NewDirectoryService creates a new directory service instance
func NewDirectoryService(logger logging.Logger) *DirectoryService {
	return &DirectoryService{
		providers: make(map[string]Provider),
		logger:    logger,
	}
}

// SetModuleRegistry sets the module registry for integration with CFGMS modules
func (s *DirectoryService) SetModuleRegistry(registry ModuleRegistry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.moduleRegistry = registry
}

// RegisterProvider registers a directory provider (called by modules during initialization)
func (s *DirectoryService) RegisterProvider(provider Provider) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := provider.Name()
	if _, exists := s.providers[name]; exists {
		return fmt.Errorf("provider '%s' already registered", name)
	}

	s.providers[name] = provider
	s.logger.Info("Registered directory provider", "name", name, "display_name", provider.DisplayName())

	// Set as default if it's the first provider
	if s.defaultProvider == "" {
		s.defaultProvider = name
		s.logger.Info("Set default directory provider", "name", name)
	}

	return nil
}

// Provider Management

// GetAvailableProviders returns information about all available providers
func (s *DirectoryService) GetAvailableProviders() []ProviderInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var providers []ProviderInfo
	for _, provider := range s.providers {
		providers = append(providers, ProviderInfo{
			Name:         provider.Name(),
			DisplayName:  provider.DisplayName(),
			Description:  provider.Description(),
			Capabilities: provider.Capabilities(),
		})
	}

	return providers
}

// GetProvider returns a specific provider by name
func (s *DirectoryService) GetProvider(name string) (Provider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	provider, exists := s.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider '%s' not found", name)
	}

	return provider, nil
}

// SetDefaultProvider sets the default directory provider
func (s *DirectoryService) SetDefaultProvider(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.providers[name]; !exists {
		return fmt.Errorf("provider '%s' not found", name)
	}

	s.defaultProvider = name
	s.logger.Info("Set default directory provider", "name", name)
	return nil
}

// GetDefaultProvider returns the default directory provider
func (s *DirectoryService) GetDefaultProvider() (Provider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.defaultProvider == "" {
		return nil, fmt.Errorf("no default provider configured")
	}

	provider, exists := s.providers[s.defaultProvider]
	if !exists {
		return nil, fmt.Errorf("default provider '%s' not found", s.defaultProvider)
	}

	return provider, nil
}

// User Operations

// GetUser retrieves a user from the specified provider
func (s *DirectoryService) GetUser(ctx context.Context, providerName, userID string) (*types.DirectoryUser, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	user, err := provider.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from provider '%s': %w", provider.Name(), err)
	}

	// Ensure source is set
	if user.Source == "" {
		user.Source = provider.Name()
	}

	return user, nil
}

// CreateUser creates a user in the specified provider
func (s *DirectoryService) CreateUser(ctx context.Context, providerName string, user *types.DirectoryUser) (*types.DirectoryUser, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	// Validate user data
	if err := user.Validate(); err != nil {
		return nil, fmt.Errorf("user validation failed: %w", err)
	}

	createdUser, err := provider.CreateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user in provider '%s': %w", provider.Name(), err)
	}

	// Ensure source is set
	if createdUser.Source == "" {
		createdUser.Source = provider.Name()
	}

	s.logger.Info("Created user", "provider", provider.Name(), "user_id", createdUser.ID, "upn", createdUser.UserPrincipalName)
	return createdUser, nil
}

// UpdateUser updates a user in the specified provider
func (s *DirectoryService) UpdateUser(ctx context.Context, providerName, userID string, updates *types.DirectoryUser) (*types.DirectoryUser, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	updatedUser, err := provider.UpdateUser(ctx, userID, updates)
	if err != nil {
		return nil, fmt.Errorf("failed to update user in provider '%s': %w", provider.Name(), err)
	}

	// Ensure source is set
	if updatedUser.Source == "" {
		updatedUser.Source = provider.Name()
	}

	s.logger.Info("Updated user", "provider", provider.Name(), "user_id", userID)
	return updatedUser, nil
}

// DeleteUser deletes a user from the specified provider
func (s *DirectoryService) DeleteUser(ctx context.Context, providerName, userID string) error {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return err
	}

	err = provider.DeleteUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user from provider '%s': %w", provider.Name(), err)
	}

	s.logger.Info("Deleted user", "provider", provider.Name(), "user_id", userID)
	return nil
}

// SearchUsers searches for users in the specified provider
func (s *DirectoryService) SearchUsers(ctx context.Context, providerName string, query *SearchQuery) ([]*types.DirectoryUser, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	users, err := provider.SearchUsers(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to search users in provider '%s': %w", provider.Name(), err)
	}

	// Ensure source is set for all users
	for _, user := range users {
		if user.Source == "" {
			user.Source = provider.Name()
		}
	}

	return users, nil
}

// Group Operations

// GetGroup retrieves a group from the specified provider
func (s *DirectoryService) GetGroup(ctx context.Context, providerName, groupID string) (*types.DirectoryGroup, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	group, err := provider.GetGroup(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group from provider '%s': %w", provider.Name(), err)
	}

	// Ensure source is set
	if group.Source == "" {
		group.Source = provider.Name()
	}

	return group, nil
}

// CreateGroup creates a group in the specified provider
func (s *DirectoryService) CreateGroup(ctx context.Context, providerName string, group *types.DirectoryGroup) (*types.DirectoryGroup, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	// Validate group data
	if err := group.Validate(); err != nil {
		return nil, fmt.Errorf("group validation failed: %w", err)
	}

	createdGroup, err := provider.CreateGroup(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("failed to create group in provider '%s': %w", provider.Name(), err)
	}

	// Ensure source is set
	if createdGroup.Source == "" {
		createdGroup.Source = provider.Name()
	}

	s.logger.Info("Created group", "provider", provider.Name(), "group_id", createdGroup.ID, "display_name", createdGroup.DisplayName)
	return createdGroup, nil
}

// UpdateGroup updates a group in the specified provider
func (s *DirectoryService) UpdateGroup(ctx context.Context, providerName, groupID string, updates *types.DirectoryGroup) (*types.DirectoryGroup, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	updatedGroup, err := provider.UpdateGroup(ctx, groupID, updates)
	if err != nil {
		return nil, fmt.Errorf("failed to update group in provider '%s': %w", provider.Name(), err)
	}

	// Ensure source is set
	if updatedGroup.Source == "" {
		updatedGroup.Source = provider.Name()
	}

	s.logger.Info("Updated group", "provider", provider.Name(), "group_id", groupID)
	return updatedGroup, nil
}

// DeleteGroup deletes a group from the specified provider
func (s *DirectoryService) DeleteGroup(ctx context.Context, providerName, groupID string) error {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return err
	}

	err = provider.DeleteGroup(ctx, groupID)
	if err != nil {
		return fmt.Errorf("failed to delete group from provider '%s': %w", provider.Name(), err)
	}

	s.logger.Info("Deleted group", "provider", provider.Name(), "group_id", groupID)
	return nil
}

// SearchGroups searches for groups in the specified provider
func (s *DirectoryService) SearchGroups(ctx context.Context, providerName string, query *SearchQuery) ([]*types.DirectoryGroup, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	groups, err := provider.SearchGroups(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to search groups in provider '%s': %w", provider.Name(), err)
	}

	// Ensure source is set for all groups
	for _, group := range groups {
		if group.Source == "" {
			group.Source = provider.Name()
		}
	}

	return groups, nil
}

// Membership Operations

// AddUserToGroup adds a user to a group
func (s *DirectoryService) AddUserToGroup(ctx context.Context, providerName, userID, groupID string) error {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return err
	}

	err = provider.AddUserToGroup(ctx, userID, groupID)
	if err != nil {
		return fmt.Errorf("failed to add user to group in provider '%s': %w", provider.Name(), err)
	}

	s.logger.Info("Added user to group", "provider", provider.Name(), "user_id", userID, "group_id", groupID)
	return nil
}

// RemoveUserFromGroup removes a user from a group
func (s *DirectoryService) RemoveUserFromGroup(ctx context.Context, providerName, userID, groupID string) error {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return err
	}

	err = provider.RemoveUserFromGroup(ctx, userID, groupID)
	if err != nil {
		return fmt.Errorf("failed to remove user from group in provider '%s': %w", provider.Name(), err)
	}

	s.logger.Info("Removed user from group", "provider", provider.Name(), "user_id", userID, "group_id", groupID)
	return nil
}

// GetUserGroups gets all groups for a user
func (s *DirectoryService) GetUserGroups(ctx context.Context, providerName, userID string) ([]*types.DirectoryGroup, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	groups, err := provider.GetUserGroups(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups from provider '%s': %w", provider.Name(), err)
	}

	// Ensure source is set for all groups
	for _, group := range groups {
		if group.Source == "" {
			group.Source = provider.Name()
		}
	}

	return groups, nil
}

// GetGroupMembers gets all members of a group
func (s *DirectoryService) GetGroupMembers(ctx context.Context, providerName, groupID string) ([]*types.DirectoryUser, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	users, err := provider.GetGroupMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members from provider '%s': %w", provider.Name(), err)
	}

	// Ensure source is set for all users
	for _, user := range users {
		if user.Source == "" {
			user.Source = provider.Name()
		}
	}

	return users, nil
}

// Organizational Structure Operations (with graceful degradation)

// GetOU gets an organizational unit (AD-specific, gracefully degrades for other providers)
func (s *DirectoryService) GetOU(ctx context.Context, providerName, ouID string) (*OrganizationalUnit, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	if !provider.SupportsOUs() {
		return nil, fmt.Errorf("provider '%s' does not support organizational units", provider.Name())
	}

	return provider.GetOU(ctx, ouID)
}

// CreateOU creates an organizational unit
func (s *DirectoryService) CreateOU(ctx context.Context, providerName string, ou *OrganizationalUnit) (*OrganizationalUnit, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	if !provider.SupportsOUs() {
		return nil, fmt.Errorf("provider '%s' does not support organizational units", provider.Name())
	}

	createdOU, err := provider.CreateOU(ctx, ou)
	if err != nil {
		return nil, fmt.Errorf("failed to create OU in provider '%s': %w", provider.Name(), err)
	}

	s.logger.Info("Created OU", "provider", provider.Name(), "ou_id", createdOU.ID, "name", createdOU.Name)
	return createdOU, nil
}

// UpdateOU updates an organizational unit
func (s *DirectoryService) UpdateOU(ctx context.Context, providerName, ouID string, updates *OrganizationalUnit) (*OrganizationalUnit, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	if !provider.SupportsOUs() {
		return nil, fmt.Errorf("provider '%s' does not support organizational units", provider.Name())
	}

	return provider.UpdateOU(ctx, ouID, updates)
}

// DeleteOU deletes an organizational unit
func (s *DirectoryService) DeleteOU(ctx context.Context, providerName, ouID string) error {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return err
	}

	if !provider.SupportsOUs() {
		return fmt.Errorf("provider '%s' does not support organizational units", provider.Name())
	}

	return provider.DeleteOU(ctx, ouID)
}

// ListOUs lists organizational units
func (s *DirectoryService) ListOUs(ctx context.Context, providerName string) ([]*OrganizationalUnit, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	if !provider.SupportsOUs() {
		return nil, fmt.Errorf("provider '%s' does not support organizational units", provider.Name())
	}

	return provider.ListOUs(ctx)
}

// Administrative Unit Operations (Entra ID-specific with graceful degradation)

// GetAdminUnit gets an administrative unit
func (s *DirectoryService) GetAdminUnit(ctx context.Context, providerName, unitID string) (*AdministrativeUnit, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	if !provider.SupportsAdminUnits() {
		return nil, fmt.Errorf("provider '%s' does not support administrative units", provider.Name())
	}

	return provider.GetAdminUnit(ctx, unitID)
}

// CreateAdminUnit creates an administrative unit
func (s *DirectoryService) CreateAdminUnit(ctx context.Context, providerName string, unit *AdministrativeUnit) (*AdministrativeUnit, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	if !provider.SupportsAdminUnits() {
		return nil, fmt.Errorf("provider '%s' does not support administrative units", provider.Name())
	}

	createdUnit, err := provider.CreateAdminUnit(ctx, unit)
	if err != nil {
		return nil, fmt.Errorf("failed to create admin unit in provider '%s': %w", provider.Name(), err)
	}

	s.logger.Info("Created admin unit", "provider", provider.Name(), "unit_id", createdUnit.ID, "display_name", createdUnit.DisplayName)
	return createdUnit, nil
}

// UpdateAdminUnit updates an administrative unit
func (s *DirectoryService) UpdateAdminUnit(ctx context.Context, providerName, unitID string, updates *AdministrativeUnit) (*AdministrativeUnit, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	if !provider.SupportsAdminUnits() {
		return nil, fmt.Errorf("provider '%s' does not support administrative units", provider.Name())
	}

	return provider.UpdateAdminUnit(ctx, unitID, updates)
}

// DeleteAdminUnit deletes an administrative unit
func (s *DirectoryService) DeleteAdminUnit(ctx context.Context, providerName, unitID string) error {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return err
	}

	if !provider.SupportsAdminUnits() {
		return fmt.Errorf("provider '%s' does not support administrative units", provider.Name())
	}

	return provider.DeleteAdminUnit(ctx, unitID)
}

// ListAdminUnits lists administrative units
func (s *DirectoryService) ListAdminUnits(ctx context.Context, providerName string) ([]*AdministrativeUnit, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	if !provider.SupportsAdminUnits() {
		return nil, fmt.Errorf("provider '%s' does not support administrative units", provider.Name())
	}

	return provider.ListAdminUnits(ctx)
}

// Cross-Provider Operations

// SyncUser syncs a user between providers
func (s *DirectoryService) SyncUser(ctx context.Context, sourceProvider, targetProvider, userID string) error {
	// Get user from source provider
	sourceUser, err := s.GetUser(ctx, sourceProvider, userID)
	if err != nil {
		return fmt.Errorf("failed to get user from source provider '%s': %w", sourceProvider, err)
	}

	// Create or update user in target provider
	_, err = s.CreateUser(ctx, targetProvider, sourceUser)
	if err != nil {
		// If creation fails, try update
		if _, updateErr := s.UpdateUser(ctx, targetProvider, userID, sourceUser); updateErr != nil {
			return fmt.Errorf("failed to sync user to target provider '%s': create failed (%w), update failed (%w)", targetProvider, err, updateErr)
		}
	}

	s.logger.Info("Synced user between providers", "source", sourceProvider, "target", targetProvider, "user_id", userID)
	return nil
}

// SyncGroup syncs a group between providers
func (s *DirectoryService) SyncGroup(ctx context.Context, sourceProvider, targetProvider, groupID string) error {
	// Get group from source provider
	sourceGroup, err := s.GetGroup(ctx, sourceProvider, groupID)
	if err != nil {
		return fmt.Errorf("failed to get group from source provider '%s': %w", sourceProvider, err)
	}

	// Create or update group in target provider
	_, err = s.CreateGroup(ctx, targetProvider, sourceGroup)
	if err != nil {
		// If creation fails, try update
		if _, updateErr := s.UpdateGroup(ctx, targetProvider, groupID, sourceGroup); updateErr != nil {
			return fmt.Errorf("failed to sync group to target provider '%s': create failed (%w), update failed (%w)", targetProvider, err, updateErr)
		}
	}

	s.logger.Info("Synced group between providers", "source", sourceProvider, "target", targetProvider, "group_id", groupID)
	return nil
}

// CompareDirectories compares two directories and returns differences
func (s *DirectoryService) CompareDirectories(ctx context.Context, provider1, provider2 string) (*DirectoryComparison, error) {
	// This is a complex operation that would compare users and groups between providers
	// Implementation would involve fetching all objects from both providers and comparing
	// For now, return a placeholder
	return &DirectoryComparison{
		Provider1:      provider1,
		Provider2:      provider2,
		ComparisonTime: time.Now(),
		Summary: DirectoryComparisonSummary{
			TotalDifferences: 0, // Would be calculated
		},
	}, fmt.Errorf("directory comparison not yet implemented")
}

// Health and Statistics

// GetProviderHealth gets the health status of a provider
func (s *DirectoryService) GetProviderHealth(ctx context.Context, providerName string) (*ProviderHealth, error) {
	provider, err := s.getProviderOrDefault(providerName)
	if err != nil {
		return nil, err
	}

	return provider.HealthCheck(ctx)
}

// GetProviderStatistics gets statistics for a provider
func (s *DirectoryService) GetProviderStatistics(ctx context.Context, providerName string) (*ProviderStatistics, error) {
	// This would be implemented to gather statistics from the provider
	// For now, return placeholder
	return &ProviderStatistics{
		RequestCount:   0,
		ErrorCount:     0,
		AverageLatency: 0,
	}, fmt.Errorf("provider statistics not yet implemented")
}

// Helper methods

// getProviderOrDefault returns the specified provider or the default if providerName is empty
func (s *DirectoryService) getProviderOrDefault(providerName string) (Provider, error) {
	if providerName == "" {
		return s.GetDefaultProvider()
	}
	return s.GetProvider(providerName)
}
