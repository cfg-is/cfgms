// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package config provides configuration inheritance logic using storage backend queries
package config

import (
	"context"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// InheritanceResolver handles configuration inheritance across tenant hierarchy
type InheritanceResolver struct {
	configStore       interfaces.ConfigStore
	clientTenantStore interfaces.ClientTenantStore
}

// NewInheritanceResolver creates a new inheritance resolver
func NewInheritanceResolver(configStore interfaces.ConfigStore, clientTenantStore interfaces.ClientTenantStore) *InheritanceResolver {
	return &InheritanceResolver{
		configStore:       configStore,
		clientTenantStore: clientTenantStore,
	}
}

// NewInheritanceResolverWithStorageManager creates an inheritance resolver from storage manager
func NewInheritanceResolverWithStorageManager(storageManager *interfaces.StorageManager) *InheritanceResolver {
	return &InheritanceResolver{
		configStore:       storageManager.GetConfigStore(),
		clientTenantStore: storageManager.GetClientTenantStore(),
	}
}

// EffectiveConfiguration represents the final configuration after inheritance
type EffectiveConfiguration struct {
	StewardID   string                        `json:"steward_id"`
	TenantID    string                        `json:"tenant_id"`
	Config      *stewardconfig.StewardConfig  `json:"config"`
	Sources     map[string]*InheritanceSource `json:"sources"` // Tracks source of each configuration element
	GeneratedAt time.Time                     `json:"generated_at"`
}

// InheritanceSource tracks where a configuration element came from
type InheritanceSource struct {
	Level      int       `json:"level"` // 0=MSP, 1=Client, 2=Group, 3=Device
	TenantID   string    `json:"tenant_id"`
	ConfigName string    `json:"config_name"`
	Version    int64     `json:"version"`
	UpdatedAt  time.Time `json:"updated_at"`
	Source     string    `json:"source"` // Description of the source
}

// InheritanceLevel represents the hierarchy levels in multi-tenant configuration
type InheritanceLevel int

const (
	LevelMSP    InheritanceLevel = 0 // MSP-wide policies
	LevelClient InheritanceLevel = 1 // Client-specific overrides
	LevelGroup  InheritanceLevel = 2 // Group configurations
	LevelDevice InheritanceLevel = 3 // Device-specific configurations
)

// ResolveConfiguration resolves configuration with full tenant hierarchy inheritance
func (ir *InheritanceResolver) ResolveConfiguration(ctx context.Context, tenantID, stewardID string) (*EffectiveConfiguration, error) {
	// Get tenant hierarchy path
	tenantPath, err := ir.getTenantPath(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve tenant hierarchy: %w", err)
	}

	// Initialize effective configuration
	effective := &EffectiveConfiguration{
		StewardID:   stewardID,
		TenantID:    tenantID,
		Config:      &stewardconfig.StewardConfig{},
		Sources:     make(map[string]*InheritanceSource),
		GeneratedAt: time.Now(),
	}

	// Apply configurations from MSP level down to device level
	for level, currentTenantID := range tenantPath {
		if err := ir.applyConfigurationLevel(ctx, effective, currentTenantID, stewardID, level); err != nil {
			return nil, fmt.Errorf("failed to apply configuration at level %d (tenant %s): %w", level, currentTenantID, err)
		}
	}

	// Apply device-specific configuration last (highest priority)
	if err := ir.applyDeviceConfiguration(ctx, effective, tenantID, stewardID); err != nil {
		return nil, fmt.Errorf("failed to apply device configuration: %w", err)
	}

	return effective, nil
}

// getTenantPath returns the tenant hierarchy path from MSP to the specified tenant
func (ir *InheritanceResolver) getTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	// Get the tenant hierarchy using ClientTenantStore
	// This is a simplified implementation - full implementation would traverse the hierarchy

	// For now, return a basic path structure
	// In full implementation, this would query the tenant store for the complete hierarchy
	return []string{"msp", tenantID}, nil
}

// applyConfigurationLevel applies configuration from a specific hierarchy level
func (ir *InheritanceResolver) applyConfigurationLevel(ctx context.Context, effective *EffectiveConfiguration, tenantID, stewardID string, level int) error {
	// Try to get configuration at this level
	var configNamespace string
	var configName string

	switch InheritanceLevel(level) {
	case LevelMSP:
		configNamespace = "msp-policies"
		configName = "global"
	case LevelClient:
		configNamespace = "client-policies"
		configName = tenantID
	case LevelGroup:
		configNamespace = "group-policies"
		configName = fmt.Sprintf("%s-groups", tenantID)
	default:
		return nil // Skip unknown levels
	}

	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: configNamespace,
		Name:      configName,
	}

	configEntry, err := ir.configStore.GetConfig(ctx, configKey)
	if err != nil {
		// No configuration at this level is OK - continue with inheritance
		return nil
	}

	// Parse the configuration
	var levelConfig stewardconfig.StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &levelConfig); err != nil {
		return fmt.Errorf("failed to parse configuration at level %d: %w", level, err)
	}

	// Create inheritance source tracking
	source := &InheritanceSource{
		Level:      level,
		TenantID:   tenantID,
		ConfigName: configName,
		Version:    configEntry.Version,
		UpdatedAt:  configEntry.UpdatedAt,
		Source:     fmt.Sprintf("Level %d (%s)", level, configNamespace),
	}

	// Apply configuration using declarative merging (named resources replace entirely)
	ir.applyConfigurationWithSource(effective, &levelConfig, source)

	return nil
}

// applyDeviceConfiguration applies device-specific configuration
func (ir *InheritanceResolver) applyDeviceConfiguration(ctx context.Context, effective *EffectiveConfiguration, tenantID, stewardID string) error {
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	configEntry, err := ir.configStore.GetConfig(ctx, configKey)
	if err != nil {
		// No device-specific configuration is OK
		return nil
	}

	// Parse the configuration
	var deviceConfig stewardconfig.StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &deviceConfig); err != nil {
		return fmt.Errorf("failed to parse device configuration: %w", err)
	}

	// Create inheritance source tracking
	source := &InheritanceSource{
		Level:      int(LevelDevice),
		TenantID:   tenantID,
		ConfigName: stewardID,
		Version:    configEntry.Version,
		UpdatedAt:  configEntry.UpdatedAt,
		Source:     "Device Configuration",
	}

	// Apply device configuration (highest priority)
	ir.applyConfigurationWithSource(effective, &deviceConfig, source)

	return nil
}

// applyConfigurationWithSource applies configuration and tracks inheritance sources
func (ir *InheritanceResolver) applyConfigurationWithSource(effective *EffectiveConfiguration, config *stewardconfig.StewardConfig, source *InheritanceSource) {
	// Initialize effective config if needed
	if effective.Config == nil {
		effective.Config = &stewardconfig.StewardConfig{
			Resources: []stewardconfig.ResourceConfig{},
			Modules:   make(map[string]string),
		}
	}

	// Apply resources using declarative merging (named resources replace entirely)
	resourceMap := make(map[string]stewardconfig.ResourceConfig)
	for _, resource := range effective.Config.Resources {
		resourceMap[resource.Name] = resource
	}

	for _, resource := range config.Resources {
		resourceMap[resource.Name] = resource
		effective.Sources[fmt.Sprintf("resource.%s", resource.Name)] = source
	}

	// Convert map back to slice
	effective.Config.Resources = make([]stewardconfig.ResourceConfig, 0, len(resourceMap))
	for _, resource := range resourceMap {
		effective.Config.Resources = append(effective.Config.Resources, resource)
	}

	// Apply steward settings
	if config.Steward.ID != "" {
		effective.Config.Steward.ID = config.Steward.ID
		effective.Sources["steward.id"] = source
	}

	if config.Steward.Mode != "" {
		effective.Config.Steward.Mode = config.Steward.Mode
		effective.Sources["steward.mode"] = source
	}

	if len(config.Steward.ModulePaths) > 0 {
		effective.Config.Steward.ModulePaths = config.Steward.ModulePaths
		effective.Sources["steward.module_paths"] = source
	}

	// Apply logging settings
	if config.Steward.Logging.Level != "" {
		effective.Config.Steward.Logging.Level = config.Steward.Logging.Level
		effective.Sources["steward.logging.level"] = source
	}

	if config.Steward.Logging.Format != "" {
		effective.Config.Steward.Logging.Format = config.Steward.Logging.Format
		effective.Sources["steward.logging.format"] = source
	}

	// Apply error handling settings
	if config.Steward.ErrorHandling.ModuleLoadFailure != "" {
		effective.Config.Steward.ErrorHandling.ModuleLoadFailure = config.Steward.ErrorHandling.ModuleLoadFailure
		effective.Sources["steward.error_handling.module_load_failure"] = source
	}

	if config.Steward.ErrorHandling.ResourceFailure != "" {
		effective.Config.Steward.ErrorHandling.ResourceFailure = config.Steward.ErrorHandling.ResourceFailure
		effective.Sources["steward.error_handling.resource_failure"] = source
	}

	if config.Steward.ErrorHandling.ConfigurationError != "" {
		effective.Config.Steward.ErrorHandling.ConfigurationError = config.Steward.ErrorHandling.ConfigurationError
		effective.Sources["steward.error_handling.configuration_error"] = source
	}

	// Apply module mappings
	if effective.Config.Modules == nil {
		effective.Config.Modules = make(map[string]string)
	}

	for moduleName, modulePath := range config.Modules {
		effective.Config.Modules[moduleName] = modulePath
		effective.Sources[fmt.Sprintf("modules.%s", moduleName)] = source
	}
}

// GetConfigurationSource returns the inheritance source for a specific configuration element
func (ir *InheritanceResolver) GetConfigurationSource(ctx context.Context, tenantID, stewardID, configPath string) (*InheritanceSource, error) {
	effective, err := ir.ResolveConfiguration(ctx, tenantID, stewardID)
	if err != nil {
		return nil, err
	}

	source, exists := effective.Sources[configPath]
	if !exists {
		return nil, fmt.Errorf("configuration path '%s' not found", configPath)
	}

	return source, nil
}

// ValidateInheritance validates that the inheritance chain is consistent
func (ir *InheritanceResolver) ValidateInheritance(ctx context.Context, tenantID, stewardID string) (*InheritanceValidationResult, error) {
	result := &InheritanceValidationResult{
		Valid:    true,
		Issues:   []string{},
		Warnings: []string{},
	}

	// Resolve configuration to check for issues
	effective, err := ir.ResolveConfiguration(ctx, tenantID, stewardID)
	if err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, fmt.Sprintf("Failed to resolve configuration: %v", err))
		return result, nil
	}

	// Validate the effective configuration
	if err := stewardconfig.ValidateConfiguration(*effective.Config); err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, fmt.Sprintf("Effective configuration is invalid: %v", err))
	}

	// Check for common inheritance issues
	resourceModules := make(map[string]string)
	for _, resource := range effective.Config.Resources {
		if existingModule, exists := resourceModules[resource.Name]; exists && existingModule != resource.Module {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Resource '%s' module conflict: was %s, now %s", resource.Name, existingModule, resource.Module))
		}
		resourceModules[resource.Name] = resource.Module
	}

	// Check for missing steward ID
	if effective.Config.Steward.ID == "" {
		result.Warnings = append(result.Warnings, "Steward ID not set at any inheritance level")
	}

	return result, nil
}

// InheritanceValidationResult represents the result of inheritance validation
type InheritanceValidationResult struct {
	Valid    bool     `json:"valid"`
	Issues   []string `json:"issues"`
	Warnings []string `json:"warnings"`
}

// GetInheritanceTrace returns a detailed trace of configuration inheritance
func (ir *InheritanceResolver) GetInheritanceTrace(ctx context.Context, tenantID, stewardID string) (*InheritanceTrace, error) {
	effective, err := ir.ResolveConfiguration(ctx, tenantID, stewardID)
	if err != nil {
		return nil, err
	}

	trace := &InheritanceTrace{
		StewardID:   stewardID,
		TenantID:    tenantID,
		Sources:     effective.Sources,
		GeneratedAt: effective.GeneratedAt,
		Elements:    make(map[string]*TraceElement),
	}

	// Create trace elements for each configuration path
	for configPath, source := range effective.Sources {
		trace.Elements[configPath] = &TraceElement{
			Path:        configPath,
			Value:       ir.getConfigValue(effective.Config, configPath),
			Source:      source,
			Description: ir.getPathDescription(configPath),
		}
	}

	return trace, nil
}

// InheritanceTrace provides detailed tracing of configuration inheritance
type InheritanceTrace struct {
	StewardID   string                        `json:"steward_id"`
	TenantID    string                        `json:"tenant_id"`
	Sources     map[string]*InheritanceSource `json:"sources"`
	Elements    map[string]*TraceElement      `json:"elements"`
	GeneratedAt time.Time                     `json:"generated_at"`
}

// TraceElement represents a single traced configuration element
type TraceElement struct {
	Path        string             `json:"path"`
	Value       interface{}        `json:"value"`
	Source      *InheritanceSource `json:"source"`
	Description string             `json:"description"`
}

// getConfigValue extracts the value at a specific configuration path
func (ir *InheritanceResolver) getConfigValue(config *stewardconfig.StewardConfig, path string) interface{} {
	// This is a simplified implementation - full version would use reflection or a more sophisticated path resolver
	switch path {
	case "steward.id":
		return config.Steward.ID
	case "steward.mode":
		return string(config.Steward.Mode)
	case "steward.logging.level":
		return config.Steward.Logging.Level
	case "steward.logging.format":
		return config.Steward.Logging.Format
	default:
		return nil
	}
}

// getPathDescription returns a human-readable description of a configuration path
func (ir *InheritanceResolver) getPathDescription(path string) string {
	descriptions := map[string]string{
		"steward.id":             "Unique identifier for this steward instance",
		"steward.mode":           "Operation mode (standalone or controller)",
		"steward.logging.level":  "Logging verbosity level",
		"steward.logging.format": "Log output format",
		"steward.error_handling.module_load_failure": "How to handle module loading errors",
		"steward.error_handling.resource_failure":    "How to handle resource execution errors",
		"steward.error_handling.configuration_error": "How to handle configuration validation errors",
	}

	if desc, exists := descriptions[path]; exists {
		return desc
	}

	// Handle dynamic paths like resources and modules
	if len(path) > 9 && path[:9] == "resource." {
		return fmt.Sprintf("Configuration for resource '%s'", path[9:])
	}

	if len(path) > 8 && path[:8] == "modules." {
		return fmt.Sprintf("Path mapping for module '%s'", path[8:])
	}

	return "Configuration element"
}
