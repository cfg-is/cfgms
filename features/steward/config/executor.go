// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package config provides configuration application and module execution for stewards.
//
// This package implements the configuration executor that parses YAML configurations
// and executes the appropriate modules to bring the system to the desired state.
package config

import (
	"context"
	"fmt"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/directory"
	"github.com/cfgis/cfgms/features/modules/file"
	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/pkg/logging"
	mqttTypes "github.com/cfgis/cfgms/pkg/mqtt/types"
)

// Executor applies configurations by executing modules.
type Executor struct {
	mu sync.RWMutex

	// Registered modules
	modules map[string]modules.Module

	// Logger
	logger logging.Logger

	// Tenant context
	tenantID string
}

// Config holds configuration executor settings.
type Config struct {
	// TenantID for this steward
	TenantID string

	// Logger for execution logging
	Logger logging.Logger
}

// New creates a new configuration executor.
func New(cfg *Config) (*Executor, error) {
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	executor := &Executor{
		modules:  make(map[string]modules.Module),
		logger:   cfg.Logger,
		tenantID: cfg.TenantID,
	}

	// Register built-in modules
	executor.registerModule("file", file.New())
	executor.registerModule("directory", directory.New())
	executor.registerModule("script", script.New())

	return executor, nil
}

// registerModule registers a module with the executor.
func (e *Executor) registerModule(name string, module modules.Module) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.modules[name] = module
	e.logger.Info("Registered module", "name", name)
}

// ConfigurationSpec represents a YAML configuration structure.
type ConfigurationSpec struct {
	Version string                    `yaml:"version"`
	Modules map[string][]ResourceSpec `yaml:"modules"`
}

// ResourceSpec represents a single resource configuration.
type ResourceSpec struct {
	Name       string                 `yaml:"name"`
	ResourceID string                 `yaml:"resource_id"`
	State      string                 `yaml:"state"` // present, absent
	Config     map[string]interface{} `yaml:"config"`
}

// ApplyConfiguration parses and applies a configuration.
func (e *Executor) ApplyConfiguration(ctx context.Context, configData []byte, version string) (*mqttTypes.ConfigStatusReport, error) {
	e.logger.Info("Applying configuration", "version", version, "size", len(configData))
	fmt.Printf("[DEBUG] ApplyConfiguration: Received config data:\n%s\n", string(configData))

	startTime := time.Now()
	report := &mqttTypes.ConfigStatusReport{
		ConfigVersion: version,
		Status:        "OK",
		Message:       "Configuration applied successfully",
		Modules:       make(map[string]mqttTypes.ModuleStatus),
		Timestamp:     time.Now(),
	}

	// Parse configuration (StewardConfig format)
	// Note: Configuration may be JSON or YAML (signature system always returns YAML)
	// Since JSON is valid YAML, we parse as YAML to accept both formats
	e.logger.Info("ApplyConfiguration starting", "data_size", len(configData))
	previewLen := 300
	if len(configData) < previewLen {
		previewLen = len(configData)
	}
	e.logger.Info("Config data preview", "preview", string(configData[:previewLen]))

	var config StewardConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		e.logger.Error("Failed to parse configuration", "error", err)
		e.logger.Error("Config data that failed to parse", "data", string(configData))
		report.Status = "ERROR"
		report.Message = fmt.Sprintf("Configuration parsing failed: %v", err)
		return report, fmt.Errorf("failed to parse configuration: %w", err)
	}
	e.logger.Info("ApplyConfiguration parsed", "resources", len(config.Resources), "steward_id", config.Steward.ID)

	e.logger.Info("Parsed configuration", "resource_count", len(config.Resources))

	// Group resources by module for status reporting
	resourcesByModule := make(map[string][]ResourceConfig)
	for _, resource := range config.Resources {
		resourcesByModule[resource.Module] = append(resourcesByModule[resource.Module], resource)
	}

	// Apply each module's resources
	hasErrors := false
	for moduleName, resources := range resourcesByModule {
		e.logger.Info("Processing module", "module", moduleName, "resource_count", len(resources))

		moduleStatus := e.applyModuleResources(ctx, moduleName, resources)
		report.Modules[moduleName] = moduleStatus

		if moduleStatus.Status != "OK" {
			hasErrors = true
		}
	}

	// Set overall status
	if hasErrors {
		report.Status = "ERROR"
		report.Message = "Configuration applied with errors"
	}

	executionTime := time.Since(startTime)
	report.ExecutionTimeMs = executionTime.Milliseconds()

	e.logger.Info("Configuration application completed",
		"version", version,
		"status", report.Status,
		"execution_time_ms", report.ExecutionTimeMs)

	return report, nil
}

// applyModuleResources applies all resources for a specific module using ResourceConfig format.
func (e *Executor) applyModuleResources(ctx context.Context, moduleName string, resources []ResourceConfig) mqttTypes.ModuleStatus {
	status := mqttTypes.ModuleStatus{
		Name:      moduleName,
		Status:    "OK",
		Message:   fmt.Sprintf("Applied %d resources", len(resources)),
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Get module implementation
	e.mu.RLock()
	module, exists := e.modules[moduleName]
	e.mu.RUnlock()

	if !exists {
		e.logger.Error("Module not found", "module", moduleName)
		status.Status = "ERROR"
		status.Message = fmt.Sprintf("Module not registered: %s", moduleName)
		return status
	}

	// Apply each resource
	successCount := 0
	errorCount := 0
	errors := make([]string, 0)

	for _, resource := range resources {
		// Extract resource_id from config (typically the 'path' field)
		resourceID, ok := resource.Config["path"].(string)
		if !ok || resourceID == "" {
			e.logger.Error("Resource missing path", "module", moduleName, "name", resource.Name)
			errorCount++
			errors = append(errors, fmt.Sprintf("%s: missing 'path' in config", resource.Name))
			continue
		}

		// Extract state (default to "present")
		state := "present"
		if stateVal, ok := resource.Config["state"].(string); ok {
			state = stateVal
		} else if ensureVal, ok := resource.Config["ensure"].(string); ok {
			state = ensureVal
		}

		e.logger.Info("Applying resource",
			"module", moduleName,
			"name", resource.Name,
			"resource_id", resourceID,
			"state", state)

		// Convert ResourceConfig to ResourceSpec for applyResourceInternal
		spec := ResourceSpec{
			Name:       resource.Name,
			ResourceID: resourceID,
			State:      state,
			Config:     resource.Config,
		}

		if err := e.applyResourceInternal(ctx, moduleName, module, spec); err != nil {
			e.logger.Error("Resource application failed",
				"module", moduleName,
				"name", resource.Name,
				"error", err)
			errorCount++
			errors = append(errors, fmt.Sprintf("%s: %v", resource.Name, err))
		} else {
			successCount++
		}
	}

	// Update status based on results
	status.Details["success_count"] = successCount
	status.Details["error_count"] = errorCount
	status.Details["total_count"] = len(resources)

	if errorCount > 0 {
		status.Status = "ERROR"
		status.Message = fmt.Sprintf("Applied %d/%d resources (%d errors)", successCount, len(resources), errorCount)
		status.Details["errors"] = errors
	}

	return status
}

// applyResourceInternal applies a single resource using the appropriate module.
func (e *Executor) applyResourceInternal(ctx context.Context, moduleName string, module modules.Module, resource ResourceSpec) error {
	// Add tenant context
	ctx = logging.WithTenant(ctx, e.tenantID)

	// Handle state: present vs absent
	if resource.State == "absent" {
		// Resource deletion is not yet implemented
		// Return error to prevent configuration drift (resources expected to be deleted remain)
		e.logger.Error("Resource deletion not yet implemented",
			"resource", resource.Name,
			"resource_id", resource.ResourceID,
			"state", resource.State)
		return fmt.Errorf("resource state 'absent' is not yet implemented (resource: %s)", resource.Name)
	}

	// Module-specific config adjustments
	config := resource.Config
	if config == nil {
		config = make(map[string]interface{})
	}

	// Validate permissions for file and directory modules
	if moduleName == "file" || moduleName == "directory" {
		if perms, hasPerms := config["permissions"]; hasPerms {
			if err := validatePermissions(perms); err != nil {
				return fmt.Errorf("permissions validation failed: %w", err)
			}
		}
	}

	// For directory module, ensure 'path' field is set from resource_id
	if moduleName == "directory" {
		if _, hasPath := config["path"]; !hasPath {
			config["path"] = resource.ResourceID
		}
	}

	// Convert config map to ConfigState
	configState, err := e.buildConfigState(config)
	if err != nil {
		return fmt.Errorf("failed to build config state: %w", err)
	}

	// Apply the resource
	if err := module.Set(ctx, resource.ResourceID, configState); err != nil {
		return fmt.Errorf("module.Set failed: %w", err)
	}

	e.logger.Info("Resource applied successfully",
		"resource", resource.Name,
		"resource_id", resource.ResourceID)

	return nil
}

// buildConfigState converts a map to a ConfigState interface.
func (e *Executor) buildConfigState(config map[string]interface{}) (modules.ConfigState, error) {
	// Use genericConfigState that implements ConfigState interface
	return &genericConfigState{data: config}, nil
}

// genericConfigState is a generic implementation of ConfigState.
type genericConfigState struct {
	data map[string]interface{}
}

func (g *genericConfigState) AsMap() map[string]interface{} {
	// Normalize types for module consumption
	normalized := make(map[string]interface{})
	for k, v := range g.data {
		normalized[k] = normalizeValue(v)
	}
	return normalized
}

// normalizeValue converts YAML-parsed values to expected Go types.
func normalizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case float64:
		// YAML parser might return numbers as float64
		// Convert to int if it's a whole number (for permissions, etc.)
		if val == float64(int(val)) {
			return int(val)
		}
		return val
	case int64:
		return int(val)
	default:
		return val
	}
}

// validatePermissions validates that a permissions value is within valid range (0-0777 octal)
func validatePermissions(perms interface{}) error {
	var permValue int

	switch v := perms.(type) {
	case int:
		permValue = v
	case int64:
		permValue = int(v)
	case float64:
		permValue = int(v)
	default:
		return fmt.Errorf("invalid permissions type: %T", perms)
	}

	// Check range: permissions must be between 0 and 0777 (octal)
	// In decimal, 0777 octal = 511 decimal
	if permValue < 0 || permValue > 0777 {
		return fmt.Errorf("invalid permissions value: %d (must be between 0 and 0777 octal)", permValue)
	}

	return nil
}

func (g *genericConfigState) ToYAML() ([]byte, error) {
	return yaml.Marshal(g.data)
}

func (g *genericConfigState) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, &g.data)
}

func (g *genericConfigState) Validate() error {
	// Generic validation - just ensure data exists
	if g.data == nil {
		return fmt.Errorf("configuration data is nil")
	}
	return nil
}

func (g *genericConfigState) GetManagedFields() []string {
	fields := make([]string, 0, len(g.data))
	for k := range g.data {
		fields = append(fields, k)
	}
	return fields
}
