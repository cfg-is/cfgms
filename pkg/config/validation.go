// Package config provides configuration validation before storage persistence
package config

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
)

// ValidationManager handles configuration validation before storage
type ValidationManager struct {
	configStore interfaces.ConfigStore
}

// NewValidationManager creates a new validation manager
func NewValidationManager(configStore interfaces.ConfigStore) *ValidationManager {
	return &ValidationManager{
		configStore: configStore,
	}
}

// ValidationResult represents the result of configuration validation
type ValidationResult struct {
	Valid            bool                          `json:"valid"`
	Errors           []ValidationError             `json:"errors"`
	Warnings         []ValidationError             `json:"warnings"`
	TenantChecks     *TenantValidationResult       `json:"tenant_checks,omitempty"`
	DependencyChecks *DependencyValidationResult   `json:"dependency_checks,omitempty"`
	StorageChecks    *StorageValidationResult      `json:"storage_checks,omitempty"`
}

// ValidationError represents a specific validation error or warning
type ValidationError struct {
	Field       string `json:"field"`
	Message     string `json:"message"`
	Code        string `json:"code"`
	Level       string `json:"level"`       // error, warning, info
	Suggestion  string `json:"suggestion,omitempty"`
}

// TenantValidationResult represents tenant-specific validation results
type TenantValidationResult struct {
	TenantExists      bool   `json:"tenant_exists"`
	TenantID          string `json:"tenant_id"`
	InheritanceValid  bool   `json:"inheritance_valid"`
	ConflictsDetected int    `json:"conflicts_detected"`
}

// DependencyValidationResult represents module dependency validation
type DependencyValidationResult struct {
	MissingModules    []string `json:"missing_modules"`
	ConflictingModules []string `json:"conflicting_modules"`
	UnusedModules     []string `json:"unused_modules"`
}

// StorageValidationResult represents storage-level validation
type StorageValidationResult struct {
	FormatValid    bool   `json:"format_valid"`
	ChecksumValid  bool   `json:"checksum_valid"`
	SizeWithinLimits bool `json:"size_within_limits"`
	DataSize       int    `json:"data_size"`
}

// ValidateConfiguration performs comprehensive configuration validation
func (vm *ValidationManager) ValidateConfiguration(ctx context.Context, tenantID, stewardID string, config *stewardconfig.StewardConfig) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationError{},
	}

	// Basic steward configuration validation
	if err := stewardconfig.ValidateConfiguration(*config); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "steward_config",
			Message: fmt.Sprintf("Basic validation failed: %v", err),
			Code:    "BASIC_VALIDATION_FAILED",
			Level:   "error",
		})
	}

	// Validate tenant context
	result.TenantChecks = vm.validateTenantContext(ctx, tenantID, stewardID, config)
	if !result.TenantChecks.TenantExists {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "tenant_id",
			Message: fmt.Sprintf("Tenant '%s' does not exist", tenantID),
			Code:    "TENANT_NOT_FOUND",
			Level:   "error",
			Suggestion: "Ensure the tenant exists before storing configuration",
		})
	}

	// Validate module dependencies
	result.DependencyChecks = vm.validateDependencies(ctx, config)
	if len(result.DependencyChecks.MissingModules) > 0 {
		result.Warnings = append(result.Warnings, ValidationError{
			Field:   "modules",
			Message: fmt.Sprintf("Missing modules: %s", strings.Join(result.DependencyChecks.MissingModules, ", ")),
			Code:    "MISSING_MODULES",
			Level:   "warning",
			Suggestion: "Ensure all required modules are available on the target system",
		})
	}

	// Validate storage requirements
	result.StorageChecks = vm.validateStorageRequirements(ctx, config)
	if !result.StorageChecks.SizeWithinLimits {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "config_size",
			Message: fmt.Sprintf("Configuration size (%d bytes) exceeds storage limits", result.StorageChecks.DataSize),
			Code:    "CONFIG_TOO_LARGE",
			Level:   "error",
			Suggestion: "Reduce configuration size or contact administrator to increase limits",
		})
	}

	// Validate inheritance conflicts
	if result.TenantChecks.ConflictsDetected > 0 {
		result.Warnings = append(result.Warnings, ValidationError{
			Field:   "inheritance",
			Message: fmt.Sprintf("Detected %d inheritance conflicts", result.TenantChecks.ConflictsDetected),
			Code:    "INHERITANCE_CONFLICTS",
			Level:   "warning",
			Suggestion: "Review tenant hierarchy configuration for conflicting settings",
		})
	}

	// Validate resource configurations
	vm.validateResources(result, config)

	// Validate steward settings
	vm.validateStewardSettings(result, config)

	return result
}

// validateTenantContext validates tenant-related aspects of the configuration
func (vm *ValidationManager) validateTenantContext(ctx context.Context, tenantID, stewardID string, config *stewardconfig.StewardConfig) *TenantValidationResult {
	result := &TenantValidationResult{
		TenantExists:      true, // Simplified - would check tenant store in full implementation
		TenantID:          tenantID,
		InheritanceValid:  true,
		ConflictsDetected: 0,
	}

	// In a full implementation, this would:
	// 1. Check if tenant exists in ClientTenantStore
	// 2. Validate inheritance chain
	// 3. Check for configuration conflicts in the hierarchy
	// 4. Validate permissions to modify configuration

	return result
}

// validateDependencies validates module dependencies and availability
func (vm *ValidationManager) validateDependencies(ctx context.Context, config *stewardconfig.StewardConfig) *DependencyValidationResult {
	result := &DependencyValidationResult{
		MissingModules:     []string{},
		ConflictingModules: []string{},
		UnusedModules:      []string{},
	}

	// Get required modules from resources
	requiredModules := make(map[string]bool)
	for _, resource := range config.Resources {
		requiredModules[resource.Module] = true
	}

	// Check configured module paths
	configuredModules := make(map[string]bool)
	for moduleName := range config.Modules {
		configuredModules[moduleName] = true
	}

	// Find missing modules (required but not configured)
	for moduleName := range requiredModules {
		if !configuredModules[moduleName] {
			result.MissingModules = append(result.MissingModules, moduleName)
		}
	}

	// Find unused modules (configured but not required)
	for moduleName := range configuredModules {
		if !requiredModules[moduleName] {
			result.UnusedModules = append(result.UnusedModules, moduleName)
		}
	}

	return result
}

// validateStorageRequirements validates storage-level requirements
func (vm *ValidationManager) validateStorageRequirements(ctx context.Context, config *stewardconfig.StewardConfig) *StorageValidationResult {
	result := &StorageValidationResult{
		FormatValid:      true,
		ChecksumValid:    true,
		SizeWithinLimits: true,
	}

	// Estimate configuration size
	configData, err := yaml.Marshal(config)
	if err != nil {
		result.FormatValid = false
		return result
	}

	result.DataSize = len(configData)

	// Check size limits (simplified - would use storage provider capabilities)
	maxConfigSize := 1024 * 1024 // 1MB default limit
	if result.DataSize > maxConfigSize {
		result.SizeWithinLimits = false
	}

	return result
}

// validateResources validates resource configurations
func (vm *ValidationManager) validateResources(result *ValidationResult, config *stewardconfig.StewardConfig) {
	resourceNames := make(map[string]bool)

	for i, resource := range config.Resources {
		// Check for duplicate resource names
		if resourceNames[resource.Name] {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("resources[%d].name", i),
				Message: fmt.Sprintf("Duplicate resource name: %s", resource.Name),
				Code:    "DUPLICATE_RESOURCE_NAME",
				Level:   "error",
				Suggestion: "Ensure all resource names are unique within the configuration",
			})
		}
		resourceNames[resource.Name] = true

		// Validate resource name format
		if !isValidResourceName(resource.Name) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("resources[%d].name", i),
				Message: fmt.Sprintf("Invalid resource name format: %s", resource.Name),
				Code:    "INVALID_RESOURCE_NAME",
				Level:   "error",
				Suggestion: "Resource names must contain only alphanumeric characters, hyphens, and underscores",
			})
		}

		// Validate module name
		if resource.Module == "" {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("resources[%d].module", i),
				Message: "Module name is required",
				Code:    "MISSING_MODULE_NAME",
				Level:   "error",
			})
		}

		// Validate resource configuration
		if len(resource.Config) == 0 {
			result.Warnings = append(result.Warnings, ValidationError{
				Field:   fmt.Sprintf("resources[%d].config", i),
				Message: fmt.Sprintf("Resource '%s' has empty configuration", resource.Name),
				Code:    "EMPTY_RESOURCE_CONFIG",
				Level:   "warning",
				Suggestion: "Consider providing configuration for this resource or removing it",
			})
		}
	}
}

// validateStewardSettings validates steward-specific settings
func (vm *ValidationManager) validateStewardSettings(result *ValidationResult, config *stewardconfig.StewardConfig) {
	// Validate steward ID
	if config.Steward.ID == "" {
		result.Warnings = append(result.Warnings, ValidationError{
			Field:   "steward.id",
			Message: "Steward ID is empty - will use hostname as default",
			Code:    "EMPTY_STEWARD_ID",
			Level:   "warning",
			Suggestion: "Consider setting an explicit steward ID for better identification",
		})
	}

	// Validate operation mode
	validModes := []stewardconfig.OperationMode{stewardconfig.ModeStandalone, stewardconfig.ModeController}
	modeValid := false
	for _, validMode := range validModes {
		if config.Steward.Mode == validMode {
			modeValid = true
			break
		}
	}

	if !modeValid && config.Steward.Mode != "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "steward.mode",
			Message: fmt.Sprintf("Invalid operation mode: %s", config.Steward.Mode),
			Code:    "INVALID_OPERATION_MODE",
			Level:   "error",
			Suggestion: "Use 'standalone' or 'controller' as operation mode",
		})
	}

	// Validate logging configuration
	validLogLevels := []string{"debug", "info", "warn", "error"}
	if config.Steward.Logging.Level != "" {
		levelValid := false
		for _, validLevel := range validLogLevels {
			if config.Steward.Logging.Level == validLevel {
				levelValid = true
				break
			}
		}

		if !levelValid {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   "steward.logging.level",
				Message: fmt.Sprintf("Invalid log level: %s", config.Steward.Logging.Level),
				Code:    "INVALID_LOG_LEVEL",
				Level:   "error",
				Suggestion: "Use debug, info, warn, or error as log level",
			})
		}
	}

	// Validate error handling settings
	validActions := []stewardconfig.ErrorAction{stewardconfig.ActionContinue, stewardconfig.ActionFail, stewardconfig.ActionWarn}
	
	if config.Steward.ErrorHandling.ModuleLoadFailure != "" {
		if !isValidErrorAction(config.Steward.ErrorHandling.ModuleLoadFailure, validActions) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   "steward.error_handling.module_load_failure",
				Message: fmt.Sprintf("Invalid error action: %s", config.Steward.ErrorHandling.ModuleLoadFailure),
				Code:    "INVALID_ERROR_ACTION",
				Level:   "error",
				Suggestion: "Use continue, fail, or warn as error action",
			})
		}
	}
}

// isValidResourceName checks if a resource name follows the required format
func isValidResourceName(name string) bool {
	if name == "" {
		return false
	}

	for _, char := range name {
		if (char < 'a' || char > 'z') && 
			 (char < 'A' || char > 'Z') && 
			 (char < '0' || char > '9') && 
			 char != '-' && char != '_' {
			return false
		}
	}

	return true
}

// isValidErrorAction checks if an error action is valid
func isValidErrorAction(action stewardconfig.ErrorAction, validActions []stewardconfig.ErrorAction) bool {
	for _, validAction := range validActions {
		if action == validAction {
			return true
		}
	}
	return false
}

// ValidateConfigurationEntry validates a configuration entry for storage
func (vm *ValidationManager) ValidateConfigurationEntry(ctx context.Context, entry *interfaces.ConfigEntry) error {
	// Validate required fields
	if entry.Key == nil {
		return fmt.Errorf("configuration key is required")
	}

	if entry.Key.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}

	if entry.Key.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}

	if entry.Key.Name == "" {
		return fmt.Errorf("name is required")
	}

	if len(entry.Data) == 0 {
		return fmt.Errorf("configuration data is required")
	}

	// Validate format
	if entry.Format != interfaces.ConfigFormatYAML && entry.Format != interfaces.ConfigFormatJSON {
		return fmt.Errorf("invalid format: %s", entry.Format)
	}

	// Validate data format consistency
	if entry.Format == interfaces.ConfigFormatYAML {
		var temp interface{}
		if err := yaml.Unmarshal(entry.Data, &temp); err != nil {
			return fmt.Errorf("invalid YAML data: %w", err)
		}
	}

	// Use storage provider validation if available
	return vm.configStore.ValidateConfig(ctx, entry)
}