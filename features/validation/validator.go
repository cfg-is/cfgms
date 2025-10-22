// Package validation provides comprehensive configuration validation for CFGMS.
//
// This package implements a multi-layered validation framework that includes:
//   - Schema validation for structural correctness
//   - Business rules validation for logical constraints
//   - Cross-field validation for dependencies
//   - Enhanced error reporting with context and suggestions
//
// The validation system supports multiple validation levels:
//   - Critical: Errors that prevent configuration from working
//   - Error: Errors that should be fixed but may work with degraded functionality
//   - Warning: Issues that should be addressed but don't prevent operation
//   - Info: Informational messages about best practices
//
// Basic usage:
//
//	validator := validation.NewValidator()
//	result := validator.ValidateConfiguration(config)
//
//	if result.HasErrors() {
//		for _, err := range result.Errors {
//			fmt.Printf("Error: %s\n", err.Message)
//		}
//	}
package validation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/steward/config"
)

// ValidationLevel represents the severity of a validation issue
type ValidationLevel int

const (
	ValidationLevelInfo ValidationLevel = iota
	ValidationLevelWarning
	ValidationLevelError
	ValidationLevelCritical
)

// String returns the string representation of the validation level
func (vl ValidationLevel) String() string {
	switch vl {
	case ValidationLevelInfo:
		return "info"
	case ValidationLevelWarning:
		return "warning"
	case ValidationLevelError:
		return "error"
	case ValidationLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ValidationIssue represents a single validation problem
type ValidationIssue struct {
	Level      ValidationLevel        `json:"level"`
	Field      string                 `json:"field"`
	Message    string                 `json:"message"`
	Suggestion string                 `json:"suggestion,omitempty"`
	Code       string                 `json:"code"`
	Context    map[string]interface{} `json:"context,omitempty"`
}

// ValidationResult contains the complete validation outcome
type ValidationResult struct {
	Valid     bool                   `json:"valid"`
	Issues    []ValidationIssue      `json:"issues"`
	StartTime time.Time              `json:"start_time"`
	Duration  time.Duration          `json:"duration"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// HasErrors returns true if there are any error or critical level issues
func (vr *ValidationResult) HasErrors() bool {
	for _, issue := range vr.Issues {
		if issue.Level >= ValidationLevelError {
			return true
		}
	}
	return false
}

// HasCriticalErrors returns true if there are any critical level issues
func (vr *ValidationResult) HasCriticalErrors() bool {
	for _, issue := range vr.Issues {
		if issue.Level == ValidationLevelCritical {
			return true
		}
	}
	return false
}

// GetIssuesByLevel returns all issues of the specified level or higher
func (vr *ValidationResult) GetIssuesByLevel(level ValidationLevel) []ValidationIssue {
	var filtered []ValidationIssue
	for _, issue := range vr.Issues {
		if issue.Level >= level {
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

// Validator provides comprehensive configuration validation
type Validator struct {
	businessRules []BusinessRule
	enableCaching bool
	cache         map[string]*ValidationResult
	metrics       *ValidationMetrics
}

// BusinessRule represents a custom validation rule
type BusinessRule interface {
	Name() string
	Validate(config interface{}) []ValidationIssue
}

// ValidationMetrics tracks validation performance and statistics
type ValidationMetrics struct {
	TotalValidations      int64         `json:"total_validations"`
	CacheHits             int64         `json:"cache_hits"`
	CacheMisses           int64         `json:"cache_misses"`
	AverageValidationTime time.Duration `json:"average_validation_time"`
	SchemaValidationTime  time.Duration `json:"schema_validation_time"`
	BusinessRuleTime      time.Duration `json:"business_rule_time"`
}

// NewValidator creates a new configuration validator
func NewValidator() *Validator {
	return &Validator{
		businessRules: []BusinessRule{
			&ResourceNameUniquenessRule{},
			&ModuleCompatibilityRule{},
			&ResourceDependencyRule{},
			&SecurityBestPracticesRule{},
		},
		enableCaching: true,
		cache:         make(map[string]*ValidationResult),
		metrics:       &ValidationMetrics{},
	}
}

// AddBusinessRule adds a custom business rule to the validator
func (v *Validator) AddBusinessRule(rule BusinessRule) {
	v.businessRules = append(v.businessRules, rule)
}

// ValidateConfiguration performs comprehensive validation of a steward configuration
func (v *Validator) ValidateConfiguration(cfg config.StewardConfig) *ValidationResult {
	startTime := time.Now()
	result := &ValidationResult{
		Valid:     true,
		Issues:    []ValidationIssue{},
		StartTime: startTime,
		Metadata:  make(map[string]interface{}),
	}

	// Check cache first
	var cacheKey string
	if v.enableCaching {
		cacheKey = v.generateCacheKey(cfg)
		if cached, exists := v.cache[cacheKey]; exists {
			v.metrics.CacheHits++
			v.metrics.TotalValidations++
			// Return a copy with updated timestamp
			cachedResult := *cached
			cachedResult.StartTime = startTime
			cachedResult.Duration = time.Since(startTime)
			return &cachedResult
		}
		v.metrics.CacheMisses++
	}

	// Schema validation
	schemaStart := time.Now()
	schemaIssues := v.validateSchema(cfg)
	v.metrics.SchemaValidationTime = time.Since(schemaStart)
	result.Issues = append(result.Issues, schemaIssues...)

	// Business rules validation
	businessStart := time.Now()
	for _, rule := range v.businessRules {
		ruleIssues := rule.Validate(cfg)
		result.Issues = append(result.Issues, ruleIssues...)
	}
	v.metrics.BusinessRuleTime = time.Since(businessStart)

	// Module-specific validation
	moduleIssues := v.validateModuleConfigs(cfg)
	result.Issues = append(result.Issues, moduleIssues...)

	// Determine overall validity
	result.Valid = !result.HasErrors()
	result.Duration = time.Since(startTime)

	// Update metrics
	v.metrics.TotalValidations++
	v.updateAverageTime(result.Duration)

	// Cache result
	if v.enableCaching && cacheKey != "" {
		// Store a copy to prevent mutations
		cached := *result
		v.cache[cacheKey] = &cached
	}

	return result
}

// validateSchema performs basic structural validation
func (v *Validator) validateSchema(cfg config.StewardConfig) []ValidationIssue {
	var issues []ValidationIssue

	// Basic structural validation
	if cfg.Steward.ID == "" {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelCritical,
			Field:      "steward.id",
			Message:    "Steward ID is required",
			Code:       "MISSING_STEWARD_ID",
			Suggestion: "Provide a unique identifier for this steward instance",
		})
	}

	if cfg.Steward.Mode == "" {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelError,
			Field:      "steward.mode",
			Message:    "Steward mode is required",
			Code:       "MISSING_STEWARD_MODE",
			Suggestion: "Set mode to 'standalone' or 'controller'",
		})
	} else if cfg.Steward.Mode != "standalone" && cfg.Steward.Mode != "controller" {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelError,
			Field:      "steward.mode",
			Message:    fmt.Sprintf("Invalid steward mode: %s", cfg.Steward.Mode),
			Code:       "INVALID_STEWARD_MODE",
			Suggestion: "Use 'standalone' for local operation or 'controller' for remote management",
		})
	}

	if cfg.Steward.Logging.Level == "" {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelWarning,
			Field:      "steward.logging.level",
			Message:    "Logging level not specified, using default 'info'",
			Code:       "DEFAULT_LOGGING_LEVEL",
			Suggestion: "Explicitly set logging level to 'debug', 'info', 'warn', or 'error'",
		})
	}

	if cfg.Steward.Logging.Format == "" {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelWarning,
			Field:      "steward.logging.format",
			Message:    "Logging format not specified, using default 'text'",
			Code:       "DEFAULT_LOGGING_FORMAT",
			Suggestion: "Explicitly set logging format to 'text' or 'json'",
		})
	}

	return issues
}

// validateModuleConfigs validates module-specific configurations
func (v *Validator) validateModuleConfigs(cfg config.StewardConfig) []ValidationIssue {
	var issues []ValidationIssue

	for i, resource := range cfg.Resources {
		fieldPrefix := fmt.Sprintf("resources[%d]", i)

		// Validate module exists
		if !v.isValidModule(resource.Module) {
			issues = append(issues, ValidationIssue{
				Level:      ValidationLevelCritical,
				Field:      fieldPrefix + ".module",
				Message:    fmt.Sprintf("Unknown module: %s", resource.Module),
				Code:       "UNKNOWN_MODULE",
				Suggestion: fmt.Sprintf("Valid modules are: %s", strings.Join(v.getValidModules(), ", ")),
			})
			continue
		}

		// Validate module configuration using the module's own validation
		moduleIssues := v.validateModuleSpecificConfig(resource.Module, resource.Config, fieldPrefix+".config")
		issues = append(issues, moduleIssues...)
	}

	return issues
}

// generateCacheKey generates a cache key for the configuration
func (v *Validator) generateCacheKey(cfg config.StewardConfig) string {
	// Create a hash of the configuration content
	configData, _ := json.Marshal(cfg)
	hash := sha256.Sum256(configData)
	return fmt.Sprintf("%x", hash)
}

// isValidModule checks if the module name is valid
func (v *Validator) isValidModule(module string) bool {
	validModules := []string{"directory", "file", "firewall", "package"}
	for _, valid := range validModules {
		if module == valid {
			return true
		}
	}
	return false
}

// getValidModules returns the list of valid module names
func (v *Validator) getValidModules() []string {
	return []string{"directory", "file", "firewall", "package"}
}

// validateModuleSpecificConfig validates configuration for a specific module
func (v *Validator) validateModuleSpecificConfig(moduleName string, moduleConfig map[string]interface{}, fieldPrefix string) []ValidationIssue {
	// This would integrate with the module's own validation
	// For now, we'll provide basic validation
	var issues []ValidationIssue

	if len(moduleConfig) == 0 {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelError,
			Field:      fieldPrefix,
			Message:    "Module configuration cannot be empty",
			Code:       "EMPTY_MODULE_CONFIG",
			Suggestion: fmt.Sprintf("Provide configuration parameters for the %s module", moduleName),
		})
	}

	return issues
}

// updateAverageTime updates the average validation time metric
func (v *Validator) updateAverageTime(duration time.Duration) {
	if v.metrics.TotalValidations == 1 {
		v.metrics.AverageValidationTime = duration
	} else {
		// Calculate running average
		total := time.Duration(v.metrics.TotalValidations-1) * v.metrics.AverageValidationTime
		v.metrics.AverageValidationTime = (total + duration) / time.Duration(v.metrics.TotalValidations)
	}
}

// GetMetrics returns validation performance metrics
func (v *Validator) GetMetrics() *ValidationMetrics {
	return v.metrics
}

// ClearCache clears the validation cache
func (v *Validator) ClearCache() {
	v.cache = make(map[string]*ValidationResult)
}

// SetCachingEnabled enables or disables result caching
func (v *Validator) SetCachingEnabled(enabled bool) {
	v.enableCaching = enabled
	if !enabled {
		v.ClearCache()
	}
}
