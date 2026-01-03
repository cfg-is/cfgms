// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/config"
)

func TestValidator_ValidateConfiguration(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name           string
		config         config.StewardConfig
		expectValid    bool
		expectErrors   int
		expectWarnings int
		expectCritical bool
	}{
		{
			name: "valid_basic_configuration",
			config: config.StewardConfig{
				Steward: config.StewardSettings{
					ID:   "test-steward",
					Mode: config.ModeStandalone,
					Logging: config.LoggingConfig{
						Level:  "info",
						Format: "text",
					},
					ErrorHandling: config.ErrorHandlingConfig{
						ModuleLoadFailure:  config.ActionContinue,
						ResourceFailure:    config.ActionWarn,
						ConfigurationError: config.ActionFail,
					},
				},
				Resources: []config.ResourceConfig{
					{
						Name:   "test-directory",
						Module: "directory",
						Config: map[string]interface{}{
							"path":        "/opt/test",
							"permissions": 0755, // Standard directory permissions
						},
					},
				},
			},
			expectValid:    true,
			expectErrors:   0,
			expectWarnings: 0,
			expectCritical: false,
		},
		{
			name: "missing_steward_id",
			config: config.StewardConfig{
				Steward: config.StewardSettings{
					Mode: config.ModeStandalone,
					Logging: config.LoggingConfig{
						Level:  "info",
						Format: "text",
					},
				},
			},
			expectValid:    false,
			expectErrors:   1,
			expectWarnings: 0,
			expectCritical: true,
		},
		{
			name: "duplicate_resource_names",
			config: config.StewardConfig{
				Steward: config.StewardSettings{
					ID:   "test-steward",
					Mode: config.ModeStandalone,
					Logging: config.LoggingConfig{
						Level:  "info",
						Format: "text",
					},
					ErrorHandling: config.ErrorHandlingConfig{
						ModuleLoadFailure:  config.ActionContinue,
						ResourceFailure:    config.ActionWarn,
						ConfigurationError: config.ActionFail,
					},
				},
				Resources: []config.ResourceConfig{
					{
						Name:   "duplicate-name",
						Module: "directory",
						Config: map[string]interface{}{
							"path":        "/opt/test1",
							"permissions": 0755, // Standard directory permissions
						},
					},
					{
						Name:   "duplicate-name",
						Module: "file",
						Config: map[string]interface{}{
							"path":    "/opt/test2/file.txt",
							"content": "test content",
						},
					},
				},
			},
			expectValid:    false,
			expectErrors:   1, // Just duplicate name error
			expectWarnings: 1, // Missing parent directory warning
			expectCritical: false,
		},
		{
			name: "world_writable_permissions_warning",
			config: config.StewardConfig{
				Steward: config.StewardSettings{
					ID:   "test-steward",
					Mode: config.ModeStandalone,
					Logging: config.LoggingConfig{
						Level:  "info",
						Format: "text",
					},
					ErrorHandling: config.ErrorHandlingConfig{
						ModuleLoadFailure:  config.ActionContinue,
						ResourceFailure:    config.ActionWarn,
						ConfigurationError: config.ActionFail,
					},
				},
				Resources: []config.ResourceConfig{
					{
						Name:   "unsafe-directory",
						Module: "directory",
						Config: map[string]interface{}{
							"path":        "/opt/unsafe",
							"permissions": 0777, // World writable (octal)
						},
					},
				},
			},
			expectValid:    true,
			expectErrors:   0,
			expectWarnings: 1,
			expectCritical: false,
		},
		{
			name: "missing_module_config",
			config: config.StewardConfig{
				Steward: config.StewardSettings{
					ID:   "test-steward",
					Mode: config.ModeStandalone,
					Logging: config.LoggingConfig{
						Level:  "info",
						Format: "text",
					},
					ErrorHandling: config.ErrorHandlingConfig{
						ModuleLoadFailure:  config.ActionContinue,
						ResourceFailure:    config.ActionWarn,
						ConfigurationError: config.ActionFail,
					},
				},
				Resources: []config.ResourceConfig{
					{
						Name:   "empty-config",
						Module: "directory",
						Config: map[string]interface{}{}, // Empty config
					},
				},
			},
			expectValid:    false,
			expectErrors:   3, // Empty config + missing path + missing permissions
			expectWarnings: 0,
			expectCritical: true, // Missing path is critical
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateConfiguration(tt.config)

			assert.Equal(t, tt.expectValid, result.Valid, "Validation result should match expected validity")

			if tt.expectCritical {
				assert.True(t, result.HasCriticalErrors(), "Should have critical errors")
			} else {
				assert.False(t, result.HasCriticalErrors(), "Should not have critical errors")
			}

			errorCount := len(result.GetIssuesByLevel(ValidationLevelError))
			warningCount := len(result.GetIssuesByLevel(ValidationLevelWarning)) - errorCount

			assert.Equal(t, tt.expectErrors, errorCount, "Error count should match")
			assert.Equal(t, tt.expectWarnings, warningCount, "Warning count should match")

			// Validate that all issues have required fields
			for _, issue := range result.Issues {
				assert.NotEmpty(t, issue.Field, "Issue should have field specified")
				assert.NotEmpty(t, issue.Message, "Issue should have message")
				assert.NotEmpty(t, issue.Code, "Issue should have error code")
			}
		})
	}
}

func TestBusinessRules(t *testing.T) {
	t.Run("ResourceNameUniquenessRule", func(t *testing.T) {
		rule := &ResourceNameUniquenessRule{}

		config := config.StewardConfig{
			Resources: []config.ResourceConfig{
				{Name: "unique-1", Module: "directory"},
				{Name: "unique-2", Module: "file"},
				{Name: "unique-1", Module: "package"}, // Duplicate
			},
		}

		issues := rule.Validate(config)
		require.Len(t, issues, 1)
		assert.Equal(t, ValidationLevelError, issues[0].Level)
		assert.Contains(t, issues[0].Message, "Duplicate resource name")
		assert.Equal(t, "DUPLICATE_RESOURCE_NAME", issues[0].Code)
		assert.NotEmpty(t, issues[0].Suggestion)
	})

	t.Run("ModuleCompatibilityRule", func(t *testing.T) {
		rule := &ModuleCompatibilityRule{}

		config := config.StewardConfig{
			Resources: []config.ResourceConfig{
				{
					Name:   "invalid-directory",
					Module: "directory",
					Config: map[string]interface{}{
						// Missing required 'path' field
						"permissions": 0755, // Standard directory permissions
					},
				},
			},
		}

		issues := rule.Validate(config)
		require.Len(t, issues, 1)
		assert.Equal(t, ValidationLevelCritical, issues[0].Level)
		assert.Contains(t, issues[0].Message, "requires a 'path' field")
		assert.Equal(t, "MISSING_REQUIRED_FIELD", issues[0].Code)
	})

	t.Run("SecurityBestPracticesRule", func(t *testing.T) {
		rule := &SecurityBestPracticesRule{}

		config := config.StewardConfig{
			Resources: []config.ResourceConfig{
				{
					Name:   "world-writable-file",
					Module: "file",
					Config: map[string]interface{}{
						"path":        "/tmp/unsafe.txt",
						"permissions": 0646,                 // World writable (octal)
						"content":     "password=secret123", // Sensitive content
					},
				},
			},
		}

		issues := rule.Validate(config)
		require.Len(t, issues, 2) // Both permission and content warnings

		// Check for world-writable warning
		foundPermissionWarning := false
		foundContentWarning := false
		for _, issue := range issues {
			if issue.Code == "WORLD_WRITABLE_FILE" {
				foundPermissionWarning = true
				assert.Equal(t, ValidationLevelWarning, issue.Level)
			}
			if issue.Code == "POTENTIAL_SENSITIVE_DATA" {
				foundContentWarning = true
				assert.Equal(t, ValidationLevelWarning, issue.Level)
			}
		}

		assert.True(t, foundPermissionWarning, "Should detect world-writable permissions")
		assert.True(t, foundContentWarning, "Should detect potential sensitive data")
	})
}

func TestValidationResult(t *testing.T) {
	result := &ValidationResult{
		Issues: []ValidationIssue{
			{Level: ValidationLevelInfo, Message: "Info message"},
			{Level: ValidationLevelWarning, Message: "Warning message"},
			{Level: ValidationLevelError, Message: "Error message"},
			{Level: ValidationLevelCritical, Message: "Critical message"},
		},
	}

	t.Run("HasErrors", func(t *testing.T) {
		assert.True(t, result.HasErrors())
	})

	t.Run("HasCriticalErrors", func(t *testing.T) {
		assert.True(t, result.HasCriticalErrors())
	})

	t.Run("GetIssuesByLevel", func(t *testing.T) {
		errors := result.GetIssuesByLevel(ValidationLevelError)
		assert.Len(t, errors, 2) // Error and Critical

		warnings := result.GetIssuesByLevel(ValidationLevelWarning)
		assert.Len(t, warnings, 3) // Warning, Error, and Critical

		all := result.GetIssuesByLevel(ValidationLevelInfo)
		assert.Len(t, all, 4) // All issues
	})
}

func TestValidationCaching(t *testing.T) {
	validator := NewValidator()

	config := config.StewardConfig{
		Steward: config.StewardSettings{
			ID:   "cache-test",
			Mode: config.ModeStandalone,
			Logging: config.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
			ErrorHandling: config.ErrorHandlingConfig{
				ModuleLoadFailure:  config.ActionContinue,
				ResourceFailure:    config.ActionWarn,
				ConfigurationError: config.ActionFail,
			},
		},
	}

	// First validation
	result1 := validator.ValidateConfiguration(config)

	// Second validation (should use cache)
	result2 := validator.ValidateConfiguration(config)
	metrics2 := validator.GetMetrics()

	// Results should be equivalent
	assert.Equal(t, result1.Valid, result2.Valid)
	assert.Equal(t, len(result1.Issues), len(result2.Issues))

	// Cache should have been used on second validation
	assert.Equal(t, int64(1), metrics2.CacheHits)
	assert.Equal(t, int64(2), metrics2.TotalValidations)
}

func TestValidationMetrics(t *testing.T) {
	validator := NewValidator()

	config := config.StewardConfig{
		Steward: config.StewardSettings{
			ID:   "metrics-test",
			Mode: config.ModeStandalone,
			Logging: config.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
		},
	}

	// Perform multiple validations
	for i := 0; i < 3; i++ {
		validator.ValidateConfiguration(config)
	}

	metrics := validator.GetMetrics()
	assert.Equal(t, int64(3), metrics.TotalValidations)
	// On fast systems, validation can complete in under a nanosecond
	assert.True(t, metrics.AverageValidationTime >= 0)
}
