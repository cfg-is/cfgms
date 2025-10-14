// Package templates provides template testing framework for CFGMS.
// This enables automated validation and testing of configuration templates.
package templates

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// TemplateTestSuite represents a collection of tests for a template
type TemplateTestSuite struct {
	TemplateID  string
	Name        string
	Description string
	Tests       []TemplateTest
}

// TemplateTest represents a single test case for a template
type TemplateTest struct {
	Name        string
	Description string
	Input       TemplateTestInput
	Expected    TemplateTestExpected
	Timeout     time.Duration
}

// TemplateTestInput defines the input for a template test
type TemplateTestInput struct {
	// Variables to provide to the template
	Variables map[string]interface{}

	// Mock DNA data for testing
	DNA map[string]interface{}

	// Inherited variables for testing
	InheritedVariables map[string]interface{}

	// Target information
	TargetType string
	TargetID   string
}

// TemplateTestExpected defines expected outcomes for a template test
type TemplateTestExpected struct {
	// Expected strings in rendered output
	Contains []string

	// Strings that should NOT be in rendered output
	NotContains []string

	// Expected variable values in output
	Variables map[string]interface{}

	// Should render without errors
	NoErrors bool

	// Should render without warnings
	NoWarnings bool

	// Specific error/warning messages expected
	ErrorMessages   []string
	WarningMessages []string

	// Validation should pass
	ValidationPasses bool

	// Custom validation function
	CustomValidator func(result *RenderResult) error
}

// TemplateTestResult represents the result of running a template test
type TemplateTestResult struct {
	TestName     string
	Passed       bool
	Duration     time.Duration
	Error        error
	Failures     []string
	RenderResult *RenderResult
}

// TemplateTestRunner runs tests for templates
type TemplateTestRunner struct {
	engine      TemplateEngine
	store       TemplateStore
	dnaProvider DNAProvider
	resolver    VariableResolver
}

// NewTemplateTestRunner creates a new template test runner
func NewTemplateTestRunner(engine TemplateEngine, store TemplateStore, dnaProvider DNAProvider, resolver VariableResolver) *TemplateTestRunner {
	return &TemplateTestRunner{
		engine:      engine,
		store:       store,
		dnaProvider: dnaProvider,
		resolver:    resolver,
	}
}

// RunTest runs a single template test
func (r *TemplateTestRunner) RunTest(ctx context.Context, templateID string, test TemplateTest) (*TemplateTestResult, error) {
	start := time.Now()
	result := &TemplateTestResult{
		TestName: test.Name,
		Passed:   true,
	}

	// Set up timeout
	if test.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, test.Timeout)
		defer cancel()
	}

	// Get template
	template, err := r.store.Get(ctx, templateID)
	if err != nil {
		result.Passed = false
		result.Error = fmt.Errorf("failed to get template: %w", err)
		result.Duration = time.Since(start)
		return result, nil
	}

	// Set up mock DNA provider with test data
	if mockDNA, ok := r.dnaProvider.(*MockDNAProvider); ok {
		mockDNA.SetDNA(test.Input.TargetType, test.Input.TargetID, test.Input.DNA)
	}

	// Override template variables with test input
	if test.Input.Variables != nil {
		for k, v := range test.Input.Variables {
			template.Variables[k] = v
		}
	}

	// Resolve variables
	templateContext, err := r.resolver.Resolve(ctx, template, test.Input.TargetType, test.Input.TargetID)
	if err != nil {
		result.Passed = false
		result.Error = fmt.Errorf("failed to resolve variables: %w", err)
		result.Duration = time.Since(start)
		return result, nil
	}

	// Add inherited variables from test input
	if test.Input.InheritedVariables != nil {
		for k, v := range test.Input.InheritedVariables {
			templateContext.InheritedVariables[k] = v
		}
	}

	// Render template
	renderResult, err := r.engine.Render(ctx, template, templateContext, RenderOptions{
		Timeout:    30 * time.Second,
		StrictMode: false,
	})
	if err != nil {
		if test.Expected.NoErrors {
			result.Passed = false
			result.Error = fmt.Errorf("render failed but expected success: %w", err)
		}
	} else {
		result.RenderResult = renderResult

		// Check expectations
		failures := r.checkExpectations(renderResult, test.Expected)
		if len(failures) > 0 {
			result.Passed = false
			result.Failures = failures
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// RunTestSuite runs all tests in a test suite
func (r *TemplateTestRunner) RunTestSuite(ctx context.Context, suite TemplateTestSuite) ([]TemplateTestResult, error) {
	var results []TemplateTestResult

	for _, test := range suite.Tests {
		result, err := r.RunTest(ctx, suite.TemplateID, test)
		if err != nil {
			return nil, fmt.Errorf("test '%s' failed to run: %w", test.Name, err)
		}
		results = append(results, *result)
	}

	return results, nil
}

// checkExpectations validates that render result matches expectations
func (r *TemplateTestRunner) checkExpectations(result *RenderResult, expected TemplateTestExpected) []string {
	var failures []string

	rendered := string(result.Content)

	// Check expected strings are present
	for _, expectedStr := range expected.Contains {
		if !strings.Contains(rendered, expectedStr) {
			failures = append(failures, fmt.Sprintf("expected string not found: '%s'", expectedStr))
		}
	}

	// Check strings that should NOT be present
	for _, notExpectedStr := range expected.NotContains {
		if strings.Contains(rendered, notExpectedStr) {
			failures = append(failures, fmt.Sprintf("unexpected string found: '%s'", notExpectedStr))
		}
	}

	// Check no errors expectation
	if expected.NoErrors && result.Warnings != nil && len(result.Warnings) > 0 {
		// Check if any warnings are actually errors
		for _, warning := range result.Warnings {
			if strings.Contains(strings.ToLower(warning.Type), "error") {
				failures = append(failures, fmt.Sprintf("unexpected error: %s", warning.Message))
			}
		}
	}

	// Check no warnings expectation
	if expected.NoWarnings && len(result.Warnings) > 0 {
		failures = append(failures, fmt.Sprintf("unexpected warnings: %d warnings generated", len(result.Warnings)))
	}

	// Check for expected error messages
	if len(expected.ErrorMessages) > 0 {
		foundErrors := make(map[string]bool)
		for _, expectedError := range expected.ErrorMessages {
			found := false
			for _, warning := range result.Warnings {
				if strings.Contains(warning.Message, expectedError) {
					found = true
					foundErrors[expectedError] = true
					break
				}
			}
			if !found {
				failures = append(failures, fmt.Sprintf("expected error message not found: '%s'", expectedError))
			}
		}
	}

	// Check for expected warning messages
	if len(expected.WarningMessages) > 0 {
		for _, expectedWarning := range expected.WarningMessages {
			found := false
			for _, warning := range result.Warnings {
				if strings.Contains(warning.Message, expectedWarning) {
					found = true
					break
				}
			}
			if !found {
				failures = append(failures, fmt.Sprintf("expected warning message not found: '%s'", expectedWarning))
			}
		}
	}

	// Check expected variable values
	for key, expectedValue := range expected.Variables {
		actualValue, exists := result.Variables[key]
		if !exists {
			failures = append(failures, fmt.Sprintf("expected variable not found: %s", key))
		} else if actualValue != expectedValue {
			failures = append(failures, fmt.Sprintf("variable mismatch for %s: expected %v, got %v", key, expectedValue, actualValue))
		}
	}

	// Run custom validator if provided
	if expected.CustomValidator != nil {
		if err := expected.CustomValidator(result); err != nil {
			failures = append(failures, fmt.Sprintf("custom validation failed: %s", err.Error()))
		}
	}

	return failures
}

// FormatTestResults formats test results for display
func FormatTestResults(results []TemplateTestResult) string {
	var sb strings.Builder

	totalTests := len(results)
	passedTests := 0
	failedTests := 0
	totalDuration := time.Duration(0)

	for _, result := range results {
		totalDuration += result.Duration
		if result.Passed {
			passedTests++
			sb.WriteString(fmt.Sprintf("✓ %s (%.2fs)\n", result.TestName, result.Duration.Seconds()))
		} else {
			failedTests++
			sb.WriteString(fmt.Sprintf("✗ %s (%.2fs)\n", result.TestName, result.Duration.Seconds()))
			if result.Error != nil {
				sb.WriteString(fmt.Sprintf("  Error: %s\n", result.Error.Error()))
			}
			for _, failure := range result.Failures {
				sb.WriteString(fmt.Sprintf("  - %s\n", failure))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\nTotal: %d tests, %d passed, %d failed (%.2fs)\n",
		totalTests, passedTests, failedTests, totalDuration.Seconds()))

	return sb.String()
}

// ValidateTemplateStructure performs structural validation on a template
func ValidateTemplateStructure(template *Template) []ValidationError {
	var errors []ValidationError

	// Check required fields
	if template.ID == "" {
		errors = append(errors, ValidationError{
			Type:    "MISSING_FIELD",
			Message: "Template ID is required",
		})
	}

	if template.Name == "" {
		errors = append(errors, ValidationError{
			Type:    "MISSING_FIELD",
			Message: "Template Name is required",
		})
	}

	if len(template.Content) == 0 {
		errors = append(errors, ValidationError{
			Type:    "MISSING_FIELD",
			Message: "Template Content is required",
		})
	}

	if template.Version == "" {
		errors = append(errors, ValidationError{
			Type:    "MISSING_FIELD",
			Message: "Template Version is required",
		})
	}

	// Check for circular dependencies
	if template.Extends != "" && template.Extends == template.ID {
		errors = append(errors, ValidationError{
			Type:    "CIRCULAR_DEPENDENCY",
			Message: "Template cannot extend itself",
		})
	}

	// Check includes for self-reference
	for _, include := range template.Includes {
		if include == template.ID {
			errors = append(errors, ValidationError{
				Type:    "CIRCULAR_DEPENDENCY",
				Message: "Template cannot include itself",
			})
		}
	}

	return errors
}

// ValidateMarketplaceTemplate validates a marketplace template for publishing
func ValidateMarketplaceTemplate(template *MarketplaceTemplate) []ValidationError {
	var errors []ValidationError

	// First validate basic template structure
	errors = append(errors, ValidateTemplateStructure(template.Template)...)

	// Check marketplace-specific fields
	if template.Author == "" {
		errors = append(errors, ValidationError{
			Type:    "MISSING_FIELD",
			Message: "Author is required for marketplace templates",
		})
	}

	if template.License == "" {
		errors = append(errors, ValidationError{
			Type:    "MISSING_FIELD",
			Message: "License is required for marketplace templates",
		})
	}

	if template.Category == "" {
		errors = append(errors, ValidationError{
			Type:    "MISSING_FIELD",
			Message: "Category is required for marketplace templates",
		})
	}

	if template.SemanticVersion == "" {
		errors = append(errors, ValidationError{
			Type:    "MISSING_FIELD",
			Message: "Semantic version is required for marketplace templates",
		})
	} else {
		// Validate semantic version format (basic check)
		parts := strings.Split(template.SemanticVersion, ".")
		if len(parts) != 3 {
			errors = append(errors, ValidationError{
				Type:    "INVALID_FORMAT",
				Message: "Semantic version must be in format MAJOR.MINOR.PATCH",
			})
		}
	}

	// Check description is meaningful (at least 20 characters)
	if len(template.Description) < 20 {
		errors = append(errors, ValidationError{
			Type:    "INVALID_FIELD",
			Message: "Description must be at least 20 characters",
		})
	}

	return errors
}

// TestScenarioFromYAML loads a test scenario from YAML content
func TestScenarioFromYAML(data []byte) (*TemplateTestSuite, error) {
	// In a real implementation, parse YAML into TemplateTestSuite
	return nil, fmt.Errorf("not implemented")
}
