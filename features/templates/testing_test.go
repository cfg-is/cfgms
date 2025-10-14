package templates_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/cfgis/cfgms/features/templates"
)

func TestTemplateTestRunner_BasicTest(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	dnaProvider := templates.NewMockDNAProvider()
	configService := templates.NewMockConfigService()
	resolver := templates.NewVariableResolver(dnaProvider, configService)
	engine := templates.NewTemplateEngine(store, dnaProvider)
	runner := templates.NewTemplateTestRunner(engine, store, dnaProvider, resolver)

	ctx := context.Background()

	// Create simple template
	template := &templates.Template{
		ID:      "test-template",
		Name:    "Test Template",
		Content: []byte(`variables:
  hostname: "server-01"

config:
  name: "$hostname"
  os: "$DNA.System.OS"`),
		Variables: make(map[string]interface{}),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := store.Save(ctx, template)
	require.NoError(t, err)

	// Create test case
	test := templates.TemplateTest{
		Name:        "Basic Variable Substitution",
		Description: "Test that variables are substituted correctly",
		Input: templates.TemplateTestInput{
			Variables: map[string]interface{}{
				"hostname": "test-server",
			},
			DNA: map[string]interface{}{
				"System": map[string]interface{}{
					"OS": "linux",
				},
			},
			TargetType: "device",
			TargetID:   "test-device",
		},
		Expected: templates.TemplateTestExpected{
			Contains: []string{
				`name: "test-server"`,
				`os: "linux"`,
			},
			NoErrors: true,
		},
		Timeout: 5 * time.Second,
	}

	// Run test
	result, err := runner.RunTest(ctx, "test-template", test)
	require.NoError(t, err)
	assert.True(t, result.Passed, "Test should pass")
	assert.Empty(t, result.Failures)
}

func TestTemplateTestRunner_FailedExpectations(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	dnaProvider := templates.NewMockDNAProvider()
	configService := templates.NewMockConfigService()
	resolver := templates.NewVariableResolver(dnaProvider, configService)
	engine := templates.NewTemplateEngine(store, dnaProvider)
	runner := templates.NewTemplateTestRunner(engine, store, dnaProvider, resolver)

	ctx := context.Background()

	// Create template
	template := &templates.Template{
		ID:      "test-template",
		Name:    "Test Template",
		Content: []byte(`config:
  value: "actual-value"`),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := store.Save(ctx, template)
	require.NoError(t, err)

	// Create test with expectations that will fail
	test := templates.TemplateTest{
		Name: "Failed Expectations Test",
		Input: templates.TemplateTestInput{
			TargetType: "device",
			TargetID:   "test-device",
		},
		Expected: templates.TemplateTestExpected{
			Contains: []string{
				"expected-value",  // This won't be found
			},
			NotContains: []string{
				"actual-value",    // This will be found but shouldn't
			},
		},
	}

	// Run test
	result, err := runner.RunTest(ctx, "test-template", test)
	require.NoError(t, err)
	assert.False(t, result.Passed, "Test should fail")
	assert.NotEmpty(t, result.Failures)
	assert.Contains(t, result.Failures[0], "expected string not found")
	assert.Contains(t, result.Failures[1], "unexpected string found")
}

func TestTemplateTestRunner_CustomValidator(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	dnaProvider := templates.NewMockDNAProvider()
	configService := templates.NewMockConfigService()
	resolver := templates.NewVariableResolver(dnaProvider, configService)
	engine := templates.NewTemplateEngine(store, dnaProvider)
	runner := templates.NewTemplateTestRunner(engine, store, dnaProvider, resolver)

	ctx := context.Background()

	// Create template
	template := &templates.Template{
		ID:      "test-template",
		Name:    "Test Template",
		Content: []byte(`config:
  port: 8080`),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := store.Save(ctx, template)
	require.NoError(t, err)

	// Create test with custom validator
	test := templates.TemplateTest{
		Name: "Custom Validator Test",
		Input: templates.TemplateTestInput{
			TargetType: "device",
			TargetID:   "test-device",
		},
		Expected: templates.TemplateTestExpected{
			CustomValidator: func(result *templates.RenderResult) error {
				rendered := string(result.Content)
				if !strings.Contains(rendered, "port:") {
					return assert.AnError
				}
				return nil
			},
		},
	}

	// Run test
	result, err := runner.RunTest(ctx, "test-template", test)
	require.NoError(t, err)
	assert.True(t, result.Passed)
}

func TestTemplateTestSuite(t *testing.T) {
	// Setup
	store := templates.NewInMemoryTemplateStore()
	dnaProvider := templates.NewMockDNAProvider()
	configService := templates.NewMockConfigService()
	resolver := templates.NewVariableResolver(dnaProvider, configService)
	engine := templates.NewTemplateEngine(store, dnaProvider)
	runner := templates.NewTemplateTestRunner(engine, store, dnaProvider, resolver)

	ctx := context.Background()

	// Create template
	template := &templates.Template{
		ID:      "test-template",
		Name:    "Test Template",
		Content: []byte(`variables:
  env: "production"

config:
  environment: "$env"
  $if "$env" == "production"
  secure: true
  $endif`),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := store.Save(ctx, template)
	require.NoError(t, err)

	// Create test suite
	suite := templates.TemplateTestSuite{
		TemplateID:  "test-template",
		Name:        "Test Template Suite",
		Description: "Comprehensive tests for test template",
		Tests: []templates.TemplateTest{
			{
				Name: "Production Environment",
				Input: templates.TemplateTestInput{
					Variables: map[string]interface{}{
						"env": "production",
					},
					TargetType: "device",
					TargetID:   "prod-device",
				},
				Expected: templates.TemplateTestExpected{
					Contains: []string{
						`environment: "production"`,
						"secure: true",
					},
					NoErrors: true,
				},
			},
			{
				Name: "Development Environment",
				Input: templates.TemplateTestInput{
					Variables: map[string]interface{}{
						"env": "development",
					},
					TargetType: "device",
					TargetID:   "dev-device",
				},
				Expected: templates.TemplateTestExpected{
					Contains: []string{
						`environment: "development"`,
					},
					NotContains: []string{
						"secure: true",
					},
					NoErrors: true,
				},
			},
		},
	}

	// Run test suite
	results, err := runner.RunTestSuite(ctx, suite)
	require.NoError(t, err)
	assert.Equal(t, 2, len(results))
	assert.True(t, results[0].Passed)
	assert.True(t, results[1].Passed)
}

func TestFormatTestResults(t *testing.T) {
	results := []templates.TemplateTestResult{
		{
			TestName: "Passing Test",
			Passed:   true,
			Duration: 100 * time.Millisecond,
		},
		{
			TestName: "Failing Test",
			Passed:   false,
			Duration: 150 * time.Millisecond,
			Failures: []string{
				"Expected value not found",
				"Unexpected value present",
			},
		},
	}

	formatted := templates.FormatTestResults(results)
	assert.Contains(t, formatted, "✓ Passing Test")
	assert.Contains(t, formatted, "✗ Failing Test")
	assert.Contains(t, formatted, "Total: 2 tests")
	assert.Contains(t, formatted, "1 passed")
	assert.Contains(t, formatted, "1 failed")
	assert.Contains(t, formatted, "Expected value not found")
	assert.Contains(t, formatted, "Unexpected value present")
}

func TestValidateTemplateStructure(t *testing.T) {
	tests := []struct {
		name          string
		template      *templates.Template
		expectErrors  int
		errorContains string
	}{
		{
			name: "Valid Template",
			template: &templates.Template{
				ID:      "valid-template",
				Name:    "Valid Template",
				Content: []byte("content"),
				Version: "1.0.0",
			},
			expectErrors: 0,
		},
		{
			name: "Missing ID",
			template: &templates.Template{
				Name:    "Template",
				Content: []byte("content"),
				Version: "1.0.0",
			},
			expectErrors:  1,
			errorContains: "ID is required",
		},
		{
			name: "Missing Name",
			template: &templates.Template{
				ID:      "template",
				Content: []byte("content"),
				Version: "1.0.0",
			},
			expectErrors:  1,
			errorContains: "Name is required",
		},
		{
			name: "Missing Content",
			template: &templates.Template{
				ID:      "template",
				Name:    "Template",
				Version: "1.0.0",
			},
			expectErrors:  1,
			errorContains: "Content is required",
		},
		{
			name: "Circular Dependency - Extends Self",
			template: &templates.Template{
				ID:      "template",
				Name:    "Template",
				Content: []byte("content"),
				Version: "1.0.0",
				Extends: "template",
			},
			expectErrors:  1,
			errorContains: "cannot extend itself",
		},
		{
			name: "Circular Dependency - Includes Self",
			template: &templates.Template{
				ID:       "template",
				Name:     "Template",
				Content:  []byte("content"),
				Version:  "1.0.0",
				Includes: []string{"template"},
			},
			expectErrors:  1,
			errorContains: "cannot include itself",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := templates.ValidateTemplateStructure(tt.template)
			assert.Equal(t, tt.expectErrors, len(errors))

			if tt.errorContains != "" && len(errors) > 0 {
				assert.Contains(t, errors[0].Message, tt.errorContains)
			}
		})
	}
}

func TestValidateMarketplaceTemplate(t *testing.T) {
	tests := []struct {
		name          string
		template      *templates.MarketplaceTemplate
		expectErrors  int
		errorContains string
	}{
		{
			name: "Valid Marketplace Template",
			template: &templates.MarketplaceTemplate{
				Template: &templates.Template{
					ID:          "valid-template",
					Name:        "Valid Template",
					Content:     []byte("content with at least twenty characters here"),
					Version:     "1.0.0",
					Description: "A valid description that is long enough",
				},
				Author:          "Author Name",
				License:         "MIT",
				Category:        "security",
				SemanticVersion: "1.0.0",
			},
			expectErrors: 0,
		},
		{
			name: "Missing Author",
			template: &templates.MarketplaceTemplate{
				Template: &templates.Template{
					ID:          "template",
					Name:        "Template",
					Content:     []byte("content with at least twenty characters"),
					Version:     "1.0.0",
					Description: "A valid description that is long enough",
				},
				License:         "MIT",
				Category:        "security",
				SemanticVersion: "1.0.0",
			},
			expectErrors:  1,
			errorContains: "Author is required",
		},
		{
			name: "Invalid Semantic Version",
			template: &templates.MarketplaceTemplate{
				Template: &templates.Template{
					ID:          "template",
					Name:        "Template",
					Content:     []byte("content with at least twenty characters"),
					Version:     "1.0.0",
					Description: "A valid description that is long enough",
				},
				Author:          "Author",
				License:         "MIT",
				Category:        "security",
				SemanticVersion: "invalid",
			},
			expectErrors:  1,
			errorContains: "MAJOR.MINOR.PATCH",
		},
		{
			name: "Short Description",
			template: &templates.MarketplaceTemplate{
				Template: &templates.Template{
					ID:          "template",
					Name:        "Template",
					Content:     []byte("content with at least twenty characters"),
					Version:     "1.0.0",
					Description: "Short",
				},
				Author:          "Author",
				License:         "MIT",
				Category:        "security",
				SemanticVersion: "1.0.0",
			},
			expectErrors:  1,
			errorContains: "at least 20 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := templates.ValidateMarketplaceTemplate(tt.template)
			assert.Equal(t, tt.expectErrors, len(errors))

			if tt.errorContains != "" && len(errors) > 0 {
				found := false
				for _, err := range errors {
					if strings.Contains(err.Message, tt.errorContains) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected error message containing: %s", tt.errorContains)
			}
		})
	}
}
