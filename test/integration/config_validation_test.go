// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors

// Package integration contains integration tests that validate CFGMS deployment scenarios
// as documented in QUICK_START.md. These tests ensure that the documented workflows
// actually work as described.
package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/features/steward/config"
)

// ConfigValidationTestSuite validates YAML configuration file parsing
// with focus on providing helpful error messages for common issues.
//
// This test suite ensures users get clear, actionable feedback when:
//   - YAML syntax is invalid
//   - Required fields are missing
//   - Environment variables are referenced but not set
//   - Resource configurations are malformed
//
// Philosophy: "Test what you ship, ship what you test"
type ConfigValidationTestSuite struct {
	suite.Suite
	tempDir string
}

func (s *ConfigValidationTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "cfgms-config-validation-*")
	require.NoError(s.T(), err)
}

func (s *ConfigValidationTestSuite) TearDownSuite() {
	if s.tempDir != "" {
		_ = os.RemoveAll(s.tempDir)
	}
}

// writeConfig is a helper to write config content to a temporary file
func (s *ConfigValidationTestSuite) writeConfig(content string) string {
	configPath := filepath.Join(s.tempDir, "test-config.yaml")
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(s.T(), err)
	return configPath
}

// TestValidYAMLConfiguration validates that properly formatted configs load successfully
func (s *ConfigValidationTestSuite) TestValidYAMLConfiguration() {
	tests := []struct {
		name           string
		content        string
		expectedID     string
		resourceCount  int
		expectedModule string
	}{
		{
			name: "minimal valid config",
			content: `steward:
  id: minimal-steward

resources:
  - name: test-resource
    module: file
    config:
      path: /tmp/test.txt
      content: "test"
`,
			expectedID:     "minimal-steward",
			resourceCount:  1,
			expectedModule: "file",
		},
		{
			name: "full config with all options",
			content: `steward:
  id: full-config-steward
  mode: standalone
  logging:
    level: debug
    format: json
  error_handling:
    module_load_failure: continue
    resource_failure: warn
    configuration_error: fail

resources:
  - name: test-directory
    module: directory
    config:
      path: /tmp/test-dir
      state: present
      mode: "0755"
  - name: test-file
    module: file
    config:
      path: /tmp/test.txt
      content: "test content"
      state: present
`,
			expectedID:    "full-config-steward",
			resourceCount: 2,
		},
		{
			name: "config matching QUICK_START.md format",
			content: `steward:
  id: quickstart-steward

resources:
  - name: hello-file
    module: file
    config:
      path: /tmp/hello-cfgms.txt
      content: |
        Hello from CFGMS!
        This file was created by CFGMS standalone mode.
      state: present
      mode: "0644"

  - name: test-directory
    module: directory
    config:
      path: /tmp/cfgms-test
      state: present
      mode: "0755"
`,
			expectedID:    "quickstart-steward",
			resourceCount: 2,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			configPath := s.writeConfig(tt.content)

			cfg, err := config.LoadConfiguration(configPath)

			assert.NoError(s.T(), err, "Valid config should load without error")
			assert.Equal(s.T(), tt.expectedID, cfg.Steward.ID)
			assert.Len(s.T(), cfg.Resources, tt.resourceCount)
		})
	}
}

// TestInvalidYAMLSyntax validates that YAML syntax errors produce helpful messages
func (s *ConfigValidationTestSuite) TestInvalidYAMLSyntax() {
	tests := []struct {
		name            string
		content         string
		expectedErrPart string
	}{
		{
			name: "unclosed bracket",
			content: `steward:
  id: test-steward

resources:
  - name: test
    module: file
    config:
      items: [unclosed
`,
			expectedErrPart: "parse",
		},
		{
			name: "invalid indentation",
			content: `steward:
id: test-steward
  mode: standalone
`,
			expectedErrPart: "parse",
		},
		{
			name: "duplicate keys",
			content: `steward:
  id: test-steward
  id: duplicate-id
`,
			expectedErrPart: "parse",
		},
		{
			name:            "tabs instead of spaces (mixed)",
			content:         "steward:\n\tid: test-steward\n  mode: standalone\n",
			expectedErrPart: "parse",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			configPath := s.writeConfig(tt.content)

			_, err := config.LoadConfiguration(configPath)

			assert.Error(s.T(), err, "Invalid YAML should produce an error")
			assert.Contains(s.T(), strings.ToLower(err.Error()), tt.expectedErrPart,
				"Error message should indicate parsing issue")
		})
	}
}

// TestMissingRequiredFields validates that missing fields produce helpful messages
func (s *ConfigValidationTestSuite) TestMissingRequiredFields() {
	tests := []struct {
		name            string
		content         string
		expectedErrPart string
	}{
		{
			name: "missing resource name",
			content: `steward:
  id: test-steward

resources:
  - module: file
    config:
      path: /tmp/test.txt
`,
			expectedErrPart: "name is required",
		},
		{
			name: "missing resource module",
			content: `steward:
  id: test-steward

resources:
  - name: test-resource
    config:
      path: /tmp/test.txt
`,
			expectedErrPart: "module is required",
		},
		{
			name: "missing resource config",
			content: `steward:
  id: test-steward

resources:
  - name: test-resource
    module: file
`,
			expectedErrPart: "config is required",
		},
		{
			name: "duplicate resource names",
			content: `steward:
  id: test-steward

resources:
  - name: duplicate-name
    module: file
    config:
      path: /tmp/test1.txt
  - name: duplicate-name
    module: directory
    config:
      path: /tmp/test-dir
`,
			expectedErrPart: "duplicate resource name",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			configPath := s.writeConfig(tt.content)

			_, err := config.LoadConfiguration(configPath)

			assert.Error(s.T(), err, "Missing field should produce an error")
			assert.Contains(s.T(), strings.ToLower(err.Error()), strings.ToLower(tt.expectedErrPart),
				"Error message should indicate the missing field")
		})
	}
}

// TestInvalidFieldValues validates that invalid field values produce helpful messages
func (s *ConfigValidationTestSuite) TestInvalidFieldValues() {
	tests := []struct {
		name            string
		content         string
		expectedErrPart string
	}{
		{
			name: "invalid operation mode",
			content: `steward:
  id: test-steward
  mode: invalid-mode

resources:
  - name: test
    module: file
    config:
      path: /tmp/test.txt
`,
			expectedErrPart: "invalid operation mode",
		},
		{
			name: "invalid log level",
			content: `steward:
  id: test-steward
  logging:
    level: verbose

resources:
  - name: test
    module: file
    config:
      path: /tmp/test.txt
`,
			expectedErrPart: "invalid log level",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			configPath := s.writeConfig(tt.content)

			_, err := config.LoadConfiguration(configPath)

			assert.Error(s.T(), err, "Invalid field value should produce an error")
			assert.Contains(s.T(), strings.ToLower(err.Error()), strings.ToLower(tt.expectedErrPart),
				"Error message should indicate the invalid value")
		})
	}
}

// TestEnvironmentVariableExpansion validates env var handling as documented in QUICK_START.md
func (s *ConfigValidationTestSuite) TestEnvironmentVariableExpansion() {
	tests := []struct {
		name        string
		content     string
		envVars     map[string]string
		expectedID  string
		expectError bool
		errContains string
	}{
		{
			name: "env var with default used",
			content: `steward:
  id: ${TEST_STEWARD_ID:-default-id}

resources:
  - name: test
    module: file
    config:
      path: /tmp/test.txt
      content: "test"
`,
			envVars:    map[string]string{},
			expectedID: "default-id",
		},
		{
			name: "env var set overrides default",
			content: `steward:
  id: ${TEST_STEWARD_ID:-default-id}

resources:
  - name: test
    module: file
    config:
      path: /tmp/test.txt
      content: "test"
`,
			envVars:    map[string]string{"TEST_STEWARD_ID": "custom-id"},
			expectedID: "custom-id",
		},
		{
			name: "required env var not set fails",
			content: `steward:
  id: ${REQUIRED_VAR}

resources:
  - name: test
    module: file
    config:
      path: /tmp/test.txt
      content: "test"
`,
			envVars:     map[string]string{},
			expectError: true,
			errContains: "missing required environment variables",
		},
		{
			name: "required env var set succeeds",
			content: `steward:
  id: ${REQUIRED_VAR}

resources:
  - name: test
    module: file
    config:
      path: /tmp/test.txt
      content: "test"
`,
			envVars:    map[string]string{"REQUIRED_VAR": "required-steward"},
			expectedID: "required-steward",
		},
		{
			name: "multiple env vars in config",
			content: `steward:
  id: ${STEWARD_ID:-steward-1}
  logging:
    level: ${LOG_LEVEL:-info}

resources:
  - name: test
    module: file
    config:
      path: ${CONFIG_PATH:-/tmp/test.txt}
      content: "test"
`,
			envVars:    map[string]string{"STEWARD_ID": "custom-steward", "LOG_LEVEL": "debug"},
			expectedID: "custom-steward",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			// Set environment variables
			for k, v := range tt.envVars {
				s.T().Setenv(k, v)
			}

			configPath := s.writeConfig(tt.content)

			cfg, err := config.LoadConfiguration(configPath)

			if tt.expectError {
				assert.Error(s.T(), err, "Should produce error for missing env var")
				if tt.errContains != "" {
					assert.Contains(s.T(), strings.ToLower(err.Error()), strings.ToLower(tt.errContains))
				}
			} else {
				assert.NoError(s.T(), err)
				assert.Equal(s.T(), tt.expectedID, cfg.Steward.ID)
			}
		})
	}
}

// TestFileNotFound validates helpful error for missing config files
func (s *ConfigValidationTestSuite) TestFileNotFound() {
	_, err := config.LoadConfiguration("/nonexistent/path/config.yaml")

	assert.Error(s.T(), err, "Non-existent file should produce error")
	// Error should indicate file reading issue
	assert.Contains(s.T(), strings.ToLower(err.Error()), "read",
		"Error should indicate file reading issue")
}

// TestDefaultsApplied validates that defaults are correctly applied
func (s *ConfigValidationTestSuite) TestDefaultsApplied() {
	// Minimal config with only required fields
	content := `steward:
  id: defaults-test

resources:
  - name: test
    module: file
    config:
      path: /tmp/test.txt
`
	configPath := s.writeConfig(content)

	cfg, err := config.LoadConfiguration(configPath)

	require.NoError(s.T(), err)

	// Verify defaults are applied
	assert.Equal(s.T(), config.ModeStandalone, cfg.Steward.Mode, "Default mode should be standalone")
	assert.Equal(s.T(), "info", cfg.Steward.Logging.Level, "Default log level should be info")
	assert.Equal(s.T(), "text", cfg.Steward.Logging.Format, "Default log format should be text")
	assert.Equal(s.T(), config.ActionContinue, cfg.Steward.ErrorHandling.ModuleLoadFailure)
	assert.Equal(s.T(), config.ActionWarn, cfg.Steward.ErrorHandling.ResourceFailure)
	assert.Equal(s.T(), config.ActionFail, cfg.Steward.ErrorHandling.ConfigurationError)
}

// TestGetConfiguredModules validates module extraction from config
func (s *ConfigValidationTestSuite) TestGetConfiguredModules() {
	content := `steward:
  id: modules-test

resources:
  - name: file1
    module: file
    config:
      path: /tmp/test1.txt
  - name: file2
    module: file
    config:
      path: /tmp/test2.txt
  - name: dir1
    module: directory
    config:
      path: /tmp/test-dir
  - name: fw1
    module: firewall
    config:
      rules: []
`
	configPath := s.writeConfig(content)

	cfg, err := config.LoadConfiguration(configPath)
	require.NoError(s.T(), err)

	modules := config.GetConfiguredModules(cfg)

	// Should have 3 unique modules (file appears twice but counted once)
	assert.Len(s.T(), modules, 3)
	assert.Contains(s.T(), modules, "file")
	assert.Contains(s.T(), modules, "directory")
	assert.Contains(s.T(), modules, "firewall")
}

// TestComplexYAMLStructures validates handling of complex YAML features
func (s *ConfigValidationTestSuite) TestComplexYAMLStructures() {
	tests := []struct {
		name          string
		content       string
		resourceCount int
	}{
		{
			name: "multiline strings",
			content: `steward:
  id: multiline-test

resources:
  - name: script-file
    module: file
    config:
      path: /tmp/script.sh
      content: |
        #!/bin/bash
        echo "Hello World"
        echo "Line 2"
`,
			resourceCount: 1,
		},
		{
			name: "nested config objects",
			content: `steward:
  id: nested-test

resources:
  - name: complex-config
    module: file
    config:
      path: /tmp/config.json
      content: "test"
      options:
        nested:
          deep:
            value: true
`,
			resourceCount: 1,
		},
		{
			name: "arrays in config",
			content: `steward:
  id: array-test

resources:
  - name: firewall-rules
    module: firewall
    config:
      rules:
        - port: 80
          protocol: tcp
        - port: 443
          protocol: tcp
`,
			resourceCount: 1,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			configPath := s.writeConfig(tt.content)

			cfg, err := config.LoadConfiguration(configPath)

			assert.NoError(s.T(), err)
			assert.Len(s.T(), cfg.Resources, tt.resourceCount)
		})
	}
}

// TestEmptyConfig validates handling of empty or minimal configs
func (s *ConfigValidationTestSuite) TestEmptyConfig() {
	tests := []struct {
		name        string
		content     string
		expectError bool
	}{
		{
			name:        "completely empty file",
			content:     "",
			expectError: false, // ID defaults to hostname, which is valid
		},
		{
			name:        "empty steward block",
			content:     "steward:\n",
			expectError: false, // ID defaults to hostname, which is valid
		},
		{
			name: "no resources",
			content: `steward:
  id: no-resources
`,
			expectError: false, // Valid - resources are optional
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			configPath := s.writeConfig(tt.content)

			_, err := config.LoadConfiguration(configPath)

			if tt.expectError {
				assert.Error(s.T(), err)
			} else {
				assert.NoError(s.T(), err)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	suite.Run(t, new(ConfigValidationTestSuite))
}
