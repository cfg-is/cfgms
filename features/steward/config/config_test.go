// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfiguration(t *testing.T) {
	tests := []struct {
		name              string
		setupFunc         func(t *testing.T) (string, func())
		expectedID        string
		expectedMode      OperationMode
		expectedResources int
		wantErr           bool
	}{
		{
			name: "valid configuration file",
			setupFunc: func(t *testing.T) (string, func()) {
				tempDir := t.TempDir()
				configFile := filepath.Join(tempDir, "test.cfg")

				configData := `steward:
  id: test-steward
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
      path: /tmp/test
      permissions: 755
  - name: test-file
    module: file
    config:
      path: /tmp/test.txt
      content: "test content"
`
				require.NoError(t, os.WriteFile(configFile, []byte(configData), 0644))
				return configFile, func() {}
			},
			expectedID:        "test-steward",
			expectedMode:      ModeStandalone,
			expectedResources: 2,
			wantErr:           false,
		},
		{
			name: "configuration with defaults applied",
			setupFunc: func(t *testing.T) (string, func()) {
				tempDir := t.TempDir()
				configFile := filepath.Join(tempDir, "minimal.cfg")

				configData := `steward:
  id: minimal-steward

resources:
  - name: test-resource
    module: test-module
    config:
      key: value
`
				require.NoError(t, os.WriteFile(configFile, []byte(configData), 0644))
				return configFile, func() {}
			},
			expectedID:        "minimal-steward",
			expectedMode:      ModeStandalone, // default
			expectedResources: 1,
			wantErr:           false,
		},
		{
			name: "invalid YAML",
			setupFunc: func(t *testing.T) (string, func()) {
				tempDir := t.TempDir()
				configFile := filepath.Join(tempDir, "invalid.cfg")

				configData := `invalid: yaml: content: [unclosed`
				require.NoError(t, os.WriteFile(configFile, []byte(configData), 0644))
				return configFile, func() {}
			},
			wantErr: true,
		},
		{
			name: "non-existent file",
			setupFunc: func(t *testing.T) (string, func()) {
				return "/non/existent/file.cfg", func() {}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath, cleanup := tt.setupFunc(t)
			defer cleanup()

			config, err := LoadConfiguration(configPath)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedID, config.Steward.ID)
			assert.Equal(t, tt.expectedMode, config.Steward.Mode)
			assert.Len(t, config.Resources, tt.expectedResources)
		})
	}
}

func TestValidateConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		config  StewardConfig
		wantErr bool
	}{
		{
			name: "valid configuration",
			config: StewardConfig{
				Steward: StewardSettings{
					ID:   "test-steward",
					Mode: ModeStandalone,
					Logging: LoggingConfig{
						Level:  "info",
						Format: "text",
					},
				},
				Resources: []ResourceConfig{
					{
						Name:   "test-resource",
						Module: "test-module",
						Config: map[string]interface{}{"key": "value"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing steward ID",
			config: StewardConfig{
				Steward: StewardSettings{
					Mode:    ModeStandalone,
					Logging: LoggingConfig{Level: "info"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid operation mode",
			config: StewardConfig{
				Steward: StewardSettings{
					ID:      "test-steward",
					Mode:    "invalid-mode",
					Logging: LoggingConfig{Level: "info"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid log level",
			config: StewardConfig{
				Steward: StewardSettings{
					ID:      "test-steward",
					Mode:    ModeStandalone,
					Logging: LoggingConfig{Level: "invalid"},
				},
			},
			wantErr: true,
		},
		{
			name: "resource missing name",
			config: StewardConfig{
				Steward: StewardSettings{
					ID:      "test-steward",
					Mode:    ModeStandalone,
					Logging: LoggingConfig{Level: "info"},
				},
				Resources: []ResourceConfig{
					{
						Module: "test-module",
						Config: map[string]interface{}{"key": "value"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "resource missing module",
			config: StewardConfig{
				Steward: StewardSettings{
					ID:      "test-steward",
					Mode:    ModeStandalone,
					Logging: LoggingConfig{Level: "info"},
				},
				Resources: []ResourceConfig{
					{
						Name:   "test-resource",
						Config: map[string]interface{}{"key": "value"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate resource names",
			config: StewardConfig{
				Steward: StewardSettings{
					ID:      "test-steward",
					Mode:    ModeStandalone,
					Logging: LoggingConfig{Level: "info"},
				},
				Resources: []ResourceConfig{
					{
						Name:   "duplicate",
						Module: "test-module",
						Config: map[string]interface{}{"key": "value"},
					},
					{
						Name:   "duplicate",
						Module: "other-module",
						Config: map[string]interface{}{"key": "value"},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfiguration(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetConfiguredModules(t *testing.T) {
	config := StewardConfig{
		Resources: []ResourceConfig{
			{Name: "resource1", Module: "directory"},
			{Name: "resource2", Module: "file"},
			{Name: "resource3", Module: "directory"}, // duplicate module
			{Name: "resource4", Module: "firewall"},
		},
	}

	modules := GetConfiguredModules(config)

	assert.Len(t, modules, 3) // directory, file, firewall (directory not duplicated)
	assert.Contains(t, modules, "directory")
	assert.Contains(t, modules, "file")
	assert.Contains(t, modules, "firewall")
}

func TestApplyDefaults(t *testing.T) {
	config := StewardConfig{
		Steward: StewardSettings{
			ID: "test-steward",
		},
	}

	applyDefaults(&config)

	assert.Equal(t, ModeStandalone, config.Steward.Mode)
	assert.Equal(t, "info", config.Steward.Logging.Level)
	assert.Equal(t, "text", config.Steward.Logging.Format)
	assert.Equal(t, ActionContinue, config.Steward.ErrorHandling.ModuleLoadFailure)
	assert.Equal(t, ActionWarn, config.Steward.ErrorHandling.ResourceFailure)
	assert.Equal(t, ActionFail, config.Steward.ErrorHandling.ConfigurationError)
}

func TestGetConfigSearchPaths(t *testing.T) {
	paths := getConfigSearchPaths()

	// Should always have at least one path
	assert.NotEmpty(t, paths)

	// First path should be current working directory
	cwd, err := os.Getwd()
	require.NoError(t, err)

	hostname, err := os.Hostname()
	require.NoError(t, err)

	expectedFirst := filepath.Join(cwd, hostname+".cfg")
	assert.Equal(t, expectedFirst, paths[0])
}

func TestEnvironmentVariableExpansion(t *testing.T) {
	tests := []struct {
		name           string
		configContent  string
		envVars        map[string]string
		expectedID     string
		expectedLogDir string
		wantErr        bool
	}{
		{
			name: "expand env var with default",
			configContent: `steward:
  id: ${TEST_STEWARD_ID:-default-steward}
  mode: standalone
  logging:
    level: info
    format: text

resources:
  - name: test-resource
    module: test-module
    config:
      path: ${TEST_PATH:-/tmp/default}
`,
			envVars:    map[string]string{}, // no env vars set
			expectedID: "default-steward",
			wantErr:    false,
		},
		{
			name: "expand env var when set",
			configContent: `steward:
  id: ${TEST_STEWARD_ID:-default-steward}
  mode: standalone
  logging:
    level: info
    format: text

resources:
  - name: test-resource
    module: test-module
    config:
      path: /tmp/test
`,
			envVars:    map[string]string{"TEST_STEWARD_ID": "custom-steward"},
			expectedID: "custom-steward",
			wantErr:    false,
		},
		{
			name: "fail on missing env var without default",
			configContent: `steward:
  id: ${MISSING_VAR}
  mode: standalone
  logging:
    level: info
    format: text

resources:
  - name: test-resource
    module: test-module
    config:
      path: /tmp/test
`,
			envVars: map[string]string{},
			wantErr: true, // Should fail because MISSING_VAR is not set and has no default
		},
		{
			name: "pass when env var without default is set",
			configContent: `steward:
  id: ${REQUIRED_VAR}
  mode: standalone
  logging:
    level: info
    format: text

resources:
  - name: test-resource
    module: test-module
    config:
      path: /tmp/test
`,
			envVars:    map[string]string{"REQUIRED_VAR": "required-steward"},
			expectedID: "required-steward",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment variables
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			// Create temporary config file
			tempDir := t.TempDir()
			configFile := filepath.Join(tempDir, "test.cfg")
			require.NoError(t, os.WriteFile(configFile, []byte(tt.configContent), 0644))

			// Load configuration
			config, err := LoadConfiguration(configFile)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedID, config.Steward.ID)
		})
	}
}

func TestValidateEnvVars(t *testing.T) {
	tests := []struct {
		name    string
		content string
		envVars map[string]string
		wantErr bool
	}{
		{
			name:    "no env vars",
			content: "key: value",
			envVars: map[string]string{},
			wantErr: false,
		},
		{
			name:    "env var with default - no validation needed",
			content: "key: ${VAR:-default}",
			envVars: map[string]string{},
			wantErr: false, // ${VAR:-default} pattern doesn't trigger validation
		},
		{
			name:    "env var without default - not set",
			content: "key: ${MISSING_VAR}",
			envVars: map[string]string{},
			wantErr: true,
		},
		{
			name:    "env var without default - is set",
			content: "key: ${SET_VAR}",
			envVars: map[string]string{"SET_VAR": "value"},
			wantErr: false,
		},
		{
			name:    "multiple env vars - all set",
			content: "key1: ${VAR1}\nkey2: ${VAR2}",
			envVars: map[string]string{"VAR1": "val1", "VAR2": "val2"},
			wantErr: false,
		},
		{
			name:    "multiple env vars - one missing",
			content: "key1: ${VAR1}\nkey2: ${VAR2}",
			envVars: map[string]string{"VAR1": "val1"},
			wantErr: true,
		},
		{
			name:    "mixed env vars with and without defaults",
			content: "key1: ${VAR1:-default}\nkey2: ${VAR2}",
			envVars: map[string]string{"VAR2": "val2"},
			wantErr: false, // VAR1 has default, VAR2 is set
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment variables
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			err := validateEnvVars(tt.content)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "missing required environment variables")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
