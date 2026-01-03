// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package modules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ModuleTestSuite provides a set of standard tests that all modules must pass
type ModuleTestSuite struct {
	// NewModule is a function that creates a new instance of the module being tested
	NewModule func() Module
	// ResourceID is a valid resource ID for testing
	ResourceID string
	// ValidConfig is a valid configuration for testing
	ValidConfig string
	// ModulePath is the path to the module directory
	ModulePath string
	// CreateConfigFromYAML creates a ConfigState from YAML string
	CreateConfigFromYAML func(yamlData string) ConfigState
}

// RunCoreTests executes all core module interface tests
func (ts *ModuleTestSuite) RunCoreTests(t *testing.T) {
	t.Run("Get", ts.testGet)
	t.Run("Set", ts.testSet)
	t.Run("ModuleStructure", ts.testModuleStructure)
}

// testModuleStructure validates the module's directory structure and required files
func (ts *ModuleTestSuite) testModuleStructure(t *testing.T) {
	// Test module.yaml
	t.Run("module.yaml", func(t *testing.T) {
		yamlPath := filepath.Join(ts.ModulePath, "module.yaml")
		data, err := os.ReadFile(yamlPath)
		if err != nil {
			t.Fatalf("Failed to read module.yaml: %v", err)
		}

		var config struct {
			Name        string   `yaml:"name"`
			Version     string   `yaml:"version"`
			Description string   `yaml:"description"`
			Interfaces  []string `yaml:"interfaces"`
			Security    struct {
				RequiresRoot bool     `yaml:"requires_root"`
				Capabilities []string `yaml:"capabilities"`
				Ports        []int    `yaml:"ports"`
			} `yaml:"security"`
		}

		if err := yaml.Unmarshal(data, &config); err != nil {
			t.Fatalf("Failed to parse module.yaml: %v", err)
		}

		// Validate required fields
		if config.Name == "" {
			t.Error("module.yaml: name is required")
		}
		if config.Version == "" {
			t.Error("module.yaml: version is required")
		}
		if config.Description == "" {
			t.Error("module.yaml: description is required")
		}
		if len(config.Interfaces) == 0 {
			t.Error("module.yaml: interfaces is required")
		}

		// Validate required interfaces
		requiredInterfaces := map[string]bool{
			"Get":  false,
			"Set":  false,
			"Test": false,
		}
		for _, iface := range config.Interfaces {
			requiredInterfaces[iface] = true
		}
		for iface, found := range requiredInterfaces {
			if !found {
				t.Errorf("module.yaml: missing required interface: %s", iface)
			}
		}
	})

	// Test README.md
	t.Run("README.md", func(t *testing.T) {
		readmePath := filepath.Join(ts.ModulePath, "README.md")
		data, err := os.ReadFile(readmePath)
		if err != nil {
			t.Fatalf("Failed to read README.md: %v", err)
		}

		content := string(data)
		requiredSections := []string{
			"Purpose and scope",
			"Configuration options",
			"Usage examples",
			"Known limitations",
			"Security considerations",
		}

		for _, section := range requiredSections {
			if !containsSection(content, section) {
				t.Errorf("README.md: missing required section: %s", section)
			}
		}
	})

	// Test test coverage
	t.Run("TestCoverage", func(t *testing.T) {
		// Note: This is a placeholder. Actual test coverage would need to be
		// calculated using the Go test coverage tools and parsed from the output.
		// For now, we just verify that tests exist.
		testDir := filepath.Join(ts.ModulePath, "tests")
		if _, err := os.Stat(testDir); os.IsNotExist(err) {
			t.Error("Missing tests directory")
		}
	})
}

// containsSection checks if the content contains a section header
func containsSection(content, section string) bool {
	// Look for markdown headers (## or ###) followed by the section name
	patterns := []string{
		"## " + section,
		"### " + section,
		"#### " + section,
	}
	for _, pattern := range patterns {
		if containsSubstring(content, pattern) {
			return true
		}
	}
	return false
}

// containsSubstring checks if a string contains a substring
func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}

func (ts *ModuleTestSuite) testGet(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		wantErr    bool
	}{
		{
			name:       "Valid Resource ID",
			resourceID: ts.ResourceID,
			wantErr:    false,
		},
		{
			name:       "Empty Resource ID",
			resourceID: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := ts.NewModule()
			ctx := context.Background()

			_, err := module.Get(ctx, tt.resourceID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func (ts *ModuleTestSuite) testSet(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		configData string
		wantErr    bool
	}{
		{
			name:       "Valid Input",
			resourceID: ts.ResourceID,
			configData: ts.ValidConfig,
			wantErr:    false,
		},
		{
			name:       "Empty Resource ID",
			resourceID: "",
			configData: ts.ValidConfig,
			wantErr:    true,
		},
		{
			name:       "Empty Config Data",
			resourceID: ts.ResourceID,
			configData: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := ts.NewModule()
			ctx := context.Background()

			// Convert YAML string to ConfigState
			var config ConfigState
			if tt.configData != "" {
				config = ts.CreateConfigFromYAML(tt.configData)
				if config == nil && !tt.wantErr {
					t.Fatalf("Failed to create config from YAML: %s", tt.configData)
				}
			}

			err := module.Set(ctx, tt.resourceID, config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
