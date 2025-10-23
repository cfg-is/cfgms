// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadModuleMetadata(t *testing.T) {
	// Create a temporary file with valid module metadata
	tempDir := t.TempDir()
	metadataFile := filepath.Join(tempDir, "module.yaml")

	validYAML := `name: test-module
version: 1.2.3
description: A test module
author: Test Author
license: MIT
module_dependencies:
  - name: dependency1
    version: ">=1.0.0"
    reason: Required for core functionality
  - name: dependency2
    version: "~2.1.0"
    optional: true
    reason: Optional enhancement
platforms:
  - linux
  - windows
interfaces:
  - Get
  - Set
security:
  requires_root: false
  capabilities: []
  ports: []
`

	err := os.WriteFile(metadataFile, []byte(validYAML), 0644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Test loading valid metadata
	metadata, err := LoadModuleMetadata(metadataFile)
	if err != nil {
		t.Fatalf("failed to load metadata: %v", err)
	}

	// Validate loaded data
	if metadata.Name != "test-module" {
		t.Errorf("Name = %v, expected test-module", metadata.Name)
	}

	if metadata.Version != "1.2.3" {
		t.Errorf("Version = %v, expected 1.2.3", metadata.Version)
	}

	if len(metadata.ModuleDependencies) != 2 {
		t.Errorf("ModuleDependencies length = %v, expected 2", len(metadata.ModuleDependencies))
	}

	// Validate first dependency
	dep1 := metadata.ModuleDependencies[0]
	if dep1.Name != "dependency1" {
		t.Errorf("Dependency 1 Name = %v, expected dependency1", dep1.Name)
	}
	if dep1.Version != ">=1.0.0" {
		t.Errorf("Dependency 1 Version = %v, expected >=1.0.0", dep1.Version)
	}
	if dep1.Optional {
		t.Error("Dependency 1 should not be optional")
	}

	// Validate second dependency
	dep2 := metadata.ModuleDependencies[1]
	if dep2.Name != "dependency2" {
		t.Errorf("Dependency 2 Name = %v, expected dependency2", dep2.Name)
	}
	if !dep2.Optional {
		t.Error("Dependency 2 should be optional")
	}

	// Test loading non-existent file
	_, err = LoadModuleMetadata("/nonexistent/file.yaml")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestParseModuleMetadata(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		expectError bool
		validate    func(*ModuleMetadata) error
	}{
		{
			name: "valid minimal metadata",
			yaml: `name: test
version: 1.0.0`,
			expectError: false,
			validate: func(m *ModuleMetadata) error {
				if m.Name != "test" {
					t.Errorf("Name = %v, expected test", m.Name)
				}
				if m.Version != "1.0.0" {
					t.Errorf("Version = %v, expected 1.0.0", m.Version)
				}
				return nil
			},
		},
		{
			name:        "missing name",
			yaml:        `version: 1.0.0`,
			expectError: true,
		},
		{
			name:        "missing version",
			yaml:        `name: test`,
			expectError: true,
		},
		{
			name: "invalid version format",
			yaml: `name: test
version: invalid`,
			expectError: true,
		},
		{
			name: "invalid dependency version constraint",
			yaml: `name: test
version: 1.0.0
module_dependencies:
  - name: dep1
    version: "invalid_constraint"`,
			expectError: true,
		},
		{
			name: "dependency without name",
			yaml: `name: test
version: 1.0.0
module_dependencies:
  - version: "1.0.0"`,
			expectError: true,
		},
		{
			name: "valid complex metadata",
			yaml: `name: complex-module
version: 2.1.0-alpha.1
description: A complex module with all features
author: CFGMS Team
license: Apache-2.0
module_dependencies:
  - name: base
    version: "^1.0.0"
    reason: Foundation module
  - name: utils
    version: "~2.3.0"
    optional: true
    reason: Utility functions
platforms:
  - linux
  - windows
  - darwin
interfaces:
  - Get
  - Set
  - Monitor
security:
  requires_root: true
  capabilities:
    - CAP_NET_ADMIN
  ports:
    - 8080
    - 8443
documentation:
  api: "docs/api.md"
  examples: "examples/"
  readme: "README.md"
schema: schema.yaml`,
			expectError: false,
			validate: func(m *ModuleMetadata) error {
				if m.Name != "complex-module" {
					t.Errorf("Name = %v, expected complex-module", m.Name)
				}
				if m.Version != "2.1.0-alpha.1" {
					t.Errorf("Version = %v, expected 2.1.0-alpha.1", m.Version)
				}
				if len(m.ModuleDependencies) != 2 {
					t.Errorf("ModuleDependencies length = %v, expected 2", len(m.ModuleDependencies))
				}
				if len(m.Platforms) != 3 {
					t.Errorf("Platforms length = %v, expected 3", len(m.Platforms))
				}
				if !m.Security.RequiresRoot {
					t.Error("Security.RequiresRoot should be true")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.yaml)
			metadata, err := ParseModuleMetadata(reader)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.validate != nil {
				_ = tt.validate(metadata) // Ignore error in test validation
			}
		})
	}
}

func TestModuleMetadata_SaveModuleMetadata(t *testing.T) {
	tempDir := t.TempDir()
	metadataFile := filepath.Join(tempDir, "test", "module.yaml")

	metadata := &ModuleMetadata{
		Name:        "save-test",
		Version:     "1.0.0",
		Description: "Test saving metadata",
		ModuleDependencies: []ModuleDependency{
			{Name: "dep1", Version: "^1.0.0"},
		},
	}

	// Test saving
	err := metadata.SaveModuleMetadata(metadataFile)
	if err != nil {
		t.Fatalf("failed to save metadata: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(metadataFile); os.IsNotExist(err) {
		t.Fatal("metadata file was not created")
	}

	// Test loading back
	loaded, err := LoadModuleMetadata(metadataFile)
	if err != nil {
		t.Fatalf("failed to load saved metadata: %v", err)
	}

	// Validate round-trip
	if loaded.Name != metadata.Name {
		t.Errorf("Name mismatch after round-trip: got %v, expected %v", loaded.Name, metadata.Name)
	}

	if loaded.Version != metadata.Version {
		t.Errorf("Version mismatch after round-trip: got %v, expected %v", loaded.Version, metadata.Version)
	}

	if len(loaded.ModuleDependencies) != len(metadata.ModuleDependencies) {
		t.Errorf("Dependencies length mismatch after round-trip: got %v, expected %v",
			len(loaded.ModuleDependencies), len(metadata.ModuleDependencies))
	}
}

func TestModuleMetadata_ToYAML(t *testing.T) {
	metadata := &ModuleMetadata{
		Name:    "yaml-test",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "dep1", Version: "^1.0.0"},
		},
	}

	yamlData, err := metadata.ToYAML()
	if err != nil {
		t.Fatalf("failed to convert to YAML: %v", err)
	}

	// Verify YAML can be parsed back
	var parsed ModuleMetadata
	err = yaml.Unmarshal(yamlData, &parsed)
	if err != nil {
		t.Fatalf("failed to parse generated YAML: %v", err)
	}

	if parsed.Name != metadata.Name {
		t.Errorf("Name mismatch: got %v, expected %v", parsed.Name, metadata.Name)
	}
}

func TestModuleMetadata_FromYAML(t *testing.T) {
	yamlData := []byte(`name: from-yaml-test
version: 1.0.0
module_dependencies:
  - name: dep1
    version: "^1.0.0"`)

	var metadata ModuleMetadata
	err := metadata.FromYAML(yamlData)
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	if metadata.Name != "from-yaml-test" {
		t.Errorf("Name = %v, expected from-yaml-test", metadata.Name)
	}

	if len(metadata.ModuleDependencies) != 1 {
		t.Errorf("ModuleDependencies length = %v, expected 1", len(metadata.ModuleDependencies))
	}
}

func TestModuleMetadata_Validate(t *testing.T) {
	tests := []struct {
		name        string
		metadata    *ModuleMetadata
		expectError bool
	}{
		{
			name: "valid metadata",
			metadata: &ModuleMetadata{
				Name:    "valid",
				Version: "1.0.0",
			},
			expectError: false,
		},
		{
			name: "missing name",
			metadata: &ModuleMetadata{
				Version: "1.0.0",
			},
			expectError: true,
		},
		{
			name: "missing version",
			metadata: &ModuleMetadata{
				Name: "test",
			},
			expectError: true,
		},
		{
			name: "invalid version",
			metadata: &ModuleMetadata{
				Name:    "test",
				Version: "invalid",
			},
			expectError: true,
		},
		{
			name: "invalid dependency",
			metadata: &ModuleMetadata{
				Name:    "test",
				Version: "1.0.0",
				ModuleDependencies: []ModuleDependency{
					{Name: "", Version: "1.0.0"},
				},
			},
			expectError: true,
		},
		{
			name: "invalid dependency version constraint",
			metadata: &ModuleMetadata{
				Name:    "test",
				Version: "1.0.0",
				ModuleDependencies: []ModuleDependency{
					{Name: "dep", Version: "invalid_constraint"},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.metadata.Validate()

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestModuleMetadata_DependencyMethods(t *testing.T) {
	metadata := &ModuleMetadata{
		Name:    "dependency-test",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "dep1", Version: "^1.0.0"},
			{Name: "dep2", Version: "~2.0.0", Optional: true},
		},
	}

	// Test GetDependencyNames
	names := metadata.GetDependencyNames()
	expectedNames := []string{"dep1", "dep2"}
	if len(names) != len(expectedNames) {
		t.Errorf("GetDependencyNames length = %v, expected %v", len(names), len(expectedNames))
	}

	for i, name := range names {
		if name != expectedNames[i] {
			t.Errorf("GetDependencyNames[%d] = %v, expected %v", i, name, expectedNames[i])
		}
	}

	// Test HasDependency
	if !metadata.HasDependency("dep1") {
		t.Error("HasDependency('dep1') should return true")
	}

	if metadata.HasDependency("nonexistent") {
		t.Error("HasDependency('nonexistent') should return false")
	}

	// Test GetDependency
	dep, exists := metadata.GetDependency("dep1")
	if !exists {
		t.Error("GetDependency('dep1') should return true")
	}
	if dep.Name != "dep1" {
		t.Errorf("Dependency name = %v, expected dep1", dep.Name)
	}

	_, exists = metadata.GetDependency("nonexistent")
	if exists {
		t.Error("GetDependency('nonexistent') should return false")
	}

	// Test AddDependency
	newDep := ModuleDependency{Name: "dep3", Version: "1.0.0"}
	err := metadata.AddDependency(newDep)
	if err != nil {
		t.Errorf("AddDependency failed: %v", err)
	}

	if !metadata.HasDependency("dep3") {
		t.Error("Added dependency 'dep3' not found")
	}

	// Test adding duplicate dependency
	err = metadata.AddDependency(newDep)
	if err == nil {
		t.Error("expected error when adding duplicate dependency")
	}

	// Test RemoveDependency
	removed := metadata.RemoveDependency("dep2")
	if !removed {
		t.Error("RemoveDependency('dep2') should return true")
	}

	if metadata.HasDependency("dep2") {
		t.Error("Dependency 'dep2' should have been removed")
	}

	removed = metadata.RemoveDependency("nonexistent")
	if removed {
		t.Error("RemoveDependency('nonexistent') should return false")
	}
}

func TestModuleMetadata_Clone(t *testing.T) {
	original := &ModuleMetadata{
		Name:        "original",
		Version:     "1.0.0",
		Description: "Original module",
		Author:      "Test Author",
		License:     "MIT",
		Schema:      "schema.yaml",
		ModuleDependencies: []ModuleDependency{
			{Name: "dep1", Version: "^1.0.0"},
		},
		Platforms:  []string{"linux", "windows"},
		Interfaces: []string{"Get", "Set"},
		Requirements: &ModuleRequirements{
			OS:        []string{"linux"},
			Arch:      []string{"amd64"},
			MinMemory: "256MB",
			MinDisk:   "10MB",
		},
		Security: &ModuleSecurity{
			RequiresRoot: true,
			Capabilities: []string{"CAP_NET_ADMIN"},
			Ports:        []int{8080},
		},
		Documentation: &ModuleDocumentation{
			API:      "api.md",
			Examples: "examples/",
			README:   "README.md",
		},
	}

	// Clone the metadata
	clone := original.Clone()

	// Verify basic fields
	if clone.Name != original.Name {
		t.Errorf("Clone Name = %v, expected %v", clone.Name, original.Name)
	}

	// Verify deep copy by modifying clone
	clone.Name = "modified"
	if original.Name == "modified" {
		t.Error("Modifying clone affected original")
	}

	// Verify slice deep copy
	clone.ModuleDependencies[0].Name = "modified-dep"
	if original.ModuleDependencies[0].Name == "modified-dep" {
		t.Error("Modifying clone dependencies affected original")
	}

	// Verify nested struct deep copy
	clone.Requirements.MinMemory = "512MB"
	if original.Requirements.MinMemory == "512MB" {
		t.Error("Modifying clone requirements affected original")
	}

	clone.Security.RequiresRoot = false
	if original.Security.RequiresRoot == false {
		t.Error("Modifying clone security affected original")
	}

	clone.Documentation.API = "modified.md"
	if original.Documentation.API == "modified.md" {
		t.Error("Modifying clone documentation affected original")
	}
}

// Benchmark tests
func BenchmarkLoadModuleMetadata(b *testing.B) {
	// Create temporary metadata file
	tempDir := b.TempDir()
	metadataFile := filepath.Join(tempDir, "module.yaml")

	yamlContent := `name: benchmark-module
version: 1.0.0
description: Benchmark test module
module_dependencies:
  - name: dep1
    version: "^1.0.0"
  - name: dep2
    version: "~2.0.0"
platforms:
  - linux
  - windows
interfaces:
  - Get
  - Set`

	_ = os.WriteFile(metadataFile, []byte(yamlContent), 0644) // Ignore error in benchmark setup

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadModuleMetadata(metadataFile)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkModuleMetadata_ToYAML(b *testing.B) {
	metadata := &ModuleMetadata{
		Name:    "benchmark",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "dep1", Version: "^1.0.0"},
			{Name: "dep2", Version: "~2.0.0"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := metadata.ToYAML()
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkModuleMetadata_Clone(b *testing.B) {
	metadata := &ModuleMetadata{
		Name:    "benchmark",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "dep1", Version: "^1.0.0"},
			{Name: "dep2", Version: "~2.0.0"},
		},
		Platforms:  []string{"linux", "windows"},
		Interfaces: []string{"Get", "Set"},
		Requirements: &ModuleRequirements{
			OS:   []string{"linux"},
			Arch: []string{"amd64"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = metadata.Clone()
	}
}
