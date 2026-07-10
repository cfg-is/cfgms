// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
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
publisher: cfgms
executors:
  - steward
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

	if metadata.Publisher != "cfgms" {
		t.Errorf("Publisher = %v, expected cfgms", metadata.Publisher)
	}

	if len(metadata.Executors) != 1 || metadata.Executors[0] != "steward" {
		t.Errorf("Executors = %v, expected [steward]", metadata.Executors)
	}

	if metadata.Kind != "steward" {
		t.Errorf("Kind = %v, expected steward", metadata.Kind)
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
version: 1.0.0
publisher: cfgms
executors:
  - steward`,
			expectError: false,
			validate: func(m *ModuleMetadata) error {
				if m.Name != "test" {
					t.Errorf("Name = %v, expected test", m.Name)
				}
				if m.Version != "1.0.0" {
					t.Errorf("Version = %v, expected 1.0.0", m.Version)
				}
				if m.Kind != "steward" {
					t.Errorf("Kind = %v, expected steward", m.Kind)
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
publisher: cfgms
executors:
  - steward
module_dependencies:
  - name: dep1
    version: "invalid_constraint"`,
			expectError: true,
		},
		{
			name: "dependency without name",
			yaml: `name: test
version: 1.0.0
publisher: cfgms
executors:
  - steward
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
publisher: cfgms
executors:
  - steward
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
				if m.Publisher != "cfgms" {
					t.Errorf("Publisher = %v, expected cfgms", m.Publisher)
				}
				if m.Kind != "steward" {
					t.Errorf("Kind = %v, expected steward", m.Kind)
				}
				return nil
			},
		},
		{
			name: "missing executors",
			yaml: `name: test
version: 1.0.0
publisher: cfgms`,
			expectError: true,
		},
		{
			name: "multiple executors rejected",
			yaml: `name: test
version: 1.0.0
publisher: cfgms
executors:
  - steward
  - outpost`,
			expectError: true,
		},
		{
			name: "invalid executor value",
			yaml: `name: test
version: 1.0.0
publisher: cfgms
executors:
  - agent`,
			expectError: true,
		},
		{
			name: "missing publisher",
			yaml: `name: test
version: 1.0.0
executors:
  - steward`,
			expectError: true,
		},
		{
			name: "outpost executor derives correct kind",
			yaml: `name: test
version: 1.0.0
publisher: cfgms
executors:
  - outpost`,
			expectError: false,
			validate: func(m *ModuleMetadata) error {
				if m.Kind != "outpost" {
					t.Errorf("Kind = %v, expected outpost", m.Kind)
				}
				return nil
			},
		},
		{
			name: "controller executor derives workflow kind",
			yaml: `name: test
version: 1.0.0
publisher: cfgms
executors:
  - controller`,
			expectError: false,
			validate: func(m *ModuleMetadata) error {
				if m.Kind != "workflow" {
					t.Errorf("Kind = %v, expected workflow for controller executor", m.Kind)
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
				if err := tt.validate(metadata); err != nil {
					t.Errorf("validate function returned error: %v", err)
				}
			}
		})
	}
}

func TestParseModuleMetadata_BehavioralEnvelopeRoundTrip(t *testing.T) {
	input := `name: test-module
version: 1.0.0
publisher: cfgms
executors:
  - steward
behavioral_envelope:
  shells_out_to:
    - /bin/sh
    - /usr/bin/bash
  writes_paths:
    - /etc/config
  reads_paths:
    - /etc/config
    - /var/run/state
  network_egress:
    - api.example.com:443
  lolbin_usage_justification: "required for system management"
`

	reader := strings.NewReader(input)
	metadata, err := ParseModuleMetadata(reader)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if metadata.BehavioralEnvelope == nil {
		t.Fatal("BehavioralEnvelope should not be nil")
	}

	be := metadata.BehavioralEnvelope
	if len(be.ShellsOutTo) != 2 {
		t.Errorf("ShellsOutTo length = %d, expected 2", len(be.ShellsOutTo))
	}
	if be.ShellsOutTo[0] != "/bin/sh" {
		t.Errorf("ShellsOutTo[0] = %v, expected /bin/sh", be.ShellsOutTo[0])
	}
	if len(be.WritesPaths) != 1 || be.WritesPaths[0] != "/etc/config" {
		t.Errorf("WritesPaths = %v, expected [/etc/config]", be.WritesPaths)
	}
	if len(be.ReadsPaths) != 2 {
		t.Errorf("ReadsPaths length = %d, expected 2", len(be.ReadsPaths))
	}
	if len(be.NetworkEgress) != 1 || be.NetworkEgress[0] != "api.example.com:443" {
		t.Errorf("NetworkEgress = %v, expected [api.example.com:443]", be.NetworkEgress)
	}
	if be.LolbinUsageJustification != "required for system management" {
		t.Errorf("LolbinUsageJustification = %v, expected 'required for system management'", be.LolbinUsageJustification)
	}

	// Verify round-trip via YAML: kind must not appear in serialized output
	yamlBytes, err := metadata.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML() error: %v", err)
	}

	yamlStr := string(yamlBytes)
	if strings.Contains(yamlStr, "kind:") {
		t.Error("serialized YAML must not contain 'kind:' — kind is derived, not stored")
	}

	// Deserialize and verify behavioral_envelope survives the round-trip
	var reparsed ModuleMetadata
	if err := yaml.Unmarshal(yamlBytes, &reparsed); err != nil {
		t.Fatalf("failed to unmarshal round-tripped YAML: %v", err)
	}
	if reparsed.BehavioralEnvelope == nil {
		t.Fatal("BehavioralEnvelope missing after round-trip")
	}
	if len(reparsed.BehavioralEnvelope.ShellsOutTo) != 2 {
		t.Errorf("ShellsOutTo after round-trip = %v, expected 2 entries", reparsed.BehavioralEnvelope.ShellsOutTo)
	}
}

func TestParseModuleMetadata_KindNotParsedFromYAML(t *testing.T) {
	// kind: field in YAML must be ignored; Kind is always derived from Executors[0]
	input := `name: test
version: 1.0.0
publisher: cfgms
executors:
  - steward
kind: workflow
`
	reader := strings.NewReader(input)
	metadata, err := ParseModuleMetadata(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Kind must be derived from executors[0]="steward", not read from YAML ("workflow")
	if metadata.Kind != "steward" {
		t.Errorf("Kind = %v, expected steward (derived), not the YAML value 'workflow'", metadata.Kind)
	}
}

func TestModuleMetadata_SaveModuleMetadata(t *testing.T) {
	tempDir := t.TempDir()
	metadataFile := filepath.Join(tempDir, "test", "module.yaml")

	metadata := &ModuleMetadata{
		Name:        "save-test",
		Version:     "1.0.0",
		Description: "Test saving metadata",
		Publisher:   "cfgms",
		Executors:   []string{"steward"},
		Kind:        "steward",
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

	if loaded.Publisher != "cfgms" {
		t.Errorf("Publisher mismatch after round-trip: got %v, expected cfgms", loaded.Publisher)
	}

	// Kind is derived from executors on load, not stored in YAML
	if loaded.Kind != "steward" {
		t.Errorf("Kind after round-trip: got %v, expected steward (derived from executors)", loaded.Kind)
	}

	if len(loaded.ModuleDependencies) != len(metadata.ModuleDependencies) {
		t.Errorf("Dependencies length mismatch after round-trip: got %v, expected %v",
			len(loaded.ModuleDependencies), len(metadata.ModuleDependencies))
	}
}

func TestModuleMetadata_ToYAML(t *testing.T) {
	metadata := &ModuleMetadata{
		Name:      "yaml-test",
		Version:   "1.0.0",
		Publisher: "cfgms",
		Executors: []string{"steward"},
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
		wantKind    string
	}{
		{
			name: "valid metadata",
			metadata: &ModuleMetadata{
				Name:      "valid",
				Version:   "1.0.0",
				Publisher: "cfgms",
				Executors: []string{"steward"},
			},
			expectError: false,
			wantKind:    "steward",
		},
		{
			name: "valid outpost executor",
			metadata: &ModuleMetadata{
				Name:      "valid",
				Version:   "1.0.0",
				Publisher: "cfgms",
				Executors: []string{"outpost"},
			},
			expectError: false,
			wantKind:    "outpost",
		},
		{
			name: "valid controller executor",
			metadata: &ModuleMetadata{
				Name:      "valid",
				Version:   "1.0.0",
				Publisher: "cfgms",
				Executors: []string{"controller"},
			},
			expectError: false,
			wantKind:    "workflow",
		},
		{
			name: "missing name",
			metadata: &ModuleMetadata{
				Version:   "1.0.0",
				Publisher: "cfgms",
				Executors: []string{"steward"},
			},
			expectError: true,
		},
		{
			name: "missing version",
			metadata: &ModuleMetadata{
				Name:      "test",
				Publisher: "cfgms",
				Executors: []string{"steward"},
			},
			expectError: true,
		},
		{
			name: "invalid version",
			metadata: &ModuleMetadata{
				Name:      "test",
				Version:   "invalid",
				Publisher: "cfgms",
				Executors: []string{"steward"},
			},
			expectError: true,
		},
		{
			name: "invalid dependency",
			metadata: &ModuleMetadata{
				Name:      "test",
				Version:   "1.0.0",
				Publisher: "cfgms",
				Executors: []string{"steward"},
				ModuleDependencies: []ModuleDependency{
					{Name: "", Version: "1.0.0"},
				},
			},
			expectError: true,
		},
		{
			name: "invalid dependency version constraint",
			metadata: &ModuleMetadata{
				Name:      "test",
				Version:   "1.0.0",
				Publisher: "cfgms",
				Executors: []string{"steward"},
				ModuleDependencies: []ModuleDependency{
					{Name: "dep", Version: "invalid_constraint"},
				},
			},
			expectError: true,
		},
		{
			name: "missing executors",
			metadata: &ModuleMetadata{
				Name:      "test",
				Version:   "1.0.0",
				Publisher: "cfgms",
			},
			expectError: true,
		},
		{
			name: "multiple executors rejected",
			metadata: &ModuleMetadata{
				Name:      "test",
				Version:   "1.0.0",
				Publisher: "cfgms",
				Executors: []string{"steward", "outpost"},
			},
			expectError: true,
		},
		{
			name: "invalid executor value",
			metadata: &ModuleMetadata{
				Name:      "test",
				Version:   "1.0.0",
				Publisher: "cfgms",
				Executors: []string{"agent"},
			},
			expectError: true,
		},
		{
			name: "missing publisher",
			metadata: &ModuleMetadata{
				Name:      "test",
				Version:   "1.0.0",
				Executors: []string{"steward"},
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

			if !tt.expectError && err == nil && tt.wantKind != "" {
				if tt.metadata.Kind != tt.wantKind {
					t.Errorf("Kind = %q, want %q after Validate()", tt.metadata.Kind, tt.wantKind)
				}
			}
		})
	}
}

func TestModuleMetadata_DependencyMethods(t *testing.T) {
	metadata := &ModuleMetadata{
		Name:      "dependency-test",
		Version:   "1.0.0",
		Publisher: "cfgms",
		Executors: []string{"steward"},
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
		Publisher:   "cfgms",
		Executors:   []string{"steward"},
		Kind:        "steward",
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
		BehavioralEnvelope: &BehavioralEnvelope{
			ShellsOutTo:              []string{"/bin/sh"},
			WritesPaths:              []string{"/etc/config"},
			ReadsPaths:               []string{"/etc/config"},
			NetworkEgress:            []string{"api.example.com:443"},
			LolbinUsageJustification: "required",
		},
	}

	// Clone the metadata
	clone := original.Clone()

	// Verify basic fields
	if clone.Name != original.Name {
		t.Errorf("Clone Name = %v, expected %v", clone.Name, original.Name)
	}

	if clone.Publisher != original.Publisher {
		t.Errorf("Clone Publisher = %v, expected %v", clone.Publisher, original.Publisher)
	}

	if clone.Kind != original.Kind {
		t.Errorf("Clone Kind = %v, expected %v", clone.Kind, original.Kind)
	}

	if len(clone.Executors) != len(original.Executors) || clone.Executors[0] != original.Executors[0] {
		t.Errorf("Clone Executors = %v, expected %v", clone.Executors, original.Executors)
	}

	// Verify deep copy by modifying clone
	clone.Name = "modified"
	if original.Name == "modified" {
		t.Error("Modifying clone affected original")
	}

	// Verify executors deep copy
	clone.Executors[0] = "outpost"
	if original.Executors[0] == "outpost" {
		t.Error("Modifying clone executors affected original")
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

	// Verify behavioral envelope deep copy
	if clone.BehavioralEnvelope == nil {
		t.Fatal("Clone BehavioralEnvelope should not be nil")
	}
	clone.BehavioralEnvelope.ShellsOutTo[0] = "/bin/zsh"
	if original.BehavioralEnvelope.ShellsOutTo[0] == "/bin/zsh" {
		t.Error("Modifying clone BehavioralEnvelope.ShellsOutTo affected original")
	}
	clone.BehavioralEnvelope.LolbinUsageJustification = "modified"
	if original.BehavioralEnvelope.LolbinUsageJustification == "modified" {
		t.Error("Modifying clone BehavioralEnvelope.LolbinUsageJustification affected original")
	}
}

func TestParseModuleMetadata_Owns(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantOwns  []OwnershipDeclaration
		wantCount int
	}{
		{
			name: "no owns field — zero value, backward compatible",
			yaml: `name: test
version: 1.0.0
publisher: cfgms
executors:
  - steward`,
			wantOwns:  nil,
			wantCount: 0,
		},
		{
			name: "single owns entry",
			yaml: `name: test
version: 1.0.0
publisher: cfgms
executors:
  - steward
owns:
  - kind: service`,
			wantOwns:  []OwnershipDeclaration{{Kind: "service"}},
			wantCount: 1,
		},
		{
			name: "multiple owns entries",
			yaml: `name: test
version: 1.0.0
publisher: cfgms
executors:
  - steward
owns:
  - kind: file
  - kind: directory`,
			wantOwns:  []OwnershipDeclaration{{Kind: "file"}, {Kind: "directory"}},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.yaml)
			metadata, err := ParseModuleMetadata(reader)
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			if len(metadata.Owns) != tt.wantCount {
				t.Errorf("Owns length = %d, want %d", len(metadata.Owns), tt.wantCount)
			}

			for i, want := range tt.wantOwns {
				if i >= len(metadata.Owns) {
					t.Errorf("Owns[%d] missing, want kind=%q", i, want.Kind)
					continue
				}
				if metadata.Owns[i].Kind != want.Kind {
					t.Errorf("Owns[%d].Kind = %q, want %q", i, metadata.Owns[i].Kind, want.Kind)
				}
			}
		})
	}
}

func TestModuleMetadata_Clone_Owns(t *testing.T) {
	original := &ModuleMetadata{
		Name:      "test",
		Version:   "1.0.0",
		Publisher: "cfgms",
		Executors: []string{"steward"},
		Kind:      "steward",
		Owns:      []OwnershipDeclaration{{Kind: "service"}, {Kind: "file"}},
	}

	clone := original.Clone()

	if len(clone.Owns) != len(original.Owns) {
		t.Fatalf("Clone Owns length = %d, want %d", len(clone.Owns), len(original.Owns))
	}
	for i, want := range original.Owns {
		if clone.Owns[i].Kind != want.Kind {
			t.Errorf("Clone Owns[%d].Kind = %q, want %q", i, clone.Owns[i].Kind, want.Kind)
		}
	}

	// Verify deep copy — mutating clone must not affect original
	clone.Owns[0].Kind = "mutated"
	if original.Owns[0].Kind == "mutated" {
		t.Error("Mutating clone Owns[0] affected original")
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
publisher: cfgms
executors:
  - steward
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
		Name:      "benchmark",
		Version:   "1.0.0",
		Publisher: "cfgms",
		Executors: []string{"steward"},
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
		Name:      "benchmark",
		Version:   "1.0.0",
		Publisher: "cfgms",
		Executors: []string{"steward"},
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
