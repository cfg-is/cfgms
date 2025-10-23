// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package modules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Mock module implementation for testing
type mockModule struct {
	name    string
	getFunc func(ctx context.Context, resourceID string) (ConfigState, error)
	setFunc func(ctx context.Context, resourceID string, config ConfigState) error
}

func (m *mockModule) Get(ctx context.Context, resourceID string) (ConfigState, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, resourceID)
	}
	return &mockConfigState{data: map[string]interface{}{"id": resourceID}}, nil
}

func (m *mockModule) Set(ctx context.Context, resourceID string, config ConfigState) error {
	if m.setFunc != nil {
		return m.setFunc(ctx, resourceID, config)
	}
	return nil
}

// Mock config state implementation
type mockConfigState struct {
	data map[string]interface{}
}

func (m *mockConfigState) AsMap() map[string]interface{} {
	return m.data
}

func (m *mockConfigState) ToYAML() ([]byte, error) {
	return []byte("test: data"), nil
}

func (m *mockConfigState) FromYAML(data []byte) error {
	return nil
}

func (m *mockConfigState) Validate() error {
	return nil
}

func (m *mockConfigState) GetManagedFields() []string {
	return []string{"test"}
}

func TestNewModuleRegistry(t *testing.T) {
	registry := NewModuleRegistry()

	if registry.modules == nil {
		t.Error("modules map should be initialized")
	}

	if registry.instances == nil {
		t.Error("instances map should be initialized")
	}

	if registry.dependencyGraph == nil {
		t.Error("dependencyGraph should be initialized")
	}

	if registry.initialized {
		t.Error("registry should not be initialized initially")
	}
}

func TestModuleRegistry_RegisterModule(t *testing.T) {
	registry := NewModuleRegistry()

	tests := []struct {
		name        string
		metadata    *ModuleMetadata
		instance    Module
		expectError bool
	}{
		{
			name:        "nil metadata",
			metadata:    nil,
			instance:    &mockModule{},
			expectError: true,
		},
		{
			name:        "nil instance",
			metadata:    &ModuleMetadata{Name: "test", Version: "1.0.0"},
			instance:    nil,
			expectError: true,
		},
		{
			name:        "invalid metadata",
			metadata:    &ModuleMetadata{Name: "", Version: "1.0.0"},
			instance:    &mockModule{},
			expectError: true,
		},
		{
			name:        "valid registration",
			metadata:    &ModuleMetadata{Name: "valid", Version: "1.0.0"},
			instance:    &mockModule{name: "valid"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.RegisterModule(tt.metadata, tt.instance)

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	// Test duplicate registration
	metadata := &ModuleMetadata{Name: "duplicate", Version: "1.0.0"}
	instance := &mockModule{name: "duplicate"}

	err := registry.RegisterModule(metadata, instance)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	err = registry.RegisterModule(metadata, instance)
	if err == nil {
		t.Error("expected error for duplicate registration")
	}

	// Test version conflict
	conflictMetadata := &ModuleMetadata{Name: "duplicate", Version: "2.0.0"}
	err = registry.RegisterModule(conflictMetadata, instance)
	if err == nil {
		t.Error("expected error for version conflict")
	}
}

func TestModuleRegistry_UnregisterModule(t *testing.T) {
	registry := NewModuleRegistry()

	// Test unregistering non-existent module
	err := registry.UnregisterModule("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent module")
	}

	// Register modules with dependencies
	baseMetadata := &ModuleMetadata{Name: "base", Version: "1.0.0"}
	baseInstance := &mockModule{name: "base"}

	appMetadata := &ModuleMetadata{
		Name:    "app",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "base", Version: "1.0.0"},
		},
	}
	appInstance := &mockModule{name: "app"}

	_ = registry.RegisterModule(baseMetadata, baseInstance) // Ignore error in test setup
	_ = registry.RegisterModule(appMetadata, appInstance)   // Ignore error in test setup

	// Try to unregister base module (should fail - app depends on it)
	err = registry.UnregisterModule("base")
	if err == nil {
		t.Error("expected error when unregistering module with dependents")
	}

	// Unregister app first (should succeed)
	err = registry.UnregisterModule("app")
	if err != nil {
		t.Errorf("unexpected error unregistering app: %v", err)
	}

	// Now unregister base (should succeed)
	err = registry.UnregisterModule("base")
	if err != nil {
		t.Errorf("unexpected error unregistering base: %v", err)
	}
}

func TestModuleRegistry_GetModule(t *testing.T) {
	registry := NewModuleRegistry()

	// Test getting non-existent module
	_, err := registry.GetModule("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent module")
	}

	// Register and get module
	metadata := &ModuleMetadata{Name: "test", Version: "1.0.0"}
	instance := &mockModule{name: "test"}

	_ = registry.RegisterModule(metadata, instance) // Ignore error in test setup

	retrieved, err := registry.GetModule("test")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if retrieved != instance {
		t.Error("retrieved instance should be the same as registered")
	}
}

func TestModuleRegistry_GetModuleMetadata(t *testing.T) {
	registry := NewModuleRegistry()

	// Test getting non-existent metadata
	_, err := registry.GetModuleMetadata("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent module")
	}

	// Register and get metadata
	metadata := &ModuleMetadata{Name: "test", Version: "1.0.0", Description: "Test module"}
	instance := &mockModule{name: "test"}

	_ = registry.RegisterModule(metadata, instance) // Ignore error in test setup

	retrieved, err := registry.GetModuleMetadata("test")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if retrieved.Name != metadata.Name {
		t.Errorf("retrieved metadata name = %v, expected %v", retrieved.Name, metadata.Name)
	}

	// Verify it's a clone (modify and check original)
	retrieved.Description = "Modified"
	if metadata.Description == "Modified" {
		t.Error("modifying retrieved metadata affected original")
	}
}

func TestModuleRegistry_ListModules(t *testing.T) {
	registry := NewModuleRegistry()

	// Test empty registry
	modules := registry.ListModules()
	if len(modules) != 0 {
		t.Errorf("expected empty list, got %d modules", len(modules))
	}

	// Register modules
	moduleNames := []string{"module1", "module2", "module3"}
	for _, name := range moduleNames {
		metadata := &ModuleMetadata{Name: name, Version: "1.0.0"}
		instance := &mockModule{name: name}
		_ = registry.RegisterModule(metadata, instance) // Ignore error in test setup
	}

	// Get list
	modules = registry.ListModules()
	if len(modules) != len(moduleNames) {
		t.Errorf("expected %d modules, got %d", len(moduleNames), len(modules))
	}

	// Sort for comparison
	sort.Strings(modules)
	sort.Strings(moduleNames)

	for i, name := range moduleNames {
		if modules[i] != name {
			t.Errorf("modules[%d] = %v, expected %v", i, modules[i], name)
		}
	}
}

func TestModuleRegistry_Initialize(t *testing.T) {
	registry := NewModuleRegistry()

	// Test initializing empty registry
	err := registry.Initialize()
	if err != nil {
		t.Errorf("unexpected error initializing empty registry: %v", err)
	}

	if !registry.initialized {
		t.Error("registry should be marked as initialized")
	}

	// Test with circular dependency
	registry = NewModuleRegistry()

	moduleA := &ModuleMetadata{
		Name:    "a",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "b", Version: "1.0.0"},
		},
	}

	moduleB := &ModuleMetadata{
		Name:    "b",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "a", Version: "1.0.0"},
		},
	}

	_ = registry.RegisterModule(moduleA, &mockModule{name: "a"}) // Ignore error in test setup
	_ = registry.RegisterModule(moduleB, &mockModule{name: "b"}) // Ignore error in test setup

	err = registry.Initialize()
	if err == nil {
		t.Error("expected error for circular dependency")
	}

	// Test with missing dependency
	registry = NewModuleRegistry()

	moduleWithMissingDep := &ModuleMetadata{
		Name:    "app",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "missing", Version: "1.0.0"},
		},
	}

	_ = registry.RegisterModule(moduleWithMissingDep, &mockModule{name: "app"}) // Ignore error in test setup

	err = registry.Initialize()
	if err == nil {
		t.Error("expected error for missing dependency")
	}
}

func TestModuleRegistry_GetLoadingOrder(t *testing.T) {
	registry := NewModuleRegistry()

	// Test uninitialized registry
	_, err := registry.GetLoadingOrder()
	if err == nil {
		t.Error("expected error for uninitialized registry")
	}

	// Register modules with dependencies
	// crypto <- auth <- middleware <- app
	//      <- database <-

	crypto := &ModuleMetadata{Name: "crypto", Version: "1.0.0"}
	auth := &ModuleMetadata{
		Name:    "auth",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "crypto", Version: "1.0.0"},
		},
	}
	database := &ModuleMetadata{
		Name:    "database",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "crypto", Version: "1.0.0"},
		},
	}
	middleware := &ModuleMetadata{
		Name:    "middleware",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "auth", Version: "1.0.0"},
		},
	}
	app := &ModuleMetadata{
		Name:    "app",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "middleware", Version: "1.0.0"},
			{Name: "database", Version: "1.0.0"},
		},
	}

	modules := []*ModuleMetadata{crypto, auth, database, middleware, app}
	for _, metadata := range modules {
		instance := &mockModule{name: metadata.Name}
		_ = registry.RegisterModule(metadata, instance) // Ignore error in test setup
	}

	// Initialize
	err = registry.Initialize()
	if err != nil {
		t.Fatalf("initialization failed: %v", err)
	}

	// Get loading order
	order, err := registry.GetLoadingOrder()
	if err != nil {
		t.Fatalf("failed to get loading order: %v", err)
	}

	if len(order) != len(modules) {
		t.Errorf("loading order length = %d, expected %d", len(order), len(modules))
	}

	// Validate order constraints
	positions := make(map[string]int)
	for i, name := range order {
		positions[name] = i
	}

	// crypto should come before auth and database
	if positions["crypto"] >= positions["auth"] {
		t.Error("crypto should come before auth")
	}
	if positions["crypto"] >= positions["database"] {
		t.Error("crypto should come before database")
	}

	// auth should come before middleware
	if positions["auth"] >= positions["middleware"] {
		t.Error("auth should come before middleware")
	}

	// middleware and database should come before app
	if positions["middleware"] >= positions["app"] {
		t.Error("middleware should come before app")
	}
	if positions["database"] >= positions["app"] {
		t.Error("database should come before app")
	}
}

func TestModuleRegistry_DetectConflicts(t *testing.T) {
	registry := NewModuleRegistry()

	// Test no conflicts
	crypto := &ModuleMetadata{Name: "crypto", Version: "1.0.0"}
	_ = registry.RegisterModule(crypto, &mockModule{name: "crypto"}) // Ignore error in test setup

	conflicts, err := registry.DetectConflicts()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(conflicts) != 0 {
		t.Errorf("expected no conflicts, got: %v", conflicts)
	}

	// Test circular dependency
	registry = NewModuleRegistry()

	moduleA := &ModuleMetadata{
		Name:    "a",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "b", Version: "1.0.0"},
		},
	}

	moduleB := &ModuleMetadata{
		Name:    "b",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "a", Version: "1.0.0"},
		},
	}

	_ = registry.RegisterModule(moduleA, &mockModule{name: "a"}) // Ignore error in test setup
	_ = registry.RegisterModule(moduleB, &mockModule{name: "b"}) // Ignore error in test setup

	conflicts, err = registry.DetectConflicts()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(conflicts) == 0 {
		t.Error("expected conflicts for circular dependency")
	}
}

func TestModuleRegistry_LoadModulesFromDirectory(t *testing.T) {
	// Create temporary directory with module metadata files
	tempDir := t.TempDir()

	// Create module directories
	module1Dir := filepath.Join(tempDir, "module1")
	module2Dir := filepath.Join(tempDir, "module2")
	_ = os.MkdirAll(module1Dir, 0755) // Ignore error in test setup
	_ = os.MkdirAll(module2Dir, 0755) // Ignore error in test setup

	// Create module.yaml files
	module1YAML := `name: module1
version: 1.0.0
description: Test module 1`

	module2YAML := `name: module2
version: 1.0.0
description: Test module 2
module_dependencies:
  - name: module1
    version: "^1.0.0"`

	_ = os.WriteFile(filepath.Join(module1Dir, "module.yaml"), []byte(module1YAML), 0644) // Ignore error in test setup
	_ = os.WriteFile(filepath.Join(module2Dir, "module.yaml"), []byte(module2YAML), 0644) // Ignore error in test setup

	registry := NewModuleRegistry()

	// Load modules from directory
	loaded, errors := registry.LoadModulesFromDirectory(tempDir)

	if len(errors) != 0 {
		t.Errorf("unexpected errors loading modules: %v", errors)
	}

	if len(loaded) != 2 {
		t.Errorf("expected 2 loaded modules, got %d", len(loaded))
	}

	// Verify modules were loaded
	sort.Strings(loaded)
	expected := []string{"module1", "module2"}
	for i, name := range expected {
		if loaded[i] != name {
			t.Errorf("loaded[%d] = %v, expected %v", i, loaded[i], name)
		}
	}
}

func TestModuleRegistry_GetRegistryStatus(t *testing.T) {
	registry := NewModuleRegistry()

	// Test empty registry
	status := registry.GetRegistryStatus()
	if status.TotalModules != 0 {
		t.Errorf("expected 0 modules, got %d", status.TotalModules)
	}

	if status.Initialized {
		t.Error("registry should not be initialized")
	}

	// Add modules and initialize
	module1 := &ModuleMetadata{Name: "module1", Version: "1.0.0"}
	module2 := &ModuleMetadata{Name: "module2", Version: "1.0.0"}

	_ = registry.RegisterModule(module1, &mockModule{name: "module1"}) // Ignore error in test setup
	_ = registry.RegisterModule(module2, &mockModule{name: "module2"}) // Ignore error in test setup
	_ = registry.Initialize()                                          // Ignore error in test setup

	status = registry.GetRegistryStatus()
	if status.TotalModules != 2 {
		t.Errorf("expected 2 modules, got %d", status.TotalModules)
	}

	if !status.Initialized {
		t.Error("registry should be initialized")
	}

	if status.HasConflicts {
		t.Error("registry should not have conflicts")
	}
}

func TestRegistryStatus_String(t *testing.T) {
	status := RegistryStatus{
		TotalModules: 5,
		Initialized:  true,
		HasConflicts: false,
	}

	str := status.String()
	expected := "Registry Status: 5 modules (initialized)"
	if str != expected {
		t.Errorf("String() = %v, expected %v", str, expected)
	}

	// Test with conflicts
	status.HasConflicts = true
	status.Conflicts = []string{"conflict1", "conflict2"}

	str = status.String()
	if !strings.Contains(str, "2 conflicts detected") {
		t.Errorf("String() should mention conflicts: %v", str)
	}
}

// Concurrent access tests
func TestModuleRegistry_ConcurrentAccess(t *testing.T) {
	registry := NewModuleRegistry()

	// Register some modules
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("module%d", i)
		metadata := &ModuleMetadata{Name: name, Version: "1.0.0"}
		instance := &mockModule{name: name}
		_ = registry.RegisterModule(metadata, instance) // Ignore error in test setup
	}

	_ = registry.Initialize() // Ignore error in test setup

	// Concurrent reads
	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func(i int) {
			defer func() { done <- true }()

			// Various read operations
			registry.ListModules()
			_, _ = registry.GetLoadingOrder() // Ignore error in concurrent test
			registry.GetRegistryStatus()

			name := fmt.Sprintf("module%d", i%10)
			_, _ = registry.GetModule(name)         // Ignore error in concurrent test
			_, _ = registry.GetModuleMetadata(name) // Ignore error in concurrent test
			_, _ = registry.GetDependencies(name)   // Ignore error in concurrent test
			_, _ = registry.GetDependents(name)     // Ignore error in concurrent test
		}(i)
	}

	// Wait for all goroutines
	timeout := time.After(5 * time.Second)
	for i := 0; i < 100; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("test timed out - possible deadlock")
		}
	}
}

// Benchmark tests
func BenchmarkModuleRegistry_RegisterModule(b *testing.B) {
	registry := NewModuleRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("module%d", i)
		metadata := &ModuleMetadata{Name: name, Version: "1.0.0"}
		instance := &mockModule{name: name}
		_ = registry.RegisterModule(metadata, instance) // Ignore error in benchmark
	}
}

func BenchmarkModuleRegistry_GetModule(b *testing.B) {
	registry := NewModuleRegistry()

	// Register modules
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("module%d", i)
		metadata := &ModuleMetadata{Name: name, Version: "1.0.0"}
		instance := &mockModule{name: name}
		_ = registry.RegisterModule(metadata, instance) // Ignore error in benchmark setup
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("module%d", i%100)
		_, _ = registry.GetModule(name) // Ignore error in benchmark
	}
}

func BenchmarkModuleRegistry_Initialize(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		registry := NewModuleRegistry()

		// Register modules with dependencies
		for j := 0; j < 20; j++ {
			var deps []ModuleDependency
			if j > 0 {
				deps = append(deps, ModuleDependency{
					Name:    fmt.Sprintf("module%d", j-1),
					Version: "1.0.0",
				})
			}

			name := fmt.Sprintf("module%d", j)
			metadata := &ModuleMetadata{
				Name:               name,
				Version:            "1.0.0",
				ModuleDependencies: deps,
			}
			instance := &mockModule{name: name}
			_ = registry.RegisterModule(metadata, instance) // Ignore error in benchmark setup
		}

		b.StartTimer()
		_ = registry.Initialize() // Ignore error in benchmark
	}
}
