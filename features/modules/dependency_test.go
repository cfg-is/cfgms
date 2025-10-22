package modules

import (
	"testing"
)

func TestModuleDependency_String(t *testing.T) {
	tests := []struct {
		name     string
		dep      ModuleDependency
		expected string
	}{
		{
			name:     "basic dependency",
			dep:      ModuleDependency{Name: "test", Version: "1.0.0"},
			expected: "test 1.0.0",
		},
		{
			name:     "optional dependency",
			dep:      ModuleDependency{Name: "test", Version: "1.0.0", Optional: true},
			expected: "test 1.0.0 (optional)",
		},
		{
			name:     "version constraint",
			dep:      ModuleDependency{Name: "test", Version: ">=1.0.0"},
			expected: "test >=1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.dep.String()
			if result != tt.expected {
				t.Errorf("String() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestNewDependencyGraph(t *testing.T) {
	graph := NewDependencyGraph()

	if graph.modules == nil {
		t.Error("modules map should be initialized")
	}

	if graph.adjacencyList == nil {
		t.Error("adjacencyList map should be initialized")
	}

	if graph.reverseList == nil {
		t.Error("reverseList map should be initialized")
	}
}

func TestDependencyGraph_AddModule(t *testing.T) {
	graph := NewDependencyGraph()

	tests := []struct {
		name        string
		metadata    *ModuleMetadata
		expectError bool
	}{
		{
			name:        "nil metadata",
			metadata:    nil,
			expectError: true,
		},
		{
			name: "empty name",
			metadata: &ModuleMetadata{
				Name: "",
			},
			expectError: true,
		},
		{
			name: "valid module",
			metadata: &ModuleMetadata{
				Name:    "test",
				Version: "1.0.0",
			},
			expectError: false,
		},
		{
			name: "module with dependencies",
			metadata: &ModuleMetadata{
				Name:    "test2",
				Version: "1.0.0",
				ModuleDependencies: []ModuleDependency{
					{Name: "test", Version: "1.0.0"},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := graph.AddModule(tt.metadata)

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDependencyGraph_GetDependencies(t *testing.T) {
	graph := NewDependencyGraph()

	// Add modules
	moduleA := &ModuleMetadata{
		Name:    "a",
		Version: "1.0.0",
		ModuleDependencies: []ModuleDependency{
			{Name: "b", Version: "1.0.0"},
			{Name: "c", Version: "1.0.0"},
		},
	}

	moduleB := &ModuleMetadata{
		Name:    "b",
		Version: "1.0.0",
	}

	_ = graph.AddModule(moduleA) // Ignore error in test setup
	_ = graph.AddModule(moduleB) // Ignore error in test setup

	// Test getting dependencies
	deps := graph.GetDependencies("a")
	expected := []string{"b", "c"}

	if len(deps) != len(expected) {
		t.Errorf("expected %d dependencies, got %d", len(expected), len(deps))
	}

	for _, exp := range expected {
		found := false
		for _, dep := range deps {
			if dep == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected dependency %s not found", exp)
		}
	}

	// Test non-existent module
	deps = graph.GetDependencies("nonexistent")
	if len(deps) != 0 {
		t.Errorf("expected empty dependencies for non-existent module, got %v", deps)
	}
}

func TestDependencyGraph_HasCycles(t *testing.T) {
	tests := []struct {
		name        string
		modules     []*ModuleMetadata
		expectCycle bool
	}{
		{
			name: "no cycles",
			modules: []*ModuleMetadata{
				{Name: "a", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "b", Version: "1.0.0"}}},
				{Name: "b", Version: "1.0.0"},
			},
			expectCycle: false,
		},
		{
			name: "simple cycle",
			modules: []*ModuleMetadata{
				{Name: "a", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "b", Version: "1.0.0"}}},
				{Name: "b", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "a", Version: "1.0.0"}}},
			},
			expectCycle: true,
		},
		{
			name: "three-way cycle",
			modules: []*ModuleMetadata{
				{Name: "a", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "b", Version: "1.0.0"}}},
				{Name: "b", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "c", Version: "1.0.0"}}},
				{Name: "c", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "a", Version: "1.0.0"}}},
			},
			expectCycle: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph := NewDependencyGraph()

			for _, module := range tt.modules {
				_ = graph.AddModule(module) // Ignore error in test setup
			}

			hasCycles, cycle := graph.HasCycles()

			if hasCycles != tt.expectCycle {
				t.Errorf("expected cycle detection: %v, got: %v", tt.expectCycle, hasCycles)
			}

			if tt.expectCycle && len(cycle) == 0 {
				t.Error("expected cycle path but got empty")
			}

			if !tt.expectCycle && len(cycle) > 0 {
				t.Errorf("expected no cycle but got: %v", cycle)
			}
		})
	}
}

func TestDependencyGraph_TopologicalSort(t *testing.T) {
	tests := []struct {
		name        string
		modules     []*ModuleMetadata
		expectError bool
		validate    func([]string) bool
	}{
		{
			name: "simple chain",
			modules: []*ModuleMetadata{
				{Name: "a", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "b", Version: "1.0.0"}}},
				{Name: "b", Version: "1.0.0"},
			},
			expectError: false,
			validate: func(order []string) bool {
				// b should come before a
				bIndex, aIndex := -1, -1
				for i, name := range order {
					if name == "b" {
						bIndex = i
					}
					if name == "a" {
						aIndex = i
					}
				}
				return bIndex < aIndex
			},
		},
		{
			name: "with cycle",
			modules: []*ModuleMetadata{
				{Name: "a", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "b", Version: "1.0.0"}}},
				{Name: "b", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "a", Version: "1.0.0"}}},
			},
			expectError: true,
		},
		{
			name: "complex dependencies",
			modules: []*ModuleMetadata{
				{Name: "app", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "middleware", Version: "1.0.0"}, {Name: "database", Version: "1.0.0"}}},
				{Name: "middleware", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "auth", Version: "1.0.0"}}},
				{Name: "auth", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "crypto", Version: "1.0.0"}}},
				{Name: "database", Version: "1.0.0", ModuleDependencies: []ModuleDependency{{Name: "crypto", Version: "1.0.0"}}},
				{Name: "crypto", Version: "1.0.0"},
			},
			expectError: false,
			validate: func(order []string) bool {
				positions := make(map[string]int)
				for i, name := range order {
					positions[name] = i
				}

				// crypto should come before everything else
				// auth should come before middleware
				// middleware and database should come before app
				return positions["crypto"] < positions["auth"] &&
					positions["crypto"] < positions["database"] &&
					positions["auth"] < positions["middleware"] &&
					positions["middleware"] < positions["app"] &&
					positions["database"] < positions["app"]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph := NewDependencyGraph()

			for _, module := range tt.modules {
				_ = graph.AddModule(module) // Ignore error in test setup
			}

			order, err := graph.TopologicalSort()

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !tt.expectError && tt.validate != nil && !tt.validate(order) {
				t.Errorf("topological sort validation failed for order: %v", order)
			}
		})
	}
}

func TestDependencyGraph_ValidateAllDependencies(t *testing.T) {
	graph := NewDependencyGraph()

	// Add modules with various dependency scenarios
	modules := []*ModuleMetadata{
		{
			Name:    "app",
			Version: "2.0.0",
			ModuleDependencies: []ModuleDependency{
				{Name: "middleware", Version: "^1.0.0"}, // Should be satisfied
				{Name: "missing", Version: "1.0.0"},     // Missing dependency
				{Name: "database", Version: ">=3.0.0"},  // Version mismatch
			},
		},
		{
			Name:    "middleware",
			Version: "1.2.0", // Satisfies ^1.0.0
		},
		{
			Name:    "database",
			Version: "2.0.0", // Does not satisfy >=3.0.0
		},
	}

	for _, module := range modules {
		_ = graph.AddModule(module) // Ignore error in test setup
	}

	errors := graph.ValidateAllDependencies()

	// Should have 2 errors: missing dependency and version mismatch
	if len(errors) != 2 {
		t.Errorf("expected 2 validation errors, got %d", len(errors))
	}

	// Check error types
	errorTypes := make(map[DependencyErrorType]int)
	for _, err := range errors {
		errorTypes[err.Type]++
	}

	if errorTypes[DependencyErrorMissing] != 1 {
		t.Errorf("expected 1 missing dependency error, got %d", errorTypes[DependencyErrorMissing])
	}

	if errorTypes[DependencyErrorVersionMismatch] != 1 {
		t.Errorf("expected 1 version mismatch error, got %d", errorTypes[DependencyErrorVersionMismatch])
	}
}

func TestDependencyError_Error(t *testing.T) {
	err := DependencyError{
		Type:       DependencyErrorMissing,
		Module:     "app",
		Dependency: "database",
		Message:    "required dependency 'database' not found",
	}

	expected := "dependency error in module 'app': required dependency 'database' not found"
	if err.Error() != expected {
		t.Errorf("Error() = %v, expected %v", err.Error(), expected)
	}
}

func TestDependencyErrorType_String(t *testing.T) {
	tests := []struct {
		errorType DependencyErrorType
		expected  string
	}{
		{DependencyErrorMissing, "missing"},
		{DependencyErrorVersionMismatch, "version_mismatch"},
		{DependencyErrorInvalidVersion, "invalid_version"},
		{DependencyErrorCircular, "circular"},
		{DependencyErrorType(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.errorType.String()
			if result != tt.expected {
				t.Errorf("String() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// Benchmark tests for performance validation
func BenchmarkDependencyGraph_AddModule(b *testing.B) {
	graph := NewDependencyGraph()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metadata := &ModuleMetadata{
			Name:    "test" + string(rune(i)),
			Version: "1.0.0",
		}
		_ = graph.AddModule(metadata) // Ignore error in benchmark setup
	}
}

func BenchmarkDependencyGraph_TopologicalSort(b *testing.B) {
	graph := NewDependencyGraph()

	// Add a moderate number of modules with dependencies
	for i := 0; i < 50; i++ {
		var deps []ModuleDependency
		if i > 0 {
			// Each module depends on the previous one
			deps = append(deps, ModuleDependency{
				Name:    "module" + string(rune(i-1)),
				Version: "1.0.0",
			})
		}

		metadata := &ModuleMetadata{
			Name:               "module" + string(rune(i)),
			Version:            "1.0.0",
			ModuleDependencies: deps,
		}
		_ = graph.AddModule(metadata) // Ignore error in benchmark setup
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := graph.TopologicalSort()
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
