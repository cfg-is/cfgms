package modules

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultModuleVersionRegistry_RegisterVersion(t *testing.T) {
	tests := []struct {
		name      string
		metadata  *ModuleMetadata
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid module registration",
			metadata: &ModuleMetadata{
				Name:        "test-module",
				Version:     "1.0.0",
				Description: "Test module",
			},
			expectErr: false,
		},
		{
			name:      "nil metadata",
			metadata:  nil,
			expectErr: true,
			errMsg:    "module metadata cannot be nil",
		},
		{
			name: "invalid version format",
			metadata: &ModuleMetadata{
				Name:        "test-module",
				Version:     "invalid-version",
				Description: "Test module",
			},
			expectErr: true,
			errMsg:    "invalid module metadata",
		},
		{
			name: "empty module name",
			metadata: &ModuleMetadata{
				Name:        "",
				Version:     "1.0.0",
				Description: "Test module",
			},
			expectErr: true,
			errMsg:    "invalid module metadata",
		},
		{
			name: "duplicate version registration",
			metadata: &ModuleMetadata{
				Name:        "duplicate-module",
				Version:     "1.0.0",
				Description: "Duplicate test",
			},
			expectErr: false, // First registration should succeed
		},
	}

	registry := NewDefaultModuleVersionRegistry()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.RegisterVersion(tt.metadata)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)

				if tt.metadata != nil {
					// Verify the version was registered
					assert.True(t, registry.IsVersionInstalled(tt.metadata.Name, tt.metadata.Version))

					// Test duplicate registration
					err = registry.RegisterVersion(tt.metadata)
					assert.Error(t, err)
					assert.Contains(t, err.Error(), "is already registered")
				}
			}
		})
	}
}

func TestDefaultModuleVersionRegistry_GetAvailableVersions(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()

	// Register multiple versions
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0"}
	for _, version := range versions {
		metadata := &ModuleMetadata{
			Name:        "test-module",
			Version:     version,
			Description: "Test module",
		}
		require.NoError(t, registry.RegisterVersion(metadata))
	}

	t.Run("get available versions", func(t *testing.T) {
		availableVersions, err := registry.GetAvailableVersions("test-module")
		require.NoError(t, err)
		assert.Equal(t, versions, availableVersions) // Should be sorted
	})

	t.Run("non-existent module", func(t *testing.T) {
		_, err := registry.GetAvailableVersions("non-existent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is not registered")
	})
}

func TestDefaultModuleVersionRegistry_GetLatestVersion(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()

	// Register versions in random order
	versions := []string{"1.2.0", "2.0.0", "1.0.0", "1.1.0"}
	for _, version := range versions {
		metadata := &ModuleMetadata{
			Name:        "test-module",
			Version:     version,
			Description: "Test module",
		}
		require.NoError(t, registry.RegisterVersion(metadata))
	}

	t.Run("get latest version", func(t *testing.T) {
		latestVersion, err := registry.GetLatestVersion("test-module")
		require.NoError(t, err)
		assert.Equal(t, "2.0.0", latestVersion.String())
	})

	t.Run("non-existent module", func(t *testing.T) {
		_, err := registry.GetLatestVersion("non-existent")
		assert.Error(t, err)
	})
}

func TestDefaultModuleVersionRegistry_GetCompatibleVersions(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()

	// Register multiple versions
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"}
	for _, version := range versions {
		metadata := &ModuleMetadata{
			Name:        "test-module",
			Version:     version,
			Description: "Test module",
		}
		require.NoError(t, registry.RegisterVersion(metadata))
	}

	tests := []struct {
		name             string
		constraint       string
		expectedVersions []string
	}{
		{
			name:             "exact version",
			constraint:       "1.1.0",
			expectedVersions: []string{"1.1.0"},
		},
		{
			name:             "caret constraint",
			constraint:       "^1.0.0",
			expectedVersions: []string{"1.0.0", "1.1.0", "1.2.0"},
		},
		{
			name:             "tilde constraint",
			constraint:       "~1.1.0",
			expectedVersions: []string{"1.1.0"},
		},
		{
			name:             "greater than or equal",
			constraint:       ">=1.2.0",
			expectedVersions: []string{"1.2.0", "2.0.0", "2.1.0"},
		},
		{
			name:             "less than",
			constraint:       "<2.0.0",
			expectedVersions: []string{"1.0.0", "1.1.0", "1.2.0"},
		},
		{
			name:             "any version",
			constraint:       "*",
			expectedVersions: []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatibleVersions, err := registry.GetCompatibleVersions("test-module", tt.constraint)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedVersions, compatibleVersions)
		})
	}
}

func TestDefaultModuleVersionRegistry_UnregisterVersion(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()

	// Register a version
	metadata := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	require.NoError(t, registry.RegisterVersion(metadata))

	t.Run("successful unregistration", func(t *testing.T) {
		err := registry.UnregisterVersion("test-module", "1.0.0")
		assert.NoError(t, err)
		assert.False(t, registry.IsVersionInstalled("test-module", "1.0.0"))
	})

	t.Run("unregister non-existent module", func(t *testing.T) {
		err := registry.UnregisterVersion("non-existent", "1.0.0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is not registered")
	})

	t.Run("unregister non-existent version", func(t *testing.T) {
		// Re-register for this test
		require.NoError(t, registry.RegisterVersion(metadata))

		err := registry.UnregisterVersion("test-module", "2.0.0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is not registered")
	})
}

func TestDefaultModuleVersionRegistry_ResolveVersionConstraints(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()

	// Register modules with various versions
	modules := map[string][]string{
		"module-a": {"1.0.0", "1.1.0", "1.2.0"},
		"module-b": {"2.0.0", "2.1.0"},
		"module-c": {"1.0.0", "2.0.0", "3.0.0"},
	}

	for moduleName, versions := range modules {
		for _, version := range versions {
			metadata := &ModuleMetadata{
				Name:        moduleName,
				Version:     version,
				Description: fmt.Sprintf("Test module %s", moduleName),
			}
			require.NoError(t, registry.RegisterVersion(metadata))
		}
	}

	t.Run("successful resolution", func(t *testing.T) {
		requirements := []ModuleVersionRequirement{
			{ModuleName: "module-a", Constraint: "^1.0.0"},
			{ModuleName: "module-b", Constraint: ">=2.0.0"},
			{ModuleName: "module-c", Constraint: "~2.0.0"},
		}

		resolution, err := registry.ResolveVersionConstraints(requirements)
		require.NoError(t, err)
		assert.NotNil(t, resolution)

		assert.Equal(t, 3, len(resolution.Resolved))
		assert.Equal(t, "1.2.0", resolution.Resolved["module-a"]) // Latest compatible
		assert.Equal(t, "2.1.0", resolution.Resolved["module-b"]) // Latest compatible
		assert.Equal(t, "2.0.0", resolution.Resolved["module-c"]) // Only tilde compatible

		assert.Equal(t, 0, len(resolution.Conflicts))
		assert.Equal(t, 3, resolution.TotalModules)
		assert.Greater(t, resolution.ResolutionTime, time.Duration(0))
	})

	t.Run("resolution with conflicts", func(t *testing.T) {
		requirements := []ModuleVersionRequirement{
			{ModuleName: "non-existent", Constraint: "1.0.0"},
		}

		resolution, err := registry.ResolveVersionConstraints(requirements)
		require.NoError(t, err)
		assert.NotNil(t, resolution)

		assert.Equal(t, 1, len(resolution.Conflicts))
		assert.Equal(t, 0, len(resolution.Resolved))
	})

	t.Run("optional requirement", func(t *testing.T) {
		requirements := []ModuleVersionRequirement{
			{ModuleName: "module-a", Constraint: "^1.0.0"},
			{ModuleName: "non-existent", Constraint: "1.0.0", Optional: true},
		}

		resolution, err := registry.ResolveVersionConstraints(requirements)
		require.NoError(t, err)
		assert.NotNil(t, resolution)

		assert.Equal(t, 1, len(resolution.Resolved))
		assert.Equal(t, "1.2.0", resolution.Resolved["module-a"])
		assert.Equal(t, 0, len(resolution.Conflicts)) // Optional requirement doesn't create conflict
	})
}

func TestDefaultModuleVersionRegistry_VersionHistory(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()

	metadata := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	require.NoError(t, registry.RegisterVersion(metadata))

	t.Run("get version history", func(t *testing.T) {
		history, err := registry.GetVersionHistory("test-module")
		require.NoError(t, err)
		assert.NotNil(t, history)

		assert.Equal(t, "test-module", history.ModuleName)
		assert.Equal(t, "1.0.0", history.CurrentVersion)
		assert.Equal(t, 1, len(history.Transitions)) // Should have install transition

		transition := history.Transitions[0]
		assert.Equal(t, "", transition.FromVersion)
		assert.Equal(t, "1.0.0", transition.ToVersion)
		assert.Equal(t, TransitionInstall, transition.TransitionType)
		assert.Equal(t, TransitionCompleted, transition.Status)
	})

	t.Run("record manual transition", func(t *testing.T) {
		metadata2 := &ModuleMetadata{
			Name:        "test-module",
			Version:     "1.1.0",
			Description: "Test module v1.1.0",
		}
		require.NoError(t, registry.RegisterVersion(metadata2))

		// Record an upgrade transition
		err := registry.RecordVersionTransition("test-module", "1.0.0", "1.1.0", TransitionUpgrade, map[string]interface{}{
			"test": "data",
		})
		require.NoError(t, err)

		history, err := registry.GetVersionHistory("test-module")
		require.NoError(t, err)

		assert.Equal(t, 3, len(history.Transitions)) // install 1.0.0, install 1.1.0, upgrade 1.0.0->1.1.0
		assert.Equal(t, "1.1.0", history.CurrentVersion)

		// Find the upgrade transition
		var upgradeTransition *VersionTransition
		for _, transition := range history.Transitions {
			if transition.TransitionType == TransitionUpgrade {
				upgradeTransition = &transition
				break
			}
		}

		require.NotNil(t, upgradeTransition)
		assert.Equal(t, "1.0.0", upgradeTransition.FromVersion)
		assert.Equal(t, "1.1.0", upgradeTransition.ToVersion)
		assert.Equal(t, "data", upgradeTransition.Metadata["test"])
	})

	t.Run("non-existent module history", func(t *testing.T) {
		_, err := registry.GetVersionHistory("non-existent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no history found")
	})
}

func TestDefaultModuleVersionRegistry_RegistryStatus(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()

	t.Run("empty registry status", func(t *testing.T) {
		status := registry.GetRegistryStatus()
		assert.NotNil(t, status)

		assert.Equal(t, 0, status.TotalModules)
		assert.Equal(t, 0, status.TotalVersions)
		assert.Equal(t, 0, len(status.ActiveVersions))
		assert.Equal(t, 100.0, status.RegistryHealthScore) // Perfect score for empty registry
	})

	t.Run("populated registry status", func(t *testing.T) {
		// Register some modules
		modules := []struct {
			name    string
			version string
		}{
			{"module-a", "1.0.0"},
			{"module-a", "1.1.0"},
			{"module-b", "2.0.0"},
		}

		for _, module := range modules {
			metadata := &ModuleMetadata{
				Name:        module.name,
				Version:     module.version,
				Description: "Test module",
			}
			require.NoError(t, registry.RegisterVersion(metadata))
		}

		status := registry.GetRegistryStatus()
		assert.NotNil(t, status)

		assert.Equal(t, 2, status.TotalModules)
		assert.Equal(t, 3, status.TotalVersions)
		assert.Equal(t, 2, len(status.ActiveVersions))
		assert.Equal(t, "1.1.0", status.ActiveVersions["module-a"]) // Latest version should be active
		assert.Equal(t, "2.0.0", status.ActiveVersions["module-b"])
		assert.Equal(t, 100.0, status.RegistryHealthScore) // All versions are healthy
	})
}

func TestDefaultModuleVersionRegistry_ListAllVersions(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()

	// Register modules
	modules := map[string][]string{
		"module-a": {"1.0.0", "1.1.0", "1.2.0"},
		"module-b": {"2.0.0", "2.1.0"},
	}

	for moduleName, versions := range modules {
		for _, version := range versions {
			metadata := &ModuleMetadata{
				Name:        moduleName,
				Version:     version,
				Description: "Test module",
			}
			require.NoError(t, registry.RegisterVersion(metadata))
		}
	}

	t.Run("list all versions", func(t *testing.T) {
		allVersions := registry.ListAllVersions()
		assert.NotNil(t, allVersions)

		assert.Equal(t, 2, len(allVersions))
		assert.Equal(t, modules["module-a"], allVersions["module-a"])
		assert.Equal(t, modules["module-b"], allVersions["module-b"])
	})
}

func TestDefaultModuleVersionRegistry_ActiveVersionManagement(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()

	t.Run("first version becomes active", func(t *testing.T) {
		metadata := &ModuleMetadata{
			Name:        "test-module",
			Version:     "1.0.0",
			Description: "Test module",
		}
		require.NoError(t, registry.RegisterVersion(metadata))

		status := registry.GetRegistryStatus()
		assert.Equal(t, "1.0.0", status.ActiveVersions["test-module"])
	})

	t.Run("higher version becomes active", func(t *testing.T) {
		metadata := &ModuleMetadata{
			Name:        "test-module",
			Version:     "1.1.0",
			Description: "Test module v1.1.0",
		}
		require.NoError(t, registry.RegisterVersion(metadata))

		status := registry.GetRegistryStatus()
		assert.Equal(t, "1.1.0", status.ActiveVersions["test-module"])
	})

	t.Run("lower version doesn't become active", func(t *testing.T) {
		metadata := &ModuleMetadata{
			Name:        "test-module",
			Version:     "0.9.0",
			Description: "Test module v0.9.0",
		}
		require.NoError(t, registry.RegisterVersion(metadata))

		status := registry.GetRegistryStatus()
		assert.Equal(t, "1.1.0", status.ActiveVersions["test-module"]) // Should still be 1.1.0
	})

	t.Run("unregistering active version selects new active", func(t *testing.T) {
		err := registry.UnregisterVersion("test-module", "1.1.0")
		require.NoError(t, err)

		status := registry.GetRegistryStatus()
		assert.Equal(t, "1.0.0", status.ActiveVersions["test-module"]) // Should fall back to 1.0.0
	})
}

func TestDefaultModuleVersionRegistry_ConcurrencyBasics(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()

	t.Run("concurrent version registration", func(t *testing.T) {
		// This is a basic concurrency test - in practice you'd want more sophisticated testing
		metadata1 := &ModuleMetadata{
			Name:        "concurrent-module",
			Version:     "1.0.0",
			Description: "Concurrent test",
		}

		metadata2 := &ModuleMetadata{
			Name:        "concurrent-module",
			Version:     "1.1.0",
			Description: "Concurrent test",
		}

		// Register versions concurrently
		done := make(chan error, 2)

		go func() {
			done <- registry.RegisterVersion(metadata1)
		}()

		go func() {
			done <- registry.RegisterVersion(metadata2)
		}()

		// Wait for both to complete
		err1 := <-done
		err2 := <-done

		// Both should succeed (no race condition)
		assert.NoError(t, err1)
		assert.NoError(t, err2)

		// Both versions should be registered
		assert.True(t, registry.IsVersionInstalled("concurrent-module", "1.0.0"))
		assert.True(t, registry.IsVersionInstalled("concurrent-module", "1.1.0"))
	})
}

// Benchmark tests for performance
func BenchmarkVersionRegistry_RegisterVersion(b *testing.B) {
	registry := NewDefaultModuleVersionRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metadata := &ModuleMetadata{
			Name:        fmt.Sprintf("bench-module-%d", i),
			Version:     "1.0.0",
			Description: "Benchmark module",
		}
		_ = registry.RegisterVersion(metadata) // Ignore error in test setup
	}
}

func BenchmarkVersionRegistry_GetAvailableVersions(b *testing.B) {
	registry := NewDefaultModuleVersionRegistry()

	// Pre-populate with versions
	for i := 0; i < 100; i++ {
		metadata := &ModuleMetadata{
			Name:        "bench-module",
			Version:     fmt.Sprintf("1.%d.0", i),
			Description: "Benchmark module",
		}
		_ = registry.RegisterVersion(metadata) // Ignore error in test setup
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = registry.GetAvailableVersions("bench-module") // Ignore error in benchmark
	}
}

func BenchmarkVersionRegistry_ResolveVersionConstraints(b *testing.B) {
	registry := NewDefaultModuleVersionRegistry()

	// Pre-populate with modules and versions
	for moduleIdx := 0; moduleIdx < 10; moduleIdx++ {
		for versionIdx := 0; versionIdx < 10; versionIdx++ {
			metadata := &ModuleMetadata{
				Name:        fmt.Sprintf("bench-module-%d", moduleIdx),
				Version:     fmt.Sprintf("1.%d.0", versionIdx),
				Description: "Benchmark module",
			}
			_ = registry.RegisterVersion(metadata) // Ignore error in test setup
		}
	}

	requirements := []ModuleVersionRequirement{
		{ModuleName: "bench-module-0", Constraint: "^1.0.0"},
		{ModuleName: "bench-module-1", Constraint: ">=1.5.0"},
		{ModuleName: "bench-module-2", Constraint: "~1.3.0"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = registry.ResolveVersionConstraints(requirements) // Ignore error in benchmark
	}
}
