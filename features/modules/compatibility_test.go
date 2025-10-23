// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package modules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCompatibilityMatrix_RecordCompatibility(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Register a test version
	metadata := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	require.NoError(t, registry.RegisterVersion(metadata))

	tests := []struct {
		name          string
		moduleName    string
		version       string
		compatibility *VersionCompatibilityInfo
		expectErr     bool
		errContains   string
	}{
		{
			name:       "valid compatibility info",
			moduleName: "test-module",
			version:    "1.0.0",
			compatibility: &VersionCompatibilityInfo{
				BackwardsCompatible: []string{"0.9.0"},
				ForwardsCompatible:  []string{"1.0.1", "1.1.0"},
				BreakingChanges: []BreakingChange{
					{
						Type:        BreakingChangeRemoval,
						Description: "Removed deprecated function",
						Severity:    SeverityMedium,
					},
				},
				MigrationRequired:   false,
				MigrationComplexity: MigrationComplexityLow,
			},
			expectErr: false,
		},
		{
			name:          "empty module name",
			moduleName:    "",
			version:       "1.0.0",
			compatibility: &VersionCompatibilityInfo{},
			expectErr:     true,
			errContains:   "module name and version are required",
		},
		{
			name:          "empty version",
			moduleName:    "test-module",
			version:       "",
			compatibility: &VersionCompatibilityInfo{},
			expectErr:     true,
			errContains:   "module name and version are required",
		},
		{
			name:          "nil compatibility info",
			moduleName:    "test-module",
			version:       "1.0.0",
			compatibility: nil,
			expectErr:     true,
			errContains:   "compatibility information cannot be nil",
		},
		{
			name:          "non-existent version",
			moduleName:    "test-module",
			version:       "2.0.0",
			compatibility: &VersionCompatibilityInfo{},
			expectErr:     true,
			errContains:   "is not installed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := matrix.RecordCompatibility(tt.moduleName, tt.version, tt.compatibility)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify the compatibility was recorded
				recorded, err := matrix.GetCompatibility(tt.moduleName, tt.version)
				require.NoError(t, err)
				assert.Equal(t, tt.compatibility.BackwardsCompatible, recorded.BackwardsCompatible)
				assert.Equal(t, tt.compatibility.ForwardsCompatible, recorded.ForwardsCompatible)
				assert.Equal(t, len(tt.compatibility.BreakingChanges), len(recorded.BreakingChanges))
				assert.Equal(t, tt.compatibility.MigrationRequired, recorded.MigrationRequired)
				assert.Equal(t, tt.compatibility.MigrationComplexity, recorded.MigrationComplexity)
			}
		})
	}
}

func TestDefaultCompatibilityMatrix_GetCompatibility(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Register and record compatibility for a test version
	metadata := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	require.NoError(t, registry.RegisterVersion(metadata))

	compatibility := &VersionCompatibilityInfo{
		BackwardsCompatible: []string{"0.9.0"},
		ForwardsCompatible:  []string{"1.0.1", "1.1.0"},
		MigrationRequired:   false,
		MigrationComplexity: MigrationComplexityLow,
	}
	require.NoError(t, matrix.RecordCompatibility("test-module", "1.0.0", compatibility))

	t.Run("get existing compatibility", func(t *testing.T) {
		retrieved, err := matrix.GetCompatibility("test-module", "1.0.0")
		require.NoError(t, err)
		assert.NotNil(t, retrieved)
		assert.Equal(t, compatibility.BackwardsCompatible, retrieved.BackwardsCompatible)
		assert.Equal(t, compatibility.ForwardsCompatible, retrieved.ForwardsCompatible)
	})

	t.Run("get non-existent module", func(t *testing.T) {
		_, err := matrix.GetCompatibility("non-existent", "1.0.0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no compatibility information for module")
	})

	t.Run("get non-existent version", func(t *testing.T) {
		_, err := matrix.GetCompatibility("test-module", "2.0.0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no compatibility information for version")
	})
}

func TestDefaultCompatibilityMatrix_UpdateCompatibility(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Register and record initial compatibility
	metadata := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	require.NoError(t, registry.RegisterVersion(metadata))

	initialCompat := &VersionCompatibilityInfo{
		BackwardsCompatible: []string{"0.9.0"},
		MigrationRequired:   false,
	}
	require.NoError(t, matrix.RecordCompatibility("test-module", "1.0.0", initialCompat))

	t.Run("update existing compatibility", func(t *testing.T) {
		updatedCompat := &VersionCompatibilityInfo{
			BackwardsCompatible: []string{"0.9.0", "0.8.0"},
			ForwardsCompatible:  []string{"1.0.1"},
			MigrationRequired:   true,
			MigrationComplexity: MigrationComplexityMedium,
		}

		err := matrix.UpdateCompatibility("test-module", "1.0.0", updatedCompat)
		require.NoError(t, err)

		// Verify update
		retrieved, err := matrix.GetCompatibility("test-module", "1.0.0")
		require.NoError(t, err)
		assert.Equal(t, updatedCompat.BackwardsCompatible, retrieved.BackwardsCompatible)
		assert.Equal(t, updatedCompat.ForwardsCompatible, retrieved.ForwardsCompatible)
		assert.Equal(t, updatedCompat.MigrationRequired, retrieved.MigrationRequired)
		assert.Equal(t, updatedCompat.MigrationComplexity, retrieved.MigrationComplexity)
	})

	t.Run("update non-existent compatibility", func(t *testing.T) {
		err := matrix.UpdateCompatibility("test-module", "2.0.0", &VersionCompatibilityInfo{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot update non-existent compatibility info")
	})
}

func TestDefaultCompatibilityMatrix_RemoveCompatibility(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Register and record compatibility
	metadata := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	require.NoError(t, registry.RegisterVersion(metadata))

	compatibility := &VersionCompatibilityInfo{
		BackwardsCompatible: []string{"0.9.0"},
	}
	require.NoError(t, matrix.RecordCompatibility("test-module", "1.0.0", compatibility))

	t.Run("remove existing compatibility", func(t *testing.T) {
		err := matrix.RemoveCompatibility("test-module", "1.0.0")
		require.NoError(t, err)

		// Verify removal
		_, err = matrix.GetCompatibility("test-module", "1.0.0")
		assert.Error(t, err)
	})

	t.Run("remove non-existent module", func(t *testing.T) {
		err := matrix.RemoveCompatibility("non-existent", "1.0.0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no compatibility information for module")
	})

	t.Run("remove non-existent version", func(t *testing.T) {
		// Re-add compatibility for this test
		require.NoError(t, matrix.RecordCompatibility("test-module", "1.0.0", compatibility))

		err := matrix.RemoveCompatibility("test-module", "2.0.0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no compatibility information for version")
	})
}

func TestDefaultCompatibilityMatrix_CheckCrossModuleCompatibility(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Register multiple modules with versions
	modules := []struct {
		name    string
		version string
	}{
		{"module-a", "1.0.0"},
		{"module-b", "2.0.0"},
		{"module-c", "1.5.0"},
	}

	for _, module := range modules {
		metadata := &ModuleMetadata{
			Name:        module.name,
			Version:     module.version,
			Description: "Test module",
		}
		require.NoError(t, registry.RegisterVersion(metadata))

		// Record compatibility info
		compatibility := &VersionCompatibilityInfo{
			BackwardsCompatible: []string{},
			ForwardsCompatible:  []string{},
			BreakingChanges: []BreakingChange{
				{
					Type:        BreakingChangeModification,
					Description: "Minor API changes",
					Severity:    SeverityLow,
				},
			},
			MigrationRequired:   false,
			MigrationComplexity: MigrationComplexityLow,
		}
		require.NoError(t, matrix.RecordCompatibility(module.name, module.version, compatibility))
	}

	t.Run("check compatibility of multiple modules", func(t *testing.T) {
		moduleVersions := map[string]string{
			"module-a": "1.0.0",
			"module-b": "2.0.0",
			"module-c": "1.5.0",
		}

		report, err := matrix.CheckCrossModuleCompatibility(moduleVersions)
		require.NoError(t, err)
		assert.NotNil(t, report)

		// Verify report structure
		assert.Equal(t, moduleVersions, report.ModuleVersions)
		assert.False(t, report.AnalysisTime.IsZero())
		assert.GreaterOrEqual(t, report.CompatibilityScore, 0.0)
		assert.LessOrEqual(t, report.CompatibilityScore, 1.0)
		assert.NotNil(t, report.Issues)
		assert.NotNil(t, report.Warnings)
		assert.NotNil(t, report.Recommendations)
		assert.NotNil(t, report.DetailedResults)

		// Should have pairwise results for all combinations
		expectedPairs := 3 // C(3,2) = 3 pairs
		assert.Equal(t, expectedPairs, len(report.DetailedResults))

		// Verify each pair result
		for _, pairResult := range report.DetailedResults {
			assert.NotEmpty(t, pairResult.ModuleA)
			assert.NotEmpty(t, pairResult.VersionA)
			assert.NotEmpty(t, pairResult.ModuleB)
			assert.NotEmpty(t, pairResult.VersionB)
			assert.NotEqual(t, CompatibilityLevelUnknown, pairResult.CompatibilityLevel)
		}
	})

	t.Run("single module compatibility", func(t *testing.T) {
		moduleVersions := map[string]string{
			"module-a": "1.0.0",
		}

		report, err := matrix.CheckCrossModuleCompatibility(moduleVersions)
		require.NoError(t, err)
		assert.NotNil(t, report)

		assert.Equal(t, 1.0, report.CompatibilityScore) // Single module is always compatible
		assert.Equal(t, 0, len(report.DetailedResults)) // No pairs to analyze
	})

	t.Run("empty module set", func(t *testing.T) {
		moduleVersions := map[string]string{}

		report, err := matrix.CheckCrossModuleCompatibility(moduleVersions)
		require.NoError(t, err)
		assert.NotNil(t, report)

		assert.Equal(t, 1.0, report.CompatibilityScore) // Empty set is considered compatible
		assert.Equal(t, 0, len(report.DetailedResults))
	})
}

func TestDefaultCompatibilityMatrix_FindCompatibleVersionSet(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Register modules with multiple versions
	modules := map[string][]string{
		"module-a": {"1.0.0", "1.1.0", "1.2.0"},
		"module-b": {"2.0.0", "2.1.0"},
		"module-c": {"1.0.0", "2.0.0"},
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

	t.Run("find compatible version set", func(t *testing.T) {
		requirements := []ModuleVersionRequirement{
			{ModuleName: "module-a", Constraint: "^1.0.0"},
			{ModuleName: "module-b", Constraint: ">=2.0.0"},
			{ModuleName: "module-c", Constraint: "*"},
		}

		versionSet, err := matrix.FindCompatibleVersionSet(requirements)
		require.NoError(t, err)
		assert.NotNil(t, versionSet)

		assert.NotEmpty(t, versionSet.ID)
		assert.Equal(t, 3, len(versionSet.ModuleVersions))
		assert.False(t, versionSet.GenerationTime.IsZero())
		assert.GreaterOrEqual(t, versionSet.CompatibilityScore, 0.0)
		assert.LessOrEqual(t, versionSet.CompatibilityScore, 1.0)

		// Verify that selected versions satisfy constraints
		assert.Equal(t, "1.2.0", versionSet.ModuleVersions["module-a"])                       // Latest compatible
		assert.Equal(t, "2.1.0", versionSet.ModuleVersions["module-b"])                       // Latest compatible
		assert.Contains(t, []string{"1.0.0", "2.0.0"}, versionSet.ModuleVersions["module-c"]) // Any version
	})

	t.Run("impossible constraints", func(t *testing.T) {
		requirements := []ModuleVersionRequirement{
			{ModuleName: "non-existent", Constraint: "1.0.0"},
		}

		_, err := matrix.FindCompatibleVersionSet(requirements)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get compatible versions")
	})

	t.Run("no compatible versions", func(t *testing.T) {
		requirements := []ModuleVersionRequirement{
			{ModuleName: "module-a", Constraint: ">2.0.0"}, // No versions satisfy this
		}

		_, err := matrix.FindCompatibleVersionSet(requirements)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no compatible versions found")
	})
}

func TestDefaultCompatibilityMatrix_BreakingChangeAnalysis(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Register test versions
	metadata1 := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	metadata2 := &ModuleMetadata{
		Name:        "test-module",
		Version:     "2.0.0",
		Description: "Test module v2",
	}
	require.NoError(t, registry.RegisterVersion(metadata1))
	require.NoError(t, registry.RegisterVersion(metadata2))

	// Record breaking changes for v2.0.0
	breakingChanges := []BreakingChange{
		{
			Type:        BreakingChangeRemoval,
			Description: "Removed deprecated function oldFunc()",
			Severity:    SeverityHigh,
		},
		{
			Type:        BreakingChangeSignature,
			Description: "Changed function signature for newFunc()",
			Severity:    SeverityMedium,
		},
	}

	for _, change := range breakingChanges {
		require.NoError(t, matrix.RecordBreakingChange("test-module", "2.0.0", change))
	}

	t.Run("analyze breaking changes", func(t *testing.T) {
		analysis, err := matrix.AnalyzeBreakingChanges("test-module", "1.0.0", "2.0.0")
		require.NoError(t, err)
		assert.NotNil(t, analysis)

		assert.Equal(t, "test-module", analysis.ModuleName)
		assert.Equal(t, "1.0.0", analysis.FromVersion)
		assert.Equal(t, "2.0.0", analysis.ToVersion)
		assert.Equal(t, len(breakingChanges), len(analysis.BreakingChanges))
		assert.Equal(t, SeverityHigh, analysis.OverallSeverity) // Should be max severity
		assert.True(t, analysis.MigrationRequired)              // High severity requires migration
		assert.False(t, analysis.AnalysisTime.IsZero())
		assert.NotEmpty(t, analysis.MitigationSteps)

		// Verify mitigation steps were generated
		hasRemovalStep := false
		hasSignatureStep := false
		for _, step := range analysis.MitigationSteps {
			if contains(step, "remove") || contains(step, "removed") {
				hasRemovalStep = true
			}
			if contains(step, "signature") || contains(step, "calls") {
				hasSignatureStep = true
			}
		}
		assert.True(t, hasRemovalStep, "Should have mitigation step for removal")
		assert.True(t, hasSignatureStep, "Should have mitigation step for signature change")
	})

	t.Run("analyze no breaking changes", func(t *testing.T) {
		analysis, err := matrix.AnalyzeBreakingChanges("test-module", "1.0.0", "1.0.0")
		require.NoError(t, err)
		assert.NotNil(t, analysis)

		assert.Equal(t, 0, len(analysis.BreakingChanges))
		assert.Equal(t, SeverityLow, analysis.OverallSeverity)
		assert.False(t, analysis.MigrationRequired)
	})

	t.Run("analyze non-existent module", func(t *testing.T) {
		analysis, err := matrix.AnalyzeBreakingChanges("non-existent", "1.0.0", "2.0.0")
		require.NoError(t, err)
		assert.NotNil(t, analysis)

		// Should return empty analysis for non-existent module
		assert.Equal(t, 0, len(analysis.BreakingChanges))
		assert.Equal(t, SeverityLow, analysis.OverallSeverity)
	})
}

func TestDefaultCompatibilityMatrix_APIChanges(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Register test versions
	metadata := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.1.0",
		Description: "Test module",
	}
	require.NoError(t, registry.RegisterVersion(metadata))

	t.Run("record API changes", func(t *testing.T) {
		apiChanges := []APIChange{
			{
				Type:        APIChangeAddition,
				Method:      "newMethod",
				Description: "Added new convenience method",
			},
			{
				Type:        APIChangeDeprecation,
				Method:      "oldMethod",
				Description: "Deprecated old method",
			},
		}

		for _, change := range apiChanges {
			err := matrix.RecordAPIChange("test-module", "1.1.0", change)
			require.NoError(t, err)
		}

		// Retrieve API changes
		retrievedChanges, err := matrix.GetAPIChanges("test-module", "1.0.0", "1.1.0")
		require.NoError(t, err)
		assert.Equal(t, len(apiChanges), len(retrievedChanges))

		// Verify changes were recorded correctly
		assert.Equal(t, apiChanges[0].Type, retrievedChanges[0].Type)
		assert.Equal(t, apiChanges[0].Method, retrievedChanges[0].Method)
		assert.Equal(t, apiChanges[1].Type, retrievedChanges[1].Type)
		assert.Equal(t, apiChanges[1].Method, retrievedChanges[1].Method)
	})

	t.Run("get API changes for non-existent version", func(t *testing.T) {
		changes, err := matrix.GetAPIChanges("test-module", "1.0.0", "3.0.0")
		require.NoError(t, err)
		assert.Empty(t, changes)
	})

	t.Run("get API changes for non-existent module", func(t *testing.T) {
		changes, err := matrix.GetAPIChanges("non-existent", "1.0.0", "2.0.0")
		require.NoError(t, err)
		assert.Empty(t, changes)
	})
}

func TestDefaultCompatibilityMatrix_CompatibilityQueries(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Register test versions
	metadata := &ModuleMetadata{
		Name:        "test-module",
		Version:     "1.0.0",
		Description: "Test module",
	}
	require.NoError(t, registry.RegisterVersion(metadata))

	// Record compatibility with backwards and forwards compatible versions
	compatibility := &VersionCompatibilityInfo{
		BackwardsCompatible: []string{"0.9.0", "0.8.0"},
		ForwardsCompatible:  []string{"1.0.1", "1.1.0", "1.2.0"},
	}
	require.NoError(t, matrix.RecordCompatibility("test-module", "1.0.0", compatibility))

	t.Run("get backwards compatible versions", func(t *testing.T) {
		versions, err := matrix.GetBackwardsCompatibleVersions("test-module", "1.0.0")
		require.NoError(t, err)
		assert.Equal(t, compatibility.BackwardsCompatible, versions)
	})

	t.Run("get forwards compatible versions", func(t *testing.T) {
		versions, err := matrix.GetForwardsCompatibleVersions("test-module", "1.0.0")
		require.NoError(t, err)
		assert.Equal(t, compatibility.ForwardsCompatible, versions)
	})

	t.Run("get compatible versions for non-existent module", func(t *testing.T) {
		_, err := matrix.GetBackwardsCompatibleVersions("non-existent", "1.0.0")
		assert.Error(t, err)

		_, err = matrix.GetForwardsCompatibleVersions("non-existent", "1.0.0")
		assert.Error(t, err)
	})
}

func TestDefaultCompatibilityMatrix_IsCompatible(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Register test versions
	metadata1 := &ModuleMetadata{Name: "module-a", Version: "1.0.0", Description: "Test"}
	metadata2 := &ModuleMetadata{Name: "module-a", Version: "1.1.0", Description: "Test"}
	metadata3 := &ModuleMetadata{Name: "module-b", Version: "2.0.0", Description: "Test"}

	require.NoError(t, registry.RegisterVersion(metadata1))
	require.NoError(t, registry.RegisterVersion(metadata2))
	require.NoError(t, registry.RegisterVersion(metadata3))

	// Record compatibility for module-a v1.0.0
	compatibility := &VersionCompatibilityInfo{
		ForwardsCompatible: []string{"1.1.0"},
	}
	require.NoError(t, matrix.RecordCompatibility("module-a", "1.0.0", compatibility))

	tests := []struct {
		name         string
		moduleA      string
		versionA     string
		moduleB      string
		versionB     string
		expectCompat bool
		expectErr    bool
	}{
		{
			name:         "same module same version",
			moduleA:      "module-a",
			versionA:     "1.0.0",
			moduleB:      "module-a",
			versionB:     "1.0.0",
			expectCompat: true,
			expectErr:    false,
		},
		{
			name:         "same module compatible versions",
			moduleA:      "module-a",
			versionA:     "1.0.0",
			moduleB:      "module-a",
			versionB:     "1.1.0",
			expectCompat: true, // 1.1.0 is in forwards compatible list
			expectErr:    false,
		},
		{
			name:         "same module incompatible versions",
			moduleA:      "module-a",
			versionA:     "1.1.0",
			moduleB:      "module-a",
			versionB:     "1.0.0",
			expectCompat: false, // 1.0.0 is not in 1.1.0's compatibility list
			expectErr:    false,
		},
		{
			name:         "different modules",
			moduleA:      "module-a",
			versionA:     "1.0.0",
			moduleB:      "module-b",
			versionB:     "2.0.0",
			expectCompat: true, // Cross-module compatibility defaults to compatible with warning
			expectErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatible, err := matrix.IsCompatible(tt.moduleA, tt.versionA, tt.moduleB, tt.versionB)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectCompat, compatible)
			}
		})
	}
}

func TestDefaultCompatibilityMatrix_GetMatrixStatus(t *testing.T) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	t.Run("empty matrix status", func(t *testing.T) {
		status := matrix.GetMatrixStatus()
		assert.NotNil(t, status)

		assert.Equal(t, 0, status.TotalModules)
		assert.Equal(t, 0, status.TotalVersions)
		assert.Equal(t, 0, status.CoveredPairs)
		assert.Equal(t, 0, status.VerifiedPairs)
		assert.Equal(t, 0, status.KnownIncompatibilities)
		assert.Equal(t, 100.0, status.MatrixCompleteness)
		assert.False(t, status.LastUpdated.IsZero())
	})

	t.Run("populated matrix status", func(t *testing.T) {
		// Register modules and record compatibility
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

			compatibility := &VersionCompatibilityInfo{
				BackwardsCompatible: []string{},
				ForwardsCompatible:  []string{},
			}
			require.NoError(t, matrix.RecordCompatibility(module.name, module.version, compatibility))
		}

		status := matrix.GetMatrixStatus()
		assert.NotNil(t, status)

		assert.Equal(t, 2, status.TotalModules)  // module-a and module-b
		assert.Equal(t, 3, status.TotalVersions) // 2 versions of module-a + 1 version of module-b
		assert.GreaterOrEqual(t, status.MatrixCompleteness, 0.0)
		assert.LessOrEqual(t, status.MatrixCompleteness, 100.0)
	})
}

func TestCompatibilityStatus_String(t *testing.T) {
	tests := []struct {
		status   CompatibilityStatus
		expected string
	}{
		{CompatibilityStatusUnknown, "unknown"},
		{CompatibilityStatusCompatible, "compatible"},
		{CompatibilityStatusPartiallyCompatible, "partially_compatible"},
		{CompatibilityStatusIncompatible, "incompatible"},
		{CompatibilityStatusConflicting, "conflicting"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestCompatibilityIssueType_String(t *testing.T) {
	tests := []struct {
		issueType CompatibilityIssueType
		expected  string
	}{
		{IssueTypeBreakingChange, "breaking_change"},
		{IssueTypeAPIIncompatibility, "api_incompatibility"},
		{IssueTypeVersionConflict, "version_conflict"},
		{IssueTypeDependencyMismatch, "dependency_mismatch"},
		{IssueTypeUnsupportedFeature, "unsupported_feature"},
		{IssueTypePerformanceDegradation, "performance_degradation"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.issueType.String())
		})
	}
}

func TestCompatibilityLevel_String(t *testing.T) {
	tests := []struct {
		level    CompatibilityLevel
		expected string
	}{
		{CompatibilityLevelUnknown, "unknown"},
		{CompatibilityLevelFullyCompatible, "fully_compatible"},
		{CompatibilityLevelBackwardsCompatible, "backwards_compatible"},
		{CompatibilityLevelForwardsCompatible, "forwards_compatible"},
		{CompatibilityLevelPartiallyCompatible, "partially_compatible"},
		{CompatibilityLevelIncompatible, "incompatible"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.level.String())
		})
	}
}

func TestBreakingChangeType_String(t *testing.T) {
	tests := []struct {
		changeType BreakingChangeType
		expected   string
	}{
		{BreakingChangeRemoval, "removal"},
		{BreakingChangeModification, "modification"},
		{BreakingChangeSignature, "signature"},
		{BreakingChangeBehavior, "behavior"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.changeType.String())
		})
	}
}

func TestAPIChangeType_String(t *testing.T) {
	tests := []struct {
		changeType APIChangeType
		expected   string
	}{
		{APIChangeAddition, "addition"},
		{APIChangeDeprecation, "deprecation"},
		{APIChangeModification, "modification"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.changeType.String())
		})
	}
}

func TestChangeSeverity_String(t *testing.T) {
	tests := []struct {
		severity ChangeSeverity
		expected string
	}{
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.severity.String())
		})
	}
}

// Benchmark tests for performance
func BenchmarkCompatibilityMatrix_RecordCompatibility(b *testing.B) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Pre-register modules
	for i := 0; i < 100; i++ {
		metadata := &ModuleMetadata{
			Name:        fmt.Sprintf("bench-module-%d", i),
			Version:     "1.0.0",
			Description: "Benchmark module",
		}
		_ = registry.RegisterVersion(metadata) // Ignore error in test setup
	}

	compatibility := &VersionCompatibilityInfo{
		BackwardsCompatible: []string{"0.9.0"},
		ForwardsCompatible:  []string{"1.0.1", "1.1.0"},
		MigrationRequired:   false,
		MigrationComplexity: MigrationComplexityLow,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		moduleName := fmt.Sprintf("bench-module-%d", i%100)
		_ = matrix.RecordCompatibility(moduleName, "1.0.0", compatibility) // Ignore error in test setup
	}
}

func BenchmarkCompatibilityMatrix_CheckCrossModuleCompatibility(b *testing.B) {
	registry := NewDefaultModuleVersionRegistry()
	matrix := NewDefaultCompatibilityMatrix(registry)

	// Pre-populate with modules
	moduleVersions := make(map[string]string)
	for i := 0; i < 10; i++ {
		moduleName := fmt.Sprintf("bench-module-%d", i)
		metadata := &ModuleMetadata{
			Name:        moduleName,
			Version:     "1.0.0",
			Description: "Benchmark module",
		}
		_ = registry.RegisterVersion(metadata) // Ignore error in test setup

		compatibility := &VersionCompatibilityInfo{
			BackwardsCompatible: []string{},
			ForwardsCompatible:  []string{},
			MigrationRequired:   false,
		}
		_ = matrix.RecordCompatibility(moduleName, "1.0.0", compatibility) // Ignore error in test setup

		moduleVersions[moduleName] = "1.0.0"
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = matrix.CheckCrossModuleCompatibility(moduleVersions) // Ignore error in test
	}
}
