// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSemanticVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected *SemanticVersion
		hasError bool
	}{
		{
			name:    "basic version",
			version: "1.2.3",
			expected: &SemanticVersion{
				Major: 1,
				Minor: 2,
				Patch: 3,
			},
		},
		{
			name:    "version with pre-release",
			version: "1.2.3-alpha.1",
			expected: &SemanticVersion{
				Major:      1,
				Minor:      2,
				Patch:      3,
				PreRelease: "alpha.1",
			},
		},
		{
			name:    "version with build metadata",
			version: "1.2.3+build.123",
			expected: &SemanticVersion{
				Major:     1,
				Minor:     2,
				Patch:     3,
				BuildMeta: "build.123",
			},
		},
		{
			name:    "version with pre-release and build metadata",
			version: "1.2.3-beta.2+build.456",
			expected: &SemanticVersion{
				Major:      1,
				Minor:      2,
				Patch:      3,
				PreRelease: "beta.2",
				BuildMeta:  "build.456",
			},
		},
		{
			name:     "invalid version",
			version:  "invalid",
			hasError: true,
		},
		{
			name:     "incomplete version",
			version:  "1.2",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSemanticVersion(tt.version)

			if tt.hasError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestSemanticVersionString(t *testing.T) {
	tests := []struct {
		name     string
		version  SemanticVersion
		expected string
	}{
		{
			name: "basic version",
			version: SemanticVersion{
				Major: 1,
				Minor: 2,
				Patch: 3,
			},
			expected: "1.2.3",
		},
		{
			name: "version with pre-release",
			version: SemanticVersion{
				Major:      1,
				Minor:      2,
				Patch:      3,
				PreRelease: "alpha.1",
			},
			expected: "1.2.3-alpha.1",
		},
		{
			name: "version with build metadata",
			version: SemanticVersion{
				Major:     1,
				Minor:     2,
				Patch:     3,
				BuildMeta: "build.123",
			},
			expected: "1.2.3+build.123",
		},
		{
			name: "version with pre-release and build metadata",
			version: SemanticVersion{
				Major:      1,
				Minor:      2,
				Patch:      3,
				PreRelease: "beta.2",
				BuildMeta:  "build.456",
			},
			expected: "1.2.3-beta.2+build.456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.version.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSemanticVersionCompare(t *testing.T) {
	tests := []struct {
		name     string
		version1 SemanticVersion
		version2 SemanticVersion
		expected int
	}{
		{
			name:     "equal versions",
			version1: SemanticVersion{1, 2, 3, "", ""},
			version2: SemanticVersion{1, 2, 3, "", ""},
			expected: 0,
		},
		{
			name:     "major version difference",
			version1: SemanticVersion{1, 2, 3, "", ""},
			version2: SemanticVersion{2, 0, 0, "", ""},
			expected: -1,
		},
		{
			name:     "minor version difference",
			version1: SemanticVersion{1, 3, 0, "", ""},
			version2: SemanticVersion{1, 2, 5, "", ""},
			expected: 1,
		},
		{
			name:     "patch version difference",
			version1: SemanticVersion{1, 2, 3, "", ""},
			version2: SemanticVersion{1, 2, 4, "", ""},
			expected: -1,
		},
		{
			name:     "pre-release vs normal",
			version1: SemanticVersion{1, 2, 3, "alpha", ""},
			version2: SemanticVersion{1, 2, 3, "", ""},
			expected: -1,
		},
		{
			name:     "pre-release comparison",
			version1: SemanticVersion{1, 2, 3, "alpha", ""},
			version2: SemanticVersion{1, 2, 3, "beta", ""},
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.version1.Compare(tt.version2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSemanticVersionIsCompatible(t *testing.T) {
	tests := []struct {
		name     string
		version1 SemanticVersion
		version2 SemanticVersion
		expected bool
	}{
		{
			name:     "same version",
			version1: SemanticVersion{1, 2, 3, "", ""},
			version2: SemanticVersion{1, 2, 3, "", ""},
			expected: true,
		},
		{
			name:     "compatible minor upgrade",
			version1: SemanticVersion{1, 3, 0, "", ""},
			version2: SemanticVersion{1, 2, 0, "", ""},
			expected: true,
		},
		{
			name:     "compatible patch upgrade",
			version1: SemanticVersion{1, 2, 4, "", ""},
			version2: SemanticVersion{1, 2, 3, "", ""},
			expected: true,
		},
		{
			name:     "incompatible major version",
			version1: SemanticVersion{2, 0, 0, "", ""},
			version2: SemanticVersion{1, 9, 9, "", ""},
			expected: false,
		},
		{
			name:     "incompatible downgrade",
			version1: SemanticVersion{1, 2, 0, "", ""},
			version2: SemanticVersion{1, 3, 0, "", ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.version1.IsCompatible(tt.version2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSemanticVersionNext(t *testing.T) {
	baseVersion := SemanticVersion{1, 2, 3, "", ""}

	t.Run("next major", func(t *testing.T) {
		next := baseVersion.NextMajor()
		expected := SemanticVersion{2, 0, 0, "", ""}
		assert.Equal(t, expected, next)
	})

	t.Run("next minor", func(t *testing.T) {
		next := baseVersion.NextMinor()
		expected := SemanticVersion{1, 3, 0, "", ""}
		assert.Equal(t, expected, next)
	})

	t.Run("next patch", func(t *testing.T) {
		next := baseVersion.NextPatch()
		expected := SemanticVersion{1, 2, 4, "", ""}
		assert.Equal(t, expected, next)
	})
}

func TestParseVersionRange(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *VersionRange
		hasError bool
	}{
		{
			name:  "exact version",
			input: "1.2.3",
			expected: &VersionRange{
				Exact: &SemanticVersion{1, 2, 3, "", ""},
			},
		},
		{
			name:  "minimum version",
			input: ">=1.2.0",
			expected: &VersionRange{
				Min:        &SemanticVersion{1, 2, 0, "", ""},
				IncludeMin: true,
				IncludeMax: false,
			},
		},
		{
			name:  "range",
			input: ">=1.2.0,<2.0.0",
			expected: &VersionRange{
				Min:        &SemanticVersion{1, 2, 0, "", ""},
				Max:        &SemanticVersion{2, 0, 0, "", ""},
				IncludeMin: true,
				IncludeMax: false,
			},
		},
		{
			name:     "invalid version in range",
			input:    ">=invalid",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseVersionRange(tt.input)

			if tt.hasError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestVersionRangeSatisfies(t *testing.T) {
	tests := []struct {
		name     string
		vrange   *VersionRange
		version  SemanticVersion
		expected bool
	}{
		{
			name: "exact match",
			vrange: &VersionRange{
				Exact: &SemanticVersion{1, 2, 3, "", ""},
			},
			version:  SemanticVersion{1, 2, 3, "", ""},
			expected: true,
		},
		{
			name: "exact no match",
			vrange: &VersionRange{
				Exact: &SemanticVersion{1, 2, 3, "", ""},
			},
			version:  SemanticVersion{1, 2, 4, "", ""},
			expected: false,
		},
		{
			name: "minimum satisfied",
			vrange: &VersionRange{
				Min:        &SemanticVersion{1, 2, 0, "", ""},
				IncludeMin: true,
			},
			version:  SemanticVersion{1, 2, 3, "", ""},
			expected: true,
		},
		{
			name: "minimum not satisfied",
			vrange: &VersionRange{
				Min:        &SemanticVersion{1, 2, 0, "", ""},
				IncludeMin: true,
			},
			version:  SemanticVersion{1, 1, 9, "", ""},
			expected: false,
		},
		{
			name: "range satisfied",
			vrange: &VersionRange{
				Min:        &SemanticVersion{1, 0, 0, "", ""},
				Max:        &SemanticVersion{2, 0, 0, "", ""},
				IncludeMin: true,
				IncludeMax: false,
			},
			version:  SemanticVersion{1, 5, 0, "", ""},
			expected: true,
		},
		{
			name: "range not satisfied (too high)",
			vrange: &VersionRange{
				Min:        &SemanticVersion{1, 0, 0, "", ""},
				Max:        &SemanticVersion{2, 0, 0, "", ""},
				IncludeMin: true,
				IncludeMax: false,
			},
			version:  SemanticVersion{2, 0, 0, "", ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.vrange.Satisfies(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateVersionUpgrade(t *testing.T) {
	tests := []struct {
		name     string
		from     SemanticVersion
		to       SemanticVersion
		hasError bool
	}{
		{
			name:     "valid patch upgrade",
			from:     SemanticVersion{1, 2, 3, "", ""},
			to:       SemanticVersion{1, 2, 4, "", ""},
			hasError: false,
		},
		{
			name:     "valid minor upgrade",
			from:     SemanticVersion{1, 2, 3, "", ""},
			to:       SemanticVersion{1, 3, 0, "", ""},
			hasError: false,
		},
		{
			name:     "valid major upgrade",
			from:     SemanticVersion{1, 2, 3, "", ""},
			to:       SemanticVersion{2, 0, 0, "", ""},
			hasError: false,
		},
		{
			name:     "invalid downgrade",
			from:     SemanticVersion{1, 2, 3, "", ""},
			to:       SemanticVersion{1, 2, 2, "", ""},
			hasError: true,
		},
		{
			name:     "invalid same version",
			from:     SemanticVersion{1, 2, 3, "", ""},
			to:       SemanticVersion{1, 2, 3, "", ""},
			hasError: true,
		},
		{
			name:     "invalid minor upgrade with non-zero patch",
			from:     SemanticVersion{1, 2, 3, "", ""},
			to:       SemanticVersion{1, 3, 1, "", ""},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateVersionUpgrade(tt.from, tt.to)

			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
