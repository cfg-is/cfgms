// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package modules

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expected    *SemanticVersion
		expectError bool
	}{
		{
			name:    "basic version",
			version: "1.2.3",
			expected: &SemanticVersion{
				Major: 1,
				Minor: 2,
				Patch: 3,
			},
			expectError: false,
		},
		{
			name:    "version with v prefix",
			version: "v1.2.3",
			expected: &SemanticVersion{
				Major: 1,
				Minor: 2,
				Patch: 3,
			},
			expectError: false,
		},
		{
			name:    "version with prerelease",
			version: "1.2.3-alpha.1",
			expected: &SemanticVersion{
				Major:      1,
				Minor:      2,
				Patch:      3,
				PreRelease: "alpha.1",
			},
			expectError: false,
		},
		{
			name:    "version with build",
			version: "1.2.3+build.123",
			expected: &SemanticVersion{
				Major: 1,
				Minor: 2,
				Patch: 3,
				Build: "build.123",
			},
			expectError: false,
		},
		{
			name:    "version with prerelease and build",
			version: "1.2.3-alpha.1+build.123",
			expected: &SemanticVersion{
				Major:      1,
				Minor:      2,
				Patch:      3,
				PreRelease: "alpha.1",
				Build:      "build.123",
			},
			expectError: false,
		},
		{
			name:        "empty version",
			version:     "",
			expectError: true,
		},
		{
			name:        "invalid format",
			version:     "1.2",
			expectError: true,
		},
		{
			name:        "non-numeric major",
			version:     "a.2.3",
			expectError: true,
		},
		{
			name:        "non-numeric minor",
			version:     "1.b.3",
			expectError: true,
		},
		{
			name:        "non-numeric patch",
			version:     "1.2.c",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseVersion(tt.version)

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

			if result.Major != tt.expected.Major {
				t.Errorf("Major = %v, expected %v", result.Major, tt.expected.Major)
			}
			if result.Minor != tt.expected.Minor {
				t.Errorf("Minor = %v, expected %v", result.Minor, tt.expected.Minor)
			}
			if result.Patch != tt.expected.Patch {
				t.Errorf("Patch = %v, expected %v", result.Patch, tt.expected.Patch)
			}
			if result.PreRelease != tt.expected.PreRelease {
				t.Errorf("PreRelease = %v, expected %v", result.PreRelease, tt.expected.PreRelease)
			}
			if result.Build != tt.expected.Build {
				t.Errorf("Build = %v, expected %v", result.Build, tt.expected.Build)
			}
		})
	}
}

func TestSemanticVersion_String(t *testing.T) {
	tests := []struct {
		name     string
		version  *SemanticVersion
		expected string
	}{
		{
			name:     "basic version",
			version:  &SemanticVersion{Major: 1, Minor: 2, Patch: 3},
			expected: "1.2.3",
		},
		{
			name:     "version with prerelease",
			version:  &SemanticVersion{Major: 1, Minor: 2, Patch: 3, PreRelease: "alpha.1"},
			expected: "1.2.3-alpha.1",
		},
		{
			name:     "version with build",
			version:  &SemanticVersion{Major: 1, Minor: 2, Patch: 3, Build: "build.123"},
			expected: "1.2.3+build.123",
		},
		{
			name:     "version with prerelease and build",
			version:  &SemanticVersion{Major: 1, Minor: 2, Patch: 3, PreRelease: "alpha.1", Build: "build.123"},
			expected: "1.2.3-alpha.1+build.123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.version.String()
			if result != tt.expected {
				t.Errorf("String() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestSemanticVersion_Compare(t *testing.T) {
	tests := []struct {
		name     string
		v1       *SemanticVersion
		v2       *SemanticVersion
		expected int
	}{
		{
			name:     "equal versions",
			v1:       &SemanticVersion{Major: 1, Minor: 2, Patch: 3},
			v2:       &SemanticVersion{Major: 1, Minor: 2, Patch: 3},
			expected: 0,
		},
		{
			name:     "v1 greater major",
			v1:       &SemanticVersion{Major: 2, Minor: 0, Patch: 0},
			v2:       &SemanticVersion{Major: 1, Minor: 9, Patch: 9},
			expected: 1,
		},
		{
			name:     "v1 lesser major",
			v1:       &SemanticVersion{Major: 1, Minor: 9, Patch: 9},
			v2:       &SemanticVersion{Major: 2, Minor: 0, Patch: 0},
			expected: -1,
		},
		{
			name:     "v1 greater minor",
			v1:       &SemanticVersion{Major: 1, Minor: 3, Patch: 0},
			v2:       &SemanticVersion{Major: 1, Minor: 2, Patch: 9},
			expected: 1,
		},
		{
			name:     "v1 lesser minor",
			v1:       &SemanticVersion{Major: 1, Minor: 2, Patch: 9},
			v2:       &SemanticVersion{Major: 1, Minor: 3, Patch: 0},
			expected: -1,
		},
		{
			name:     "v1 greater patch",
			v1:       &SemanticVersion{Major: 1, Minor: 2, Patch: 4},
			v2:       &SemanticVersion{Major: 1, Minor: 2, Patch: 3},
			expected: 1,
		},
		{
			name:     "v1 lesser patch",
			v1:       &SemanticVersion{Major: 1, Minor: 2, Patch: 3},
			v2:       &SemanticVersion{Major: 1, Minor: 2, Patch: 4},
			expected: -1,
		},
		{
			name:     "prerelease vs release",
			v1:       &SemanticVersion{Major: 1, Minor: 2, Patch: 3, PreRelease: "alpha.1"},
			v2:       &SemanticVersion{Major: 1, Minor: 2, Patch: 3},
			expected: -1,
		},
		{
			name:     "release vs prerelease",
			v1:       &SemanticVersion{Major: 1, Minor: 2, Patch: 3},
			v2:       &SemanticVersion{Major: 1, Minor: 2, Patch: 3, PreRelease: "alpha.1"},
			expected: 1,
		},
		{
			name:     "prerelease comparison",
			v1:       &SemanticVersion{Major: 1, Minor: 2, Patch: 3, PreRelease: "beta.1"},
			v2:       &SemanticVersion{Major: 1, Minor: 2, Patch: 3, PreRelease: "alpha.1"},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.v1.Compare(tt.v2)
			if result != tt.expected {
				t.Errorf("Compare() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsVersionCompatible(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		constraint  string
		expected    bool
		expectError bool
	}{
		// Exact version matching
		{
			name:       "exact match",
			version:    "1.2.3",
			constraint: "1.2.3",
			expected:   true,
		},
		{
			name:       "exact mismatch",
			version:    "1.2.4",
			constraint: "1.2.3",
			expected:   false,
		},

		// Wildcard
		{
			name:       "wildcard",
			version:    "1.2.3",
			constraint: "*",
			expected:   true,
		},
		{
			name:       "empty constraint",
			version:    "1.2.3",
			constraint: "",
			expected:   true,
		},

		// Greater than or equal
		{
			name:       ">=1.2.0 satisfied",
			version:    "1.2.3",
			constraint: ">=1.2.0",
			expected:   true,
		},
		{
			name:       ">=1.2.0 not satisfied",
			version:    "1.1.9",
			constraint: ">=1.2.0",
			expected:   false,
		},
		{
			name:       ">=1.2.0 equal",
			version:    "1.2.0",
			constraint: ">=1.2.0",
			expected:   true,
		},

		// Greater than
		{
			name:       ">1.2.0 satisfied",
			version:    "1.2.1",
			constraint: ">1.2.0",
			expected:   true,
		},
		{
			name:       ">1.2.0 equal",
			version:    "1.2.0",
			constraint: ">1.2.0",
			expected:   false,
		},

		// Less than or equal
		{
			name:       "<=1.2.0 satisfied",
			version:    "1.1.9",
			constraint: "<=1.2.0",
			expected:   true,
		},
		{
			name:       "<=1.2.0 not satisfied",
			version:    "1.2.1",
			constraint: "<=1.2.0",
			expected:   false,
		},
		{
			name:       "<=1.2.0 equal",
			version:    "1.2.0",
			constraint: "<=1.2.0",
			expected:   true,
		},

		// Less than
		{
			name:       "<1.2.0 satisfied",
			version:    "1.1.9",
			constraint: "<1.2.0",
			expected:   true,
		},
		{
			name:       "<1.2.0 equal",
			version:    "1.2.0",
			constraint: "<1.2.0",
			expected:   false,
		},

		// Tilde constraints (compatible within minor version)
		{
			name:       "~1.2.0 patch update",
			version:    "1.2.5",
			constraint: "~1.2.0",
			expected:   true,
		},
		{
			name:       "~1.2.0 minor update",
			version:    "1.3.0",
			constraint: "~1.2.0",
			expected:   false,
		},
		{
			name:       "~1.2.0 major update",
			version:    "2.0.0",
			constraint: "~1.2.0",
			expected:   false,
		},
		{
			name:       "~1.2.0 exact",
			version:    "1.2.0",
			constraint: "~1.2.0",
			expected:   true,
		},
		{
			name:       "~1.2.0 older patch",
			version:    "1.1.9",
			constraint: "~1.2.0",
			expected:   false,
		},

		// Caret constraints (compatible within major version)
		{
			name:       "^1.2.0 patch update",
			version:    "1.2.5",
			constraint: "^1.2.0",
			expected:   true,
		},
		{
			name:       "^1.2.0 minor update",
			version:    "1.3.0",
			constraint: "^1.2.0",
			expected:   true,
		},
		{
			name:       "^1.2.0 major update",
			version:    "2.0.0",
			constraint: "^1.2.0",
			expected:   false,
		},
		{
			name:       "^1.2.0 exact",
			version:    "1.2.0",
			constraint: "^1.2.0",
			expected:   true,
		},
		{
			name:       "^1.2.0 older minor",
			version:    "1.1.9",
			constraint: "^1.2.0",
			expected:   false,
		},

		// Error cases
		{
			name:        "invalid version",
			version:     "invalid",
			constraint:  "1.0.0",
			expectError: true,
		},
		{
			name:        "invalid constraint version",
			version:     "1.0.0",
			constraint:  ">=invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := IsVersionCompatible(tt.version, tt.constraint)

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

			if result != tt.expected {
				t.Errorf("IsVersionCompatible(%q, %q) = %v, expected %v", tt.version, tt.constraint, result, tt.expected)
			}
		})
	}
}

// Benchmark tests for performance validation
func BenchmarkParseVersion(b *testing.B) {
	version := "1.2.3-alpha.1+build.123"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseVersion(version)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkSemanticVersion_Compare(b *testing.B) {
	v1 := &SemanticVersion{Major: 1, Minor: 2, Patch: 3}
	v2 := &SemanticVersion{Major: 1, Minor: 2, Patch: 4}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v1.Compare(v2)
	}
}

func BenchmarkIsVersionCompatible(b *testing.B) {
	version := "1.2.3"
	constraint := "^1.0.0"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := IsVersionCompatible(version, constraint)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
