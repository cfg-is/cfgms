// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package version

import (
	"errors"
	"testing"
)

func TestCompareSemantic(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{name: "major", a: "v2.0.0", b: "v1.9.9", want: 1},
		{name: "minor", a: "1.10.0", b: "1.9.99", want: 1},
		{name: "patch", a: "1.0.10", b: "1.0.9", want: 1},
		{name: "equal with prefix", a: "v1.2.3", b: "1.2.3", want: 0},
		{name: "build metadata ignored", a: "1.2.3+one", b: "1.2.3+two", want: 0},
		{name: "release after prerelease", a: "1.0.0", b: "1.0.0-rc.1", want: 1},
		{name: "prerelease before release", a: "1.0.0-rc.1", b: "1.0.0", want: -1},
		{name: "numeric prerelease", a: "1.0.0-rc.10", b: "1.0.0-rc.2", want: 1},
		{name: "numeric lower than text", a: "1.0.0-1", b: "1.0.0-alpha", want: -1},
		{name: "shorter prerelease", a: "1.0.0-alpha", b: "1.0.0-alpha.1", want: -1},
		{name: "large component", a: "999999999999999999999.0.0", b: "2.0.0", want: 1},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := CompareSemantic(tt.a, tt.b)
			if err != nil {
				t.Fatalf("CompareSemantic(%q, %q): %v", tt.a, tt.b, err)
			}
			if got != tt.want {
				t.Fatalf("CompareSemantic(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareSemanticRejectsInvalidVersions(t *testing.T) {
	t.Parallel()
	invalid := []string{
		"",
		"v",
		"1",
		"1.2",
		"1.2.3.4",
		"01.2.3",
		"1.02.3",
		"1.2.03",
		"1.2.3-01",
		"1.2.3-alpha..1",
		"vv1.2.3",
		"1.2.3/",
	}
	for _, candidate := range invalid {
		candidate := candidate
		t.Run(candidate, func(t *testing.T) {
			t.Parallel()
			_, err := CompareSemantic(candidate, "1.0.0")
			if !errors.Is(err, ErrInvalidSemanticVersion) {
				t.Fatalf("CompareSemantic(%q, 1.0.0) error = %v, want ErrInvalidSemanticVersion", candidate, err)
			}
			if IsSemantic(candidate) {
				t.Fatalf("IsSemantic(%q) = true", candidate)
			}
		})
	}
}
