// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type versionCase struct {
	a, b string
	want int
}

func runVersionCases(t *testing.T, cmp func(a, b string) (int, error), cases []versionCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.a+" vs "+c.b, func(t *testing.T) {
			got, err := cmp(c.a, c.b)
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
			// Ordering must be antisymmetric.
			rev, err := cmp(c.b, c.a)
			require.NoError(t, err)
			assert.Equal(t, -c.want, rev)
		})
	}
}

func TestCompareDebianVersions(t *testing.T) {
	runVersionCases(t, compareDebianVersions, []versionCase{
		{"1:2.0-1", "2.1-1", 1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"8.7.1-1", "8.7.1-1ubuntu0.1", -1},
		{"1.10", "1.9", 1},
		{"1.0-1", "1.0-1", 0},
		{"1:1.0", "1:1.0", 0},
		{"1.0", "1.0-0", 0},
		{"1.0~~", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0+b1", "1.0", 1},
		{"1.0a", "1.0+", -1},
		{"1.002", "1.2", 0},
		{"2.0-1", "10.0-1", -1},
		{"1.0-1-2", "1.0-1-3", -1},
	})
}

func TestCompareDebianVersions_Errors(t *testing.T) {
	for _, bad := range []string{"", "  ", "x:1.0", ":1.0", "1:"} {
		_, err := compareDebianVersions(bad, "1.0")
		require.ErrorIs(t, err, ErrUnparseableVersion, "installed %q", bad)
		_, err = compareDebianVersions("1.0", bad)
		require.ErrorIs(t, err, ErrUnparseableVersion, "declared %q", bad)
	}
}

func TestCompareRPMVersions(t *testing.T) {
	runVersionCases(t, compareRPMVersions, []versionCase{
		{"7.76.1", "7.9", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0^post", "1.0", 1},
		{"1.0", "1.0", 0},
		{"1.0^post", "1.0.1", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0", "1.0.0", -1},
		{"1.01", "1.1", 0},
		{"1.0a", "1.0", 1},
		{"1.0a", "1.0.1", -1},
		{"1.0", "1.0a", -1},
		{"10", "9", 1},
		{"1.0_1", "1.0.1", 0},
		{"1.0^1", "1.0^2", -1},
		{"1.0~", "1.0^", -1},
		{"a", "1", -1},
	})
}

func TestCompareRPMVersions_Errors(t *testing.T) {
	_, err := compareRPMVersions("", "1.0")
	require.ErrorIs(t, err, ErrUnparseableVersion)
	_, err = compareRPMVersions("1.0", " ")
	require.ErrorIs(t, err, ErrUnparseableVersion)
}
