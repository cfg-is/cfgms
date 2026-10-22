// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package clusterregistry test-only provider construction.
// The concrete flatfile import is confined to this allowlisted */providers_test.go
// path (see scripts/check-providers.sh).
package clusterregistry

import (
	"testing"

	"github.com/stretchr/testify/require"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// newFlatFileConfigStore returns a real flatfile-backed ConfigStore rooted in
// a per-test temp directory (no mocks).
func newFlatFileConfigStore(t *testing.T) cfgconfig.ConfigStore {
	t.Helper()
	cs, err := flatfile.NewFlatFileConfigStore(t.TempDir())
	require.NoError(t, err)
	return cs
}
