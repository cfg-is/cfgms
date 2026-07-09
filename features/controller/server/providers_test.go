// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package server test-only provider registrations.
// The concrete flatfile import is confined to this allowlisted */providers_test.go
// path (see scripts/check-providers.sh).
package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	memoryprovider "github.com/cfgis/cfgms/pkg/storage/providers/memory"
)

// newFlatFileStewardStore returns a real flat-file StewardStore rooted at a
// t.TempDir() (no external infrastructure required). The concrete flatfile
// import is confined to this allowlisted */providers_test.go path (see
// scripts/check-providers.sh).
func newFlatFileStewardStore(t *testing.T) business.StewardStore {
	t.Helper()
	st, err := flatfile.NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err, "creating flat-file steward store")
	return st
}

// requireInMemoryUpgradeStore asserts that store is the in-memory fallback
// UpgradeStore. The concrete memoryprovider import is confined to this
// allowlisted */providers_test.go path (see scripts/check-providers.sh) so that
// business-logic tests depend on pkg/storage/interfaces only.
func requireInMemoryUpgradeStore(t *testing.T, store business.UpgradeStore, msgAndArgs ...interface{}) {
	t.Helper()
	require.IsType(t, (*memoryprovider.UpgradeStore)(nil), store, msgAndArgs...)
}
