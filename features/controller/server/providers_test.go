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
