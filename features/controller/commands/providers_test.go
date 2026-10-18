// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// newTestStewardStore returns a real flat-file StewardStore rooted at a t.TempDir()
// and that root. Two controller nodes sharing it model a cluster sharing the steward
// store. The concrete flatfile import is confined to this allowlisted
// */providers_test.go path (see scripts/check-providers.sh).
func newTestStewardStore(t *testing.T) (business.StewardStore, string) {
	t.Helper()
	root := t.TempDir()
	st, err := flatfile.NewFlatFileStewardStore(root)
	require.NoError(t, err)
	return st, root
}
