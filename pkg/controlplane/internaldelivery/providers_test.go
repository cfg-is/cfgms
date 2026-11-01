// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package internaldelivery test-only provider registrations.
// The concrete flatfile import is confined to this allowlisted */providers_test.go
// path (see scripts/check-providers.sh).
package internaldelivery

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// Compile-time documentation that business.RoutingStore is the seam
// ClusterAwareSender consults — asserted here rather than relying on an
// import-only reference. The concrete flatfile import is confined to this
// allowlisted */providers_test.go path (see scripts/check-providers.sh).
var _ business.RoutingStore = (*flatfile.FlatFileRoutingStore)(nil)

// newFlatFileRoutingStore returns a real flat-file RoutingStore rooted at a
// t.TempDir(). The concrete flatfile import is confined to this allowlisted
// */providers_test.go path (see scripts/check-providers.sh).
func newFlatFileRoutingStore(t *testing.T) business.RoutingStore {
	t.Helper()
	st, err := flatfile.NewFlatFileRoutingStore(t.TempDir())
	require.NoError(t, err, "creating flat-file routing store")
	return st
}
