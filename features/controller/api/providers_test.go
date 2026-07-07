// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package api test-only provider registrations.
// The blank import triggers init() to register the filesystem blob provider so that
// handlers_installer_test.go can use blob.CreateBlobStoreFromConfig("filesystem", ...).
// newTestAPIBatchJobStore is defined here so that the concrete memory-provider import
// is confined to the allowlisted */providers_test.go path (see scripts/check-providers.sh).
package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/blobstore/filesystem" // register filesystem blob provider for installer tests
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	"github.com/cfgis/cfgms/pkg/storage/providers/memory"

	"github.com/cfgis/cfgms/features/controller/batchjob"
)

// newTestAPIBatchJobStore returns a memory-backed BatchJobStore for handler tests.
func newTestAPIBatchJobStore() batchjob.BatchJobStore {
	return memory.NewBatchJobStore()
}

// newTestStewardDurableStore returns a real flat-file StewardStore rooted at a
// t.TempDir() (no external infrastructure required) along with its backing root
// directory. Tests that need to induce a genuine durable-store write failure use
// the returned root to toggle directory permissions. The concrete flatfile import
// is confined to this allowlisted */providers_test.go path (see scripts/check-providers.sh).
func newTestStewardDurableStore(t *testing.T) (business.StewardStore, string) {
	t.Helper()
	root := t.TempDir()
	st, err := flatfile.NewFlatFileStewardStore(root)
	require.NoError(t, err, "creating flat-file steward store")
	return st, root
}
