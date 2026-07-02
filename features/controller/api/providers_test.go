// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package api test-only provider registrations.
// The blank import triggers init() to register the filesystem blob provider so that
// handlers_installer_test.go can use blob.CreateBlobStoreFromConfig("filesystem", ...).
// newTestAPIBatchJobStore is defined here so that the concrete memory-provider import
// is confined to the allowlisted */providers_test.go path (see scripts/check-providers.sh).
package api

import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/blobstore/filesystem" // register filesystem blob provider for installer tests
	"github.com/cfgis/cfgms/pkg/storage/providers/memory"

	"github.com/cfgis/cfgms/features/controller/batchjob"
)

// newTestAPIBatchJobStore returns a memory-backed BatchJobStore for handler tests.
func newTestAPIBatchJobStore() batchjob.BatchJobStore {
	return memory.NewBatchJobStore()
}
