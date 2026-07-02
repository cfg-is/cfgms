// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob_test

import (
	"github.com/cfgis/cfgms/features/controller/batchjob"
	"github.com/cfgis/cfgms/pkg/storage/providers/memory"
)

// newTestBatchJobStore returns a memory-backed BatchJobStore for tests.
//
// The concrete pkg/storage/providers/memory import lives here — an allowlisted
// */providers_test.go file (see scripts/check-providers.sh) — so the rest of the
// batchjob test suite depends only on the batchjob.BatchJobStore interface and
// stays free of direct storage-provider imports.
func newTestBatchJobStore() batchjob.BatchJobStore {
	return memory.NewBatchJobStore()
}
