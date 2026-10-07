// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package nodes

import (
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/memory"
)

// newTestUpgradeStore returns a memory-backed UpgradeStore for tests.
//
// The concrete pkg/storage/providers/memory import lives here — an allowlisted
// */providers_test.go file (see scripts/check-providers.sh) — so the rest of the
// nodes test suite depends only on the business.UpgradeStore interface and stays
// free of direct storage-provider imports.
func newTestUpgradeStore() business.UpgradeStore {
	return memory.NewUpgradeStore()
}
