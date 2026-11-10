// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package memory_test

import (
	"testing"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/memory"
)

// TestUpgradeStore_Memory_Contract runs the shared UpgradeStore contract against
// the in-memory store, which is kept for tests only.
func TestUpgradeStore_Memory_Contract(t *testing.T) {
	business.UpgradeStoreContract(t, memory.NewUpgradeStore())
}
