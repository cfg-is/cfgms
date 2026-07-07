// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package nodes test-only provider registrations.
// newTestUpgradeStore is defined here so that the concrete memory-provider import
// is confined to the allowlisted */providers_test.go path (see scripts/check-providers.sh).
package nodes

import (
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/memory"
)

// newTestUpgradeStore returns a memory-backed UpgradeStore for ring health tests.
func newTestUpgradeStore() business.UpgradeStore {
	return memory.NewUpgradeStore()
}
