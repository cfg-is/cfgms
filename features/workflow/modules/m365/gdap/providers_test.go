// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package gdap

// Provider registration for tests in this package.
// Benchmark and other tests use interfaces.CreateOSSStorageManager which
// requires these providers to be registered via their init() functions.
import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)
