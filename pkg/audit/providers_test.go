// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package audit

// Provider registration for tests in this package.
// The audit manager tests use interfaces.CreateOSSStorageManager which
// requires database, flatfile, and sqlite providers to be registered.
// These blank imports trigger the providers' init() registration.
// Isolated to this file so manager_test.go does not directly import
// concrete provider packages (per epic #731).
import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)
