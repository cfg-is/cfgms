// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package trigger

// Provider registration for tests in this package.
//
// The store-requirement tests compose real deployment-shape StorageManagers
// (interfaces.CreateOSSStorageManager for the OSS shape, the registered
// "database" provider for the cluster shape) rather than hand-assembling one
// from an in-memory store, so the providers backing those shapes must be
// registered. These blank imports trigger their init() registration.
//
// Cannot use pkg/testing helpers here: pkg/testutil pulls in
// features/controller/config, which is a heavier dependency than the two
// blank imports it would replace. Same pattern as features/rbac/providers_test.go.
import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)
