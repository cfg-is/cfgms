// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rbac

// Provider registration for tests in this package.
// RBAC tests use interfaces.CreateOSSStorageManager which requires
// these providers to be registered. These blank imports trigger the
// providers' init() registration.
// Cannot use pkg/testing helpers due to import cycle (pkg/testing
// imports features/rbac). See epic #731.
import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)
