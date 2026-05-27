// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package terminal_test

// Provider registration for interceptor audit tests.
// CreateOSSStorageManager requires flatfile and sqlite providers to be registered.
// These blank imports trigger each provider's init() registration.
import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)
