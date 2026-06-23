// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package initialization — provider registration for tests.
// Blank-imports the database provider so cluster-mode tests can call
// CreateClusterStorageManager without a full controller binary.
package initialization

import _ "github.com/cfgis/cfgms/pkg/storage/providers/database"
