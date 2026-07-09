// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package interfaces_test — provider registration for tests.
// Blank-imports the database provider so cluster-manager tests can call
// CreateClusterStorageManager against a real Postgres instance.
package interfaces_test

import _ "github.com/cfgis/cfgms/pkg/storage/providers/database"
