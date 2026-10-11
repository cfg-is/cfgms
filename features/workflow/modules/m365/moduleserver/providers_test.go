// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package moduleserver_test

// Provider registration for tests in this package.
// server_test.go builds a real sops secret store over a flatfile storage
// root, which requires the flatfile storage provider to be registered.
// This blank import triggers the provider's init() registration.
// Isolated to this file so server_test.go does not directly import
// concrete storage provider packages (per epic #731).
import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)
