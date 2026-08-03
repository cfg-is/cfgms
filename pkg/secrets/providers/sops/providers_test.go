// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sops

// Provider registration for tests in this package.
// The SOPS store tests build a real secret store over a concrete storage
// backend (no mocks), selecting it by name via "storage_provider": "flatfile".
// That name only resolves once the provider's init() has registered it, which
// this blank import triggers.
// Isolated to this file so provider_test.go does not directly import a
// concrete provider package (per epic #731) — scripts/check-providers.sh
// allows the direct import in */providers_test.go only.
import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)
