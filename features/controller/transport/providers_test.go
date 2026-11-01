// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

// Registers the real flatfile storage provider for this package's tests
// (dna_bulk_store_test.go resolves it via interfaces.GetStorageProvider). The
// registration lives in providers_test.go because that is the one test-file
// name the provider-import check (scripts/check-providers.sh) allows to import
// pkg/storage/providers/*.

import (
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)
