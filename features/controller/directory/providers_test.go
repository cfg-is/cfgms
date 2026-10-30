// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package directory

// This file is the one test-file name scripts/check-providers.sh allows to import
// a storage provider: it supplies the real file-backed config store the membership
// tests run against.

import (
	"testing"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

func newFlatStore(t *testing.T) cfgconfig.ConfigStore {
	t.Helper()
	s, err := flatfile.NewFlatFileConfigStore(t.TempDir())
	if err != nil {
		t.Fatalf("flatfile store: %v", err)
	}
	return s
}
