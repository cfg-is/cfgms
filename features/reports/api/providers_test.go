// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package api test-only provider registrations. The concrete flatfile import is
// confined to this allowlisted */providers_test.go path (see scripts/check-providers.sh).
package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// newTestAlertStore returns a real flat-file AlertStore rooted at t.TempDir().
func newTestAlertStore(t *testing.T) business.AlertStore {
	t.Helper()
	st, err := flatfile.NewFlatFileAlertStore(t.TempDir())
	require.NoError(t, err, "creating flat-file alert store for reports handler tests")
	return st
}

// newUnreadableTestAlertStore returns the same real flat-file AlertStore with
// its backing alert_states.json replaced by bytes that are not valid JSON, so
// every GetAlertState call fails with a genuine store decode error. This is
// filesystem-level fault injection against the production provider, not a mock:
// the store, its parser and its error path are the real ones, and the same
// failure occurs in production when the state file is truncated or corrupted.
func newUnreadableTestAlertStore(t *testing.T) business.AlertStore {
	t.Helper()
	root := t.TempDir()
	st, err := flatfile.NewFlatFileAlertStore(root)
	require.NoError(t, err, "creating flat-file alert store for reports handler tests")

	corrupt := filepath.Join(root, "alerts", "alert_states.json")
	require.NoError(t, os.WriteFile(corrupt, []byte("{ this is not valid JSON"), 0o600),
		"seeding a corrupt alert state file")
	return st
}
