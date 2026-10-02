// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package lease

// Concrete test-store construction for tests in this package.
// The lease manager tests exercise a real (not mocked) business.LeaseStore per
// CLAUDE.md's no-mocks rule, which necessarily names a concrete provider.
// Isolated to this file so lease_test.go imports pkg/storage/interfaces only
// (per epic #731); */providers_test.go is the allowlisted location for that
// import in scripts/check-providers.sh.

import (
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// newTestStore returns a real (not mocked) business.LeaseStore backed by a
// temp-dir flatfile store, matching CLAUDE.md's no-mocks rule.
func newTestStore(t *testing.T) business.LeaseStore {
	t.Helper()
	store, err := flatfile.NewFlatFileLeaseStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}
