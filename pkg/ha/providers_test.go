// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package ha

// Concrete test-store construction for the lease-backed HasLeadership()/GetTerm()
// tests in this package (Issue #3760). manager_test.go exercises a real (not
// mocked) business.LeaseStore per CLAUDE.md's no-mocks rule, which necessarily
// names a concrete provider. Isolated to this file so manager_test.go does not
// need to import a storage provider directly; */providers_test.go is the
// allowlisted location for that import (scripts/check-providers.sh).

import (
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// newTestLeaseStore returns a real (not mocked) business.LeaseStore backed by a
// temp-dir flatfile store — the same test-store pattern pkg/lease's own tests use
// (pkg/lease/providers_test.go). Safe to share across multiple *Manager instances
// within one test process: FlatFileLeaseStore serializes concurrent access with
// its own in-process mutex.
func newTestLeaseStore(t *testing.T) business.LeaseStore {
	t.Helper()
	store, err := flatfile.NewFlatFileLeaseStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// newTestNodeRegistryStore returns a real (not mocked) business.NodeRegistryStore
// backed by a temp-dir flatfile store (Issue #3763, ADR-031 Decision 5's post-Raft
// membership mechanism). Safe to share across multiple *Manager instances within
// one test process: FlatFileNodeRegistryStore serializes concurrent access with
// its own in-process mutex.
func newTestNodeRegistryStore(t *testing.T) business.NodeRegistryStore {
	t.Helper()
	store, err := flatfile.NewFlatFileNodeRegistryStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}
