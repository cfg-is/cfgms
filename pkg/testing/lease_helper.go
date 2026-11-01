// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package testing

import (
	"testing"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// SetupTestLeaseStore returns a real (not mocked) business.LeaseStore backed by
// a temp-dir flatfile store, for tests that need two or more pkg/lease.Manager
// instances to contend over the same lease rows (simulating multiple cluster
// nodes in-process; CLAUDE.md's no-mocks rule). The flatfile provider's
// exclusion is an in-process mutex, not a networked substrate — sufficient to
// prove a lease algorithm's mutual exclusion, not evidence of node-shared
// storage (see business.NodeSharedLeaseStore).
func SetupTestLeaseStore(t *testing.T) business.LeaseStore {
	t.Helper()
	store, err := flatfile.NewFlatFileLeaseStore(t.TempDir())
	if err != nil {
		t.Fatalf("SetupTestLeaseStore: failed to create flatfile lease store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Logf("SetupTestLeaseStore cleanup: close error: %v", err)
		}
	})
	return store
}
