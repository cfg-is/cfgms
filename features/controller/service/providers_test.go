// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package service_test test-only provider registrations.
// The concrete sqlite import is confined to this allowlisted */providers_test.go
// path (see scripts/check-providers.sh).
package service_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newSQLiteDrainHookStores returns real, in-memory SQLite-backed CommandStore
// and StewardStore instances (no mocks) for exercising the pending-delivery
// drain hook. The concrete sqlite import is confined to this allowlisted
// */providers_test.go path (see scripts/check-providers.sh).
func newSQLiteDrainHookStores(t *testing.T) (business.CommandStore, business.StewardStore) {
	t.Helper()
	provider := &sqlite.SQLiteProvider{}
	commandStore, err := provider.CreateCommandStore(map[string]interface{}{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = commandStore.Close() })

	stewardStore, err := provider.CreateStewardStore(map[string]interface{}{})
	require.NoError(t, err)
	return commandStore, stewardStore
}
