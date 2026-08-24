// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package testing provides testing utilities for CFGMS components
package testing

import (
	"testing"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/database"
)

// testClusterSessionHMACKey is a fixed, non-secret key used only to satisfy
// CreateClusterStorageManager's session-store construction in tests that do not
// exercise session behaviour.
const testClusterSessionHMACKey = "test-hmac-key-32-bytes-padding--"

// decliningPendingRegistrationProvider wraps the real database provider and
// declines PendingRegistrationStore, reproducing the #3400 condition (the
// database provider returning business.ErrNotSupported for that store) against
// an actual provider implementation rather than a synthetic store-less
// StorageManager. All other methods are the real database provider's, promoted
// via embedding. Mirrors pkg/storage/interfaces/providers_test.go's
// decliningRegistrationDatabaseProvider for subsystem-level tests that cannot
// import pkg/storage/providers/database directly (see scripts/check-providers.sh).
type decliningPendingRegistrationProvider struct {
	*database.DatabaseProvider
}

func (d *decliningPendingRegistrationProvider) CreatePendingRegistrationStore(_ map[string]interface{}) (business.PendingRegistrationStore, error) {
	return nil, business.ErrNotSupported
}

// SetupDecliningPendingRegistrationClusterStorage temporarily swaps the registered
// "database" storage provider for one that declines CreatePendingRegistrationStore,
// composes a cluster StorageManager against pgDSN through the real
// CreateClusterStorageManager path, and restores the original provider and closes
// the manager via t.Cleanup. The returned manager has every store the real database
// provider supplies except PendingRegistrationStore, which is absent — the #3400
// condition reproduced against a genuine provider gap rather than a hand-built
// store-less manager.
func SetupDecliningPendingRegistrationClusterStorage(t *testing.T, pgDSN string) *interfaces.StorageManager {
	t.Helper()

	original, err := interfaces.GetStorageProvider("database")
	if err != nil {
		t.Fatalf("failed to look up registered database provider: %v", err)
	}
	interfaces.RegisterStorageProvider(&decliningPendingRegistrationProvider{DatabaseProvider: &database.DatabaseProvider{}})
	t.Cleanup(func() { interfaces.RegisterStorageProvider(original) })

	sm, err := interfaces.CreateClusterStorageManager(pgDSN, testClusterSessionHMACKey, nil)
	if err != nil {
		t.Fatalf("CreateClusterStorageManager must tolerate a declined optional-at-construction store as a nil field: %v", err)
	}
	t.Cleanup(func() { _ = sm.Close() })

	return sm
}
