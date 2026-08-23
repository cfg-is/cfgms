// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package interfaces_test — provider registration for tests.
// Blank-imports the database provider so cluster-manager tests can call
// CreateClusterStorageManager against a real Postgres instance, and exposes
// constructors for the OSS providers so the registry and factory tests run
// against real implementations rather than substitutes. Direct
// pkg/storage/providers/* imports are confined to this allowlisted
// */providers_test.go path (see scripts/check-providers.sh).
package interfaces_test

import (
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/database"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newFlatFileProvider returns the real flat-file StorageProvider (config, audit,
// steward and IP-trust stores on the local filesystem).
func newFlatFileProvider() interfaces.StorageProvider {
	return &flatfile.FlatFileProvider{}
}

// newSQLiteProvider returns the real SQLite StorageProvider (business-data tier).
func newSQLiteProvider() interfaces.StorageProvider {
	return &sqlite.SQLiteProvider{}
}

// decliningRegistrationDatabaseProvider wraps the real database provider and
// declines PendingRegistrationStore, reproducing the #3400 condition (the
// database provider returning business.ErrNotSupported for that store) against
// an actual provider implementation rather than a synthetic StorageManager. All
// other methods are the real database provider's, promoted via embedding.
type decliningRegistrationDatabaseProvider struct {
	*database.DatabaseProvider
}

func (d *decliningRegistrationDatabaseProvider) CreatePendingRegistrationStore(_ map[string]interface{}) (business.PendingRegistrationStore, error) {
	return nil, business.ErrNotSupported
}

// newDecliningRegistrationDatabaseProvider returns a database-backed StorageProvider
// identical to the real one except that it declines PendingRegistrationStore, for
// the #3400 regression test in requirements_test.go.
func newDecliningRegistrationDatabaseProvider() interfaces.StorageProvider {
	return &decliningRegistrationDatabaseProvider{DatabaseProvider: &database.DatabaseProvider{}}
}
