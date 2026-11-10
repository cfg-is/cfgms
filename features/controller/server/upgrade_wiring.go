// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"os"

	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// databaseProviderName is the StorageManager provider name of the shared
// database backend, used by both the cluster and the single-provider database
// constructors.
const databaseProviderName = "database"

// wireUpgradeStore hands the steward upgrade store to the HTTP API server
// (Issue #5977).
//
// The store comes from the configured storage provider's optional
// interfaces.UpgradeStoreCreator: the shared database provider in a cluster, the
// SQLite provider on a single node. A provider without the creator leaves
// GetUpgradeStore nil, nothing is wired, and the upgrade endpoints keep answering
// 503 UPGRADE_STORE_UNAVAILABLE — there is no in-memory fallback. A nil interface
// is checked before SetUpgradeStore so the server is never handed a typed nil.
func wireUpgradeStore(httpServer *api.Server, storageManager *interfaces.StorageManager, cfg *config.Config, logger logging.Logger) {
	if httpServer == nil || storageManager == nil {
		return
	}
	store := storageManager.GetUpgradeStore()
	if store == nil {
		return
	}
	httpServer.SetUpgradeStore(store)
	logLegacyUpgradeRecords(logger, storageManager.GetProviderName(), cfg)
}

// logLegacyUpgradeRecords tells the operator, once at startup, that the
// configured SQLite file may hold per-node upgrade records from before upgrade
// records moved to the shared database. They are not migrated and no longer read.
// It logs only when the active upgrade store came from the database provider and
// the configured SQLite file exists.
func logLegacyUpgradeRecords(logger logging.Logger, providerName string, cfg *config.Config) {
	if providerName != databaseProviderName || cfg == nil || cfg.Storage == nil || cfg.Storage.SQLitePath == "" {
		return
	}
	if _, err := os.Stat(cfg.Storage.SQLitePath); err != nil {
		return
	}
	logger.Info("Steward upgrade records are stored in the shared database; the SQLite file may hold legacy per-node upgrade records that are no longer read",
		"sqlite_path", cfg.Storage.SQLitePath)
}
