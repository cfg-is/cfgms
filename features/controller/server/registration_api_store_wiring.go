// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// wireRegistrationAPIStores hands the registration admission stores to the HTTP
// API server, which is the only place the /api/v1/registration/* handlers read
// them from. A nil store is left nil so the handlers keep returning their
// explicit 503 rather than panicking — the OSS composite (flatfile+SQLite)
// backend supplies neither.
//
// This exists as a named function, rather than two inline `if` blocks in New(),
// so controller startup wiring is directly testable without standing up a
// Postgres-backed StorageManager: only the database provider returns a non-nil
// IPTrustStore, so a New()-level test on the SQLite path cannot tell "unwired"
// from "unsupported by this backend" (see registration_api_store_wiring_test.go).
//
// The ip-trust half was missing entirely until story #3096: SetIPTrustStore
// (Issue #1698) had no production caller, so every deployment served
// "ip-trust store unavailable" from all three ip-trust endpoints while the store
// itself was alive and being handed to the approval hook a few lines later.
func wireRegistrationAPIStores(
	httpServer *api.Server,
	pendingStore business.PendingRegistrationStore,
	ipTrustStore business.IPTrustStore,
	logger logging.Logger,
) {
	// Issue #1696: durable pending registration store for the status poll endpoint.
	if pendingStore != nil {
		httpServer.SetPendingStore(pendingStore)
		logger.Info("Durable pending registration store wired to HTTP API server (Issue #1696)")
	}

	// Issue #1698 / story #3096: operator ip-trust management endpoints.
	if ipTrustStore != nil {
		httpServer.SetIPTrustStore(ipTrustStore)
		logger.Info("IP-trust store wired to HTTP API server (Issue #1698)")
	}
}
