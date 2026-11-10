// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// rolloutSweepTimeout bounds the startup sweep so an unreachable store cannot
// hold controller startup.
const rolloutSweepTimeout = 30 * time.Second

// wireRolloutStore hands the shared rollout store to the HTTP API server and then
// halts the rollouts this node left in progress (Issue #5976).
//
// The store exists only when the storage provider implements
// interfaces.RolloutStoreCreator (the cluster Postgres tier). Otherwise
// GetRolloutStore returns a nil interface, nothing is wired, and the rollout
// endpoints keep answering 503 ROLLOUT_STORE_UNAVAILABLE. A nil interface is
// checked before SetRolloutStore so the server is never handed a typed nil.
//
// The sweep is best effort: a failure is logged as a warning and never blocks
// startup.
func wireRolloutStore(httpServer *api.Server, storageManager *interfaces.StorageManager, logger logging.Logger) {
	if httpServer == nil || storageManager == nil {
		return
	}
	store := storageManager.GetRolloutStore()
	if store == nil {
		return
	}
	httpServer.SetRolloutStore(store)

	ctx, cancel := context.WithTimeout(context.Background(), rolloutSweepTimeout)
	defer cancel()
	halted, err := httpServer.HaltOrphanedRollouts(ctx)
	if err != nil {
		logger.Warn("Startup rollout sweep did not finish; continuing",
			"halted", halted,
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	if halted > 0 {
		logger.Info("Halted rollouts orphaned by a restart of this node", "halted", halted)
	}
}
