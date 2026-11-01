// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"database/sql"
	"sync"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// ProjectionUpdaterFunc incrementally updates the derived projections for one
// observation inside the ingesting transaction. It runs after the observation
// log row and current-state row for obs have been written; logSeq is the
// eg_observation_log id assigned to that row.
type ProjectionUpdaterFunc func(ctx context.Context, tx *sql.Tx, obs types.Observation, logSeq int64) error

var (
	mu                 sync.RWMutex
	projectionUpdaters = map[string]ProjectionUpdaterFunc{}
)

// RegisterProjectionUpdater registers a projection updater for a subject kind
// (e.g. "entity", "edge"). Called from init() in the same package. Registering
// the same kind twice replaces the prior updater.
func RegisterProjectionUpdater(subjectKind string, fn ProjectionUpdaterFunc) {
	mu.Lock()
	defer mu.Unlock()
	projectionUpdaters[subjectKind] = fn
}

// dispatchProjectionUpdate invokes the registered updater for subjectKind, if
// any. Subject kinds without a registered updater are a no-op (nil error).
func dispatchProjectionUpdate(ctx context.Context, tx *sql.Tx, subjectKind string, obs types.Observation, logSeq int64) error {
	mu.RLock()
	fn, ok := projectionUpdaters[subjectKind]
	mu.RUnlock()
	if !ok {
		return nil
	}
	return fn(ctx, tx, obs, logSeq)
}
