// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/internal/egcommon"
)

// Watch returns a durable, cursor-replayable change feed backed by
// eg_observation_log. The cursor is the last-seen row id (decimal string);
// empty starts from the current tail (no replay). The channel is closed when
// ctx is cancelled.
//
// SQLite WAL single-writer mode guarantees commit-order == sequence-order
// (ADR-023 §5): the AUTOINCREMENT primary key is assigned at commit time,
// never reused, and always monotonically increasing within a single writer,
// so no gap-safety logic is needed here.
//
// A non-zero cursor that predates the earliest retained log row returns
// ErrCursorExpired — the caller must resync via a fresh snapshot read (ADR-023 §7).
func (p *SQLiteEntityGraphProvider) Watch(ctx context.Context, filter interfaces.WatchFilter, cursor string) (<-chan interfaces.WatchEvent, error) {
	return egcommon.StartWatch(ctx, p.db, dialect, filter, cursor, p.pollWatchLog)
}

// pollWatchLog queries eg_observation_log for rows after cursor, converts them
// to WatchEvents, applies the filter, and returns the new cursor (the highest
// id seen, whether or not it matched the filter).
//
// The tenant filter uses eg_entity_index.owning_tenant — the sole access-control
// axis per ADR-023 §111-119 — via a LEFT JOIN. The observation log's own
// tenant_path column is ingest-time provenance and is NOT used for filtering.
// Edge subjects have no index entry, so COALESCE yields empty string for them; edges are
// excluded from tenant filtering anyway (see egcommon.WatchFilterMatches).
func (p *SQLiteEntityGraphProvider) pollWatchLog(ctx context.Context, cursor int64, filter interfaces.WatchFilter) ([]interfaces.WatchEvent, int64, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT l.id, l.subject, l.kind, l.observed_at,
		        COALESCE(ei.owning_tenant, '') AS effective_tenant
		 FROM eg_observation_log l
		 LEFT JOIN eg_entity_index ei ON ei.subject = l.subject
		 WHERE l.id > ?
		 ORDER BY l.id ASC
		 LIMIT ?`,
		cursor, egcommon.WatchBatchSize,
	)
	if err != nil {
		return nil, cursor, fmt.Errorf("entitygraph/sqlite: watch poll: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return egcommon.ScanWatchRows(rows, dialect, cursor, filter)
}
