// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

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
// Under concurrent writes, PostgreSQL's BIGSERIAL assigns ids at INSERT time,
// not at COMMIT time, so two concurrent transactions can commit out of order.
// pollWatchLog uses a txid-snapshot watermark (txid_snapshot_xmin) to ensure
// we never advance the cursor past a row whose inserting transaction is still
// in-flight: only rows whose xmin < the minimum active transaction id are
// returned. This prevents gaps caused by out-of-order commits (ADR-023 §5/§6).
//
// A non-zero cursor that predates the earliest retained log row returns
// ErrCursorExpired — the caller must resync via a fresh snapshot read (ADR-023 §7).
func (p *DatabaseEntityGraphProvider) Watch(ctx context.Context, filter interfaces.WatchFilter, cursor string) (<-chan interfaces.WatchEvent, error) {
	return egcommon.StartWatch(ctx, p.db, dialect, filter, cursor, p.pollWatchLog)
}

// pollWatchLog queries eg_observation_log for committed rows after cursor. The
// xmin watermark filter (`xmin::text::bigint < txid_snapshot_xmin(txid_current_snapshot())`)
// guarantees that we only return rows from transactions whose xid is lower than
// the minimum currently-active transaction id. This prevents the out-of-order
// commit hazard: if T1 (xid=X1) is still in-flight when we poll and T2 (xid=X2
// > X1) has committed, T2's row is excluded from the result set until T1 also
// commits, ensuring the caller's cursor never skips past T1's (potentially
// lower-id) row (ADR-023 §5/§6).
//
// The tenant filter uses eg_entity_index.owning_tenant — the sole access-control
// axis per ADR-023 §111-119 — via a LEFT JOIN. Edge subjects have no index entry
// so COALESCE yields empty string for them; edges skip tenant filtering (see egcommon.WatchFilterMatches).
func (p *DatabaseEntityGraphProvider) pollWatchLog(ctx context.Context, cursor int64, filter interfaces.WatchFilter) ([]interfaces.WatchEvent, int64, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT l.id, l.subject, l.kind, l.observed_at,
		       COALESCE(ei.owning_tenant, '') AS effective_tenant
		FROM eg_observation_log l
		LEFT JOIN eg_entity_index ei ON ei.subject = l.subject
		WHERE l.id > $1
		  AND xmin::text::bigint < txid_snapshot_xmin(txid_current_snapshot())
		ORDER BY l.id ASC
		LIMIT $2`,
		cursor, egcommon.WatchBatchSize,
	)
	if err != nil {
		return nil, cursor, fmt.Errorf("entitygraph/database: watch poll: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return egcommon.ScanWatchRows(rows, dialect, cursor, filter)
}
