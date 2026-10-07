// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

const (
	watchPollInterval = 100 * time.Millisecond
	watchBatchSize    = 100
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
	startSeq, err := dbResolveWatchCursor(ctx, p.db, cursor)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: watch: %w", err)
	}

	// Check for expired cursor. A non-zero cursor that predates the earliest
	// retained log row signals that GC has pruned the rows the consumer would
	// need to replay (ADR-023 §7). Cursor=0 is the "start from the very
	// beginning" sentinel and is exempt.
	if startSeq > 0 {
		if err := checkDatabaseCursorExpiry(ctx, p.db, startSeq); err != nil {
			return nil, err
		}
	}

	ch := make(chan interfaces.WatchEvent, 64)
	go p.watchLoop(ctx, startSeq, filter, ch)
	return ch, nil
}

// checkDatabaseCursorExpiry returns ErrCursorExpired if seq predates the
// earliest retained log row. Called only for non-zero cursors.
func checkDatabaseCursorExpiry(ctx context.Context, db *sql.DB, seq int64) error {
	var minID sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT MIN(id) FROM eg_observation_log`,
	).Scan(&minID); err != nil {
		return fmt.Errorf("entitygraph/database: watch: get min log id: %w", err)
	}
	if minID.Valid && seq < minID.Int64 {
		return interfaces.ErrCursorExpired
	}
	return nil
}

// dbResolveWatchCursor returns the starting sequence position for Watch.
// An empty cursor means "start from now" — the current max log id.
// Any other cursor is parsed as a decimal int64. This function is pure
// (no DB access for non-empty cursors); expiry detection is handled by
// the caller after this function returns.
func dbResolveWatchCursor(ctx context.Context, db *sql.DB, cursor string) (int64, error) {
	if cursor == "" {
		var cur int64
		if err := db.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(id), 0) FROM eg_observation_log`,
		).Scan(&cur); err != nil {
			return 0, fmt.Errorf("get tail position: %w", err)
		}
		return cur, nil
	}
	seq, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid cursor %q: must be a decimal integer", cursor)
	}
	return seq, nil
}

// watchLoop polls the observation log on a fixed interval and sends matching
// WatchEvents to ch. It closes ch when ctx is done.
func (p *DatabaseEntityGraphProvider) watchLoop(ctx context.Context, startSeq int64, filter interfaces.WatchFilter, ch chan<- interfaces.WatchEvent) {
	defer close(ch)
	cur := startSeq
	tick := time.NewTicker(watchPollInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			events, newCur, err := p.pollWatchLog(ctx, cur, filter)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			cur = newCur
			for _, ev := range events {
				select {
				case ch <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}
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
// so COALESCE yields empty string for them; edges skip tenant filtering (see dbWatchFilterMatches).
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
		cursor, watchBatchSize,
	)
	if err != nil {
		return nil, cursor, fmt.Errorf("entitygraph/database: watch poll: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []interfaces.WatchEvent
	newCursor := cursor
	for rows.Next() {
		var id int64
		var subject, kind, observedAt, tenantPath string
		if err := rows.Scan(&id, &subject, &kind, &observedAt, &tenantPath); err != nil {
			return nil, cursor, fmt.Errorf("entitygraph/database: watch scan: %w", err)
		}
		// Always advance the cursor past every processed row so non-matching
		// rows don't stall the stream.
		newCursor = id

		ev, ok := dbBuildWatchEvent(subject, kind, observedAt, id)
		if !ok {
			continue
		}
		if !dbWatchFilterMatches(ev, tenantPath, filter) {
			continue
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, cursor, fmt.Errorf("entitygraph/database: watch iterate: %w", err)
	}
	return events, newCursor, nil
}

// dbBuildWatchEvent converts a raw eg_observation_log row into a WatchEvent.
// Returns ok=false when the row cannot be represented — for example, an edge
// subject whose from-EID does not parse as a valid EID.
func dbBuildWatchEvent(subject, kind, observedAt string, logSeq int64) (interfaces.WatchEvent, bool) {
	isEdge := strings.Contains(subject, "|")

	var eventKind string
	var subjectEID interfaces.EIDRef

	if isEdge {
		_, fromSubj, _, err := parseEdgeSubject(subject)
		if err != nil {
			return interfaces.WatchEvent{}, false
		}
		eid, err := types.ParseEID(fromSubj)
		if err != nil {
			return interfaces.WatchEvent{}, false
		}
		subjectEID = eid
		eventKind = "edge-updated"
	} else {
		eid, err := types.ParseEID(subject)
		if err != nil {
			return interfaces.WatchEvent{}, false
		}
		subjectEID = eid
		if kind == string(types.ObservationKindDriftDiff) {
			eventKind = "drift-updated"
		} else {
			eventKind = "entity-updated"
		}
	}

	t, _ := time.Parse(time.RFC3339Nano, observedAt)
	return interfaces.WatchEvent{
		Subject:   subjectEID,
		EventKind: eventKind,
		Version:   logSeq,
		At:        t,
	}, true
}

// dbWatchFilterMatches reports whether a WatchEvent passes the WatchFilter.
// tenantPath is the effective_tenant derived from eg_entity_index.owning_tenant
// (the sole access-control axis, ADR-023 §111-119). Entity and drift events are
// filtered by it; edge events skip tenant filtering (edges store no owning_tenant).
func dbWatchFilterMatches(ev interfaces.WatchEvent, tenantPath string, f interfaces.WatchFilter) bool {
	if len(f.Kinds) > 0 {
		matched := false
		for _, k := range f.Kinds {
			if k == ev.EventKind {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if f.TenantFilter != "" && ev.EventKind != "edge-updated" {
		if !tenantVisible(tenantPath, f.TenantFilter) {
			return false
		}
	}

	if len(f.EIDs) > 0 {
		subj := ev.Subject.String()
		matched := false
		for _, eid := range f.EIDs {
			if eid.String() == subj {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}
