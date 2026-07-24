// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

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
// SQLite WAL single-writer mode guarantees commit-order == sequence-order
// (ADR-023 §5): the AUTOINCREMENT primary key is assigned at commit time,
// never reused, and always monotonically increasing within a single writer,
// so no gap-safety logic is needed here.
func (p *SQLiteEntityGraphProvider) Watch(ctx context.Context, filter interfaces.WatchFilter, cursor string) (<-chan interfaces.WatchEvent, error) {
	startSeq, err := resolveWatchCursor(ctx, p.db, cursor)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: watch: %w", err)
	}

	ch := make(chan interfaces.WatchEvent, 64)
	go p.watchLoop(ctx, startSeq, filter, ch)
	return ch, nil
}

// resolveWatchCursor returns the starting sequence position for Watch.
// An empty cursor means "start from now" — the current max log id.
// Any other cursor is parsed as a decimal int64.
func resolveWatchCursor(ctx context.Context, db *sql.DB, cursor string) (int64, error) {
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
func (p *SQLiteEntityGraphProvider) watchLoop(ctx context.Context, startSeq int64, filter interfaces.WatchFilter, ch chan<- interfaces.WatchEvent) {
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

// pollWatchLog queries eg_observation_log for rows after cursor, converts them
// to WatchEvents, applies the filter, and returns the new cursor (the highest
// id seen, whether or not it matched the filter).
//
// The tenant filter uses eg_entity_index.owning_tenant — the sole access-control
// axis per ADR-023 §111-119 — via a LEFT JOIN. The observation log's own
// tenant_path column is ingest-time provenance and is NOT used for filtering.
// Edge subjects have no index entry, so COALESCE yields empty string for them; edges are
// excluded from tenant filtering anyway (see watchFilterMatches).
func (p *SQLiteEntityGraphProvider) pollWatchLog(ctx context.Context, cursor int64, filter interfaces.WatchFilter) ([]interfaces.WatchEvent, int64, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT l.id, l.subject, l.kind, l.observed_at,
		        COALESCE(ei.owning_tenant, '') AS effective_tenant
		 FROM eg_observation_log l
		 LEFT JOIN eg_entity_index ei ON ei.subject = l.subject
		 WHERE l.id > ?
		 ORDER BY l.id ASC
		 LIMIT ?`,
		cursor, watchBatchSize,
	)
	if err != nil {
		return nil, cursor, fmt.Errorf("entitygraph/sqlite: watch poll: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []interfaces.WatchEvent
	newCursor := cursor
	for rows.Next() {
		var id int64
		var subject, kind, observedAt, tenantPath string
		if err := rows.Scan(&id, &subject, &kind, &observedAt, &tenantPath); err != nil {
			return nil, cursor, fmt.Errorf("entitygraph/sqlite: watch scan: %w", err)
		}
		// Always advance the cursor past every row we've processed, even if the
		// row doesn't match the filter. This ensures the cursor never stalls on
		// a non-matching row.
		newCursor = id

		ev, ok := buildWatchEvent(subject, kind, observedAt, id)
		if !ok {
			continue
		}
		if !watchFilterMatches(ev, tenantPath, filter) {
			continue
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, cursor, fmt.Errorf("entitygraph/sqlite: watch iterate: %w", err)
	}
	return events, newCursor, nil
}

// buildWatchEvent converts a raw eg_observation_log row into a WatchEvent.
// Returns ok=false when the row cannot be represented as a WatchEvent — for
// example, an edge subject whose from-EID does not parse as a valid EID.
func buildWatchEvent(subject, kind, observedAt string, logSeq int64) (interfaces.WatchEvent, bool) {
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

// watchFilterMatches reports whether a WatchEvent passes the WatchFilter.
// tenantPath is the effective_tenant derived from eg_entity_index.owning_tenant
// (the sole access-control axis, ADR-023 §111-119). Entity and drift events are
// filtered by it; edge events skip tenant filtering (edges store no owning_tenant).
func watchFilterMatches(ev interfaces.WatchEvent, tenantPath string, f interfaces.WatchFilter) bool {
	// Kinds filter: only pass events whose EventKind is in the list.
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

	// Tenant filter: applied to entity-updated and drift-updated events via the
	// tenant_path column (which stores owning_tenant from the observation payload).
	if f.TenantFilter != "" && ev.EventKind != "edge-updated" {
		if !tenantVisible(tenantPath, f.TenantFilter) {
			return false
		}
	}

	// EIDs filter: only pass events whose subject matches one of the listed EIDs.
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
