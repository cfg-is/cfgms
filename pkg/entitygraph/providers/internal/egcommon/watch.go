// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package egcommon

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
	// WatchPollInterval is how often the watch loop polls the observation log.
	WatchPollInterval = 100 * time.Millisecond
	// WatchBatchSize is the maximum number of log rows read per poll.
	WatchBatchSize = 100
)

// PollFunc reads the observation log rows after cursor, returns the matching
// events and the new cursor. It holds the provider's dialect-bound query.
type PollFunc func(ctx context.Context, cursor int64, filter interfaces.WatchFilter) ([]interfaces.WatchEvent, int64, error)

// StartWatch implements the provider-independent part of Watch: it resolves
// and validates the cursor, then starts the polling loop. A non-zero cursor
// that predates the earliest retained log row returns ErrCursorExpired
// (ADR-023 §7); cursor 0 is the "from the very beginning" sentinel and is
// exempt. The channel is closed when ctx is cancelled.
func StartWatch(ctx context.Context, db *sql.DB, d Dialect, filter interfaces.WatchFilter, cursor string, poll PollFunc) (<-chan interfaces.WatchEvent, error) {
	startSeq, err := ResolveWatchCursor(ctx, db, cursor)
	if err != nil {
		return nil, fmt.Errorf("%s: watch: %w", d.Prefix, err)
	}

	if startSeq > 0 {
		if err := CheckCursorExpiry(ctx, db, d, startSeq); err != nil {
			return nil, err
		}
	}

	ch := make(chan interfaces.WatchEvent, 64)
	go watchLoop(ctx, startSeq, filter, ch, poll)
	return ch, nil
}

// CheckCursorExpiry returns ErrCursorExpired if seq predates the earliest
// retained log row. Called only for non-zero cursors.
func CheckCursorExpiry(ctx context.Context, db *sql.DB, d Dialect, seq int64) error {
	var minID sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT MIN(id) FROM eg_observation_log`,
	).Scan(&minID); err != nil {
		return fmt.Errorf("%s: watch: get min log id: %w", d.Prefix, err)
	}
	if minID.Valid && seq < minID.Int64 {
		return interfaces.ErrCursorExpired
	}
	return nil
}

// ResolveWatchCursor returns the starting sequence position for Watch.
// An empty cursor means "start from now" — the current max log id.
// Any other cursor is parsed as a decimal int64. This function is pure
// (no DB access for non-empty cursors); expiry detection is handled by
// the caller after this function returns.
func ResolveWatchCursor(ctx context.Context, db *sql.DB, cursor string) (int64, error) {
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
func watchLoop(ctx context.Context, startSeq int64, filter interfaces.WatchFilter, ch chan<- interfaces.WatchEvent, poll PollFunc) {
	defer close(ch)
	cur := startSeq
	tick := time.NewTicker(WatchPollInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			events, newCur, err := poll(ctx, cur, filter)
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

// ScanWatchRows converts the rows of a watch poll query into filtered events
// and returns the new cursor (the highest id seen, whether or not it matched
// the filter). The columns are id, subject, kind, observed_at and the
// effective tenant from eg_entity_index.owning_tenant — the sole access-control
// axis per ADR-023 §111-119; the log's own tenant_path column is ingest-time
// provenance and is not used for filtering. The caller closes rows.
func ScanWatchRows(rows *sql.Rows, d Dialect, cursor int64, filter interfaces.WatchFilter) ([]interfaces.WatchEvent, int64, error) {
	var events []interfaces.WatchEvent
	newCursor := cursor
	for rows.Next() {
		var id int64
		var subject, kind, observedAt, tenantPath string
		if err := rows.Scan(&id, &subject, &kind, &observedAt, &tenantPath); err != nil {
			return nil, cursor, fmt.Errorf("%s: watch scan: %w", d.Prefix, err)
		}
		// Always advance the cursor past every row we've processed, even if the
		// row doesn't match the filter. This ensures the cursor never stalls on
		// a non-matching row.
		newCursor = id

		ev, ok := BuildWatchEvent(subject, kind, observedAt, id)
		if !ok {
			continue
		}
		if !WatchFilterMatches(ev, tenantPath, filter) {
			continue
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, cursor, fmt.Errorf("%s: watch iterate: %w", d.Prefix, err)
	}
	return events, newCursor, nil
}

// BuildWatchEvent converts a raw eg_observation_log row into a WatchEvent.
// Returns ok=false when the row cannot be represented as a WatchEvent — for
// example, an edge subject whose from-EID does not parse as a valid EID.
func BuildWatchEvent(subject, kind, observedAt string, logSeq int64) (interfaces.WatchEvent, bool) {
	isEdge := strings.Contains(subject, "|")

	var eventKind string
	var subjectEID interfaces.EIDRef

	if isEdge {
		// Edge subjects are edge_type|from|to.
		parts := strings.SplitN(subject, "|", 3)
		if len(parts) != 3 {
			return interfaces.WatchEvent{}, false
		}
		eid, err := types.ParseEID(parts[1])
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

// WatchFilterMatches reports whether a WatchEvent passes the WatchFilter.
// tenantPath is the effective_tenant derived from eg_entity_index.owning_tenant
// (the sole access-control axis, ADR-023 §111-119). Entity and drift events are
// filtered by it; edge events skip tenant filtering (edges store no owning_tenant).
func WatchFilterMatches(ev interfaces.WatchEvent, tenantPath string, f interfaces.WatchFilter) bool {
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
		if !interfaces.NewTenantCut(f.TenantFilter, f.TenantSubtreeIDs).Visible(tenantPath) {
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
