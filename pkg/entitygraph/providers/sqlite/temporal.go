// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
)

// currentEntityRow holds one scanned row from the entity source queries,
// carrying both the fields needed for precedence resolution and the fields
// needed for building types.Observation values.
type currentEntityRow struct {
	source      string
	sourceClass string
	kind        string
	confidence  string
	observedAt  time.Time
	recordedAt  time.Time
	payloadHash string
	payload     map[string]interface{}
}

// loadEntityRowsCurrent returns all per-source current-state rows for subject
// from eg_entity_current (the fast path for non-temporal reads).
func (p *SQLiteEntityGraphProvider) loadEntityRowsCurrent(ctx context.Context, subject string) ([]currentEntityRow, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT c.source, c.source_class, c.kind, c.confidence, c.observed_at, c.recorded_at, c.payload_hash, pc.payload
		 FROM eg_entity_current c
		 JOIN eg_payload_content pc ON pc.payload_hash = c.payload_hash
		 WHERE c.subject = ? AND c.kind != 'desired-state'`,
		subject,
	)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: load current rows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []currentEntityRow
	for rows.Next() {
		var r currentEntityRow
		var observedAt, recordedAt, payloadJSON string
		if err := rows.Scan(&r.source, &r.sourceClass, &r.kind, &r.confidence,
			&observedAt, &recordedAt, &r.payloadHash, &payloadJSON); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: scan current row: %w", err)
		}
		r.observedAt, _ = time.Parse(time.RFC3339Nano, observedAt)
		r.recordedAt, _ = time.Parse(time.RFC3339Nano, recordedAt)
		if payloadJSON != "" {
			if err := json.Unmarshal([]byte(payloadJSON), &r.payload); err != nil {
				return nil, fmt.Errorf("entitygraph/sqlite: decode current payload: %w", err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: iterate current rows: %w", err)
	}
	return out, nil
}

// loadEntityRowsAsOf reconstructs the per-source state at or before asOf by
// scanning the observation log. For each source the highest-id state or presence
// observation at or before asOf is returned; sources whose latest row is an
// absence are excluded (the source had retracted its assertion at that time).
func (p *SQLiteEntityGraphProvider) loadEntityRowsAsOf(ctx context.Context, subject string, asOf time.Time) ([]currentEntityRow, error) {
	asOfStr := rfc3339(asOf)
	rows, err := p.db.QueryContext(ctx, `
		SELECT l.source, l.source_class, l.kind, l.confidence, l.observed_at, l.recorded_at, l.payload_hash, pc.payload
		FROM eg_observation_log l
		JOIN eg_payload_content pc ON pc.payload_hash = l.payload_hash
		WHERE l.subject = ?
		  AND l.observed_at <= ?
		  AND l.id = (
		      SELECT MAX(id) FROM eg_observation_log
		      WHERE subject = l.subject AND source = l.source AND observed_at <= ?
		  )
		  AND l.kind IN ('state', 'presence')`,
		subject, asOfStr, asOfStr,
	)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: load as-of rows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []currentEntityRow
	for rows.Next() {
		var r currentEntityRow
		var observedAt, recordedAt, payloadJSON string
		if err := rows.Scan(&r.source, &r.sourceClass, &r.kind, &r.confidence,
			&observedAt, &recordedAt, &r.payloadHash, &payloadJSON); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: scan as-of row: %w", err)
		}
		r.observedAt, _ = time.Parse(time.RFC3339Nano, observedAt)
		r.recordedAt, _ = time.Parse(time.RFC3339Nano, recordedAt)
		if payloadJSON != "" {
			if err := json.Unmarshal([]byte(payloadJSON), &r.payload); err != nil {
				return nil, fmt.Errorf("entitygraph/sqlite: decode as-of payload: %w", err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: iterate as-of rows: %w", err)
	}
	return out, nil
}

// entityRowsToEntries converts currentEntityRow slices to sourceEntry slices for
// use with the precedence resolution helpers.
func entityRowsToEntries(rows []currentEntityRow) []sourceEntry {
	entries := make([]sourceEntry, len(rows))
	for i, r := range rows {
		entries[i] = sourceEntry{
			source:      r.source,
			sourceClass: r.sourceClass,
			observedAt:  r.observedAt,
			payloadHash: r.payloadHash,
			payload:     r.payload,
		}
	}
	return entries
}

// entityStateAsOf returns the merged attribute map for a subject as-of asOf, or
// nil if no state observations existed at or before that time.
func (p *SQLiteEntityGraphProvider) entityStateAsOf(ctx context.Context, subject string, asOf time.Time) (map[string]interface{}, error) {
	rows, err := p.loadEntityRowsAsOf(ctx, subject, asOf)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return mergeAttributes(entityRowsToEntries(rows)), nil
}

// computeAttributeChanges returns the set of attributes that differ between two
// merged state snapshots. Either snapshot may be nil (entity did not exist).
// Attributes present in only one snapshot are included (Before or After nil).
// The result is sorted by attribute name for deterministic output.
func computeAttributeChanges(atT1, atT2 map[string]interface{}) []interfaces.AttributeChange {
	keys := make(map[string]struct{})
	for k := range atT1 {
		keys[k] = struct{}{}
	}
	for k := range atT2 {
		keys[k] = struct{}{}
	}

	var changes []interfaces.AttributeChange
	for k := range keys {
		v1, ok1 := atT1[k]
		v2, ok2 := atT2[k]
		if !ok1 && !ok2 {
			continue
		}
		j1, _ := json.Marshal(v1)
		j2, _ := json.Marshal(v2)
		if ok1 == ok2 && string(j1) == string(j2) {
			continue
		}
		changes = append(changes, interfaces.AttributeChange{
			Attribute: k,
			Before:    v1,
			After:     v2,
		})
	}

	sort.Slice(changes, func(i, j int) bool {
		return changes[i].Attribute < changes[j].Attribute
	})
	return changes
}

// Diff computes the attribute delta between two as-of states of a subject. It
// projects the merged entity state at r.From and r.To, then returns the set of
// attributes whose values differ.
func (p *SQLiteEntityGraphProvider) Diff(ctx context.Context, eid interfaces.EIDRef, r interfaces.TimeRange) (*interfaces.StateDiff, error) {
	subject := eid.String()

	atT1, err := p.entityStateAsOf(ctx, subject, r.From)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: diff state at T1: %w", err)
	}
	atT2, err := p.entityStateAsOf(ctx, subject, r.To)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: diff state at T2: %w", err)
	}

	return &interfaces.StateDiff{
		Subject: eid,
		T1:      r.From,
		T2:      r.To,
		Changes: computeAttributeChanges(atT1, atT2),
	}, nil
}

// GetTimeline returns a merged, time-ordered change-event stream across the
// supplied subjects over the time range. This story delivers state-change events
// (entity state and absence observations) and same-as-change events (same-as edge
// observations). Drift and apply-outcome events are deferred per ADR-022 §9.
func (p *SQLiteEntityGraphProvider) GetTimeline(ctx context.Context, eids []interfaces.EIDRef, r interfaces.TimeRange) ([]*interfaces.TimelineEvent, error) {
	if len(eids) == 0 {
		return nil, nil
	}

	var events []*interfaces.TimelineEvent

	for _, eid := range eids {
		subject := eid.String()

		// State and absence observations for this subject.
		srows, err := p.db.QueryContext(ctx, `
			SELECT l.id, l.source, l.observed_at, l.kind, pc.payload
			FROM eg_observation_log l
			JOIN eg_payload_content pc ON pc.payload_hash = l.payload_hash
			WHERE l.subject = ?
			  AND l.kind IN ('state', 'absence')
			  AND l.observed_at >= ?
			  AND l.observed_at <= ?
			ORDER BY l.id ASC`,
			subject, rfc3339(r.From), rfc3339(r.To),
		)
		if err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: timeline scan for %s: %w", subject, err)
		}

		for srows.Next() {
			var id int64
			var source, observedAt, kind, payloadJSON string
			if err := srows.Scan(&id, &source, &observedAt, &kind, &payloadJSON); err != nil {
				_ = srows.Close()
				return nil, fmt.Errorf("entitygraph/sqlite: scan timeline row: %w", err)
			}
			var payload map[string]interface{}
			if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
				payload = map[string]interface{}{}
			}
			oa, _ := time.Parse(time.RFC3339Nano, observedAt)
			events = append(events, &interfaces.TimelineEvent{
				Subject:    eid,
				OccurredAt: oa,
				Kind:       "state-change",
				Detail: map[string]interface{}{
					"source":           source,
					"observation_kind": kind,
					"version":          id,
					"payload":          payload,
				},
			})
		}
		if err := srows.Err(); err != nil {
			_ = srows.Close()
			return nil, fmt.Errorf("entitygraph/sqlite: iterate timeline rows for %s: %w", subject, err)
		}
		_ = srows.Close()

		// Same-as edge observations involving this subject (group-membership changes).
		saRows, err := p.db.QueryContext(ctx, `
			SELECT l.id, l.observed_at, l.kind, l.subject
			FROM eg_observation_log l
			WHERE (l.subject LIKE ? ESCAPE '\' OR l.subject LIKE ? ESCAPE '\')
			  AND l.observed_at >= ?
			  AND l.observed_at <= ?
			ORDER BY l.id ASC`,
			"same-as|"+escapeLIKE(subject)+"|%",
			"same-as|%|"+escapeLIKE(subject),
			rfc3339(r.From), rfc3339(r.To),
		)
		if err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: timeline same-as scan for %s: %w", subject, err)
		}

		for saRows.Next() {
			var id int64
			var observedAt, kind, edgeSubject string
			if err := saRows.Scan(&id, &observedAt, &kind, &edgeSubject); err != nil {
				_ = saRows.Close()
				return nil, fmt.Errorf("entitygraph/sqlite: scan same-as timeline row: %w", err)
			}
			oa, _ := time.Parse(time.RFC3339Nano, observedAt)
			_, fromSubj, toSubj, _ := parseEdgeSubject(edgeSubject)
			events = append(events, &interfaces.TimelineEvent{
				Subject:    eid,
				OccurredAt: oa,
				Kind:       "same-as-change",
				Detail: map[string]interface{}{
					"edge_subject":     edgeSubject,
					"from":             fromSubj,
					"to":               toSubj,
					"observation_kind": kind,
					"version":          id,
				},
			})
		}
		if err := saRows.Err(); err != nil {
			_ = saRows.Close()
			return nil, fmt.Errorf("entitygraph/sqlite: iterate same-as timeline rows for %s: %w", subject, err)
		}
		_ = saRows.Close()
	}

	// Merge all events into a single time-ordered stream.
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			vi, _ := events[i].Detail["version"].(int64)
			vj, _ := events[j].Detail["version"].(int64)
			return vi < vj
		}
		return events[i].OccurredAt.Before(events[j].OccurredAt)
	})

	return events, nil
}

// Watch is implemented by a later story.
func (p *SQLiteEntityGraphProvider) Watch(_ context.Context, _ interfaces.WatchFilter, _ string) (<-chan interfaces.WatchEvent, error) {
	return nil, interfaces.ErrNotImplemented
}
