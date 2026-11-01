// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"

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
//
// Kinds that never project into entity state — desired-state, drift-diff,
// lifecycle and apply-outcome — are excluded from the per-source "latest row"
// selection as well as from the result. Without that exclusion an apply-outcome
// or drift-diff row appended after the state row would win MAX(id) and hide the
// source's state from every as-of read, mirroring the eg_entity_current rule.
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
		        AND kind NOT IN ('desired-state', 'drift-diff', 'lifecycle', 'apply-outcome')
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
// supplied subjects over the time range. Delivers state-change events (entity
// state and absence observations), same-as-change events (same-as edge
// observations), and apply-outcome events (ObservationKindApplyOutcome records
// written by handleConfigAppliedEvent, ADR-022 §6, Issue #3375).
func (p *SQLiteEntityGraphProvider) GetTimeline(ctx context.Context, eids []interfaces.EIDRef, r interfaces.TimeRange) ([]*interfaces.TimelineEvent, error) {
	if len(eids) == 0 {
		return nil, nil
	}

	cut := interfaces.NewTenantCut(r.TenantFilter, r.TenantSubtreeIDs)

	// The cut is constant for the call, so one answer per subject holds for every
	// matched subject and every repeated same-as peer. Errors are never cached.
	visibility := make(map[string]bool)
	visibleOnce := func(subject string) (bool, error) {
		if v, ok := visibility[subject]; ok {
			return v, nil
		}
		v, err := p.subjectVisible(ctx, cut, subject)
		if err != nil {
			return false, err
		}
		visibility[subject] = v
		return v, nil
	}
	var events []*interfaces.TimelineEvent

	for _, eid := range eids {
		subject := eid.String()

		// State, absence, and apply-outcome observations for this subject.
		srows, err := p.db.QueryContext(ctx, `
			SELECT l.id, l.source, l.observed_at, l.kind, pc.payload
			FROM eg_observation_log l
			JOIN eg_payload_content pc ON pc.payload_hash = l.payload_hash
			WHERE l.subject = ?
			  AND l.kind IN ('state', 'absence', 'apply-outcome')
			  AND l.observed_at >= ?
			  AND l.observed_at <= ?
			ORDER BY l.id DESC
			LIMIT ?`,
			subject, rfc3339(r.From), rfc3339(r.To), interfaces.MaxTimelineEvents+1,
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
			eventKind := "state-change"
			if kind == "apply-outcome" {
				eventKind = "apply-outcome"
			}
			events = append(events, &interfaces.TimelineEvent{
				Subject:    eid,
				OccurredAt: oa,
				Kind:       eventKind,
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
		// The match is exact and case-sensitive (SQLite LIKE folds case, which would
		// match another tenant's eid differing only in case), so it compares the
		// subject's own text with substr.
		sameAsPrefix := "same-as|" + subject + "|"
		sameAsSuffix := "|" + subject
		saRows, err := p.db.QueryContext(ctx, `
			SELECT l.id, l.observed_at, l.kind, l.subject
			FROM eg_observation_log l
			WHERE ((substr(l.subject, 1, ?) = ?) OR (substr(l.subject, 1, 8) = 'same-as|' AND substr(l.subject, -?) = ?))
			  AND l.observed_at >= ?
			  AND l.observed_at <= ?
			ORDER BY l.id DESC
			LIMIT ?`,
			utf8.RuneCountInString(sameAsPrefix), sameAsPrefix,
			utf8.RuneCountInString(sameAsSuffix), sameAsSuffix,
			rfc3339(r.From), rfc3339(r.To), interfaces.MaxTimelineEvents+1,
		)
		if err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: timeline same-as scan for %s: %w", subject, err)
		}

		var saEvents []*interfaces.TimelineEvent
		var saPeers []string
		for saRows.Next() {
			var id int64
			var observedAt, kind, edgeSubject string
			if err := saRows.Scan(&id, &observedAt, &kind, &edgeSubject); err != nil {
				_ = saRows.Close()
				return nil, fmt.Errorf("entitygraph/sqlite: scan same-as timeline row: %w", err)
			}
			oa, _ := time.Parse(time.RFC3339Nano, observedAt)
			_, fromSubj, toSubj, _ := parseEdgeSubject(edgeSubject)
			// Only an edge with the subject itself as an endpoint belongs here.
			if fromSubj != subject && toSubj != subject {
				continue
			}
			peer := fromSubj
			if fromSubj == subject {
				peer = toSubj
			}
			saEvents = append(saEvents, &interfaces.TimelineEvent{
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
			saPeers = append(saPeers, peer)
		}
		if err := saRows.Err(); err != nil {
			_ = saRows.Close()
			return nil, fmt.Errorf("entitygraph/sqlite: iterate same-as timeline rows for %s: %w", subject, err)
		}
		_ = saRows.Close()

		// The correlator writes cross-tenant same-as edges by design; an event
		// carries both ends, so it is dropped unless the matched endpoint and the
		// peer are both inside the cut. The checks run after the rows are closed so
		// they never hold a second connection.
		selfVisible, err := visibleOnce(subject)
		if err != nil {
			return nil, err
		}
		for i, ev := range saEvents {
			if !selfVisible {
				break
			}
			visible, err := visibleOnce(saPeers[i])
			if err != nil {
				return nil, err
			}
			if visible {
				events = append(events, ev)
			}
		}

		// Keep only the newest events so memory stays bounded across subjects.
		events = newestTimelineEvents(events)
	}

	return newestTimelineEvents(events), nil
}

// subjectVisible reports whether subject is owned inside cut. It is true for an
// inactive cut; a subject with no entity index row is outside an active cut, as
// in applyTenantCut.
func (p *SQLiteEntityGraphProvider) subjectVisible(ctx context.Context, cut interfaces.TenantCut, subject string) (bool, error) {
	if !cut.Active() {
		return true, nil
	}
	var owningTenant string
	err := p.db.QueryRowContext(ctx,
		`SELECT owning_tenant FROM eg_entity_index WHERE subject = ?`, subject,
	).Scan(&owningTenant)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("entitygraph/sqlite: timeline tenant cut for %s: %w", subject, err)
	}
	return cut.Visible(owningTenant), nil
}

// newestTimelineEvents orders events oldest first and keeps the newest
// MaxTimelineEvents+1 of them; the extra event tells the caller the stream was
// cut.
func newestTimelineEvents(events []*interfaces.TimelineEvent) []*interfaces.TimelineEvent {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			vi, _ := events[i].Detail["version"].(int64)
			vj, _ := events[j].Detail["version"].(int64)
			return vi < vj
		}
		return events[i].OccurredAt.Before(events[j].OccurredAt)
	})
	if len(events) > interfaces.MaxTimelineEvents+1 {
		events = events[len(events)-(interfaces.MaxTimelineEvents+1):]
	}
	return events
}
