// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
)

// computeAttributeChanges returns the set of attributes that differ between two
// merged state snapshots. Either snapshot may be nil (entity did not exist at
// that time). Attributes present in only one snapshot are included (Before or
// After nil). The result is sorted by attribute name for deterministic output.
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

// entityStateAsOf projects the merged entity state at or before asOf from the
// observation log. Returns nil when no state observations existed at that time.
func (p *DatabaseEntityGraphProvider) entityStateAsOf(ctx context.Context, subject string, asOf time.Time) (map[string]interface{}, error) {
	rows, err := p.queryCurrentRows(ctx, subject, &asOf)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
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
	return mergeAttributes(entries), nil
}

// Diff computes the attribute delta between two as-of states of a subject. It
// projects the merged entity state at r.From and r.To, then returns the set of
// attributes whose values differ.
func (p *DatabaseEntityGraphProvider) Diff(ctx context.Context, eid interfaces.EIDRef, r interfaces.TimeRange) (*interfaces.StateDiff, error) {
	subject := eid.String()

	atT1, err := p.entityStateAsOf(ctx, subject, r.From)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: diff state at T1: %w", err)
	}
	atT2, err := p.entityStateAsOf(ctx, subject, r.To)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: diff state at T2: %w", err)
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
func (p *DatabaseEntityGraphProvider) GetTimeline(ctx context.Context, eids []interfaces.EIDRef, r interfaces.TimeRange) ([]*interfaces.TimelineEvent, error) {
	if len(eids) == 0 {
		return nil, nil
	}

	fromStr := r.From.UTC().Format(time.RFC3339Nano)
	toStr := r.To.UTC().Format(time.RFC3339Nano)

	cut := interfaces.NewTenantCut(r.TenantFilter, r.TenantSubtreeIDs)
	var events []*interfaces.TimelineEvent

	for _, eid := range eids {
		subject := eid.String()

		// State, absence, and apply-outcome observations for this subject.
		srows, err := p.db.QueryContext(ctx, `
			SELECT l.id, l.source, l.observed_at, l.kind, p.payload_json
			FROM eg_observation_log l
			JOIN eg_payload_content p ON p.content_hash = l.payload_hash
			WHERE l.subject = $1
			  AND l.kind IN ('state', 'absence', 'apply-outcome')
			  AND l.observed_at >= $2
			  AND l.observed_at <= $3
			ORDER BY l.id DESC
			LIMIT $4`,
			subject, fromStr, toStr, interfaces.MaxTimelineEvents+1,
		)
		if err != nil {
			return nil, fmt.Errorf("entitygraph/database: timeline scan for %s: %w", subject, err)
		}

		for srows.Next() {
			var id int64
			var source, observedAt, kind, payloadJSON string
			if err := srows.Scan(&id, &source, &observedAt, &kind, &payloadJSON); err != nil {
				_ = srows.Close()
				return nil, fmt.Errorf("entitygraph/database: scan timeline row: %w", err)
			}
			var payload map[string]interface{}
			if payloadJSON != "" {
				if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
					payload = map[string]interface{}{}
				}
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
			return nil, fmt.Errorf("entitygraph/database: iterate timeline rows for %s: %w", subject, err)
		}
		_ = srows.Close()

		// Same-as edge observations involving this subject (group-membership changes).
		saRows, err := p.db.QueryContext(ctx, `
			SELECT l.id, l.observed_at, l.kind, l.subject
			FROM eg_observation_log l
			WHERE (l.subject LIKE $1 ESCAPE '\' OR l.subject LIKE $2 ESCAPE '\')
			  AND l.observed_at >= $3
			  AND l.observed_at <= $4
			ORDER BY l.id DESC
			LIMIT $5`,
			"same-as|"+escapeLIKE(subject)+"|%",
			"same-as|%|"+escapeLIKE(subject),
			fromStr, toStr, interfaces.MaxTimelineEvents+1,
		)
		if err != nil {
			return nil, fmt.Errorf("entitygraph/database: timeline same-as scan for %s: %w", subject, err)
		}

		var saEvents []*interfaces.TimelineEvent
		var saPeers []string
		for saRows.Next() {
			var id int64
			var observedAt, kind, edgeSubject string
			if err := saRows.Scan(&id, &observedAt, &kind, &edgeSubject); err != nil {
				_ = saRows.Close()
				return nil, fmt.Errorf("entitygraph/database: scan same-as timeline row: %w", err)
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
			return nil, fmt.Errorf("entitygraph/database: iterate same-as timeline rows for %s: %w", subject, err)
		}
		_ = saRows.Close()

		// The correlator writes cross-tenant same-as edges by design; an event
		// carries both ends, so it is dropped unless the matched endpoint and the
		// peer are both inside the cut. The checks run after the rows are closed so
		// they never hold a second connection.
		selfVisible, err := p.subjectVisible(ctx, cut, subject)
		if err != nil {
			return nil, err
		}
		for i, ev := range saEvents {
			if !selfVisible {
				break
			}
			visible, err := p.subjectVisible(ctx, cut, saPeers[i])
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
func (p *DatabaseEntityGraphProvider) subjectVisible(ctx context.Context, cut interfaces.TenantCut, subject string) (bool, error) {
	if !cut.Active() {
		return true, nil
	}
	var owningTenant string
	err := p.db.QueryRowContext(ctx,
		`SELECT owning_tenant FROM eg_entity_index WHERE subject = $1`, subject,
	).Scan(&owningTenant)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("entitygraph/database: timeline tenant cut for %s: %w", subject, err)
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
