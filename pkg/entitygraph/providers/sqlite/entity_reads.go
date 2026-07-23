// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// defaultPageSize bounds QueryEntities when the caller supplies no page size.
const defaultPageSize = 100

// tenantVisible reports whether an entity owned by owningTenant is visible to a
// caller scoped to tenantFilter. An empty filter sees everything; otherwise the
// owning tenant must equal the filter or be a strict descendant separated by
// '/'. The separator is required to avoid matching a sibling tenant whose name
// merely shares a common prefix (e.g. filter "root/msp-a" must NOT match
// owningTenant "root/msp-ab"). This is the sole access-control axis (ADR-023 §111-119).
func tenantVisible(owningTenant, tenantFilter string) bool {
	if tenantFilter == "" {
		return true
	}
	return owningTenant == tenantFilter || strings.HasPrefix(owningTenant, tenantFilter+"/")
}

// GetEntity returns the current entity state, provenance, and freshness,
// applying the caller's tenant cut and source-precedence attribute merge.
func (p *SQLiteEntityGraphProvider) GetEntity(ctx context.Context, eid interfaces.EIDRef, opts interfaces.GetEntityOpts) (*types.EntityView, error) {
	subject := eid.String()

	var entityKind, owningTenant string
	err := p.db.QueryRowContext(ctx,
		`SELECT entity_kind, owning_tenant FROM eg_entity_index WHERE subject = ?`,
		subject,
	).Scan(&entityKind, &owningTenant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("entitygraph/sqlite: entity %s: %w", subject, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: lookup index: %w", err)
	}

	// Apply the tenant cut. A filtered-out entity is indistinguishable from a
	// missing one to the caller.
	if !tenantVisible(owningTenant, opts.TenantFilter) {
		return nil, fmt.Errorf("entitygraph/sqlite: entity %s: %w", subject, ErrNotFound)
	}

	rows, err := p.db.QueryContext(ctx,
		`SELECT c.source, c.source_class, c.kind, c.confidence, c.observed_at, c.recorded_at, c.payload_hash, p.payload
		 FROM eg_entity_current c
		 JOIN eg_payload_content p ON p.payload_hash = c.payload_hash
		 WHERE c.subject = ? AND c.kind != 'desired-state'`,
		subject,
	)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: load sources: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var (
		entries      []sourceEntry
		observations []types.Observation
	)
	for rows.Next() {
		var source, sourceClass, kind, confidence, observedAt, recordedAt, hash, payloadJSON string
		if err := rows.Scan(&source, &sourceClass, &kind, &confidence, &observedAt, &recordedAt, &hash, &payloadJSON); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: scan source: %w", err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: decode payload: %w", err)
		}
		oa, _ := time.Parse(time.RFC3339Nano, observedAt)
		ra, _ := time.Parse(time.RFC3339Nano, recordedAt)
		entries = append(entries, sourceEntry{
			source:      source,
			sourceClass: sourceClass,
			observedAt:  oa,
			payloadHash: hash,
			payload:     payload,
		})
		observations = append(observations, types.Observation{
			Source:     source,
			ObservedAt: oa,
			RecordedAt: ra,
			Subject:    subject,
			Kind:       types.ObservationKind(kind),
			Confidence: types.Confidence(confidence),
			Payload:    payload,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: iterate sources: %w", err)
	}

	// The index row exists, so there must be at least one current source; guard
	// defensively rather than index into an empty slice.
	if len(entries) == 0 {
		return nil, fmt.Errorf("entitygraph/sqlite: entity %s: %w", subject, ErrNotFound)
	}

	winIdx := winningSourceIdx(entries)
	merged := mergeAttributes(entries)

	view := &types.EntityView{
		Entity: &types.Entity{
			EID:          eid,
			Kind:         entityKind,
			Attributes:   merged,
			OwningTenant: owningTenant,
		},
		Sources: observations,
		Freshness: types.Freshness{
			ObservedAt: observations[winIdx].ObservedAt,
			RecordedAt: observations[winIdx].RecordedAt,
		},
		// CollapseGroup is wired by STORY-6; a pass-through no-op here.
		CollapseGroup: nil,
	}
	return view, nil
}

// QueryEntities returns entities matching the filter, paged via an integer
// offset encoded in the page token.
func (p *SQLiteEntityGraphProvider) QueryEntities(ctx context.Context, filter interfaces.EntityFilter, page interfaces.PageToken) (*interfaces.EntityPage, error) {
	var (
		conds []string
		args  []interface{}
	)
	if filter.Kind != "" {
		conds = append(conds, "entity_kind = ?")
		args = append(args, filter.Kind)
	}
	if filter.TenantFilter != "" {
		// Use filter+"/" to avoid matching sibling tenants that share a name prefix.
		conds = append(conds, "(owning_tenant = ? OR owning_tenant LIKE ?)")
		args = append(args, filter.TenantFilter, filter.TenantFilter+"/%")
	}

	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	pageSize := page.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	offset := 0
	if page.Token != "" {
		v, err := strconv.Atoi(page.Token)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("entitygraph/sqlite: invalid page token %q", page.Token)
		}
		offset = v
	}

	// Fetch one extra row to detect whether a further page exists.
	query := "SELECT subject, entity_kind, owning_tenant FROM eg_entity_index" + where + " ORDER BY subject LIMIT ? OFFSET ?"
	args = append(args, pageSize+1, offset)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: query entities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entities []*types.EntityView
	for rows.Next() {
		var subject, kind, tenant string
		if err := rows.Scan(&subject, &kind, &tenant); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: scan entity: %w", err)
		}
		eid, err := types.ParseEID(subject)
		if err != nil {
			// Non-EID subjects should not appear in the entity index; skip
			// rather than fail the whole page.
			continue
		}
		entities = append(entities, &types.EntityView{
			Entity: &types.Entity{
				EID:          eid,
				Kind:         kind,
				Attributes:   map[string]interface{}{},
				OwningTenant: tenant,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: iterate entities: %w", err)
	}

	nextToken := ""
	if len(entities) > pageSize {
		entities = entities[:pageSize]
		nextToken = strconv.Itoa(offset + pageSize)
	}

	return &interfaces.EntityPage{Entities: entities, NextToken: nextToken}, nil
}

// ResolveIdentity returns the EIDs whose index entry matches any of the
// supplied device/object identity claims. An empty claim set returns an empty
// result (not an error).
func (p *SQLiteEntityGraphProvider) ResolveIdentity(ctx context.Context, claims interfaces.IdentityClaims) ([]interfaces.EIDRef, error) {
	var (
		conds []string
		args  []interface{}
	)
	if claims.Hostname != "" {
		conds = append(conds, "hostname = ?")
		args = append(args, claims.Hostname)
	}
	if claims.MachineSID != "" {
		conds = append(conds, "machine_sid = ?")
		args = append(args, claims.MachineSID)
	}
	if claims.DirectoryObjectGUID != "" {
		conds = append(conds, "dir_object_guid = ?")
		args = append(args, claims.DirectoryObjectGUID)
	}
	if claims.SerialNumber != "" {
		conds = append(conds, "serial_number = ?")
		args = append(args, claims.SerialNumber)
	}
	if claims.CloudObjectID != "" {
		conds = append(conds, "cloud_object_id = ?")
		args = append(args, claims.CloudObjectID)
	}
	for _, mac := range claims.MACAddrs {
		if mac == "" {
			continue
		}
		// mac_addrs is a comma-joined list; match the MAC as a delimited token.
		conds = append(conds,
			"(mac_addrs = ? OR mac_addrs LIKE ? OR mac_addrs LIKE ? OR mac_addrs LIKE ?)")
		args = append(args, mac, mac+",%", "%,"+mac, "%,"+mac+",%")
	}

	if len(conds) == 0 {
		return nil, nil
	}

	query := "SELECT DISTINCT subject FROM eg_entity_index WHERE " + strings.Join(conds, " OR ")
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: resolve identity: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []interfaces.EIDRef
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: scan identity match: %w", err)
		}
		eid, err := types.ParseEID(subject)
		if err != nil {
			continue
		}
		result = append(result, eid)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: iterate identity matches: %w", err)
	}
	return result, nil
}

// RebuildProjections drops and rebuilds the current-state and index projections
// by replaying the observation log in sequence order. This is the recovery path
// that proves the log is the source of truth.
func (p *SQLiteEntityGraphProvider) RebuildProjections(ctx context.Context) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: begin rebuild tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM eg_entity_current`); err != nil {
		return fmt.Errorf("entitygraph/sqlite: clear current: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM eg_entity_index`); err != nil {
		return fmt.Errorf("entitygraph/sqlite: clear index: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM eg_drift_projection`); err != nil {
		return fmt.Errorf("entitygraph/sqlite: clear drift projection: %w", err)
	}

	// Collect the full log first: modernc/sqlite cannot interleave writes on a
	// transaction while a result-set cursor from the same tx is still open.
	rows, err := tx.QueryContext(ctx,
		`SELECT l.id, l.subject, l.source, l.observed_at, l.recorded_at, l.kind, l.confidence, p.payload
		 FROM eg_observation_log l
		 JOIN eg_payload_content p ON p.payload_hash = l.payload_hash
		 ORDER BY l.id ASC`,
	)
	if err != nil {
		return fmt.Errorf("entitygraph/sqlite: read log: %w", err)
	}

	type logRow struct {
		id  int64
		obs types.Observation
	}
	var logs []logRow
	for rows.Next() {
		var (
			id                                                                     int64
			subject, source, observedAt, recordedAt, kind, confidence, payloadJSON string
		)
		if err := rows.Scan(&id, &subject, &source, &observedAt, &recordedAt, &kind, &confidence, &payloadJSON); err != nil {
			_ = rows.Close()
			return fmt.Errorf("entitygraph/sqlite: scan log row: %w", err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
			_ = rows.Close()
			return fmt.Errorf("entitygraph/sqlite: decode log payload: %w", err)
		}
		oa, _ := time.Parse(time.RFC3339Nano, observedAt)
		ra, _ := time.Parse(time.RFC3339Nano, recordedAt)
		logs = append(logs, logRow{
			id: id,
			obs: types.Observation{
				Source:     source,
				ObservedAt: oa,
				RecordedAt: ra,
				Subject:    subject,
				Kind:       types.ObservationKind(kind),
				Confidence: types.Confidence(confidence),
				Payload:    payload,
			},
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("entitygraph/sqlite: iterate log: %w", err)
	}
	_ = rows.Close()

	for _, lr := range logs {
		if err := dispatchProjectionUpdate(ctx, tx, subjectKind(lr.obs.Subject), lr.obs, lr.id); err != nil {
			return fmt.Errorf("entitygraph/sqlite: replay log seq %d: %w", lr.id, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("entitygraph/sqlite: commit rebuild: %w", err)
	}
	return nil
}

// CorruptProjectionsForTesting deletes every derived projection table while
// leaving the observation log intact. Used by contract tests to verify that
// RebuildProjections genuinely recovers from corruption rather than only testing
// the idempotent no-op path. eg_drift_projection is included so that the
// drift/lifecycle replay path in RebuildProjections is exercised on recovery.
func (p *SQLiteEntityGraphProvider) CorruptProjectionsForTesting(ctx context.Context) error {
	if _, err := p.db.ExecContext(ctx, `DELETE FROM eg_entity_current`); err != nil {
		return fmt.Errorf("entitygraph/sqlite: corrupt current: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `DELETE FROM eg_entity_index`); err != nil {
		return fmt.Errorf("entitygraph/sqlite: corrupt index: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `DELETE FROM eg_drift_projection`); err != nil {
		return fmt.Errorf("entitygraph/sqlite: corrupt drift projection: %w", err)
	}
	return nil
}

// GetHistory returns the versioned observation log for a subject over a time
// range in ascending sequence order. Both state and absence observations are
// included so that source-closure events are visible in the history stream.
func (p *SQLiteEntityGraphProvider) GetHistory(ctx context.Context, eid interfaces.EIDRef, r interfaces.TimeRange) ([]*interfaces.ObservationRecord, error) {
	subject := eid.String()
	rows, err := p.db.QueryContext(ctx,
		`SELECT l.id, l.source, l.observed_at, l.recorded_at, l.kind, l.confidence, p.payload
		 FROM eg_observation_log l
		 JOIN eg_payload_content p ON p.payload_hash = l.payload_hash
		 WHERE l.subject = ? AND l.observed_at >= ? AND l.observed_at <= ?
		 ORDER BY l.id ASC`,
		subject, rfc3339(r.From), rfc3339(r.To),
	)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: get history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []*interfaces.ObservationRecord
	for rows.Next() {
		var id int64
		var source, observedAt, recordedAt, kind, confidence, payloadJSON string
		if err := rows.Scan(&id, &source, &observedAt, &recordedAt, &kind, &confidence, &payloadJSON); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: scan history row: %w", err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
			payload = map[string]interface{}{}
		}
		oa, _ := time.Parse(time.RFC3339Nano, observedAt)
		ra, _ := time.Parse(time.RFC3339Nano, recordedAt)
		records = append(records, &interfaces.ObservationRecord{
			Observation: types.Observation{
				Source:     source,
				ObservedAt: oa,
				RecordedAt: ra,
				Subject:    subject,
				Kind:       types.ObservationKind(kind),
				Confidence: types.Confidence(confidence),
				Payload:    payload,
			},
			Version: id,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: iterate history: %w", err)
	}
	return records, nil
}

// Diff is implemented by a later story.
func (p *SQLiteEntityGraphProvider) Diff(_ context.Context, _ interfaces.EIDRef, _ interfaces.TimeRange) (*interfaces.StateDiff, error) {
	return nil, interfaces.ErrNotImplemented
}

// GetTimeline is implemented by a later story.
func (p *SQLiteEntityGraphProvider) GetTimeline(_ context.Context, _ []interfaces.EIDRef, _ interfaces.TimeRange) ([]*interfaces.TimelineEvent, error) {
	return nil, interfaces.ErrNotImplemented
}

// Watch is implemented by a later story.
func (p *SQLiteEntityGraphProvider) Watch(_ context.Context, _ interfaces.WatchFilter, _ string) (<-chan interfaces.WatchEvent, error) {
	return nil, interfaces.ErrNotImplemented
}
