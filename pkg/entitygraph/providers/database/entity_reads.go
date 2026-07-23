// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

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

// currentRow is a scanned per-source current-state row joined with its payload.
type currentRow struct {
	source      string
	sourceClass string
	kind        string
	confidence  string
	observedAt  time.Time
	recordedAt  time.Time
	payloadHash string
	payload     map[string]interface{}
}

// GetEntity returns the merged current state, provenance, and freshness for an
// entity. Visibility is governed by eg_entity_index.owning_tenant (the
// current-ownership projection), not by the ingest-time tenant_path columns
// on individual source rows (ADR-023 §111-119).
func (p *DatabaseEntityGraphProvider) GetEntity(ctx context.Context, eid interfaces.EIDRef, opts interfaces.GetEntityOpts) (*types.EntityView, error) {
	subject := eid.String()

	// Apply the tenant cut via the current-ownership index — the only
	// access-control axis. A filtered-out entity is indistinguishable from a
	// missing one to the caller, regardless of ingest-time tenant_path values.
	if opts.TenantFilter != "" {
		var owningTenant string
		err := p.db.QueryRowContext(ctx,
			`SELECT owning_tenant FROM eg_entity_index WHERE subject = $1`, subject,
		).Scan(&owningTenant)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("entitygraph/database: lookup entity index: %w", err)
		}
		if !tenantVisible(owningTenant, opts.TenantFilter) {
			return nil, errNotFound
		}
	}

	// Fetch all per-source current rows without tenant filtering — visibility
	// has already been confirmed via the index lookup above, so all source
	// rows for the subject are accessible to the authorized caller.
	rows, err := p.queryCurrentRows(ctx, subject, "", opts.AsOf)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}

	entries := make([]sourceEntry, len(rows))
	sources := make([]types.Observation, len(rows))
	for i, r := range rows {
		entries[i] = sourceEntry{
			source:      r.source,
			sourceClass: r.sourceClass,
			observedAt:  r.observedAt,
			payloadHash: r.payloadHash,
			payload:     r.payload,
		}
		sources[i] = types.Observation{
			Source:     r.source,
			ObservedAt: r.observedAt,
			RecordedAt: r.recordedAt,
			Subject:    subject,
			Kind:       types.ObservationKind(r.kind),
			Confidence: types.Confidence(r.confidence),
			Payload:    r.payload,
		}
	}

	merged := mergeAttributes(entries)
	win := winningSourceIdx(entries)

	entityKind := stringAttr(merged, "entity_kind", "kind")
	if entityKind == "" {
		entityKind = subjectEntityKind(subject)
	}

	entity := &types.Entity{
		EID:          eid,
		Kind:         entityKind,
		Attributes:   merged,
		OwningTenant: stringAttr(merged, "owning_tenant", "tenant_path"),
	}

	view := &types.EntityView{
		Entity:  entity,
		Sources: sources,
		Freshness: types.Freshness{
			ObservedAt: rows[win].observedAt,
			RecordedAt: rows[win].recordedAt,
		},
	}
	return view, nil
}

// queryCurrentRows returns the per-source current-state rows for a subject.
// When asOf is nil it reads the eg_entity_current projection; when asOf is set
// it reconstructs the latest observation per source at or before asOf from the
// immutable log. The tenant filter, when non-empty, restricts rows to the
// tenant path or its subtree.
func (p *DatabaseEntityGraphProvider) queryCurrentRows(ctx context.Context, subject, tenantFilter string, asOf *time.Time) ([]currentRow, error) {
	var query string
	args := []interface{}{subject}

	if asOf == nil {
		query = `SELECT c.source, c.source_class, c.kind, c.confidence, c.observed_at, c.recorded_at, c.payload_hash, p.payload_json
			 FROM eg_entity_current c
			 JOIN eg_payload_content p ON p.content_hash = c.payload_hash
			 WHERE c.subject = $1`
		if tenantFilter != "" {
			query += ` AND (c.tenant_path = $2 OR c.tenant_path LIKE $3)`
			args = append(args, tenantFilter, tenantFilter+"/%")
		}
	} else {
		// DISTINCT ON keeps the newest log row per source at or before asOf.
		query = `SELECT DISTINCT ON (l.source) l.source, l.source_class, l.kind, l.confidence, l.observed_at, l.recorded_at, l.payload_hash, p.payload_json
			 FROM eg_observation_log l
			 JOIN eg_payload_content p ON p.content_hash = l.payload_hash
			 WHERE l.subject = $1 AND l.observed_at <= $2`
		args = append(args, asOf.UTC().Format(time.RFC3339Nano))
		if tenantFilter != "" {
			query += ` AND (l.tenant_path = $3 OR l.tenant_path LIKE $4)`
			args = append(args, tenantFilter, tenantFilter+"/%")
		}
		query += ` ORDER BY l.source, l.observed_at DESC, l.id DESC`
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: query current rows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []currentRow
	for rows.Next() {
		var (
			r                      currentRow
			observedAt, recordedAt string
			pjson                  string
		)
		if err := rows.Scan(&r.source, &r.sourceClass, &r.kind, &r.confidence, &observedAt, &recordedAt, &r.payloadHash, &pjson); err != nil {
			return nil, fmt.Errorf("entitygraph/database: scan current row: %w", err)
		}
		r.observedAt, _ = time.Parse(time.RFC3339Nano, observedAt)
		r.recordedAt, _ = time.Parse(time.RFC3339Nano, recordedAt)
		if pjson != "" {
			if err := json.Unmarshal([]byte(pjson), &r.payload); err != nil {
				return nil, fmt.Errorf("entitygraph/database: unmarshal current payload: %w", err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/database: iterate current rows: %w", err)
	}
	return out, nil
}

// QueryEntities returns entities matching the filter, paged. The page token is
// an integer offset; NextToken is empty on the final page. Kind and tenant
// filters are applied against the entity index; the tenant filter matches the
// exact tenant path or any descendant.
func (p *DatabaseEntityGraphProvider) QueryEntities(ctx context.Context, filter interfaces.EntityFilter, page interfaces.PageToken) (*interfaces.EntityPage, error) {
	pageSize := page.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	offset := 0
	if page.Token != "" {
		v, err := strconv.Atoi(page.Token)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("entitygraph/database: invalid page token %q", page.Token)
		}
		offset = v
	}

	var conds []string
	var args []interface{}
	n := 1
	if filter.Kind != "" {
		conds = append(conds, fmt.Sprintf("entity_kind = $%d", n))
		args = append(args, filter.Kind)
		n++
	}
	if filter.TenantFilter != "" {
		conds = append(conds, fmt.Sprintf("(owning_tenant = $%d OR owning_tenant LIKE $%d)", n, n+1))
		args = append(args, filter.TenantFilter, filter.TenantFilter+"/%")
		n += 2
	}

	query := "SELECT subject FROM eg_entity_index"
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY subject LIMIT $%d OFFSET $%d", n, n+1)
	args = append(args, pageSize+1, offset)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: query entities: %w", err)
	}
	subjects := make([]string, 0, pageSize+1)
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("entitygraph/database: scan subject: %w", err)
		}
		subjects = append(subjects, s)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("entitygraph/database: iterate subjects: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("entitygraph/database: close subjects rows: %w", err)
	}

	nextToken := ""
	if len(subjects) > pageSize {
		subjects = subjects[:pageSize]
		nextToken = strconv.Itoa(offset + pageSize)
	}

	entities := make([]*types.EntityView, 0, len(subjects))
	for _, s := range subjects {
		eid, err := types.ParseEID(s)
		if err != nil {
			continue
		}
		ev, err := p.GetEntity(ctx, eid, interfaces.GetEntityOpts{
			TenantFilter: filter.TenantFilter,
			AsOf:         filter.AsOf,
		})
		if err != nil {
			if errors.Is(err, errNotFound) {
				continue
			}
			return nil, err
		}
		entities = append(entities, ev)
	}

	return &interfaces.EntityPage{Entities: entities, NextToken: nextToken}, nil
}

// ResolveIdentity returns the best-known EIDs for the supplied device/object
// identity claims by matching the entity index. Any claim that matches is
// sufficient (OR semantics); results are de-duplicated by the index.
func (p *DatabaseEntityGraphProvider) ResolveIdentity(ctx context.Context, claims interfaces.IdentityClaims) ([]interfaces.EIDRef, error) {
	var conds []string
	var args []interface{}
	n := 1

	addEq := func(col, val string) {
		if val != "" {
			conds = append(conds, fmt.Sprintf("%s = $%d", col, n))
			args = append(args, val)
			n++
		}
	}
	addEq("hostname", claims.Hostname)
	addEq("machine_sid", claims.MachineSID)
	addEq("dir_object_guid", claims.DirectoryObjectGUID)
	addEq("serial_number", claims.SerialNumber)
	addEq("cloud_object_id", claims.CloudObjectID)
	for _, mac := range claims.MACAddrs {
		if mac == "" {
			continue
		}
		// mac_addrs is a comma-joined list; match as a delimited token to avoid
		// unanchored substring collisions (e.g. "00:11" matching "00:11:22:33:44:55").
		conds = append(conds, fmt.Sprintf(
			"(mac_addrs = $%d OR mac_addrs LIKE $%d OR mac_addrs LIKE $%d OR mac_addrs LIKE $%d)",
			n, n+1, n+2, n+3,
		))
		args = append(args, mac, mac+",%", "%,"+mac, "%,"+mac+",%")
		n += 4
	}

	if len(conds) == 0 {
		return nil, nil
	}

	query := "SELECT DISTINCT subject FROM eg_entity_index WHERE " + strings.Join(conds, " OR ")
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: resolve identity: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var eids []interfaces.EIDRef
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("entitygraph/database: scan identity subject: %w", err)
		}
		eid, err := types.ParseEID(s)
		if err != nil {
			continue
		}
		eids = append(eids, eid)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/database: iterate identity subjects: %w", err)
	}
	return eids, nil
}

// RebuildProjections rebuilds the entity index projection from the durable
// current-state table. It clears the index and replays every distinct subject
// through the same projection logic used during ingestion, all within one
// transaction.
func (p *DatabaseEntityGraphProvider) RebuildProjections(ctx context.Context) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("entitygraph/database: begin rebuild tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM eg_entity_index`); err != nil {
		return fmt.Errorf("entitygraph/database: clear entity index: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT subject FROM eg_entity_current`)
	if err != nil {
		return fmt.Errorf("entitygraph/database: list subjects for rebuild: %w", err)
	}
	var subjects []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			_ = rows.Close()
			return fmt.Errorf("entitygraph/database: scan rebuild subject: %w", err)
		}
		subjects = append(subjects, s)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("entitygraph/database: iterate rebuild subjects: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("entitygraph/database: close rebuild subjects: %w", err)
	}

	for _, s := range subjects {
		if subjectKind(s) != "entity" {
			continue
		}
		if err := rebuildEntityIndex(ctx, tx, s); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("entitygraph/database: commit rebuild: %w", err)
	}
	return nil
}

// --- Deferred read operations ---
//
// The following reads share the observation-log / projection substrate above
// but are scheduled in later rounds of the entity graph epic. They satisfy the
// EntityGraphProvider contract at compile time and return ErrNotImplemented
// until their round lands.

// GetDesiredState returns the desired state and originating config revision.
func (p *DatabaseEntityGraphProvider) GetDesiredState(_ context.Context, _ interfaces.EIDRef) (*types.DesiredStateView, error) {
	return nil, interfaces.ErrNotImplemented
}

// GetDriftState returns the persisted drift-diff for a managed entity.
func (p *DatabaseEntityGraphProvider) GetDriftState(_ context.Context, _ interfaces.EIDRef) (*interfaces.DriftState, error) {
	return nil, interfaces.ErrNotImplemented
}

// GetEdges returns edges matching the filter.
func (p *DatabaseEntityGraphProvider) GetEdges(_ context.Context, _ interfaces.EdgeFilter) ([]*interfaces.EdgeView, error) {
	return nil, interfaces.ErrNotImplemented
}

// GetNeighborhood returns a depth-bounded connected subgraph starting at eid.
func (p *DatabaseEntityGraphProvider) GetNeighborhood(_ context.Context, _ interfaces.EIDRef, _ []string, _ types.TraversalDirection, _ int) (*types.Neighborhood, error) {
	return nil, interfaces.ErrNotImplemented
}

// GetHistory returns the versioned observation log for a subject over a range.
func (p *DatabaseEntityGraphProvider) GetHistory(_ context.Context, _ interfaces.EIDRef, _ interfaces.TimeRange) ([]*interfaces.ObservationRecord, error) {
	return nil, interfaces.ErrNotImplemented
}

// Diff returns the attribute delta between two points in time for a subject.
func (p *DatabaseEntityGraphProvider) Diff(_ context.Context, _ interfaces.EIDRef, _ interfaces.TimeRange) (*interfaces.StateDiff, error) {
	return nil, interfaces.ErrNotImplemented
}

// GetTimeline returns a merged change-event stream for the given subjects.
func (p *DatabaseEntityGraphProvider) GetTimeline(_ context.Context, _ []interfaces.EIDRef, _ interfaces.TimeRange) ([]*interfaces.TimelineEvent, error) {
	return nil, interfaces.ErrNotImplemented
}

// ListDrifted returns entities with active drift matching the filter.
func (p *DatabaseEntityGraphProvider) ListDrifted(_ context.Context, _ interfaces.DriftFilter) ([]*interfaces.DriftState, error) {
	return nil, interfaces.ErrNotImplemented
}

// Watch returns a durable, cursor-replayable change feed.
func (p *DatabaseEntityGraphProvider) Watch(_ context.Context, _ interfaces.WatchFilter, _ string) (<-chan interfaces.WatchEvent, error) {
	return nil, interfaces.ErrNotImplemented
}

// UpdateDriftLifecycle records a workflow annotation on a drift record.
func (p *DatabaseEntityGraphProvider) UpdateDriftLifecycle(_ context.Context, _ interfaces.DriftLifecycleUpdate) error {
	return interfaces.ErrNotImplemented
}
