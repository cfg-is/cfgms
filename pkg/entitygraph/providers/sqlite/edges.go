// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

func init() {
	RegisterProjectionUpdater("edge", updateEdgeProjection)
}

// edgeKeySep is the unit-separator (ASCII 0x1F) used to join the four components
// of an edge_key. None of the component fields (EID strings, edge type names,
// source identifiers) contain control characters, so 0x1F is an unambiguous
// delimiter.
const edgeKeySep = "\x1f"

// edgeProjectionKey builds the PRIMARY KEY for an eg_edge_projection row.
// Uniqueness: one row per (from, edge_type, to, source).
func edgeProjectionKey(fromSubject, edgeType, toSubject, source string) string {
	return fromSubject + edgeKeySep + edgeType + edgeKeySep + toSubject + edgeKeySep + source
}

// parseEdgeSubject parses an edge subject string into its constituent parts.
// The expected format is "edge_type|from_eid|to_eid" (pipe-delimited, three fields).
func parseEdgeSubject(subject string) (edgeType, fromSubject, toSubject string, err error) {
	parts := strings.SplitN(subject, "|", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("entitygraph/sqlite: invalid edge subject %q: expected edge_type|from|to", subject)
	}
	return parts[0], parts[1], parts[2], nil
}

// updateEdgeProjection is the "edge" subject-kind projection updater registered
// via init(). It upserts the per-source edge projection row and materializes
// placeholder nodes in eg_entity_index for any referenced EID that has no
// prior observation (ADR-022 §2). Absence observations retract the edge.
func updateEdgeProjection(ctx context.Context, tx *sql.Tx, obs types.Observation, logSeq int64) error {
	if obs.Kind == types.ObservationKindAbsence {
		edgeType, fromSubject, toSubject, err := parseEdgeSubject(obs.Subject)
		if err != nil {
			return nil // non-edge subject in absence — skip
		}
		key := edgeProjectionKey(fromSubject, edgeType, toSubject, obs.Source)
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM eg_edge_projection WHERE edge_key = ?`, key,
		); err != nil {
			return fmt.Errorf("entitygraph/sqlite: delete edge projection for absence: %w", err)
		}
		return nil
	}
	edgeType, fromSubject, toSubject, err := parseEdgeSubject(obs.Subject)
	if err != nil {
		return err
	}

	hash, err := payloadHash(obs.Payload)
	if err != nil {
		return err
	}
	sc := resolveSourceClass(obs.Source)
	key := edgeProjectionKey(fromSubject, edgeType, toSubject, obs.Source)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_edge_projection
			(edge_key, edge_type, from_subject, to_subject, source, source_class, observed_at, payload_hash, log_seq)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(edge_key) DO UPDATE SET
			source_class = excluded.source_class,
			observed_at  = excluded.observed_at,
			payload_hash = excluded.payload_hash,
			log_seq      = excluded.log_seq`,
		key, edgeType, fromSubject, toSubject, obs.Source, string(sc),
		rfc3339(obs.ObservedAt), hash, logSeq,
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: upsert edge projection: %w", err)
	}

	// Materialize placeholder nodes for endpoint EIDs not yet in eg_entity_index.
	for _, subject := range []string{fromSubject, toSubject} {
		if err := materializePlaceholderNode(ctx, tx, subject); err != nil {
			return err
		}
	}
	return nil
}

// materializePlaceholderNode inserts a stub eg_entity_index row for subject if
// one does not already exist. The placeholder has empty owning_tenant and
// identity fields; a later observation enriches the same row (no duplicates).
// Subjects that are not valid EIDs are silently skipped.
func materializePlaceholderNode(ctx context.Context, tx *sql.Tx, subject string) error {
	eid, err := types.ParseEID(subject)
	if err != nil {
		return nil // non-EID endpoint — no placeholder
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO eg_entity_index
			(subject, entity_kind, owning_tenant, hostname, mac_addrs, machine_sid, dir_object_guid, serial_number, cloud_object_id)
		 VALUES(?, ?, '', '', '', '', '', '', '')`,
		subject, eid.AuthorityType(),
	); err != nil {
		return fmt.Errorf("entitygraph/sqlite: materialize placeholder for %s: %w", subject, err)
	}
	return nil
}

// GetEdges returns edges matching the filter. Tenant filtering is applied via a
// JOIN against eg_entity_index (current endpoint ownership), never via any
// tenant column on the edge row itself (ADR-023 §4 / Story-3 AC 5).
//
// One EdgeView is returned per eg_edge_projection row (per source). Multiple
// sources asserting the same (from, to, type) edge produce multiple EdgeViews.
func (p *SQLiteEntityGraphProvider) GetEdges(ctx context.Context, filter interfaces.EdgeFilter) ([]*interfaces.EdgeView, error) {
	var conds []string
	var args []interface{}

	if filter.FromEID != nil {
		conds = append(conds, "ep.from_subject = ?")
		args = append(args, filter.FromEID.String())
	}
	if filter.ToEID != nil {
		conds = append(conds, "ep.to_subject = ?")
		args = append(args, filter.ToEID.String())
	}
	if len(filter.Types) > 0 {
		ph := strings.Repeat("?,", len(filter.Types))
		ph = ph[:len(ph)-1] // strip trailing comma
		conds = append(conds, "ep.edge_type IN ("+ph+")")
		for _, et := range filter.Types {
			args = append(args, et)
		}
	}
	if filter.Source != "" {
		conds = append(conds, "ep.source = ?")
		args = append(args, filter.Source)
	}
	if filter.TenantFilter != "" {
		conds = append(conds,
			"(fi.owning_tenant = ? OR fi.owning_tenant LIKE ?)",
			"(ti.owning_tenant = ? OR ti.owning_tenant LIKE ?)",
		)
		args = append(args, filter.TenantFilter, filter.TenantFilter+"/%")
		args = append(args, filter.TenantFilter, filter.TenantFilter+"/%")
	}

	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	q := `SELECT ep.from_subject, ep.to_subject, ep.edge_type, ep.source, ep.observed_at, ep.payload_hash, pc.payload
		  FROM eg_edge_projection ep
		  LEFT JOIN eg_entity_index fi ON fi.subject = ep.from_subject
		  LEFT JOIN eg_entity_index ti ON ti.subject = ep.to_subject
		  LEFT JOIN eg_payload_content pc ON pc.payload_hash = ep.payload_hash` + where

	rows, err := p.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: get edges: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var views []*interfaces.EdgeView
	for rows.Next() {
		var fromSubj, toSubj, edgeType, source, observedAt, payloadHash string
		var payloadJSON sql.NullString
		if err := rows.Scan(&fromSubj, &toSubj, &edgeType, &source, &observedAt, &payloadHash, &payloadJSON); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: scan edge row: %w", err)
		}

		fromEID, err := types.ParseEID(fromSubj)
		if err != nil {
			continue
		}
		toEID, err := types.ParseEID(toSubj)
		if err != nil {
			continue
		}

		var attrs map[string]interface{}
		if payloadJSON.Valid && payloadJSON.String != "" {
			if err := json.Unmarshal([]byte(payloadJSON.String), &attrs); err != nil {
				attrs = map[string]interface{}{}
			}
		} else {
			attrs = map[string]interface{}{}
		}

		oa, _ := time.Parse(time.RFC3339Nano, observedAt)
		obs := types.Observation{
			Source:     source,
			Subject:    edgeType + "|" + fromSubj + "|" + toSubj,
			ObservedAt: oa,
			RecordedAt: oa,
			Kind:       types.ObservationKindState,
			Confidence: types.ConfidenceHigh,
			Payload:    attrs,
		}
		edge := &types.Edge{
			Type:       edgeType,
			From:       fromEID,
			To:         toEID,
			Attributes: attrs,
			Sources:    []types.Observation{obs},
		}
		views = append(views, &interfaces.EdgeView{
			Edge:      edge,
			Freshness: types.Freshness{ObservedAt: oa, RecordedAt: oa},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: iterate edge rows: %w", err)
	}
	return views, nil
}
