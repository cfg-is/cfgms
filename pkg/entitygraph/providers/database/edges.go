// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

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

// parseEdgeSubject parses an edge subject string into its constituent parts.
// The expected format is "edge_type|from_eid|to_eid".
func parseEdgeSubject(subject string) (edgeType, fromSubject, toSubject string, err error) {
	parts := strings.SplitN(subject, "|", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("entitygraph/database: invalid edge subject %q: expected edge_type|from|to", subject)
	}
	return parts[0], parts[1], parts[2], nil
}

// updateEdgeProjection is the "edge" subject-kind projection updater. It upserts
// the per-source edge projection row and materializes placeholder nodes for any
// referenced EID not yet in eg_entity_index (ADR-022 §2).
func updateEdgeProjection(ctx context.Context, tx *sql.Tx, obs types.Observation, _ int64) error {
	edgeType, fromSubject, toSubject, err := parseEdgeSubject(obs.Subject)
	if err != nil {
		return err
	}

	hash, err := payloadHash(obs.Payload)
	if err != nil {
		return err
	}
	sc := string(resolveSourceClass(obs.Source))
	observedAt := obs.ObservedAt.UTC().Format(time.RFC3339Nano)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_edge_projection
			(from_subject, to_subject, edge_type, source, source_class, observed_at, payload_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (from_subject, to_subject, edge_type, source) DO UPDATE SET
			source_class = EXCLUDED.source_class,
			observed_at  = EXCLUDED.observed_at,
			payload_hash = EXCLUDED.payload_hash`,
		fromSubject, toSubject, edgeType, obs.Source, sc, observedAt, hash,
	); err != nil {
		return fmt.Errorf("entitygraph/database: upsert edge projection: %w", err)
	}

	// Materialize placeholder nodes for endpoint EIDs not yet in eg_entity_index.
	for _, subject := range []string{fromSubject, toSubject} {
		if err := materializePlaceholderNode(ctx, tx, subject); err != nil {
			return err
		}
	}
	return nil
}

// materializePlaceholderNode ensures eg_entity_index has an entry for subject.
// If the subject is not a valid EID, it is silently skipped. If the entry already
// exists, the INSERT ... ON CONFLICT DO NOTHING is a no-op.
func materializePlaceholderNode(ctx context.Context, tx *sql.Tx, subject string) error {
	eid, err := types.ParseEID(subject)
	if err != nil {
		return nil // non-EID endpoint — no placeholder
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO eg_entity_index
			(subject, entity_kind, owning_tenant, hostname, mac_addrs, machine_sid, dir_object_guid, serial_number, cloud_object_id)
		 VALUES ($1, $2, '', '', '', '', '', '', '')
		 ON CONFLICT (subject) DO NOTHING`,
		subject, eid.AuthorityType(),
	); err != nil {
		return fmt.Errorf("entitygraph/database: materialize placeholder for %s: %w", subject, err)
	}
	return nil
}

// GetEdges returns edges matching the filter. Tenant filtering is applied via a
// JOIN against eg_entity_index (current endpoint ownership), never via any
// tenant column on the edge row itself (ADR-023 §4 / Story-3 AC 5).
func (p *DatabaseEntityGraphProvider) GetEdges(ctx context.Context, filter interfaces.EdgeFilter) ([]*interfaces.EdgeView, error) {
	var conds []string
	var args []interface{}
	n := 1

	addArg := func(v interface{}) string {
		args = append(args, v)
		s := fmt.Sprintf("$%d", n)
		n++
		return s
	}

	if filter.FromEID != nil {
		conds = append(conds, "ep.from_subject = "+addArg(filter.FromEID.String()))
	}
	if filter.ToEID != nil {
		conds = append(conds, "ep.to_subject = "+addArg(filter.ToEID.String()))
	}
	if len(filter.Types) > 0 {
		phs := make([]string, len(filter.Types))
		for i, et := range filter.Types {
			phs[i] = addArg(et)
		}
		conds = append(conds, "ep.edge_type IN ("+strings.Join(phs, ",")+")")
	}
	if filter.Source != "" {
		conds = append(conds, "ep.source = "+addArg(filter.Source))
	}
	if filter.TenantFilter != "" {
		tf, tfLike := addArg(filter.TenantFilter), addArg(filter.TenantFilter+"/%")
		conds = append(conds, "(fi.owning_tenant = "+tf+" OR fi.owning_tenant LIKE "+tfLike+")")
		tf2, tfLike2 := addArg(filter.TenantFilter), addArg(filter.TenantFilter+"/%")
		conds = append(conds, "(ti.owning_tenant = "+tf2+" OR ti.owning_tenant LIKE "+tfLike2+")")
	}

	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	q := `SELECT ep.from_subject, ep.to_subject, ep.edge_type, ep.source, ep.observed_at, ep.payload_hash, pc.payload_json
		  FROM eg_edge_projection ep
		  LEFT JOIN eg_entity_index fi ON fi.subject = ep.from_subject
		  LEFT JOIN eg_entity_index ti ON ti.subject = ep.to_subject
		  LEFT JOIN eg_payload_content pc ON pc.content_hash = ep.payload_hash` + where

	rows, err := p.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: get edges: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var views []*interfaces.EdgeView
	for rows.Next() {
		var fromSubj, toSubj, edgeType, source, observedAt, payloadHash string
		var payloadJSON sql.NullString
		if err := rows.Scan(&fromSubj, &toSubj, &edgeType, &source, &observedAt, &payloadHash, &payloadJSON); err != nil {
			return nil, fmt.Errorf("entitygraph/database: scan edge row: %w", err)
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
		return nil, fmt.Errorf("entitygraph/database: iterate edge rows: %w", err)
	}
	return views, nil
}
