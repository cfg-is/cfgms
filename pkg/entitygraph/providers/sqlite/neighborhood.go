// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

const (
	neighborhoodMaxDepth     = 3
	neighborhoodDefaultDepth = 2
)

// GetNeighborhood returns a depth-bounded connected subgraph starting at eid.
// The implicit tenant filter is the root entity's current owning_tenant: at every
// hop, both edge endpoints must be in the root entity's tenant subtree (ADR-023 §4).
//
// depth ≤ 0 is treated as the contract default (2).
// depth > 3 is rejected with an error per the access contract.
func (p *SQLiteEntityGraphProvider) GetNeighborhood(
	ctx context.Context,
	eid interfaces.EIDRef,
	edgeTypes []string,
	direction types.TraversalDirection,
	depth int,
) (*types.Neighborhood, error) {
	if depth > neighborhoodMaxDepth {
		return nil, fmt.Errorf("entitygraph/sqlite: depth %d exceeds maximum %d", depth, neighborhoodMaxDepth)
	}
	if depth <= 0 {
		depth = neighborhoodDefaultDepth
	}

	// Derive implicit tenant filter from the root entity's current owning_tenant.
	var tenantFilter string
	_ = p.db.QueryRowContext(ctx,
		`SELECT owning_tenant FROM eg_entity_index WHERE subject = ?`, eid.String(),
	).Scan(&tenantFilter)

	// BFS over the edge projection.
	type edgeKey struct{ from, to, edgeType string }
	edgeMap := make(map[edgeKey]*types.Edge)
	visited := map[string]bool{eid.String(): true}
	frontier := []string{eid.String()}

	for hop := 0; hop < depth && len(frontier) > 0; hop++ {
		hopEdges, err := p.queryNeighborhoodEdges(ctx, frontier, edgeTypes, direction, tenantFilter)
		if err != nil {
			return nil, err
		}

		var nextFrontier []string
		for _, e := range hopEdges {
			k := edgeKey{from: e.From.String(), to: e.To.String(), edgeType: e.Type}
			if existing, ok := edgeMap[k]; ok {
				existing.Sources = append(existing.Sources, e.Sources...)
			} else {
				edgeMap[k] = e
			}

			// Determine the peer node relative to what we traversed from.
			peer := peerSubject(e, frontier, direction)
			if peer != "" && !visited[peer] {
				visited[peer] = true
				nextFrontier = append(nextFrontier, peer)
			}
		}
		frontier = nextFrontier
	}

	// Collect unique edges.
	edges := make([]*types.Edge, 0, len(edgeMap))
	for _, e := range edgeMap {
		edges = append(edges, e)
	}

	// Collect node entities for all visited subjects.
	nodes := make([]*types.Entity, 0, len(visited))
	for subject := range visited {
		entityEID, err := types.ParseEID(subject)
		if err != nil {
			continue
		}
		var kind, tenant string
		err = p.db.QueryRowContext(ctx,
			`SELECT entity_kind, owning_tenant FROM eg_entity_index WHERE subject = ?`, subject,
		).Scan(&kind, &tenant)
		if err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("entitygraph/sqlite: load node %s: %w", subject, err)
		}
		if kind == "" {
			kind = entityEID.AuthorityType()
		}
		nodes = append(nodes, &types.Entity{
			EID:          entityEID,
			Kind:         kind,
			Attributes:   map[string]interface{}{},
			OwningTenant: tenant,
		})
	}

	return &types.Neighborhood{Root: eid, Nodes: nodes, Edges: edges}, nil
}

// queryNeighborhoodEdges returns all edges connected to any entity in the
// frontier (one SQL round-trip per hop). Both edge endpoints must satisfy the
// tenant filter so that cross-tenant edges are excluded at the hop level, not
// post-filtered from the final result set (ADR-023 §4 / Story-3 AC 4).
func (p *SQLiteEntityGraphProvider) queryNeighborhoodEdges(
	ctx context.Context,
	frontier []string,
	edgeTypes []string,
	direction types.TraversalDirection,
	tenantFilter string,
) ([]*types.Edge, error) {
	if len(frontier) == 0 {
		return nil, nil
	}

	ph := inPlaceholders(len(frontier))
	var args []interface{}
	for _, s := range frontier {
		args = append(args, s)
	}

	var dirCond string
	switch direction {
	case types.TraversalOutbound:
		dirCond = "ep.from_subject IN " + ph
	case types.TraversalInbound:
		dirCond = "ep.to_subject IN " + ph
	default: // TraversalBoth
		dirCond = "(ep.from_subject IN " + ph + " OR ep.to_subject IN " + ph + ")"
		// For TraversalBoth the frontier args are used twice (in and out).
		extra := make([]interface{}, len(frontier))
		for i, s := range frontier {
			extra[i] = s
		}
		args = append(args, extra...)
	}

	var conds []string
	conds = append(conds, dirCond)

	if len(edgeTypes) > 0 {
		eph := inPlaceholders(len(edgeTypes))
		conds = append(conds, "ep.edge_type IN "+eph)
		for _, et := range edgeTypes {
			args = append(args, et)
		}
	}
	if tenantFilter != "" {
		conds = append(conds,
			"(fi.owning_tenant = ? OR fi.owning_tenant LIKE ?)",
			"(ti.owning_tenant = ? OR ti.owning_tenant LIKE ?)",
		)
		args = append(args, tenantFilter, tenantFilter+"/%")
		args = append(args, tenantFilter, tenantFilter+"/%")
	}

	q := `SELECT ep.from_subject, ep.to_subject, ep.edge_type, ep.source
		  FROM eg_edge_projection ep
		  LEFT JOIN eg_entity_index fi ON fi.subject = ep.from_subject
		  LEFT JOIN eg_entity_index ti ON ti.subject = ep.to_subject
		  WHERE ` + strings.Join(conds, " AND ")

	rows, err := p.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: neighborhood hop query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var edges []*types.Edge
	for rows.Next() {
		var fromSubj, toSubj, edgeType, source string
		if err := rows.Scan(&fromSubj, &toSubj, &edgeType, &source); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: scan neighborhood edge: %w", err)
		}
		fromEID, err := types.ParseEID(fromSubj)
		if err != nil {
			continue
		}
		toEID, err := types.ParseEID(toSubj)
		if err != nil {
			continue
		}
		edges = append(edges, &types.Edge{
			Type:       edgeType,
			From:       fromEID,
			To:         toEID,
			Attributes: map[string]interface{}{},
			Sources: []types.Observation{{
				Source:  source,
				Subject: edgeType + "|" + fromSubj + "|" + toSubj,
				Kind:    types.ObservationKindState,
			}},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: iterate neighborhood edges: %w", err)
	}
	return edges, nil
}

// peerSubject returns the "other end" of an edge relative to the entities in
// the current frontier and traversal direction. Returns "" when the peer cannot
// be determined (e.g., both endpoints are in the frontier).
func peerSubject(e *types.Edge, frontier []string, direction types.TraversalDirection) string {
	frontierSet := make(map[string]bool, len(frontier))
	for _, s := range frontier {
		frontierSet[s] = true
	}
	switch direction {
	case types.TraversalOutbound:
		return e.To.String()
	case types.TraversalInbound:
		return e.From.String()
	default: // Both
		fromIn, toIn := frontierSet[e.From.String()], frontierSet[e.To.String()]
		if fromIn && !toIn {
			return e.To.String()
		}
		if toIn && !fromIn {
			return e.From.String()
		}
		return ""
	}
}

// inPlaceholders returns a parenthesised SQLite ? placeholder list of length n.
func inPlaceholders(n int) string {
	if n == 0 {
		return "(NULL)"
	}
	return "(" + strings.Repeat("?,", n-1) + "?)"
}
