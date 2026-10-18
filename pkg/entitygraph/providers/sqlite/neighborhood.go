// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

const (
	neighborhoodMaxDepth     = 3
	neighborhoodDefaultDepth = 2
	// neighborhoodChunk caps the IN-list length of one query so a large frontier
	// never reaches a driver variable limit.
	neighborhoodChunk = 500
)

// GetNeighborhood returns a depth-bounded connected subgraph starting at eid.
// The tenant filter is the caller's authorized cut, not the root entity's tenant
// (a placeholder root has none): at every hop, both edge endpoints must be inside
// it (ADR-023 §4).
//
// depth ≤ 0 is treated as the contract default (2).
// depth > 3 is rejected with an error per the access contract.
func (p *SQLiteEntityGraphProvider) GetNeighborhood(
	ctx context.Context,
	eid interfaces.EIDRef,
	edgeTypes []string,
	direction types.TraversalDirection,
	depth int,
	cut interfaces.TenantCut,
) (*types.Neighborhood, error) {
	if depth > neighborhoodMaxDepth {
		return nil, fmt.Errorf("entitygraph/sqlite: depth %d exceeds maximum %d", depth, neighborhoodMaxDepth)
	}
	if depth <= 0 {
		depth = neighborhoodDefaultDepth
	}

	// BFS over the edge projection, bounded in nodes and in projection rows.
	type edgeKey struct{ from, to, edgeType string }
	edgeMap := make(map[edgeKey]*types.Edge)
	var edgeOrder []*types.Edge
	seenRows := make(map[[4]string]struct{})
	rowCount := 0
	truncated := false
	visited := map[string]bool{eid.String(): true}
	order := []string{eid.String()}
	frontier := []string{eid.String()}

walk:
	for hop := 0; hop < depth && len(frontier) > 0; hop++ {
		var nextFrontier []string
		for start := 0; start < len(frontier); start += neighborhoodChunk {
			chunk := frontier[start:min(start+neighborhoodChunk, len(frontier))]
			remaining := interfaces.MaxNeighborhoodEdges - rowCount
			hopEdges, err := p.queryNeighborhoodEdges(ctx, chunk, edgeTypes, direction, cut, remaining+1)
			if err != nil {
				return nil, err
			}
			for _, e := range hopEdges {
				if rowCount >= interfaces.MaxNeighborhoodEdges {
					truncated = true
					break walk
				}
				// Determine the peer node relative to what we traversed from.
				peer := peerSubject(e, chunk, direction)
				if peer != "" && !visited[peer] {
					if len(visited) >= interfaces.MaxNeighborhoodNodes {
						truncated = true
						continue
					}
					visited[peer] = true
					order = append(order, peer)
					nextFrontier = append(nextFrontier, peer)
				}
				// A projection row can come back from two chunks, or again on a
				// later hop; it counts and merges once.
				rk := [4]string{e.From.String(), e.To.String(), e.Type, e.Sources[0].Source}
				if _, dup := seenRows[rk]; dup {
					continue
				}
				seenRows[rk] = struct{}{}
				rowCount++
				k := edgeKey{from: e.From.String(), to: e.To.String(), edgeType: e.Type}
				if existing, ok := edgeMap[k]; ok {
					existing.Sources = append(existing.Sources, e.Sources...)
				} else {
					edgeMap[k] = e
					edgeOrder = append(edgeOrder, e)
				}
			}
		}
		frontier = nextFrontier
	}

	// Only edges with both endpoints in the returned node set survive: an edge to
	// a peer dropped at the node cap, or visited via the other direction, is out.
	edges := make([]*types.Edge, 0, len(edgeOrder))
	for _, e := range edgeOrder {
		if visited[e.From.String()] && visited[e.To.String()] {
			edges = append(edges, e)
		}
	}

	nodes, err := p.loadNeighborhoodNodes(ctx, order)
	if err != nil {
		return nil, err
	}

	return &types.Neighborhood{Root: eid, Nodes: nodes, Edges: edges, Truncated: truncated}, nil
}

// loadNeighborhoodNodes loads the kind and owning tenant of every subject in
// batched IN queries of at most neighborhoodChunk subjects, in subjects order.
func (p *SQLiteEntityGraphProvider) loadNeighborhoodNodes(ctx context.Context, subjects []string) ([]*types.Entity, error) {
	type indexRow struct{ kind, tenant string }
	index := make(map[string]indexRow, len(subjects))
	for start := 0; start < len(subjects); start += neighborhoodChunk {
		chunk := subjects[start:min(start+neighborhoodChunk, len(subjects))]
		args := make([]interface{}, len(chunk))
		for i, s := range chunk {
			args[i] = s
		}
		// #nosec G202 -- the IN list is generated ? placeholders only; every
		// subject is bound through args.
		rows, err := p.db.QueryContext(ctx,
			`SELECT subject, entity_kind, owning_tenant FROM eg_entity_index WHERE subject IN `+inPlaceholders(len(chunk)), args...)
		if err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: load nodes: %w", err)
		}
		for rows.Next() {
			var subject string
			var r indexRow
			if err := rows.Scan(&subject, &r.kind, &r.tenant); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("entitygraph/sqlite: scan node: %w", err)
			}
			index[subject] = r
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("entitygraph/sqlite: iterate nodes: %w", err)
		}
		_ = rows.Close()
	}

	nodes := make([]*types.Entity, 0, len(subjects))
	for _, subject := range subjects {
		entityEID, err := types.ParseEID(subject)
		if err != nil {
			continue
		}
		r := index[subject]
		kind := r.kind
		if kind == "" {
			kind = entityEID.AuthorityType()
		}
		nodes = append(nodes, &types.Entity{
			EID:          entityEID,
			Kind:         kind,
			Attributes:   map[string]interface{}{},
			OwningTenant: r.tenant,
		})
	}
	return nodes, nil
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
	cut interfaces.TenantCut,
	limit int,
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
	if cut.Active() {
		conds = append(conds,
			tenantSubtreeCond("fi.owning_tenant", cut, &args),
			tenantSubtreeCond("ti.owning_tenant", cut, &args),
		)
	}

	// #nosec G202 -- conds contains only fixed predicates and generated "?"
	// placeholders; every edge type and tenant value is passed through args.
	q := `SELECT ep.from_subject, ep.to_subject, ep.edge_type, ep.source
		  FROM eg_edge_projection ep
		  LEFT JOIN eg_entity_index fi ON fi.subject = ep.from_subject
		  LEFT JOIN eg_entity_index ti ON ti.subject = ep.to_subject
		  WHERE ` + strings.Join(conds, " AND ") + " ORDER BY ep.edge_key LIMIT ?"
	args = append(args, limit)

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
