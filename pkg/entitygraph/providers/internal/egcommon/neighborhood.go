// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package egcommon

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

const (
	// NeighborhoodMaxDepth is the deepest traversal GetNeighborhood accepts.
	NeighborhoodMaxDepth = 3
	// NeighborhoodDefaultDepth applies when the caller passes depth <= 0.
	NeighborhoodDefaultDepth = 2
	// NeighborhoodChunk caps the IN-list length of one query so a large frontier
	// never reaches a driver variable limit.
	NeighborhoodChunk = 500
)

// HopFunc returns up to limit projection edges connected to the frontier
// subjects. It holds the provider's dialect-bound query, with the edge types,
// direction and tenant cut already bound.
type HopFunc func(ctx context.Context, frontier []string, limit int) ([]*types.Edge, error)

// GetNeighborhood returns a depth-bounded connected subgraph starting at eid.
// The tenant filter is the caller's authorized cut, not the root entity's tenant
// (a placeholder root has none): at every hop, both edge endpoints must be inside
// it (ADR-023 §4); hop enforces that in SQL.
//
// depth ≤ 0 is treated as the contract default (2).
// depth > 3 is rejected with an error per the access contract.
func GetNeighborhood(
	ctx context.Context,
	db *sql.DB,
	d Dialect,
	eid interfaces.EIDRef,
	direction types.TraversalDirection,
	depth int,
	hop HopFunc,
) (*types.Neighborhood, error) {
	if depth > NeighborhoodMaxDepth {
		return nil, fmt.Errorf("%s: depth %d exceeds maximum %d", d.Prefix, depth, NeighborhoodMaxDepth)
	}
	if depth <= 0 {
		depth = NeighborhoodDefaultDepth
	}

	// BFS over the edge projection, bounded in nodes and in projection rows.
	w := newWalk(eid)
	if err := w.run(ctx, depth, direction, hop); err != nil {
		return nil, err
	}
	edges := w.edgesWithinNodes()

	nodes, err := loadNeighborhoodNodes(ctx, db, d, w.order)
	if err != nil {
		return nil, err
	}

	return &types.Neighborhood{Root: eid, Nodes: nodes, Edges: edges, Truncated: w.truncated}, nil
}

// walk is the state of one breadth-first neighborhood traversal.
type walk struct {
	frontier  []string
	visited   map[string]bool
	order     []string
	edgeMap   map[edgeKey]*types.Edge
	edgeOrder []*types.Edge
	seenRows  map[[4]string]struct{}
	rowCount  int
	truncated bool
	// stop is set when the projection-row cap is reached: the walk ends.
	stop bool
}

type edgeKey struct{ from, to, edgeType string }

func newWalk(root interfaces.EIDRef) *walk {
	return &walk{
		frontier: []string{root.String()},
		visited:  map[string]bool{root.String(): true},
		order:    []string{root.String()},
		edgeMap:  make(map[edgeKey]*types.Edge),
		seenRows: make(map[[4]string]struct{}),
	}
}

// absorb folds one chunk's hop edges into the walk and returns the newly
// reached peers, which form the next frontier.
func (w *walk) absorb(hopEdges []*types.Edge, chunk []string, direction types.TraversalDirection) []string {
	var next []string
	for _, e := range hopEdges {
		if w.rowCount >= interfaces.MaxNeighborhoodEdges {
			w.truncated = true
			w.stop = true
			return next
		}
		// Determine the peer node relative to what we traversed from.
		peer := PeerSubject(e, chunk, direction)
		if peer != "" && !w.visited[peer] {
			if len(w.visited) >= interfaces.MaxNeighborhoodNodes {
				w.truncated = true
				continue
			}
			w.visited[peer] = true
			w.order = append(w.order, peer)
			next = append(next, peer)
		}
		w.addEdge(e)
	}
	return next
}

// addEdge records a projection row. A row can come back from two chunks, or
// again on a later hop; it counts and merges once.
func (w *walk) addEdge(e *types.Edge) {
	rk := [4]string{e.From.String(), e.To.String(), e.Type, e.Sources[0].Source}
	if _, dup := w.seenRows[rk]; dup {
		return
	}
	w.seenRows[rk] = struct{}{}
	w.rowCount++
	k := edgeKey{from: e.From.String(), to: e.To.String(), edgeType: e.Type}
	if existing, ok := w.edgeMap[k]; ok {
		existing.Sources = append(existing.Sources, e.Sources...)
		return
	}
	w.edgeMap[k] = e
	w.edgeOrder = append(w.edgeOrder, e)
}

// run walks up to depth hops from the root.
func (w *walk) run(ctx context.Context, depth int, direction types.TraversalDirection, hop HopFunc) error {
	for h := 0; h < depth && len(w.frontier) > 0 && !w.stop; h++ {
		var next []string
		for start := 0; start < len(w.frontier) && !w.stop; start += NeighborhoodChunk {
			chunk := w.frontier[start:min(start+NeighborhoodChunk, len(w.frontier))]
			hopEdges, err := hop(ctx, chunk, interfaces.MaxNeighborhoodEdges-w.rowCount+1)
			if err != nil {
				return err
			}
			next = append(next, w.absorb(hopEdges, chunk, direction)...)
		}
		w.frontier = next
	}
	return nil
}

// edgesWithinNodes keeps only edges with both endpoints in the returned node
// set: an edge to a peer dropped at the node cap, or visited via the other
// direction, is out.
func (w *walk) edgesWithinNodes() []*types.Edge {
	edges := make([]*types.Edge, 0, len(w.edgeOrder))
	for _, e := range w.edgeOrder {
		if w.visited[e.From.String()] && w.visited[e.To.String()] {
			edges = append(edges, e)
		}
	}
	return edges
}

// loadNeighborhoodNodes loads the kind and owning tenant of every subject in
// batched IN queries of at most NeighborhoodChunk subjects, in subjects order.
func loadNeighborhoodNodes(ctx context.Context, db *sql.DB, d Dialect, subjects []string) ([]*types.Entity, error) {
	type indexRow struct{ kind, tenant string }
	index := make(map[string]indexRow, len(subjects))
	for start := 0; start < len(subjects); start += NeighborhoodChunk {
		chunk := subjects[start:min(start+NeighborhoodChunk, len(subjects))]
		args := make([]interface{}, len(chunk))
		for i, s := range chunk {
			args[i] = s
		}
		// #nosec G202 -- the IN list is generated placeholders only; every
		// subject is bound through args.
		rows, err := db.QueryContext(ctx,
			`SELECT subject, entity_kind, owning_tenant FROM eg_entity_index WHERE subject IN `+d.Placeholders(len(chunk)), args...)
		if err != nil {
			return nil, fmt.Errorf("%s: load nodes: %w", d.Prefix, err)
		}
		for rows.Next() {
			var subject string
			var r indexRow
			if err := rows.Scan(&subject, &r.kind, &r.tenant); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("%s: scan node: %w", d.Prefix, err)
			}
			index[subject] = r
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("%s: iterate nodes: %w", d.Prefix, err)
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

// ScanNeighborhoodEdges reads the rows of a hop query (from_subject,
// to_subject, edge_type, source) into projection edges. Rows whose endpoints
// are not parseable EIDs are skipped. The caller closes rows.
func ScanNeighborhoodEdges(rows *sql.Rows, d Dialect) ([]*types.Edge, error) {
	var edges []*types.Edge
	for rows.Next() {
		var fromSubj, toSubj, edgeType, source string
		if err := rows.Scan(&fromSubj, &toSubj, &edgeType, &source); err != nil {
			return nil, fmt.Errorf("%s: scan neighborhood edge: %w", d.Prefix, err)
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
		return nil, fmt.Errorf("%s: iterate neighborhood edges: %w", d.Prefix, err)
	}
	return edges, nil
}

// PeerSubject returns the "other end" of an edge relative to the entities in
// the current frontier and traversal direction. Returns "" when the peer cannot
// be determined (e.g., both endpoints are in the frontier).
func PeerSubject(e *types.Edge, frontier []string, direction types.TraversalDirection) string {
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
