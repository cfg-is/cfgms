// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/internal/egcommon"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// dialect carries the sqlite values for the code shared through egcommon.
var dialect = egcommon.Dialect{Prefix: "entitygraph/sqlite", Placeholders: inPlaceholders}

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
	return egcommon.GetNeighborhood(ctx, p.db, dialect, eid, direction, depth,
		func(ctx context.Context, frontier []string, limit int) ([]*types.Edge, error) {
			return p.queryNeighborhoodEdges(ctx, frontier, edgeTypes, direction, cut, limit)
		})
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

	return egcommon.ScanNeighborhoodEdges(rows, dialect)
}

// inPlaceholders returns a parenthesised SQLite ? placeholder list of length n.
func inPlaceholders(n int) string {
	if n == 0 {
		return "(NULL)"
	}
	return "(" + strings.Repeat("?,", n-1) + "?)"
}
