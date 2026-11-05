// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/internal/egcommon"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// dialect carries the database values for the code shared through egcommon.
var dialect = egcommon.Dialect{Prefix: "entitygraph/database", Placeholders: dollarPlaceholders}

// GetNeighborhood returns a depth-bounded connected subgraph starting at eid.
// The tenant filter is the caller's authorized cut, not the root entity's tenant
// (a placeholder root has none): at every hop, both edge endpoints must be inside
// it (ADR-023 §4).
//
// depth ≤ 0 is treated as the contract default (2).
// depth > 3 is rejected with an error per the access contract.
func (p *DatabaseEntityGraphProvider) GetNeighborhood(
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

// queryNeighborhoodEdges returns edges connected to any subject in the frontier
// in a single SQL round-trip. Both endpoints must satisfy the tenant filter so
// cross-tenant edges are excluded at the hop level (ADR-023 §4 / Story-3 AC 4).
func (p *DatabaseEntityGraphProvider) queryNeighborhoodEdges(
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

	var args []interface{}
	n := 1

	addArg := func(v interface{}) string {
		args = append(args, v)
		s := fmt.Sprintf("$%d", n)
		n++
		return s
	}

	// Build frontier placeholders.
	fph := make([]string, len(frontier))
	for i, s := range frontier {
		fph[i] = addArg(s)
	}
	frontierIn := "(" + strings.Join(fph, ",") + ")"

	var dirCond string
	switch direction {
	case types.TraversalOutbound:
		dirCond = "ep.from_subject IN " + frontierIn
	case types.TraversalInbound:
		dirCond = "ep.to_subject IN " + frontierIn
	default: // TraversalBoth
		// Build a second set of placeholders for the to_subject IN clause.
		fph2 := make([]string, len(frontier))
		for i, s := range frontier {
			fph2[i] = addArg(s)
		}
		frontierIn2 := "(" + strings.Join(fph2, ",") + ")"
		dirCond = "(ep.from_subject IN " + frontierIn + " OR ep.to_subject IN " + frontierIn2 + ")"
	}

	var conds []string
	conds = append(conds, dirCond)

	if len(edgeTypes) > 0 {
		ephs := make([]string, len(edgeTypes))
		for i, et := range edgeTypes {
			ephs[i] = addArg(et)
		}
		conds = append(conds, "ep.edge_type IN ("+strings.Join(ephs, ",")+")")
	}

	if cut.Active() {
		conds = append(conds,
			tenantSubtreeCond("fi.owning_tenant", cut, &n, &args),
			tenantSubtreeCond("ti.owning_tenant", cut, &n, &args),
		)
	}

	// #nosec G202 -- conds contains only fixed predicates and generated $N
	// placeholders; every edge type and tenant value is bound through args.
	q := `SELECT ep.from_subject, ep.to_subject, ep.edge_type, ep.source
		  FROM eg_edge_projection ep
		  LEFT JOIN eg_entity_index fi ON fi.subject = ep.from_subject
		  LEFT JOIN eg_entity_index ti ON ti.subject = ep.to_subject
		  WHERE ` + strings.Join(conds, " AND ") +
		" ORDER BY ep.from_subject, ep.to_subject, ep.edge_type, ep.source" +
		" LIMIT " + addArg(limit)

	rows, err := p.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: neighborhood hop query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return egcommon.ScanNeighborhoodEdges(rows, dialect)
}

// dollarPlaceholders returns a parenthesised $1..$n placeholder list.
func dollarPlaceholders(n int) string {
	if n == 0 {
		return "(NULL)"
	}
	phs := make([]string, n)
	for i := range phs {
		phs[i] = fmt.Sprintf("$%d", i+1)
	}
	return "(" + strings.Join(phs, ",") + ")"
}
