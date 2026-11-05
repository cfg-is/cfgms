// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/internal/egcommon"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// nextDollar returns a placeholder source that yields $n, $n+1, ... and advances
// *n past each placeholder it hands out.
func nextDollar(n *int) func() string {
	return func() string {
		ph := fmt.Sprintf("$%d", *n)
		*n++
		return ph
	}
}

// collapseAsOfWalkBudget is the wall-clock budget of one as-of group walk. It is
// a variable only so a test can shorten it.
var collapseAsOfWalkBudget = interfaces.CollapseAsOfWalkBudget

// resolveGroupMembersCurrentState walks the same-as graph from eid using the
// current edge projection (fast path for non-temporal reads). Returns all group
// member EIDs including the subject itself. The group is traversed as an
// undirected graph: the same-as edge is symmetric. The walk is bounded by
// MaxCollapseGroupMembers and, when the cut is active, only follows edges whose
// both ends are owned inside the cut.
func (p *DatabaseEntityGraphProvider) resolveGroupMembersCurrentState(ctx context.Context, eid interfaces.EIDRef, cut interfaces.TenantCut) ([]interfaces.EIDRef, error) {
	w := egcommon.NewGroupWalk(eid.String())

	for len(w.Queue) > 0 {
		current := w.Queue[0]
		w.Queue = w.Queue[1:]

		query := `SELECT DISTINCT ep.from_subject, ep.to_subject
			 FROM eg_edge_projection ep`
		args := []interface{}{current}
		n := 2
		conds := []string{"ep.edge_type = 'same-as'", "(ep.from_subject = $1 OR ep.to_subject = $1)"}
		if cut.Active() {
			query += `
			 JOIN eg_entity_index fi ON fi.subject = ep.from_subject
			 JOIN eg_entity_index ti ON ti.subject = ep.to_subject`
			conds = append(conds,
				egcommon.TenantSubtreeCond("fi.owning_tenant", cut, nextDollar(&n), &args),
				egcommon.TenantSubtreeCond("ti.owning_tenant", cut, nextDollar(&n), &args),
			)
		}
		args = append(args, interfaces.MaxCollapseGroupMembers+1)
		// #nosec G202 -- conds holds fixed predicates and generated $N
		// placeholders; every value, including tenant IDs, is bound through args.
		query += " WHERE " + strings.Join(conds, " AND ") + fmt.Sprintf(" LIMIT $%d", n)

		rows, err := p.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("entitygraph/database: resolve group edges for %s: %w", current, err)
		}

		count := 0
		for rows.Next() {
			var fromSubj, toSubj string
			if err := rows.Scan(&fromSubj, &toSubj); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("entitygraph/database: scan group edge: %w", err)
			}
			if count++; count > interfaces.MaxCollapseGroupMembers {
				_ = rows.Close()
				return nil, interfaces.ErrCollapseGroupTooLarge
			}
			for _, peer := range []string{fromSubj, toSubj} {
				if err := w.Add(peer); err != nil {
					_ = rows.Close()
					return nil, err
				}
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("entitygraph/database: iterate group edges: %w", err)
		}
		_ = rows.Close()
	}

	return egcommon.SortedGroupMembers(w.Visited), nil
}

// resolveGroupMembersAsOf walks the same-as graph from eid using the observation
// log, considering only edges that were active (not absent) at or before asOf.
// Retracted edges and peers outside the cut are removed in SQL, so they never
// count toward MaxCollapseGroupMembers.
func (p *DatabaseEntityGraphProvider) resolveGroupMembersAsOf(ctx context.Context, eid interfaces.EIDRef, asOf time.Time, cut interfaces.TenantCut) ([]interfaces.EIDRef, error) {
	walkCtx, cancel := context.WithTimeout(ctx, collapseAsOfWalkBudget)
	defer cancel()
	members, err := p.walkGroupMembersAsOf(walkCtx, eid, asOf, cut)
	if err != nil && walkCtx.Err() != nil && ctx.Err() == nil {
		// The budget expired, not the caller: the group is too expensive to collapse.
		return nil, interfaces.ErrCollapseGroupTooLarge
	}
	return members, err
}

// walkGroupMembersAsOf is the as-of walk itself, run under the budgeted context.
// The whole walk is one WITH RECURSIVE query: "live" holds the same-as edge
// subjects whose latest observation at or before asOf is not a retraction, and
// "grp" grows from eid across them in both directions. Peers outside the cut are
// removed inside the recursion, so they never count toward
// MaxCollapseGroupMembers, and the outer LIMIT of MaxCollapseGroupMembers+1 rows
// stops the recursion once the group is past the limit.
func (p *DatabaseEntityGraphProvider) walkGroupMembersAsOf(ctx context.Context, eid interfaces.EIDRef, asOf time.Time, cut interfaces.TenantCut) ([]interfaces.EIDRef, error) {
	asOfStr := asOf.UTC().Format(time.RFC3339Nano)

	// $1 asOf, $2 start subject, $3 member limit.
	args := []interface{}{asOfStr, eid.String(), interfaces.MaxCollapseGroupMembers + 1}
	n := 4
	peerExpr := `CASE d.dir
				         WHEN 0 THEN substr(v.subject, length(g.eid) + 10)
				         ELSE substr(v.subject, 9, length(v.subject) - 9 - length(g.eid))
				       END`
	cutCond := ""
	if cut.Active() {
		cutCond = " AND " + peerExpr + " IN (SELECT subject FROM eg_entity_index WHERE " +
			egcommon.TenantSubtreeCond("owning_tenant", cut, nextDollar(&n), &args) + ")"
	}

	// Edge subjects are "same-as|<from>|<to>"; substr/length/left/right count
	// characters. A single recursive term is required, so the two directions are
	// two rows of the (VALUES) list: 0 matches "same-as|<current>|<peer>", 1
	// matches "same-as|<peer>|<current>".
	// #nosec G202 -- cutCond holds fixed SQL and generated $N placeholders;
	// every value, including tenant IDs, is bound through args.
	query := `WITH RECURSIVE live AS MATERIALIZED (
			SELECT DISTINCT ON (l.subject) l.subject, l.kind
			FROM eg_observation_log l
			WHERE l.subject LIKE 'same-as|%' AND l.observed_at <= $1
			ORDER BY l.subject, l.observed_at DESC, l.id DESC
		), grp(eid) AS (
			SELECT $2::text
			UNION
			SELECT ` + peerExpr + `
			FROM grp g
			CROSS JOIN (VALUES (0), (1)) AS d(dir)
			JOIN live v ON v.kind <> 'absence'
			 AND CASE d.dir
			       WHEN 0 THEN left(v.subject, length(g.eid) + 9) = 'same-as|' || g.eid || '|'
			       ELSE length(v.subject) > length(g.eid) + 9
			            AND right(v.subject, length(g.eid) + 1) = '|' || g.eid
			     END
			WHERE true` + cutCond + `
		)
		SELECT eid FROM grp LIMIT $3`

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: resolve group as-of for %s: %w", eid.String(), err)
	}
	defer func() { _ = rows.Close() }()

	visited, err := egcommon.ScanAsOfMembers(rows, dialect)
	if err != nil {
		return nil, err
	}
	return egcommon.SortedGroupMembers(visited), nil
}

// applyTenantCut filters group members to those whose current owning_tenant is
// visible to tenantFilter (ADR-022 §3: tenant cut before merge). Uses the current
// eg_entity_index ownership (not ingest-time tenant_path) as the access-control axis.
func (p *DatabaseEntityGraphProvider) applyTenantCut(ctx context.Context, members []interfaces.EIDRef, cut interfaces.TenantCut) ([]interfaces.EIDRef, error) {
	if !cut.Active() {
		return members, nil
	}

	var visible []interfaces.EIDRef
	for _, m := range members {
		var owningTenant string
		err := p.db.QueryRowContext(ctx,
			`SELECT owning_tenant FROM eg_entity_index WHERE subject = $1`,
			m.String(),
		).Scan(&owningTenant)
		if err != nil {
			// Not in index (placeholder with no real owning_tenant) → excluded.
			continue
		}
		if cut.Visible(owningTenant) {
			visible = append(visible, m)
		}
	}
	return visible, nil
}

// loadMemberSources loads all current sourceEntry values for a group member from
// eg_entity_current. Used during step 3 (attribute merge) of the collapse-group
// read contract.
func (p *DatabaseEntityGraphProvider) loadMemberSources(ctx context.Context, subject string) ([]sourceEntry, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT c.source, c.source_class, c.observed_at, c.payload_hash, pc.payload_json
		 FROM eg_entity_current c
		 JOIN eg_payload_content pc ON pc.content_hash = c.payload_hash
		 WHERE c.subject = $1`,
		subject,
	)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/database: load member sources for %s: %w", subject, err)
	}
	defer func() { _ = rows.Close() }()

	scanned, err := egcommon.ScanMemberSources(rows, dialect)
	if err != nil {
		return nil, err
	}
	entries := make([]sourceEntry, len(scanned))
	for i, m := range scanned {
		entries[i] = sourceEntry{
			source:      m.Source,
			sourceClass: m.SourceClass,
			observedAt:  m.ObservedAt,
			payloadHash: m.PayloadHash,
			payload:     m.Payload,
		}
	}
	return entries, nil
}

// entryView returns a source entry's source and payload for egcommon.BuildConflicts.
func entryView(e sourceEntry) (string, map[string]interface{}) {
	return e.source, e.payload
}

// resolveCollapseGroup implements the three-step collapse-group read contract
// (ADR-022 §3, ADR-023 §4):
//  1. Resolve same-as group membership as-of query time from edge history.
//  2. Apply tenant cut (current-ownership axis) before any merge.
//  3. Per-attribute precedence merge across visible members.
//
// Bound and cut: the walk is bounded by interfaces.MaxCollapseGroupMembers
// distinct members including the requested entity (exactly that many succeeds).
// When the cut is active it is applied during the walk, in SQL: an edge is
// followed only when its peer (and, on the current-state path, both ends) is
// owned inside the cut, so out-of-cut entities never count toward the limit and
// never connect members. Retracted edges never count either. A group with more
// members than the limit returns interfaces.ErrCollapseGroupTooLarge, an error
// rather than a truncated group; applyTenantCut and the member-source loads
// never run on it.
//
// Returns nil when the entity has no same-as group or all other group members
// are cut by the tenant filter (single-visible-member group is a no-op).
func (p *DatabaseEntityGraphProvider) resolveCollapseGroup(ctx context.Context, eid interfaces.EIDRef, asOf *time.Time, cut interfaces.TenantCut) (*types.CollapseGroupView, error) {
	// Step 1: resolve group membership.
	var members []interfaces.EIDRef
	var err error
	if asOf != nil {
		members, err = p.resolveGroupMembersAsOf(ctx, eid, *asOf, cut)
	} else {
		members, err = p.resolveGroupMembersCurrentState(ctx, eid, cut)
	}
	if err != nil {
		return nil, err
	}

	// No same-as edges: single-member group, no collapse needed.
	if len(members) <= 1 {
		return nil, nil
	}

	// Step 2: tenant cut before merge.
	visible, err := p.applyTenantCut(ctx, members, cut)
	if err != nil {
		return nil, err
	}

	// After the cut only the requesting entity is visible: no group to collapse.
	if len(visible) <= 1 {
		return nil, nil
	}

	// Step 3: per-attribute precedence merge across all visible members' sources.
	var allEntries []sourceEntry
	for _, m := range visible {
		entries, err := p.loadMemberSources(ctx, m.String())
		if err != nil {
			return nil, err
		}
		allEntries = append(allEntries, entries...)
	}

	merged := mergeAttributes(allEntries)
	conflicts := egcommon.BuildConflicts(allEntries, entryView, merged)

	return &types.CollapseGroupView{
		Members:   visible,
		Merged:    merged,
		Conflicts: conflicts,
	}, nil
}
