// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// escapeLIKE escapes SQL LIKE metacharacters (\, %, _) in s so s is treated as
// a literal substring when used in a LIKE pattern with ESCAPE '\'.
func escapeLIKE(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// tenantSubtreeCond returns the SQL predicate "<col> IN (?, ?, ...)" matching col
// against every tenant ID in the cut: the scoped tenant plus the descendant IDs
// the caller resolved from the tenant tree. Every ID is a bound argument, so no
// tenant string is ever interpreted as a pattern. It appends the arguments to
// *args. This is the sole builder for tenant subtree predicates in this package.
func tenantSubtreeCond(col string, cut interfaces.TenantCut, args *[]interface{}) string {
	members := cut.Members()
	phs := make([]string, len(members))
	for i, id := range members {
		phs[i] = "?"
		*args = append(*args, id)
	}
	return fmt.Sprintf("%s IN (%s)", col, strings.Join(phs, ", "))
}

// collapseAsOfWalkBudget is the wall-clock budget of one as-of group walk. It is
// a variable only so a test can shorten it.
var collapseAsOfWalkBudget = interfaces.CollapseAsOfWalkBudget

// groupWalk is the bounded breadth-first state shared by both same-as walks.
type groupWalk struct {
	visited map[string]struct{}
	queue   []string
}

func newGroupWalk(start string) *groupWalk {
	return &groupWalk{visited: map[string]struct{}{start: {}}, queue: []string{start}}
}

// add records peer as a group member. It fails with ErrCollapseGroupTooLarge as
// soon as the distinct member count passes MaxCollapseGroupMembers.
func (w *groupWalk) add(peer string) error {
	if _, seen := w.visited[peer]; seen {
		return nil
	}
	if len(w.visited) >= interfaces.MaxCollapseGroupMembers {
		return interfaces.ErrCollapseGroupTooLarge
	}
	w.visited[peer] = struct{}{}
	w.queue = append(w.queue, peer)
	return nil
}

// resolveGroupMembersCurrentState walks the same-as graph from eid using the
// current edge projection (fast path for non-temporal reads). Returns all group
// member EIDs including the subject itself. The group is traversed as an
// undirected graph: the same-as edge is symmetric. The walk is bounded by
// MaxCollapseGroupMembers and, when the cut is active, only follows edges whose
// both ends are owned inside the cut.
func (p *SQLiteEntityGraphProvider) resolveGroupMembersCurrentState(ctx context.Context, eid interfaces.EIDRef, cut interfaces.TenantCut) ([]interfaces.EIDRef, error) {
	w := newGroupWalk(eid.String())

	for len(w.queue) > 0 {
		current := w.queue[0]
		w.queue = w.queue[1:]

		query := `SELECT DISTINCT ep.from_subject, ep.to_subject
			 FROM eg_edge_projection ep`
		args := []interface{}{}
		conds := []string{"ep.edge_type = 'same-as'", "(ep.from_subject = ? OR ep.to_subject = ?)"}
		args = append(args, current, current)
		if cut.Active() {
			query += `
			 JOIN eg_entity_index fi ON fi.subject = ep.from_subject
			 JOIN eg_entity_index ti ON ti.subject = ep.to_subject`
			conds = append(conds,
				tenantSubtreeCond("fi.owning_tenant", cut, &args),
				tenantSubtreeCond("ti.owning_tenant", cut, &args),
			)
		}
		args = append(args, interfaces.MaxCollapseGroupMembers+1)
		// #nosec G202 -- conds holds fixed predicates and ? placeholders; every
		// value, including tenant IDs, is bound through args.
		query += " WHERE " + strings.Join(conds, " AND ") + " LIMIT ?"

		rows, err := p.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: resolve group edges for %s: %w", current, err)
		}

		n := 0
		for rows.Next() {
			var fromSubj, toSubj string
			if err := rows.Scan(&fromSubj, &toSubj); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("entitygraph/sqlite: scan group edge: %w", err)
			}
			if n++; n > interfaces.MaxCollapseGroupMembers {
				_ = rows.Close()
				return nil, interfaces.ErrCollapseGroupTooLarge
			}
			for _, peer := range []string{fromSubj, toSubj} {
				if err := w.add(peer); err != nil {
					_ = rows.Close()
					return nil, err
				}
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("entitygraph/sqlite: iterate group edges: %w", err)
		}
		_ = rows.Close()
	}

	return sortedGroupMembers(w.visited), nil
}

// resolveGroupMembersAsOf walks the same-as graph from eid using the observation
// log, considering only edges that were active (not absent) at or before asOf.
// Retracted edges and peers outside the cut are removed in SQL, so they never
// count toward MaxCollapseGroupMembers.
func (p *SQLiteEntityGraphProvider) resolveGroupMembersAsOf(ctx context.Context, eid interfaces.EIDRef, asOf time.Time, cut interfaces.TenantCut) ([]interfaces.EIDRef, error) {
	walkCtx, cancel := context.WithTimeout(ctx, collapseAsOfWalkBudget)
	defer cancel()
	members, err := p.walkGroupMembersAsOf(walkCtx, eid, asOf, cut)
	if err != nil && walkCtx.Err() != nil && ctx.Err() == nil {
		// The budget expired, not the caller: the group is too expensive to collapse.
		return nil, interfaces.ErrCollapseGroupTooLarge
	}
	return members, err
}

// asOfRecursiveBranch builds one recursive step of the as-of walk: it joins the
// walk so far (grp) to the live same-as edge subjects and reduces each match to
// its peer with peerExpr. Peers outside the cut are removed here, so they never
// count toward MaxCollapseGroupMembers. It appends the cut arguments to *args.
func asOfRecursiveBranch(peerExpr, edgeCond string, cut interfaces.TenantCut, args *[]interface{}) string {
	q := "SELECT " + peerExpr + " FROM grp g CROSS JOIN live v WHERE " + edgeCond
	if cut.Active() {
		q += " AND " + peerExpr + " IN (SELECT subject FROM eg_entity_index WHERE " +
			tenantSubtreeCond("owning_tenant", cut, args) + ")"
	}
	return q
}

// walkGroupMembersAsOf is the as-of walk itself, run under the budgeted context.
// The whole walk is one WITH RECURSIVE query: "live" holds the same-as edge
// subjects whose latest observation at or before asOf is not a retraction, and
// "grp" grows from eid across them in both directions. The CTE is capped at
// MaxCollapseGroupMembers+1 rows, so a group past the limit stops the recursion
// inside the query.
func (p *SQLiteEntityGraphProvider) walkGroupMembersAsOf(ctx context.Context, eid interfaces.EIDRef, asOf time.Time, cut interfaces.TenantCut) ([]interfaces.EIDRef, error) {
	asOfStr := rfc3339(asOf)
	args := []interface{}{asOfStr, asOfStr, eid.String()}

	// Edge subjects are "same-as|<from>|<to>"; SQL substr/length count
	// characters, which is what the offsets below assume.
	fromBranch := asOfRecursiveBranch("substr(v.subject, length(g.eid) + 10)",
		"v.subject >= 'same-as|' || g.eid || '|' AND v.subject < 'same-as|' || g.eid || '}'", cut, &args)
	toBranch := asOfRecursiveBranch("substr(v.subject, 9, length(v.subject) - 9 - length(g.eid))",
		"length(v.subject) > length(g.eid) + 9 AND substr(v.subject, -(length(g.eid) + 1)) = '|' || g.eid", cut, &args)
	args = append(args, interfaces.MaxCollapseGroupMembers+1)

	// #nosec G202 -- the branches hold fixed SQL and ? placeholders; every
	// value, including tenant IDs, is bound through args.
	query := `WITH RECURSIVE live(subject) AS MATERIALIZED (
			SELECT l.subject FROM eg_observation_log l
			WHERE l.subject >= 'same-as|' AND l.subject < 'same-as}'
			  AND l.observed_at <= ? AND l.kind <> 'absence'
			  AND NOT EXISTS (
			      SELECT 1 FROM eg_observation_log m
			      WHERE m.subject = l.subject AND m.observed_at <= ?
			        AND (m.observed_at > l.observed_at
			             OR (m.observed_at = l.observed_at AND m.id > l.id))
			  )
		), grp(eid) AS (
			SELECT ?
			UNION ` + fromBranch + `
			UNION ` + toBranch + `
			LIMIT ?
		)
		SELECT eid FROM grp`

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: resolve group as-of for %s: %w", eid.String(), err)
	}
	defer func() { _ = rows.Close() }()

	visited := map[string]struct{}{}
	for rows.Next() {
		var member string
		if err := rows.Scan(&member); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: scan group as-of member: %w", err)
		}
		if len(visited) >= interfaces.MaxCollapseGroupMembers {
			return nil, interfaces.ErrCollapseGroupTooLarge
		}
		visited[member] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: iterate group as-of members: %w", err)
	}
	return sortedGroupMembers(visited), nil
}

// sortedGroupMembers converts a visited-set map to a sorted EID slice.
func sortedGroupMembers(visited map[string]struct{}) []interfaces.EIDRef {
	var members []interfaces.EIDRef
	for subj := range visited {
		eid, err := types.ParseEID(subj)
		if err != nil {
			continue
		}
		members = append(members, eid)
	}
	sort.Slice(members, func(i, j int) bool {
		return members[i].String() < members[j].String()
	})
	return members
}

// applyTenantCut filters group members to those whose current owning_tenant is
// visible to tenantFilter (ADR-022 §3: tenant cut before merge). Uses the current
// eg_entity_index ownership (not ingest-time tenant_path) as the access-control axis.
func (p *SQLiteEntityGraphProvider) applyTenantCut(ctx context.Context, members []interfaces.EIDRef, cut interfaces.TenantCut) ([]interfaces.EIDRef, error) {
	if !cut.Active() {
		return members, nil
	}

	var visible []interfaces.EIDRef
	for _, m := range members {
		var owningTenant string
		err := p.db.QueryRowContext(ctx,
			`SELECT owning_tenant FROM eg_entity_index WHERE subject = ?`,
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
func (p *SQLiteEntityGraphProvider) loadMemberSources(ctx context.Context, subject string) ([]sourceEntry, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT c.source, c.source_class, c.observed_at, c.payload_hash, pc.payload
		 FROM eg_entity_current c
		 JOIN eg_payload_content pc ON pc.payload_hash = c.payload_hash
		 WHERE c.subject = ?`,
		subject,
	)
	if err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: load member sources for %s: %w", subject, err)
	}
	defer func() { _ = rows.Close() }()

	var entries []sourceEntry
	for rows.Next() {
		var source, sourceClass, observedAt, hash, payloadJSON string
		if err := rows.Scan(&source, &sourceClass, &observedAt, &hash, &payloadJSON); err != nil {
			return nil, fmt.Errorf("entitygraph/sqlite: scan member source: %w", err)
		}
		var payload map[string]interface{}
		if payloadJSON != "" {
			if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
				return nil, fmt.Errorf("entitygraph/sqlite: decode member payload: %w", err)
			}
		}
		t, _ := time.Parse(time.RFC3339Nano, observedAt)
		entries = append(entries, sourceEntry{
			source:      source,
			sourceClass: sourceClass,
			observedAt:  t,
			payloadHash: hash,
			payload:     payload,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entitygraph/sqlite: iterate member sources: %w", err)
	}
	return entries, nil
}

// buildConflicts collects per-attribute values from sources that lost the
// precedence merge. An attribute has a conflict when multiple sources assert
// different values for it.
func buildConflicts(entries []sourceEntry, merged map[string]interface{}) map[string][]types.AttributeConflict {
	conflicts := make(map[string][]types.AttributeConflict)

	for _, e := range entries {
		for k, v := range e.payload {
			mergedV, ok := merged[k]
			if !ok {
				continue
			}
			vJSON, _ := json.Marshal(v)
			mergedJSON, _ := json.Marshal(mergedV)
			if string(vJSON) != string(mergedJSON) {
				conflicts[k] = append(conflicts[k], types.AttributeConflict{
					Source: e.source,
					Value:  v,
				})
			}
		}
	}

	if len(conflicts) == 0 {
		return nil
	}

	for k, cs := range conflicts {
		sort.Slice(cs, func(i, j int) bool { return cs[i].Source < cs[j].Source })
		conflicts[k] = cs
	}
	return conflicts
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
func (p *SQLiteEntityGraphProvider) resolveCollapseGroup(ctx context.Context, eid interfaces.EIDRef, asOf *time.Time, cut interfaces.TenantCut) (*types.CollapseGroupView, error) {
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
	conflicts := buildConflicts(allEntries, merged)

	return &types.CollapseGroupView{
		Members:   visible,
		Merged:    merged,
		Conflicts: conflicts,
	}, nil
}
