// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

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

// resolveGroupMembersCurrentState walks the same-as graph from eid using the
// current edge projection (fast path for non-temporal reads). Returns all group
// member EIDs including the subject itself. The group is traversed as an
// undirected graph: the same-as edge is symmetric.
func (p *DatabaseEntityGraphProvider) resolveGroupMembersCurrentState(ctx context.Context, eid interfaces.EIDRef) ([]interfaces.EIDRef, error) {
	visited := map[string]struct{}{eid.String(): {}}
	queue := []string{eid.String()}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		rows, err := p.db.QueryContext(ctx,
			`SELECT DISTINCT from_subject, to_subject
			 FROM eg_edge_projection
			 WHERE edge_type = 'same-as'
			   AND (from_subject = $1 OR to_subject = $2)`,
			current, current,
		)
		if err != nil {
			return nil, fmt.Errorf("entitygraph/database: resolve group edges for %s: %w", current, err)
		}

		for rows.Next() {
			var fromSubj, toSubj string
			if err := rows.Scan(&fromSubj, &toSubj); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("entitygraph/database: scan group edge: %w", err)
			}
			for _, peer := range []string{fromSubj, toSubj} {
				if _, seen := visited[peer]; !seen {
					visited[peer] = struct{}{}
					queue = append(queue, peer)
				}
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("entitygraph/database: iterate group edges: %w", err)
		}
		_ = rows.Close()
	}

	return sortedGroupMembers(visited), nil
}

// resolveGroupMembersAsOf walks the same-as graph from eid using the observation
// log, considering only edges that were active (not absent) at or before asOf.
// Uses DISTINCT ON to pick the latest kind per edge subject at or before asOf.
func (p *DatabaseEntityGraphProvider) resolveGroupMembersAsOf(ctx context.Context, eid interfaces.EIDRef, asOf time.Time) ([]interfaces.EIDRef, error) {
	asOfStr := asOf.UTC().Format(time.RFC3339Nano)
	visited := map[string]struct{}{eid.String(): {}}
	queue := []string{eid.String()}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// DISTINCT ON picks the most-recent log row per edge subject at or before asOf.
		rows, err := p.db.QueryContext(ctx, `
			SELECT DISTINCT ON (l.subject) l.subject, l.kind
			FROM eg_observation_log l
			WHERE (l.subject LIKE $1 ESCAPE '\' OR l.subject LIKE $2 ESCAPE '\')
			  AND l.observed_at <= $3
			ORDER BY l.subject, l.observed_at DESC, l.id DESC`,
			"same-as|"+escapeLIKE(current)+"|%",
			"same-as|%|"+escapeLIKE(current),
			asOfStr,
		)
		if err != nil {
			return nil, fmt.Errorf("entitygraph/database: resolve group as-of for %s: %w", current, err)
		}

		for rows.Next() {
			var edgeSubject, kind string
			if err := rows.Scan(&edgeSubject, &kind); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("entitygraph/database: scan group as-of edge: %w", err)
			}
			// Absence means the edge was retracted at asOf.
			if kind == string(types.ObservationKindAbsence) {
				continue
			}
			_, fromSubj, toSubj, err := parseEdgeSubject(edgeSubject)
			if err != nil {
				continue
			}
			for _, peer := range []string{fromSubj, toSubj} {
				if _, seen := visited[peer]; !seen {
					visited[peer] = struct{}{}
					queue = append(queue, peer)
				}
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("entitygraph/database: iterate group as-of edges: %w", err)
		}
		_ = rows.Close()
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
func (p *DatabaseEntityGraphProvider) applyTenantCut(ctx context.Context, members []interfaces.EIDRef, tenantFilter string) ([]interfaces.EIDRef, error) {
	if tenantFilter == "" {
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
		if tenantVisible(owningTenant, tenantFilter) {
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

	var entries []sourceEntry
	for rows.Next() {
		var source, sourceClass, observedAt, hash, payloadJSON string
		if err := rows.Scan(&source, &sourceClass, &observedAt, &hash, &payloadJSON); err != nil {
			return nil, fmt.Errorf("entitygraph/database: scan member source: %w", err)
		}
		var payload map[string]interface{}
		if payloadJSON != "" {
			if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
				return nil, fmt.Errorf("entitygraph/database: decode member payload: %w", err)
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
		return nil, fmt.Errorf("entitygraph/database: iterate member sources: %w", err)
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
// Returns nil when the entity has no same-as group or all other group members
// are cut by the tenant filter (single-visible-member group is a no-op).
func (p *DatabaseEntityGraphProvider) resolveCollapseGroup(ctx context.Context, eid interfaces.EIDRef, asOf *time.Time, tenantFilter string) (*types.CollapseGroupView, error) {
	// Step 1: resolve group membership.
	var members []interfaces.EIDRef
	var err error
	if asOf != nil {
		members, err = p.resolveGroupMembersAsOf(ctx, eid, *asOf)
	} else {
		members, err = p.resolveGroupMembersCurrentState(ctx, eid)
	}
	if err != nil {
		return nil, err
	}

	// No same-as edges: single-member group, no collapse needed.
	if len(members) <= 1 {
		return nil, nil
	}

	// Step 2: tenant cut before merge.
	visible, err := p.applyTenantCut(ctx, members, tenantFilter)
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
