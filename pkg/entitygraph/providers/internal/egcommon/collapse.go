// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package egcommon

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// EscapeLIKE escapes SQL LIKE metacharacters (\, %, _) in s so s is treated as
// a literal substring when used in a LIKE pattern with ESCAPE '\'.
func EscapeLIKE(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// TenantSubtreeCond returns the SQL predicate "<col> IN (<p>, <p>, ...)" matching
// col against every tenant ID in the cut: the scoped tenant plus the descendant
// IDs the caller resolved from the tenant tree. Every ID is a bound argument, so
// no tenant string is ever interpreted as a pattern. nextPlaceholder returns the
// provider's next bind placeholder ("?" or "$N", advancing its counter); the
// arguments are appended to *args. This is the sole builder for tenant subtree
// predicates in the entity graph providers.
func TenantSubtreeCond(col string, cut interfaces.TenantCut, nextPlaceholder func() string, args *[]interface{}) string {
	members := cut.Members()
	phs := make([]string, len(members))
	for i, id := range members {
		phs[i] = nextPlaceholder()
		*args = append(*args, id)
	}
	return fmt.Sprintf("%s IN (%s)", col, strings.Join(phs, ", "))
}

// GroupWalk is the bounded breadth-first state shared by both same-as walks.
type GroupWalk struct {
	Visited map[string]struct{}
	Queue   []string
}

// NewGroupWalk starts a walk at start.
func NewGroupWalk(start string) *GroupWalk {
	return &GroupWalk{Visited: map[string]struct{}{start: {}}, Queue: []string{start}}
}

// Add records peer as a group member. It fails with ErrCollapseGroupTooLarge as
// soon as the distinct member count passes MaxCollapseGroupMembers.
func (w *GroupWalk) Add(peer string) error {
	if _, seen := w.Visited[peer]; seen {
		return nil
	}
	if len(w.Visited) >= interfaces.MaxCollapseGroupMembers {
		return interfaces.ErrCollapseGroupTooLarge
	}
	w.Visited[peer] = struct{}{}
	w.Queue = append(w.Queue, peer)
	return nil
}

// SortedGroupMembers converts a visited-set map to a sorted EID slice.
func SortedGroupMembers(visited map[string]struct{}) []interfaces.EIDRef {
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

// ScanAsOfMembers reads the single-column member rows of the as-of group walk
// into a visited set. It fails with ErrCollapseGroupTooLarge when the rows hold
// more than MaxCollapseGroupMembers members. The caller closes rows.
func ScanAsOfMembers(rows *sql.Rows, d Dialect) (map[string]struct{}, error) {
	visited := map[string]struct{}{}
	for rows.Next() {
		var member string
		if err := rows.Scan(&member); err != nil {
			return nil, fmt.Errorf("%s: scan group as-of member: %w", d.Prefix, err)
		}
		if len(visited) >= interfaces.MaxCollapseGroupMembers {
			return nil, interfaces.ErrCollapseGroupTooLarge
		}
		visited[member] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: iterate group as-of members: %w", d.Prefix, err)
	}
	return visited, nil
}

// MemberSource is one decoded row of a group member's current sources.
type MemberSource struct {
	Source      string
	SourceClass string
	ObservedAt  time.Time
	PayloadHash string
	Payload     map[string]interface{}
}

// ScanMemberSources decodes rows of (source, source_class, observed_at,
// payload_hash, payload) into MemberSources. The SQL that produces the rows
// stays in each provider. The caller closes rows.
func ScanMemberSources(rows *sql.Rows, d Dialect) ([]MemberSource, error) {
	var entries []MemberSource
	for rows.Next() {
		var source, sourceClass, observedAt, hash, payloadJSON string
		if err := rows.Scan(&source, &sourceClass, &observedAt, &hash, &payloadJSON); err != nil {
			return nil, fmt.Errorf("%s: scan member source: %w", d.Prefix, err)
		}
		var payload map[string]interface{}
		if payloadJSON != "" {
			if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
				return nil, fmt.Errorf("%s: decode member payload: %w", d.Prefix, err)
			}
		}
		t, _ := time.Parse(time.RFC3339Nano, observedAt)
		entries = append(entries, MemberSource{
			Source:      source,
			SourceClass: sourceClass,
			ObservedAt:  t,
			PayloadHash: hash,
			Payload:     payload,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: iterate member sources: %w", d.Prefix, err)
	}
	return entries, nil
}

// BuildConflicts collects per-attribute values from sources that lost the
// precedence merge. An attribute has a conflict when multiple sources assert
// different values for it. view returns an entry's source and payload, so each
// provider keeps its own source-entry type.
func BuildConflicts[E any](entries []E, view func(E) (string, map[string]interface{}), merged map[string]interface{}) map[string][]types.AttributeConflict {
	conflicts := make(map[string][]types.AttributeConflict)

	for _, e := range entries {
		source, payload := view(e)
		for k, v := range payload {
			mergedV, ok := merged[k]
			if !ok {
				continue
			}
			vJSON, _ := json.Marshal(v)
			mergedJSON, _ := json.Marshal(mergedV)
			if string(vJSON) != string(mergedJSON) {
				conflicts[k] = append(conflicts[k], types.AttributeConflict{
					Source: source,
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
