// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dnasync

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// edgesKey is the reserved canonical-fragment key that carries edge declarations.
// A module includes this key in its AsMap() output alongside entity state fields;
// the writer decodes it and strips it so it never reaches entity attributes.
// See docs/architecture/modules/README.md "Fragment edge declarations".
const edgesKey = "__entitygraph_edges"

// edgeSubjectSep is the delimiter of the observation edge-subject format
// "edge_type|from_eid|to_eid". Providers parse the subject back with
// strings.SplitN(subject, "|", 3) (sqlite/edges.go parseEdgeSubject,
// database/edges.go), so the encoding is injective only while no component
// contains the delimiter. Same constant and same reasoning as the sibling
// correlator writer (writers/correlator/writer.go sameAsSubject).
const edgeSubjectSep = "|"

// maxEdgeFieldLen bounds a steward-supplied edge `type` or `to` value. Both are
// unbounded on the wire — the canonical decoder accepts strings up to the 8 MiB
// fragment limit — and both reach storage keys, so they are bounded here for the
// same reason as maxClusterAuthorityNameLen (resolve.go), and to the same limit.
const maxEdgeFieldLen = 253

// validEdgeField reports whether a steward-supplied edge `type` or `to` value is
// accepted: non-empty, bounded, and safe as an edge-subject component.
func validEdgeField(s string) bool {
	if s == "" || len(s) > maxEdgeFieldLen {
		return false
	}
	return safeEdgeComponent(s)
}

// safeEdgeComponent reports whether s may appear as one of the three components
// of an edge subject: valid UTF-8, free of edgeSubjectSep, and free of control
// characters.
//
// The delimiter check is the authority boundary. Stewards run on hosts that may
// be compromised (CLAUDE.md threat model) and both the edge type and the edge
// endpoints originate in steward-supplied fragment data: `type` reaches the
// subject verbatim (or wrapped in the related: escape), and an EID authority
// segment can carry a steward-supplied cluster name, which types.ParseEID rejects
// only for '/'. A component containing '|' makes the round-trip non-injective —
// type "contains|cluster:victim" yields a subject that re-parses with
// from="cluster:victim", binding the edge to an attacker-chosen anchor in another
// authority's namespace, materializing a placeholder node there, and producing an
// edge that can never be retracted (the ClaimScope stores the unsplit type while
// the provider matches the parsed prefix). Skipping the entry keeps every
// steward-supplied value confined to its own subject component.
//
// Control characters are rejected because the provider key encodings —
// edgeProjectionKey and claimScopeKey — join components with 0x1F on the stated
// invariant that no component contains a control character.
func safeEdgeComponent(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	if strings.Contains(s, edgeSubjectSep) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// edgeSubject returns the canonical edge-subject string "edge_type|from|to" and
// reports whether it is well-formed. It is the single assembly point for the
// format, so the injectivity invariant is enforced where the string is built.
func edgeSubject(edgeType string, fromEID, toEID types.EID) (string, bool) {
	from, to := fromEID.String(), toEID.String()
	if !safeEdgeComponent(edgeType) || !safeEdgeComponent(from) || !safeEdgeComponent(to) {
		return "", false
	}
	return edgeType + edgeSubjectSep + from + edgeSubjectSep + to, true
}

// decodeEdgeDeclarations extracts the __entitygraph_edges key from payload,
// strips it so it never appears as an entity attribute, and builds one
// types.Observation per declared edge plus one types.ClaimScope per
// (peerHostAuthority, edgeType) pair present in the declaration list.
//
// The peerHostAuthority is always used as Observation.Source and
// ClaimScope.Source for edges so that source-equality holds and the
// retraction machinery fires correctly (same reasoning as the host-scoped
// entity source rule in writer.go). ClaimScope.AsOf is left as the zero value;
// callers must set it before adding the scopes to a batch.
//
// Edge type resolution: if edgeType is not registered in taxonomy and is not
// already a related:-escape, it is wrapped via taxonomy.FormatRelatedEscape so
// that discovery is never blocked on taxonomy governance (ADR-022 §2).
//
// Endpoint resolution: the "self" sentinel resolves to host:peerHostAuthority
// (the bare host-authority EID for the reporting steward). All other `to`
// values are resolved by extracting the leading kind token and calling
// ResolveSubjectEID — the same branch logic used for the fragment's own subject.
//
// Malformed, unresolvable, or unsafe entries are silently skipped; a missing
// topology edge is recoverable, an ingest failure is not. "Unsafe" means the
// resolved edge type or either endpoint fails safeEdgeComponent — see there for
// why a steward-supplied '|' or control character is an authority-boundary
// violation rather than a cosmetic encoding defect.
func decodeEdgeDeclarations(
	peerHostAuthority string,
	fromEID types.EID,
	observedAt, recordedAt time.Time,
	payload map[string]interface{},
	taxonomy *types.Taxonomy,
	membership ClusterMembership,
) ([]types.Observation, []types.ClaimScope) {
	raw, ok := payload[edgesKey]
	// Always strip the key — even if parse fails below — so the key never
	// reaches entity attribute storage.
	delete(payload, edgesKey)
	if !ok {
		return nil, nil
	}

	edgeList, ok := raw.([]interface{})
	if !ok || len(edgeList) == 0 {
		return nil, nil
	}

	// The anchor EID is shared by every declared edge and by every ClaimScope
	// built below, so an unsafe from-EID disqualifies the whole declaration list
	// rather than individual entries. (fromEID can carry a steward-supplied
	// cluster name: the bare cluster-kind branch of ResolveSubjectEID takes it
	// from the fragment_id's local part.)
	if !safeEdgeComponent(fromEID.String()) {
		return nil, nil
	}

	// seenEdgeTypes tracks which edge types this fragment declared so we build
	// exactly one ClaimScope per (peerHostAuthority, edgeType) pair.
	seenEdgeTypes := map[string]struct{}{}

	var obs []types.Observation
	for _, item := range edgeList {
		edgeMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		rawType, _ := edgeMap["type"].(string)
		if !validEdgeField(rawType) {
			continue
		}
		toStr, _ := edgeMap["to"].(string)
		if !validEdgeField(toStr) {
			continue
		}

		// Resolve edge type. Unknown types use the related: escape (ADR-022 §2).
		edgeType := rawType
		if _, known := taxonomy.LookupEdgeType(edgeType); !known && !taxonomy.IsRelatedEscape(edgeType) {
			edgeType = taxonomy.FormatRelatedEscape(rawType)
		}

		// Resolve "self" to the bare host-authority EID for the reporting steward.
		var toEID types.EID
		if toStr == "self" {
			var err error
			toEID, err = types.NewEID("host", peerHostAuthority, "")
			if err != nil {
				continue
			}
		} else {
			// Extract kind from the to value (everything before the first ':').
			toKind := toStr
			if idx := strings.Index(toStr, ":"); idx >= 0 {
				toKind = toStr[:idx]
			}
			var err error
			toEID, _, _, err = ResolveSubjectEID(toKind, peerHostAuthority, toStr, nil, taxonomy, membership)
			if err != nil {
				// Skip unresolvable endpoints rather than failing the ingest.
				continue
			}
		}

		// Build an edge observation. Source is peerHostAuthority so that
		// ClaimScope.Source and Observation.Source are equal — the retraction
		// contract (claimscope.go:collectScopeSubjects) requires string equality.
		// Re-check after resolution: the escape wrapper and the endpoint resolver
		// both compose new strings, so the invariant is enforced on the values
		// that actually reach the subject.
		subject, ok := edgeSubject(edgeType, fromEID, toEID)
		if !ok {
			continue
		}
		obs = append(obs, types.Observation{
			Source:     peerHostAuthority,
			ObservedAt: observedAt,
			RecordedAt: recordedAt,
			Subject:    subject,
			Kind:       types.ObservationKindState,
			Confidence: types.ConfidenceHigh,
		})

		seenEdgeTypes[edgeType] = struct{}{}
	}

	// Build one ClaimScope per (peerHostAuthority, edgeType) pair with
	// AnchorEID = fromEID and Direction = outbound (all declared edges are
	// FROM this fragment). AsOf is zero; callers set it before use.
	var cs []types.ClaimScope
	for et := range seenEdgeTypes {
		cs = append(cs, types.ClaimScope{
			Source: peerHostAuthority,
			Pattern: types.ClaimScopePattern{
				Edge: &types.EdgeScopePattern{
					EdgeType:  et,
					AnchorEID: fromEID,
					Direction: types.TraversalOutbound,
				},
			},
		})
	}

	return obs, cs
}
