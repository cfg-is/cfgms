// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

// Edge is a directed, typed relationship between two entities (ADR-022 §2).
type Edge struct {
	// Type is the edge kind (e.g. "contains", "runs-on", "related:custom").
	Type string
	From EID
	To   EID

	// Attributes are optional typed metadata for this edge.
	Attributes map[string]interface{}

	// Sources holds the per-source observations asserting this edge.
	Sources []Observation
}

// TraversalDirection controls the direction of neighborhood traversal.
type TraversalDirection string

const (
	TraversalOutbound TraversalDirection = "outbound"
	TraversalInbound  TraversalDirection = "inbound"
	TraversalBoth     TraversalDirection = "both"
)

// Neighborhood is the result of a depth-bounded subgraph traversal (ADR-022 §9).
// Depth is bounded at ≤3 per the access contract.
type Neighborhood struct {
	Root  EID
	Nodes []*Entity
	Edges []*Edge
}
