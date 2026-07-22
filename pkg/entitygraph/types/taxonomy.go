// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import (
	"fmt"
	"strings"
)

// SourceClass identifies the class of a knowledge source for precedence ordering
// per ADR-022 §4. Higher index = lower precedence in DefaultPrecedenceOrder.
type SourceClass string

const (
	SourceClassEnforcingModule     SourceClass = "enforcing-module"
	SourceClassManagingIntegration SourceClass = "managing-integration"
	SourceClassObserver            SourceClass = "observer"
	SourceClassOperatorAssertion   SourceClass = "operator-assertion"
	SourceClassCorrelatorInference SourceClass = "correlator-inference"
)

// DefaultPrecedenceOrder is the default source class ordering per ADR-022 §4:
// enforcing module > managing integration > observer > operator assertion > correlator inference.
var DefaultPrecedenceOrder = []SourceClass{
	SourceClassEnforcingModule,
	SourceClassManagingIntegration,
	SourceClassObserver,
	SourceClassOperatorAssertion,
	SourceClassCorrelatorInference,
}

// EntityTypeDescriptor describes a known entity kind in the taxonomy.
type EntityTypeDescriptor struct {
	// Kind is the entity type name (e.g. "host", "user").
	Kind string

	// AuthorityClasses lists the authority types that can name this entity kind.
	AuthorityClasses []string

	// PrecedenceOrder overrides DefaultPrecedenceOrder for this entity type.
	// nil means use DefaultPrecedenceOrder. No entity type in this epic sets
	// a non-default value; wiring a consumer is a named follow-on.
	PrecedenceOrder []SourceClass
}

// EdgeTypeDescriptor describes a known edge kind in the taxonomy.
type EdgeTypeDescriptor struct {
	// Kind is the edge type name (e.g. "contains", "runs-on").
	Kind string
}

// relatedPrefix is the open-subtype escape prefix per ADR-022 §2.
const relatedPrefix = "related:"

// Taxonomy is the versioned entity and edge type registry per ADR-022 §1/§2.
type Taxonomy struct {
	// Version is the registry version; bumped on each taxonomy change.
	Version int

	entityTypes map[string]*EntityTypeDescriptor
	edgeTypes   map[string]*EdgeTypeDescriptor
}

// LookupEntityType returns the descriptor for a known entity kind.
// The second return value is false for unrecognized kinds.
func (tx *Taxonomy) LookupEntityType(kind string) (*EntityTypeDescriptor, bool) {
	d, ok := tx.entityTypes[kind]
	return d, ok
}

// LookupEdgeType returns the descriptor for a known edge kind.
// Returns false for unrecognized kinds that are not the related: escape.
func (tx *Taxonomy) LookupEdgeType(kind string) (*EdgeTypeDescriptor, bool) {
	d, ok := tx.edgeTypes[kind]
	return d, ok
}

// IsRelatedEscape reports whether kind is a related:<discriminator> open-subtype.
func (tx *Taxonomy) IsRelatedEscape(kind string) bool {
	return strings.HasPrefix(kind, relatedPrefix) && len(kind) > len(relatedPrefix)
}

// ParseRelatedEscape extracts the discriminator from a related:<discriminator> kind.
func (tx *Taxonomy) ParseRelatedEscape(kind string) (string, error) {
	if !tx.IsRelatedEscape(kind) {
		return "", fmt.Errorf("entitygraph/taxonomy: %q is not a related: escape", kind)
	}
	return kind[len(relatedPrefix):], nil
}

// FormatRelatedEscape formats a discriminator into a related:<discriminator> kind.
func (tx *Taxonomy) FormatRelatedEscape(discriminator string) string {
	return relatedPrefix + discriminator
}

// EffectivePrecedenceOrder returns the precedence order for the given entity type,
// falling back to DefaultPrecedenceOrder when the descriptor carries no override.
func (tx *Taxonomy) EffectivePrecedenceOrder(desc *EntityTypeDescriptor) []SourceClass {
	if desc != nil && len(desc.PrecedenceOrder) > 0 {
		return desc.PrecedenceOrder
	}
	return DefaultPrecedenceOrder
}

// DefaultTaxonomy returns the canonical seed taxonomy (version 1).
// Seed entity kinds and edge kinds are per ADR-022 §1/§2.
func DefaultTaxonomy() *Taxonomy {
	tx := &Taxonomy{
		Version:     1,
		entityTypes: make(map[string]*EntityTypeDescriptor),
		edgeTypes:   make(map[string]*EdgeTypeDescriptor),
	}

	// Seed entity kinds per ADR-022 §1.
	entitySeeds := []*EntityTypeDescriptor{
		{Kind: "host", AuthorityClasses: []string{"host"}},
		{Kind: "cluster", AuthorityClasses: []string{"cluster"}},
		{Kind: "vm", AuthorityClasses: []string{"cluster", "host"}},
		{Kind: "vswitch", AuthorityClasses: []string{"cluster", "host"}},
		{Kind: "device", AuthorityClasses: []string{"host"}},
		{Kind: "application", AuthorityClasses: []string{"host"}},
		{Kind: "user", AuthorityClasses: []string{"directory", "m365"}},
		{Kind: "group", AuthorityClasses: []string{"directory", "m365"}},
		{Kind: "tenant", AuthorityClasses: []string{"cfgms"}},
		{Kind: "directory", AuthorityClasses: []string{"directory", "m365"}},
	}
	for _, d := range entitySeeds {
		tx.entityTypes[d.Kind] = d
	}

	// Seed edge kinds per ADR-022 §2.
	edgeSeeds := []string{
		"contains",
		"runs-on",
		"member-of",
		"depends-on",
		"serves",
		"connects-to",
		"manages",
		"managed-by",
		"assigned-to",
		"delegated-access",
		"reports-to",
		"same-as",
	}
	for _, kind := range edgeSeeds {
		tx.edgeTypes[kind] = &EdgeTypeDescriptor{Kind: kind}
	}

	return tx
}
