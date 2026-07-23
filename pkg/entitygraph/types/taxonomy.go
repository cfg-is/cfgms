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

// DefaultTaxonomy returns the canonical seed taxonomy (version 2).
// Seed entity kinds and edge kinds are per ADR-022 §1/§2.
// Version 2 adds DNA fragment kinds per ADR-017/A1.2.
func DefaultTaxonomy() *Taxonomy {
	tx := &Taxonomy{
		// Version 2: added DNA fragment kinds (ADR-017/A1.2) and host:* observe-only kinds.
		Version:     2,
		entityTypes: make(map[string]*EntityTypeDescriptor),
		edgeTypes:   make(map[string]*EdgeTypeDescriptor),
	}

	// Seed entity kinds per ADR-022 §1.
	// user carries directory/m365/host — the host class is added here (ADR-017/A1.2)
	// to merge with the pre-existing directory/m365 authority for local-account fragments
	// from the stdlib user module; a second descriptor would silently overwrite via map
	// assignment, so the merge is done in-place on this single entry.
	entitySeeds := []*EntityTypeDescriptor{
		{Kind: "host", AuthorityClasses: []string{"host"}},
		{Kind: "cluster", AuthorityClasses: []string{"cluster"}},
		{Kind: "vm", AuthorityClasses: []string{"cluster", "host"}},
		{Kind: "vswitch", AuthorityClasses: []string{"cluster", "host"}},
		{Kind: "device", AuthorityClasses: []string{"host"}},
		{Kind: "application", AuthorityClasses: []string{"host"}},
		{Kind: "user", AuthorityClasses: []string{"directory", "m365", "host"}},
		{Kind: "group", AuthorityClasses: []string{"directory", "m365"}},
		{Kind: "tenant", AuthorityClasses: []string{"cfgms"}},
		{Kind: "directory", AuthorityClasses: []string{"directory", "m365"}},
	}
	for _, d := range entitySeeds {
		tx.entityTypes[d.Kind] = d
	}

	// DNA fragment kinds per ADR-017/A1.2 — one entry per stdlib module that declares
	// owns: in features/modules/stdlib/*/module.yaml (re-grepped at story-2904 authoring
	// time: file, package, script, firewall, service, patch, hostname, cert_trust, time).
	// All are host-scoped; the user collision is handled above via the merged entry.
	dnaFragmentSeeds := []*EntityTypeDescriptor{
		{Kind: "file", AuthorityClasses: []string{"host"}},
		{Kind: "package", AuthorityClasses: []string{"host"}},
		{Kind: "script", AuthorityClasses: []string{"host"}},
		{Kind: "firewall", AuthorityClasses: []string{"host"}},
		{Kind: "service", AuthorityClasses: []string{"host"}},
		{Kind: "patch", AuthorityClasses: []string{"host"}},
		{Kind: "hostname", AuthorityClasses: []string{"host"}},
		{Kind: "cert_trust", AuthorityClasses: []string{"host"}},
		{Kind: "time", AuthorityClasses: []string{"host"}},
	}
	for _, d := range dnaFragmentSeeds {
		tx.entityTypes[d.Kind] = d
	}

	// host:* observe-only kinds per ADR-017 §8 fixed contract — hardware and OS facts
	// observed by the steward but not enforced by any module.
	hostObserveSeeds := []*EntityTypeDescriptor{
		{Kind: "host:cpu", AuthorityClasses: []string{"host"}},
		{Kind: "host:memory", AuthorityClasses: []string{"host"}},
		{Kind: "host:os", AuthorityClasses: []string{"host"}},
		{Kind: "host:bios", AuthorityClasses: []string{"host"}},
	}
	for _, d := range hostObserveSeeds {
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
