// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types_test

import (
	"strings"
	"testing"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTaxonomy_SeedEntityTypes(t *testing.T) {
	tx := types.DefaultTaxonomy()

	seedKinds := []string{
		"application", "device", "user", "group", "tenant",
		"vm", "vswitch", "host", "cluster", "directory",
	}

	for _, kind := range seedKinds {
		t.Run(kind, func(t *testing.T) {
			desc, ok := tx.LookupEntityType(kind)
			require.True(t, ok, "seed entity kind %q must be in taxonomy", kind)
			assert.Equal(t, kind, desc.Kind)
			assert.NotEmpty(t, desc.AuthorityClasses, "entity type must have at least one authority class")
		})
	}
}

func TestTaxonomy_SeedEdgeTypes(t *testing.T) {
	tx := types.DefaultTaxonomy()

	seedEdges := []string{
		"contains", "runs-on", "member-of", "depends-on", "serves",
		"connects-to", "manages", "managed-by", "assigned-to",
		"delegated-access", "reports-to", "same-as",
	}

	for _, kind := range seedEdges {
		t.Run(kind, func(t *testing.T) {
			desc, ok := tx.LookupEdgeType(kind)
			require.True(t, ok, "seed edge kind %q must be in taxonomy", kind)
			assert.Equal(t, kind, desc.Kind)
		})
	}
}

func TestTaxonomy_UnrecognizedEdgeRoundTrip(t *testing.T) {
	tx := types.DefaultTaxonomy()

	cases := []string{
		"related:custom-link",
		"related:hyperv-move",
		"related:arbitrary-discriminator",
	}

	for _, edgeKind := range cases {
		t.Run(edgeKind, func(t *testing.T) {
			require.True(t, strings.HasPrefix(edgeKind, "related:"),
				"test case should use the related: prefix")

			ok := tx.IsRelatedEscape(edgeKind)
			assert.True(t, ok, "related: edge must be recognized as escape")

			// Must parse without error and round-trip the discriminator.
			discriminator, err := tx.ParseRelatedEscape(edgeKind)
			require.NoError(t, err)
			assert.NotEmpty(t, discriminator)

			// Re-encoding must round-trip.
			roundTripped := tx.FormatRelatedEscape(discriminator)
			assert.Equal(t, edgeKind, roundTripped)
		})
	}
}

func TestTaxonomy_PrecedenceOverrideField(t *testing.T) {
	tx := types.DefaultTaxonomy()

	// Every seed entity type must carry the PrecedenceOrder field (may be nil = default).
	// This epic populates no non-default values, but the field must exist on the descriptor.
	desc, ok := tx.LookupEntityType("host")
	require.True(t, ok)

	// Field exists and nil signals "use default order" — that is correct for this epic.
	// A consumer that needs the order calls tx.EffectivePrecedenceOrder(desc).
	order := tx.EffectivePrecedenceOrder(desc)
	assert.Equal(t, types.DefaultPrecedenceOrder, order,
		"host with nil override must return DefaultPrecedenceOrder")
}

func TestTaxonomy_Version(t *testing.T) {
	tx := types.DefaultTaxonomy()
	assert.Greater(t, tx.Version, 0, "taxonomy must have a positive version")
}
