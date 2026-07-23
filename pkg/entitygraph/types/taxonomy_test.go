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

// TestTaxonomy_ParseRelatedEscapeError verifies that ParseRelatedEscape returns a
// non-nil, meaningful error for inputs that are not related:<discriminator> escapes.
// This exercises the error-return branch (taxonomy.go) that the round-trip test never hits.
func TestTaxonomy_ParseRelatedEscapeError(t *testing.T) {
	tx := types.DefaultTaxonomy()

	// Ordinary strings, a seed edge kind, and the bare prefix (no discriminator) must all
	// be rejected — IsRelatedEscape requires the prefix AND a non-empty discriminator.
	cases := []string{"widget", "same-as", "related:", "", "notrelated:x"}

	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			require.False(t, tx.IsRelatedEscape(kind),
				"test case %q must not be a related: escape", kind)

			discriminator, err := tx.ParseRelatedEscape(kind)
			require.Error(t, err, "ParseRelatedEscape(%q) must return an error", kind)
			assert.Empty(t, discriminator, "discriminator must be empty on error")
			assert.Contains(t, err.Error(), "is not a related: escape",
				"error message must explain why the input was rejected")
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

// TestTaxonomy_DNAFragmentKinds verifies that all stdlib owns: kinds (except user, which
// is a merge case) are registered with AuthorityClasses == []string{"host"} per ADR-017/A1.2.
func TestTaxonomy_DNAFragmentKinds(t *testing.T) {
	tx := types.DefaultTaxonomy()

	// These 9 kinds come from the 10 stdlib modules with owns: declarations; user is handled
	// separately because it requires merging with the pre-existing directory/m365 entry.
	hostKinds := []string{
		"file", "package", "script", "firewall", "service",
		"patch", "hostname", "cert_trust", "time",
	}

	for _, kind := range hostKinds {
		t.Run(kind, func(t *testing.T) {
			desc, ok := tx.LookupEntityType(kind)
			require.True(t, ok, "DNA fragment kind %q must be registered in taxonomy", kind)
			assert.Equal(t, kind, desc.Kind)
			assert.Equal(t, []string{"host"}, desc.AuthorityClasses,
				"DNA fragment kind %q must have AuthorityClasses == [\"host\"]", kind)
		})
	}
}

// TestTaxonomy_HostObserveOnlyKinds verifies the four fixed host:* observe-only kinds
// from ADR-017 §8 are registered per ADR-017/A1.2.
func TestTaxonomy_HostObserveOnlyKinds(t *testing.T) {
	tx := types.DefaultTaxonomy()

	observeKinds := []string{"host:cpu", "host:memory", "host:os", "host:bios"}

	for _, kind := range observeKinds {
		t.Run(kind, func(t *testing.T) {
			desc, ok := tx.LookupEntityType(kind)
			require.True(t, ok, "observe-only kind %q must be registered in taxonomy", kind)
			assert.Equal(t, kind, desc.Kind)
			assert.Equal(t, []string{"host"}, desc.AuthorityClasses,
				"observe-only kind %q must have AuthorityClasses == [\"host\"]", kind)
		})
	}
}

// TestTaxonomy_UserMergedAuthorityClasses verifies that the user kind carries all three
// authority classes after the ADR-017/A1.2 merge — the pre-existing directory/m365 entries
// must not be dropped.
func TestTaxonomy_UserMergedAuthorityClasses(t *testing.T) {
	tx := types.DefaultTaxonomy()

	desc, ok := tx.LookupEntityType("user")
	require.True(t, ok, "user kind must be registered in taxonomy")

	classes := desc.AuthorityClasses
	assert.Contains(t, classes, "directory", "user must retain directory authority class")
	assert.Contains(t, classes, "m365", "user must retain m365 authority class")
	assert.Contains(t, classes, "host", "user must gain host authority class from stdlib user module")
}

// TestTaxonomy_UnregisteredKindReturnsFalse verifies that unknown kinds return ok=false
// with no accidental wildcard match.
func TestTaxonomy_UnregisteredKindReturnsFalse(t *testing.T) {
	tx := types.DefaultTaxonomy()

	unknown := []string{"widget", "foo", "host:", "related:", "host:unknown"}
	for _, kind := range unknown {
		t.Run(kind, func(t *testing.T) {
			_, ok := tx.LookupEntityType(kind)
			assert.False(t, ok, "unregistered kind %q must return ok=false", kind)
		})
	}
}

// TestTaxonomy_VersionTwo verifies the taxonomy version is bumped to 2 per ADR-017/A1.2.
func TestTaxonomy_VersionTwo(t *testing.T) {
	tx := types.DefaultTaxonomy()
	assert.Equal(t, 2, tx.Version, "taxonomy must be at version 2 after ADR-017/A1.2 additions")
}

// TestTaxonomy_ClusterUntouched verifies that the cluster kind retains its
// pre-existing AuthorityClasses and is not modified by this story's additions.
func TestTaxonomy_ClusterUntouched(t *testing.T) {
	tx := types.DefaultTaxonomy()

	desc, ok := tx.LookupEntityType("cluster")
	require.True(t, ok, "cluster kind must remain in taxonomy")
	assert.Equal(t, []string{"cluster"}, desc.AuthorityClasses,
		"cluster AuthorityClasses must be unchanged by ADR-017/A1.2 additions")
}
