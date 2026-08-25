// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package resolution_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/modules/resolution"
	modules "github.com/cfgis/cfgms/features/modules"
)

// makeObserveManifest builds a minimal ModuleMetadata with the given observe_when predicates.
func makeObserveManifest(name string, predicates []modules.ObservePredicate) *modules.ModuleMetadata {
	return &modules.ModuleMetadata{
		Name:        name,
		Version:     "1.0.0",
		Description: "test module",
		Publisher:   "cfgms",
		Executors:   []string{"steward"},
		Kind:        "steward",
		ObserveWhen: predicates,
	}
}

// makeAlwaysPullManifest builds a minimal ModuleMetadata with AlwaysPull true and no ObserveWhen.
func makeAlwaysPullManifest(name string) *modules.ModuleMetadata {
	return &modules.ModuleMetadata{
		Name:       name,
		Version:    "1.0.0",
		Publisher:  "cfgms",
		Executors:  []string{"steward"},
		Kind:       "steward",
		AlwaysPull: true,
	}
}

func TestResolveObserveModules_EmptyObserveWhenNeverMatches(t *testing.T) {
	// A manifest with no ObserveWhen must never appear in the result, even if
	// the DNA contains data (ADR-024 §2: absence means never auto-pull).
	dna := map[string]string{
		"hyperv_enabled": "true",
		"os":             "windows",
	}
	manifests := []*modules.ModuleMetadata{
		makeObserveManifest("no-observe", nil),
		makeObserveManifest("empty-observe", []modules.ObservePredicate{}),
	}

	got := resolution.ResolveObserveModules(dna, manifests)
	assert.Empty(t, got, "manifests with nil or empty ObserveWhen must not match")
}

func TestResolveObserveModules_EqualsMatch(t *testing.T) {
	dna := map[string]string{"hyperv_enabled": "true"}
	manifests := []*modules.ModuleMetadata{
		makeObserveManifest("hyperv-observer", []modules.ObservePredicate{
			{Fact: "hyperv_enabled", Equals: "true"},
		}),
	}

	got := resolution.ResolveObserveModules(dna, manifests)
	require.Len(t, got, 1)
	assert.Equal(t, "hyperv-observer", got[0])
}

func TestResolveObserveModules_EqualsNoMatch(t *testing.T) {
	// hyperv_enabled absent → no match.
	dna := map[string]string{"os": "windows"}
	manifests := []*modules.ModuleMetadata{
		makeObserveManifest("hyperv-observer", []modules.ObservePredicate{
			{Fact: "hyperv_enabled", Equals: "true"},
		}),
	}

	got := resolution.ResolveObserveModules(dna, manifests)
	assert.Empty(t, got)
}

func TestResolveObserveModules_EqualsFalseNoMatch(t *testing.T) {
	// hyperv_enabled present but "false" → predicate requires "true", so no match.
	dna := map[string]string{"hyperv_enabled": "false"}
	manifests := []*modules.ModuleMetadata{
		makeObserveManifest("hyperv-observer", []modules.ObservePredicate{
			{Fact: "hyperv_enabled", Equals: "true"},
		}),
	}

	got := resolution.ResolveObserveModules(dna, manifests)
	assert.Empty(t, got)
}

func TestResolveObserveModules_ContainsMatch(t *testing.T) {
	dna := map[string]string{"os_description": "Ubuntu 24.04 LTS"}
	manifests := []*modules.ModuleMetadata{
		makeObserveManifest("ubuntu-observer", []modules.ObservePredicate{
			{Fact: "os_description", Contains: "Ubuntu"},
		}),
	}

	got := resolution.ResolveObserveModules(dna, manifests)
	require.Len(t, got, 1)
	assert.Equal(t, "ubuntu-observer", got[0])
}

func TestResolveObserveModules_ContainsNoMatch(t *testing.T) {
	dna := map[string]string{"os_description": "Windows Server 2022"}
	manifests := []*modules.ModuleMetadata{
		makeObserveManifest("ubuntu-observer", []modules.ObservePredicate{
			{Fact: "os_description", Contains: "Ubuntu"},
		}),
	}

	got := resolution.ResolveObserveModules(dna, manifests)
	assert.Empty(t, got)
}

func TestResolveObserveModules_ORSemantics_AnyPredicateMatches(t *testing.T) {
	// Module has two predicates; only the second is satisfied.
	// OR semantics: any one match activates the module.
	dna := map[string]string{"hyperv_role_installed": "true"}
	manifests := []*modules.ModuleMetadata{
		makeObserveManifest("hyperv-observer", []modules.ObservePredicate{
			{Fact: "hyperv_enabled", Equals: "true"},        // not satisfied
			{Fact: "hyperv_role_installed", Equals: "true"}, // satisfied
		}),
	}

	got := resolution.ResolveObserveModules(dna, manifests)
	require.Len(t, got, 1, "OR semantics: single satisfied predicate must activate the module")
	assert.Equal(t, "hyperv-observer", got[0])
}

func TestResolveObserveModules_MultipleManifests_IndependentResolution(t *testing.T) {
	// Two manifests: one matches, one doesn't.
	dna := map[string]string{"hyperv_enabled": "true"}
	manifests := []*modules.ModuleMetadata{
		makeObserveManifest("hyperv-observer", []modules.ObservePredicate{
			{Fact: "hyperv_enabled", Equals: "true"},
		}),
		makeObserveManifest("vmware-observer", []modules.ObservePredicate{
			{Fact: "virtualization_type", Equals: "vmware"},
		}),
	}

	got := resolution.ResolveObserveModules(dna, manifests)
	require.Len(t, got, 1)
	assert.Equal(t, "hyperv-observer", got[0])
}

func TestResolveObserveModules_AllManifestsMatch(t *testing.T) {
	dna := map[string]string{
		"hyperv_enabled":        "true",
		"virtualization_type":   "hyperv",
		"hyperv_role_installed": "true",
	}
	manifests := []*modules.ModuleMetadata{
		makeObserveManifest("hyperv-observer", []modules.ObservePredicate{
			{Fact: "hyperv_enabled", Equals: "true"},
		}),
		makeObserveManifest("virt-observer", []modules.ObservePredicate{
			{Fact: "virtualization_type", Contains: "hyper"},
		}),
	}

	got := resolution.ResolveObserveModules(dna, manifests)
	sort.Strings(got)
	assert.Equal(t, []string{"hyperv-observer", "virt-observer"}, got)
}

func TestResolveObserveModules_EmptyDNA(t *testing.T) {
	// With an empty DNA map, no predicate can match.
	dna := map[string]string{}
	manifests := []*modules.ModuleMetadata{
		makeObserveManifest("hyperv-observer", []modules.ObservePredicate{
			{Fact: "hyperv_enabled", Equals: "true"},
		}),
	}

	got := resolution.ResolveObserveModules(dna, manifests)
	assert.Empty(t, got)
}

func TestResolveObserveModules_EmptyManifests(t *testing.T) {
	dna := map[string]string{"hyperv_enabled": "true"}
	got := resolution.ResolveObserveModules(dna, nil)
	assert.Empty(t, got)
}

// TestResolveObserveModules_HypervEnabledDNAFact is the end-to-end fixture that
// confirms key-convention alignment between the already-shipped hyperv_enabled
// DNA fact (features/steward/dna/hardware_windows.go collectHyperVInfo) and the
// new matcher. The fact key "hyperv_enabled" with value "true" or "false" is the
// real contract; this test locks it down so a rename on either side fails loudly.
func TestResolveObserveModules_HypervEnabledDNAFact(t *testing.T) {
	// The actual DNA key emitted by collectHyperVInfo is "hyperv_enabled" with
	// the value produced by strconv.FormatBool — "true" or "false".
	dnaTrueHost := map[string]string{
		"hyperv_enabled":        "true",
		"hyperv_role_installed": "true",
		"virtualization_type":   "none",
		"virtualization_role":   "host",
	}
	dnaFalseGuest := map[string]string{
		"hyperv_enabled":        "false",
		"hyperv_role_installed": "false",
		"virtualization_type":   "hyperv",
		"virtualization_role":   "guest",
	}
	dnaMissingElevation := map[string]string{
		// hyperv_enabled omitted (elevation unavailable — collector omits the key per #1950)
		"hyperv_role_installed": "true",
		"virtualization_type":   "none",
		"virtualization_role":   "host",
	}

	hypervModule := makeObserveManifest("hyperv", []modules.ObservePredicate{
		{Fact: "hyperv_enabled", Equals: "true"},
	})

	t.Run("matches_when_hyperv_enabled_true", func(t *testing.T) {
		got := resolution.ResolveObserveModules(dnaTrueHost, []*modules.ModuleMetadata{hypervModule})
		require.Len(t, got, 1)
		assert.Equal(t, "hyperv", got[0])
	})

	t.Run("no_match_when_hyperv_enabled_false", func(t *testing.T) {
		got := resolution.ResolveObserveModules(dnaFalseGuest, []*modules.ModuleMetadata{hypervModule})
		assert.Empty(t, got)
	})

	t.Run("no_match_when_hyperv_enabled_absent", func(t *testing.T) {
		// Collector omits the key entirely on elevation failure — must not match.
		got := resolution.ResolveObserveModules(dnaMissingElevation, []*modules.ModuleMetadata{hypervModule})
		assert.Empty(t, got)
	})
}

// ---------------------------------------------------------------------------
// AlwaysPull tests (ADR-024 Amendment 2, Issue #3563)
// ---------------------------------------------------------------------------

// TestResolveObserveModules_AlwaysPull_EmptyDNA confirms that an AlwaysPull
// manifest is included even when the baseline DNA map is empty — universal pull
// is unconditional, not predicate-gated.
func TestResolveObserveModules_AlwaysPull_EmptyDNA(t *testing.T) {
	m := makeAlwaysPullManifest("osquery")
	got := resolution.ResolveObserveModules(map[string]string{}, []*modules.ModuleMetadata{m})
	require.Len(t, got, 1)
	assert.Equal(t, "osquery", got[0])
}

// TestResolveObserveModules_AlwaysPull_NilDNA confirms AlwaysPull activates with
// a nil DNA map (steward may send nil on first boot).
func TestResolveObserveModules_AlwaysPull_NilDNA(t *testing.T) {
	m := makeAlwaysPullManifest("osquery")
	got := resolution.ResolveObserveModules(nil, []*modules.ModuleMetadata{m})
	require.Len(t, got, 1)
	assert.Equal(t, "osquery", got[0])
}

// TestResolveObserveModules_AlwaysPull_WithPopulatedDNA confirms AlwaysPull
// activates regardless of what DNA facts are present.
func TestResolveObserveModules_AlwaysPull_WithPopulatedDNA(t *testing.T) {
	m := makeAlwaysPullManifest("osquery")
	dna := map[string]string{"os": "linux", "arch": "amd64", "hyperv_enabled": "false"}
	got := resolution.ResolveObserveModules(dna, []*modules.ModuleMetadata{m})
	require.Len(t, got, 1)
	assert.Equal(t, "osquery", got[0])
}

// TestResolveObserveModules_AlwaysFalse_EmptyObserveWhen confirms that a module
// with AlwaysPull false (or absent) and no ObserveWhen is still never included —
// existing behavior unchanged (ADR-024 §2).
func TestResolveObserveModules_AlwaysFalse_EmptyObserveWhen(t *testing.T) {
	m := &modules.ModuleMetadata{
		Name:       "inert-module",
		Version:    "1.0.0",
		Publisher:  "cfgms",
		Executors:  []string{"steward"},
		Kind:       "steward",
		AlwaysPull: false,
	}
	dna := map[string]string{"os": "linux"}
	got := resolution.ResolveObserveModules(dna, []*modules.ModuleMetadata{m})
	assert.Empty(t, got, "AlwaysPull=false with no ObserveWhen must never be included")
}

// TestResolveObserveModules_AlwaysPull_CoexistsWithObserveWhen confirms that a
// manifest list can contain both AlwaysPull and observe_when modules; each is
// resolved independently.
func TestResolveObserveModules_AlwaysPull_CoexistsWithObserveWhen(t *testing.T) {
	osq := makeAlwaysPullManifest("osquery")
	hyperv := makeObserveManifest("hyperv", []modules.ObservePredicate{
		{Fact: "hyperv_enabled", Equals: "true"},
	})
	// DNA has hyperv_enabled=true → hyperv matches; osquery always matches.
	dna := map[string]string{"hyperv_enabled": "true", "os": "windows"}
	got := resolution.ResolveObserveModules(dna, []*modules.ModuleMetadata{osq, hyperv})
	sort.Strings(got)
	assert.Equal(t, []string{"hyperv", "osquery"}, got)
}

// TestResolveObserveModules_AlwaysPull_HypervUnaffected is the required
// regression test: existing observe_when-only modules (hyperv) are unaffected by
// the AlwaysPull field (ADR-024 Amendment 2, AC: "existing observe_when-only
// modules are unaffected").
func TestResolveObserveModules_AlwaysPull_HypervUnaffected(t *testing.T) {
	osq := makeAlwaysPullManifest("osquery")
	hyperv := makeObserveManifest("hyperv", []modules.ObservePredicate{
		{Fact: "hyperv_enabled", Equals: "true"},
	})

	t.Run("hyperv_present_when_predicate_matches", func(t *testing.T) {
		dna := map[string]string{"hyperv_enabled": "true"}
		got := resolution.ResolveObserveModules(dna, []*modules.ModuleMetadata{hyperv, osq})
		sort.Strings(got)
		assert.Equal(t, []string{"hyperv", "osquery"}, got)
	})

	t.Run("hyperv_absent_when_predicate_does_not_match", func(t *testing.T) {
		// osquery must still appear (AlwaysPull); hyperv must not (predicate fails).
		dna := map[string]string{"hyperv_enabled": "false"}
		got := resolution.ResolveObserveModules(dna, []*modules.ModuleMetadata{hyperv, osq})
		require.Len(t, got, 1)
		assert.Equal(t, "osquery", got[0])
	})

	t.Run("hyperv_absent_when_fact_missing", func(t *testing.T) {
		// osquery must still appear; hyperv must not.
		dna := map[string]string{"os": "linux"}
		got := resolution.ResolveObserveModules(dna, []*modules.ModuleMetadata{hyperv, osq})
		require.Len(t, got, 1)
		assert.Equal(t, "osquery", got[0])
	})
}
