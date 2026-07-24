// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	entitygraphtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// hashByID returns the FragmentHash for the given fragment_id, or "" if absent.
func hashByID(frags []*commonpb.Fragment, id string) string {
	for _, f := range frags {
		if f.FragmentId == id {
			return f.FragmentHash
		}
	}
	return ""
}

// fragmentIDs builds a set of fragment_ids from a slice.
func fragmentIDSet(frags []*commonpb.Fragment) map[string]bool {
	m := make(map[string]bool, len(frags))
	for _, f := range frags {
		m[f.FragmentId] = true
	}
	return m
}

// TestPartitionHostFacts_ProducesRequiredKinds verifies that the four required
// host:* kinds are emitted when the corresponding attribute keys are populated.
func TestPartitionHostFacts_ProducesRequiredKinds(t *testing.T) {
	attrs := map[string]string{
		// host:cpu
		"cpu_count":  "8",
		"cpu_arch":   "amd64",
		"cpu_model":  "Intel Xeon E5-2670",
		"cpu_vendor": "GenuineIntel",
		// host:memory
		"memory_total_kb": "16384000",
		"memory_total_gb": "16.00",
		// host:os
		"os":             "linux",
		"os_name":        "Ubuntu",
		"os_version":     "22.04 LTS",
		"kernel_version": "5.15.0-50-generic",
		// host:bios
		"bios_vendor":  "American Megatrends Inc.",
		"bios_version": "2.1.0",
		"system_uuid":  "AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF",
	}

	taxonomy := entitygraphtypes.DefaultTaxonomy()
	fragments, envelopes, err := PartitionHostFacts(attrs, taxonomy, nil)
	require.NoError(t, err)

	ids := fragmentIDSet(fragments)
	assert.True(t, ids["host:cpu"], "must produce host:cpu fragment")
	assert.True(t, ids["host:memory"], "must produce host:memory fragment")
	assert.True(t, ids["host:os"], "must produce host:os fragment")
	assert.True(t, ids["host:bios"], "must produce host:bios fragment")

	for _, f := range fragments {
		assert.NotEmpty(t, f.FragmentHash,
			"fragment %s must have a non-empty hash", f.FragmentId)
		assert.NotEmpty(t, f.CanonicalBytes,
			"fragment %s must have non-empty canonical bytes", f.FragmentId)
		assert.Equal(t, "gatherer", f.Authority,
			"authority must be 'gatherer' for %s", f.FragmentId)

		env, ok := envelopes[f.FragmentId]
		require.True(t, ok, "envelope must exist for %s", f.FragmentId)
		assert.Equal(t, "high", env.Confidence,
			"confidence must be 'high' for %s", f.FragmentId)
		assert.NotNil(t, env.ObservedAt,
			"observed_at must be set for %s", f.FragmentId)
	}
}

// TestPartitionHostFacts_FailClosed verifies that a kind with no populated keys
// is omitted rather than emitted as an empty fragment.
func TestPartitionHostFacts_FailClosed(t *testing.T) {
	// Only CPU keys present — all other collectors produced nothing.
	attrs := map[string]string{
		"cpu_count": "4",
		"cpu_arch":  "amd64",
	}

	taxonomy := entitygraphtypes.DefaultTaxonomy()
	fragments, envelopes, err := PartitionHostFacts(attrs, taxonomy, nil)
	require.NoError(t, err)

	ids := fragmentIDSet(fragments)
	assert.True(t, ids["host:cpu"], "host:cpu must be emitted when keys are present")
	assert.False(t, ids["host:memory"], "host:memory must be omitted (fail-closed: no keys)")
	assert.False(t, ids["host:os"], "host:os must be omitted (fail-closed: no keys)")
	assert.False(t, ids["host:bios"], "host:bios must be omitted (fail-closed: no keys)")
	assert.NotContains(t, envelopes, "host:memory",
		"envelope must be absent when fragment is omitted")
}

// TestPartitionHostFacts_Deterministic verifies that two calls with the same
// attributes produce byte-for-byte identical fragment hashes.
func TestPartitionHostFacts_Deterministic(t *testing.T) {
	attrs := map[string]string{
		"cpu_count":       "4",
		"cpu_arch":        "amd64",
		"cpu_model":       "Test CPU Model",
		"memory_total_kb": "8192000",
		"os":              "linux",
		"kernel_version":  "5.15.0",
		"bios_version":    "1.0.0",
	}

	taxonomy := entitygraphtypes.DefaultTaxonomy()
	frags1, _, err := PartitionHostFacts(attrs, taxonomy, nil)
	require.NoError(t, err)
	frags2, _, err := PartitionHostFacts(attrs, taxonomy, nil)
	require.NoError(t, err)

	require.Len(t, frags2, len(frags1),
		"both calls must produce the same number of fragments")

	h1 := make(map[string]string)
	for _, f := range frags1 {
		h1[f.FragmentId] = f.FragmentHash
	}
	for _, f := range frags2 {
		assert.Equal(t, h1[f.FragmentId], f.FragmentHash,
			"fragment %s: hash must be identical across two calls with the same input",
			f.FragmentId)
	}
}

// TestPartitionHostFacts_LegacyFlatMapUnchanged is the REQUIRED regression test
// asserting that PartitionHostFacts does NOT modify the attributes map.
// The flat-map surface, Reports Engine, and every legacy consumer must be
// unaffected (additive-only claim per story #2910 scope).
func TestPartitionHostFacts_LegacyFlatMapUnchanged(t *testing.T) {
	attrs := map[string]string{
		"cpu_count":         "4",
		"cpu_arch":          "amd64",
		"cpu_model":         "Test CPU",
		"memory_total_kb":   "8192000",
		"os":                "linux",
		"timestamp":         "2026-07-24T00:00:00Z",
		"system_uptime":     "up 5 days",
		"working_directory": "/home/test",
		"local_user_count":  "42",
		"bios_version":      "1.0",
	}

	// Snapshot the map before the call.
	before := make(map[string]string, len(attrs))
	for k, v := range attrs {
		before[k] = v
	}

	taxonomy := entitygraphtypes.DefaultTaxonomy()
	_, _, err := PartitionHostFacts(attrs, taxonomy, nil)
	require.NoError(t, err)

	// The attributes map must be byte-for-byte identical to the pre-call snapshot.
	assert.Equal(t, before, attrs,
		"PartitionHostFacts must not modify the attributes map (additive-only contract)")
}

// TestPartitionHostFacts_ModuleOwnedKindExcluded is the REQUIRED test proving that
// a fragment kind claimed by a module's owns: declaration is absent from the output.
// Per AC: keys in the flat attributes map belonging to a module-owned kind remain
// in the flat map unchanged but are absent from any fragment this story produces.
func TestPartitionHostFacts_ModuleOwnedKindExcluded(t *testing.T) {
	attrs := map[string]string{
		// CPU and memory keys — would normally produce host:cpu and host:memory fragments.
		"cpu_count":       "4",
		"cpu_arch":        "amd64",
		"memory_total_kb": "8192000",
		// user/group facts from collectSecurityInfo — present in flat map, must not
		// appear in any fragment payload (user module owns the user kind; ADR-017 §2).
		"local_user_count":    "42",
		"local_group_count":   "15",
		"root_account_locked": "true",
	}

	// Claim host:cpu as owned by a test module to exercise the ownership exclusion filter.
	// (In production the stdlib modules own service, file, user, etc. — none of which
	// overlap with host:cpu/memory/os/bios, so this test uses an injected claim to
	// exercise the code path directly.)
	ownership := map[string][]modules.OwnershipDeclaration{
		"test-module": {{Kind: "host:cpu"}},
	}

	taxonomy := entitygraphtypes.DefaultTaxonomy()
	fragments, _, err := PartitionHostFacts(attrs, taxonomy, ownership)
	require.NoError(t, err)

	// host:cpu must be absent — the test module claimed it.
	ids := fragmentIDSet(fragments)
	assert.False(t, ids["host:cpu"],
		"host:cpu must be excluded because test-module declared ownership of it")

	// Flat map must be unmodified — user/group keys still present.
	assert.Equal(t, "42", attrs["local_user_count"],
		"local_user_count must remain in flat map unchanged")

	// User/group attributes must not appear in any fragment canonical bytes.
	// The canonical encoding prefixes key names as length-prefixed byte fields,
	// so checking for the key name string is sufficient.
	for _, f := range fragments {
		payload := string(f.CanonicalBytes)
		assert.NotContains(t, payload, "local_user_count",
			"user attribute must not appear in fragment %s", f.FragmentId)
		assert.NotContains(t, payload, "local_group_count",
			"group attribute must not appear in fragment %s", f.FragmentId)
		assert.NotContains(t, payload, "root_account_locked",
			"user-domain security attribute must not appear in fragment %s", f.FragmentId)
	}
}

// TestPartitionHostFacts_EphemeralKeyExcluded is the REQUIRED test proving that
// ephemeral keys (system_uptime, timestamp, etc.) are present in the flat
// attributes map but absent from every fragment payload (ADR-017 §4).
func TestPartitionHostFacts_EphemeralKeyExcluded(t *testing.T) {
	attrs := map[string]string{
		// Stable CPU keys — these should appear in the host:cpu fragment.
		"cpu_count": "4",
		"cpu_arch":  "amd64",
		// Ephemeral keys — these must NOT appear in any fragment.
		"timestamp":         "2026-07-24T12:00:00Z",
		"system_uptime":     "up 5 days, 3 hours",
		"working_directory": "/home/steward",
		"memory_go_alloc":   "1234567",
		"memory_go_sys":     "9876543",
	}

	taxonomy := entitygraphtypes.DefaultTaxonomy()
	fragments, _, err := PartitionHostFacts(attrs, taxonomy, nil)
	require.NoError(t, err)

	// Ephemeral keys must still be present in the flat map (additive-only).
	assert.Contains(t, attrs, "timestamp",
		"timestamp must remain in flat attributes map")
	assert.Contains(t, attrs, "system_uptime",
		"system_uptime must remain in flat attributes map")

	ephemeralKeys := []string{
		"timestamp", "system_uptime", "working_directory",
		"memory_go_alloc", "memory_go_sys",
	}
	for _, f := range fragments {
		payload := string(f.CanonicalBytes)
		for _, ek := range ephemeralKeys {
			assert.NotContains(t, payload, ek,
				"ephemeral key %q must not appear in fragment %s canonical bytes",
				ek, f.FragmentId)
		}
	}

	// host:cpu must still be emitted (cpu_count and cpu_arch are present).
	ids := fragmentIDSet(fragments)
	assert.True(t, ids["host:cpu"],
		"host:cpu must be emitted even when ephemeral keys are in attributes")
}

// TestPartitionHostFacts_HashDiffers verifies that different attribute values
// produce different fragment hashes, and identical values produce identical hashes.
func TestPartitionHostFacts_HashDiffers(t *testing.T) {
	taxonomy := entitygraphtypes.DefaultTaxonomy()

	attrsA := map[string]string{"cpu_count": "4", "cpu_arch": "amd64"}
	attrsB := map[string]string{"cpu_count": "8", "cpu_arch": "amd64"}

	fragsA, _, err := PartitionHostFacts(attrsA, taxonomy, nil)
	require.NoError(t, err)
	fragsB, _, err := PartitionHostFacts(attrsB, taxonomy, nil)
	require.NoError(t, err)

	hashA := hashByID(fragsA, "host:cpu")
	hashB := hashByID(fragsB, "host:cpu")
	require.NotEmpty(t, hashA, "host:cpu must be present in fragsA")
	require.NotEmpty(t, hashB, "host:cpu must be present in fragsB")
	assert.NotEqual(t, hashA, hashB,
		"different cpu_count values must produce different host:cpu hashes")

	// Same input → same hash (determinism cross-checked here too).
	fragsA2, _, err := PartitionHostFacts(attrsA, taxonomy, nil)
	require.NoError(t, err)
	assert.Equal(t, hashA, hashByID(fragsA2, "host:cpu"),
		"identical input must produce identical hash (deterministic)")
}

// TestPartitionHostFacts_UnregisteredKindNotEmitted verifies that a kind not in
// the taxonomy is never emitted — even if it appears in a hypothetical future spec.
func TestPartitionHostFacts_UnregisteredKindNotEmitted(t *testing.T) {
	attrs := map[string]string{
		"cpu_count": "4",
		"cpu_arch":  "amd64",
	}

	// An empty taxonomy has no registered kinds.
	emptyTaxonomy := &entitygraphtypes.Taxonomy{}
	fragments, envelopes, err := PartitionHostFacts(attrs, emptyTaxonomy, nil)
	require.NoError(t, err)
	assert.Empty(t, fragments,
		"no fragments must be emitted when taxonomy has no registered kinds")
	assert.Empty(t, envelopes,
		"no envelopes must be emitted when taxonomy has no registered kinds")
}

// TestPartitionHostFacts_EnvelopeSource verifies that each fragment's envelope
// Source is "gatherer:<category>" where category matches the fragment's spec.
func TestPartitionHostFacts_EnvelopeSource(t *testing.T) {
	attrs := map[string]string{
		"cpu_count":       "4",
		"cpu_arch":        "amd64",
		"memory_total_kb": "8192000",
		"os":              "linux",
		"kernel_version":  "5.15.0",
		"bios_version":    "2.0",
	}

	taxonomy := entitygraphtypes.DefaultTaxonomy()
	_, envelopes, err := PartitionHostFacts(attrs, taxonomy, nil)
	require.NoError(t, err)

	expectedSources := map[string]string{
		"host:cpu":    "gatherer:hardware",
		"host:memory": "gatherer:hardware",
		"host:os":     "gatherer:software",
		"host:bios":   "gatherer:hardware",
	}
	for kind, want := range expectedSources {
		env, ok := envelopes[kind]
		if !ok {
			continue // kind not emitted; covered by other tests
		}
		assert.Equal(t, want, env.Source,
			"fragment %s: Source must be %q", kind, want)
	}
}

// TestPartitionHostFacts_EmptyAttributes verifies graceful handling of an empty
// map — no error, no fragments (all kinds fail-closed with no keys).
func TestPartitionHostFacts_EmptyAttributes(t *testing.T) {
	taxonomy := entitygraphtypes.DefaultTaxonomy()
	fragments, envelopes, err := PartitionHostFacts(map[string]string{}, taxonomy, nil)
	require.NoError(t, err)
	assert.Empty(t, fragments, "empty attributes must produce no fragments")
	assert.Empty(t, envelopes, "empty attributes must produce no envelopes")
}

// TestPickAttributeKeys_EphemeralFiltered verifies the ephemeral-key exclusion
// in the internal pickAttributeKeys helper.
func TestPickAttributeKeys_EphemeralFiltered(t *testing.T) {
	attrs := map[string]string{
		"cpu_count":     "4",
		"system_uptime": "up 3 days",
		"timestamp":     "2026-07-24T00:00:00Z",
	}
	allowlist := []string{"cpu_count", "system_uptime", "timestamp"}
	result := pickAttributeKeys(attrs, allowlist)

	assert.Contains(t, result, "cpu_count", "cpu_count must pass through")
	assert.NotContains(t, result, "system_uptime",
		"system_uptime is ephemeral and must be filtered out")
	assert.NotContains(t, result, "timestamp",
		"timestamp is ephemeral and must be filtered out")
}

// TestBuildOwnedKindSet verifies that buildOwnedKindSet correctly aggregates
// kinds across multiple modules.
func TestBuildOwnedKindSet(t *testing.T) {
	ownership := map[string][]modules.OwnershipDeclaration{
		"service-module": {{Kind: "service"}},
		"file-module":    {{Kind: "file"}, {Kind: "directory"}},
	}
	owned := buildOwnedKindSet(ownership)

	assert.True(t, owned["service"], "service must be owned")
	assert.True(t, owned["file"], "file must be owned")
	assert.True(t, owned["directory"], "directory must be owned")
	assert.False(t, owned["host:cpu"], "host:cpu must not be owned by these modules")
}
