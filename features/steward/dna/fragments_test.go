// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	entitygraphtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// --- OsquerySource test doubles ---

// osquerySourceDouble is a deterministic OsquerySource for testing
// PartitionHostFactsFromOsquery. It implements the OsquerySource interface
// defined in this package — not the real osqueryModule — so tests control
// exactly which kinds succeed, fail, or return nil state. The real
// osqueryModule's trust-gate logic is tested independently in
// features/modules/extended/osquery/module_test.go.
type osquerySourceDouble struct {
	healthy   bool
	perKind   map[string]modules.ConfigState
	failKinds map[string]bool
	nilKinds  map[string]bool // returns (nil, nil) to test nil-state error path
}

func (s *osquerySourceDouble) IsActiveAndHealthy() bool { return s.healthy }

func (s *osquerySourceDouble) Get(_ context.Context, kind string) (modules.ConfigState, error) {
	if s.nilKinds[kind] {
		return nil, nil
	}
	if s.failKinds[kind] {
		return nil, errors.New("osquery: simulated get failure")
	}
	if state, ok := s.perKind[kind]; ok {
		return state, nil
	}
	return nil, errors.New("osquery: unsupported kind in test double")
}

var _ OsquerySource = (*osquerySourceDouble)(nil)

// osqueryStateFixture builds a ConfigState backed by the given string map for
// use with PartitionHostFactsFromOsquery tests.
func osqueryStateFixture(data map[string]string) modules.ConfigState {
	m := make(map[string]interface{}, len(data))
	for k, v := range data {
		m[k] = v
	}
	return MapState(m)
}

// defaultOsquerySource returns an osquerySourceDouble that returns plausible data
// for all four curated host:* kinds and reports itself as active and healthy.
func defaultOsquerySource() *osquerySourceDouble {
	return &osquerySourceDouble{
		healthy: true,
		perKind: map[string]modules.ConfigState{
			"host:cpu": osqueryStateFixture(map[string]string{
				"cpu_brand":          "Intel(R) Xeon(R) Gold 6154",
				"cpu_physical_cores": "18",
				"cpu_logical_cores":  "36",
			}),
			"host:memory": osqueryStateFixture(map[string]string{
				"physical_memory": "137438953472",
			}),
			"host:os": osqueryStateFixture(map[string]string{
				"os":       "Ubuntu",
				"hostname": "steward-01",
				"version":  "22.04.3 LTS",
			}),
			"host:bios": osqueryStateFixture(map[string]string{
				"hardware_vendor": "ACME Corp",
				"hardware_model":  "ProServer 9000",
				"uuid":            "AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF",
			}),
		},
		failKinds: nil,
	}
}

// --- PartitionHostFactsFromOsquery tests ---

// TestPartitionHostFactsFromOsquery_ProducesOsqueryKinds verifies that when all
// Get calls succeed, all four host:* kinds are emitted.
func TestPartitionHostFactsFromOsquery_ProducesOsqueryKinds(t *testing.T) {
	src := defaultOsquerySource()
	taxonomy := entitygraphtypes.DefaultTaxonomy()

	frags, envelopes, err := PartitionHostFactsFromOsquery(t.Context(), src, taxonomy, nil)
	require.NoError(t, err)

	ids := fragmentIDSet(frags)
	assert.True(t, ids["host:cpu"], "must produce host:cpu fragment")
	assert.True(t, ids["host:memory"], "must produce host:memory fragment")
	assert.True(t, ids["host:os"], "must produce host:os fragment")
	assert.True(t, ids["host:bios"], "must produce host:bios fragment")

	require.Len(t, envelopes, len(frags), "exactly one envelope must be co-produced per emitted fragment")
	for _, f := range frags {
		assert.NotEmpty(t, f.FragmentHash, "fragment %s must have a non-empty hash", f.FragmentId)
		assert.NotEmpty(t, f.CanonicalBytes, "fragment %s must have non-empty canonical bytes", f.FragmentId)
		env, ok := envelopes[f.FragmentId]
		require.True(t, ok, "envelope must exist for fragment %s", f.FragmentId)
		assert.Equal(t, "osquery", env.Source, "fragment %s: envelope Source must be 'osquery'", f.FragmentId)
	}
}

// TestPartitionHostFactsFromOsquery_AuthorityAndSourceAreOsquery is the REQUIRED
// test for the label-source pairing invariant: every emitted fragment must carry
// Authority:"osquery" and every envelope Source:"osquery".
func TestPartitionHostFactsFromOsquery_AuthorityAndSourceAreOsquery(t *testing.T) {
	src := defaultOsquerySource()
	taxonomy := entitygraphtypes.DefaultTaxonomy()

	frags, envelopes, err := PartitionHostFactsFromOsquery(t.Context(), src, taxonomy, nil)
	require.NoError(t, err)

	for _, f := range frags {
		assert.Equal(t, "osquery", f.Authority,
			"fragment %s: Authority must be 'osquery', not 'gatherer' or anything else", f.FragmentId)

		env, ok := envelopes[f.FragmentId]
		require.True(t, ok, "envelope must exist for fragment %s", f.FragmentId)
		assert.Equal(t, "osquery", env.Source,
			"fragment %s: envelope Source must be 'osquery'", f.FragmentId)
		assert.Equal(t, "high", env.Confidence,
			"fragment %s: Confidence must be 'high'", f.FragmentId)
		assert.NotNil(t, env.ObservedAt,
			"fragment %s: ObservedAt must be set", f.FragmentId)
	}
}

// TestPartitionHostFactsFromOsquery_FailClosedPerKind verifies that a Get failure
// for one kind omits only that kind — it does not abort the whole pass, and it
// does NOT substitute gatherer data for the failed kind.
func TestPartitionHostFactsFromOsquery_FailClosedPerKind(t *testing.T) {
	src := defaultOsquerySource()
	src.failKinds = map[string]bool{"host:cpu": true}

	taxonomy := entitygraphtypes.DefaultTaxonomy()
	frags, _, err := PartitionHostFactsFromOsquery(t.Context(), src, taxonomy, nil)
	require.NoError(t, err)

	ids := fragmentIDSet(frags)
	assert.False(t, ids["host:cpu"],
		"host:cpu must be absent when Get fails — fail-closed, not gatherer-fallback")
	assert.True(t, ids["host:memory"], "host:memory must still be emitted")
	assert.True(t, ids["host:os"], "host:os must still be emitted")
	assert.True(t, ids["host:bios"], "host:bios must still be emitted")

	// The surviving fragments must still carry Authority:"osquery" — not "gatherer".
	for _, f := range frags {
		assert.Equal(t, "osquery", f.Authority,
			"surviving fragment %s must keep Authority:'osquery' even when another kind failed",
			f.FragmentId)
	}
}

// TestPartitionHostFactsFromOsquery_NilStateReturnsError verifies the error return
// path of PartitionHostFactsFromOsquery: a source that reports success but returns
// a nil state is an OsquerySource contract violation. The function must return an
// error and no fragments rather than panicking on nil.AsMap() or emitting a
// partial pass whose provenance cannot be asserted.
func TestPartitionHostFactsFromOsquery_NilStateReturnsError(t *testing.T) {
	src := defaultOsquerySource()
	src.nilKinds = map[string]bool{"host:memory": true}

	taxonomy := entitygraphtypes.DefaultTaxonomy()
	frags, envelopes, err := PartitionHostFactsFromOsquery(t.Context(), src, taxonomy, nil)

	require.Error(t, err, "nil state with no error from source must abort the pass with an error")
	assert.Contains(t, err.Error(), "host:memory",
		"error must name the kind whose source violated the contract")
	assert.Nil(t, frags, "no fragments may be returned when the source violated its contract")
	assert.Nil(t, envelopes, "no envelopes may be returned when the source violated its contract")
}

// TestPartitionHostFactsFromOsquery_ModuleOwnedKindExcluded verifies that a kind
// claimed by a module's ownership declaration is excluded from osquery output,
// mirroring the same exclusion in PartitionHostFacts (ADR-017 §2).
func TestPartitionHostFactsFromOsquery_ModuleOwnedKindExcluded(t *testing.T) {
	src := defaultOsquerySource()
	taxonomy := entitygraphtypes.DefaultTaxonomy()
	ownership := map[string][]modules.OwnershipDeclaration{
		"cpu-module": {{Kind: "host:cpu"}},
	}

	frags, _, err := PartitionHostFactsFromOsquery(t.Context(), src, taxonomy, ownership)
	require.NoError(t, err)

	ids := fragmentIDSet(frags)
	assert.False(t, ids["host:cpu"],
		"host:cpu must be excluded because cpu-module claimed it — module authority preempts osquery")
	assert.True(t, ids["host:memory"], "host:memory must still be emitted")
	assert.True(t, ids["host:os"], "host:os must still be emitted")
}

// TestProvenance_NoGathererDataInOsqueryPath is the REQUIRED test for the
// label-source pairing invariant: no code path may emit gatherer-sourced fragment
// content labeled Authority:"osquery", nor osquery-sourced content labeled
// Authority:"gatherer".
//
// This test verifies the invariant by directly inspecting the output of both
// partition functions: gatherer output never carries "osquery", osquery output
// never carries "gatherer".
func TestProvenance_NoGathererDataInOsqueryPath(t *testing.T) {
	taxonomy := entitygraphtypes.DefaultTaxonomy()

	// Gatherer-sourced fragments must be labeled "gatherer", not "osquery".
	gatherAttrs := map[string]string{
		"cpu_count": "4",
		"cpu_arch":  "amd64",
		"os":        "linux",
	}
	gatherFrags, _, err := PartitionHostFacts(gatherAttrs, taxonomy, nil)
	require.NoError(t, err)
	for _, f := range gatherFrags {
		assert.Equal(t, "gatherer", f.Authority,
			"[REQUIRED] PartitionHostFacts must label fragments 'gatherer', never 'osquery': fragment %s",
			f.FragmentId)
		assert.NotEqual(t, "osquery", f.Authority,
			"[REQUIRED] gatherer-sourced fragment %s must never carry Authority:'osquery'", f.FragmentId)
	}

	// Osquery-sourced fragments must be labeled "osquery", not "gatherer".
	src := defaultOsquerySource()
	osqueryFrags, osqueryEnvs, err := PartitionHostFactsFromOsquery(t.Context(), src, taxonomy, nil)
	require.NoError(t, err)
	for _, f := range osqueryFrags {
		assert.Equal(t, "osquery", f.Authority,
			"[REQUIRED] PartitionHostFactsFromOsquery must label fragments 'osquery', never 'gatherer': fragment %s",
			f.FragmentId)
		assert.NotEqual(t, "gatherer", f.Authority,
			"[REQUIRED] osquery-sourced fragment %s must never carry Authority:'gatherer'", f.FragmentId)

		env := osqueryEnvs[f.FragmentId]
		require.NotNil(t, env)
		assert.Equal(t, "osquery", env.Source,
			"[REQUIRED] osquery envelope Source must be 'osquery', not 'gatherer:*': fragment %s",
			f.FragmentId)
		assert.NotContains(t, env.Source, "gatherer",
			"[REQUIRED] osquery envelope Source must not contain 'gatherer': fragment %s", f.FragmentId)
	}
}

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

// TestPartitionHostFacts_HostnameUnconditionallyPresent is the REQUIRED
// regression test for Issue #3319/#3358: the observed hostname must appear in
// the host:os fragment even when no hostname module resource is configured
// (ownership map nil/empty) — the exact shape of a steward's DNA at first
// registration, before any Tier-2 observe sweep or explicit hostname resource
// exists. Without this, the controller's required-field presence check
// (features/controller/service/dna_integrity.go) rejects every newly
// registering steward as missing "hostname".
func TestPartitionHostFacts_HostnameUnconditionallyPresent(t *testing.T) {
	attrs := map[string]string{
		"hostname": "newly-registered-steward",
		"os":       "linux",
	}

	taxonomy := entitygraphtypes.DefaultTaxonomy()
	// No ownership declarations at all — mirrors a steward that has not yet
	// had any module resource (including hostname) configured.
	fragments, _, err := PartitionHostFacts(attrs, taxonomy, nil)
	require.NoError(t, err)

	var hostOS *commonpb.Fragment
	for _, f := range fragments {
		if f.FragmentId == "host:os" {
			hostOS = f
		}
	}
	require.NotNil(t, hostOS, "host:os fragment must be emitted")

	decoded, err := DecodeCanonicalFragment(hostOS.CanonicalBytes)
	require.NoError(t, err)
	assert.Equal(t, "newly-registered-steward", decoded["hostname"],
		"host:os fragment must carry the observed hostname unconditionally, "+
			"independent of whether a hostname module resource is configured")
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

// TestFlattenFragments_ProjectsStringValues covers the flat projection the
// controller feeds its not-yet-re-homed attribute consumers from: string values
// are carried, non-string and empty values are dropped.
func TestFlattenFragments_ProjectsStringValues(t *testing.T) {
	osFrag, err := NewFragment("host:os", "gatherer", MapState(map[string]interface{}{
		"os":          "linux",
		"hostname":    "cfg-70-02",
		"os_name":     "",   // empty string: indistinguishable from absent, dropped
		"cpu_count":   8,    // non-string: not representable in a flat string map
		"secure_boot": true, // non-string
	}))
	require.NoError(t, err)

	flat := FlattenFragments([]*commonpb.Fragment{osFrag})

	assert.Equal(t, map[string]string{"os": "linux", "hostname": "cfg-70-02"}, flat)
}

// TestFlattenFragments_SkipsHostileFragments proves one unusable fragment cannot
// blank the projection. Stewards run on hosts that may be compromised, so a
// fragment with undecodable or empty canonical bytes must be skipped rather than
// abort the merge — otherwise a single crafted fragment wipes the controller's
// view of every other one.
func TestFlattenFragments_SkipsHostileFragments(t *testing.T) {
	good, err := NewFragment("host:os", "gatherer", MapState(map[string]interface{}{"os": "linux"}))
	require.NoError(t, err)

	flat := FlattenFragments([]*commonpb.Fragment{
		nil,
		{FragmentId: "host:empty"},
		{FragmentId: "host:garbage", CanonicalBytes: []byte{0xff, 0xff, 0xff, 0xff, 0x01}},
		good,
	})

	assert.Equal(t, map[string]string{"os": "linux"}, flat)
}

// TestFlattenFragments_DeterministicOnKeyCollision pins the merge order. When two
// fragments declare the same key the highest fragment_id wins, every time —
// independent of slice order. The controller hashes this projection into the DNA
// fingerprint (features/controller/fleet/storage/storage.go), so a
// map-iteration-order merge would make the fingerprint flap between identical
// snapshots and drive spurious resyncs.
func TestFlattenFragments_DeterministicOnKeyCollision(t *testing.T) {
	lower, err := NewFragment("host:aaa", "gatherer", MapState(map[string]interface{}{"hostname": "from-aaa"}))
	require.NoError(t, err)
	upper, err := NewFragment("host:zzz", "gatherer", MapState(map[string]interface{}{"hostname": "from-zzz"}))
	require.NoError(t, err)

	forward := FlattenFragments([]*commonpb.Fragment{lower, upper})
	reverse := FlattenFragments([]*commonpb.Fragment{upper, lower})

	assert.Equal(t, "from-zzz", forward["hostname"], "highest fragment_id must win")
	assert.Equal(t, forward, reverse, "projection must not depend on input slice order")

	// Repeated runs over the same input must be byte-identical: map iteration
	// order varies per run, so a single comparison would not catch a regression.
	for i := 0; i < 50; i++ {
		assert.Equal(t, forward, FlattenFragments([]*commonpb.Fragment{lower, upper}))
	}
}
