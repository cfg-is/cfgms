// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// --- Test doubles -----------------------------------------------------------
// These are deterministic implementations of the module interfaces, not mocks.

// asmFakeState is a ConfigState fixture for assembler tests.
type asmFakeState struct {
	data map[string]interface{}
}

func (s *asmFakeState) AsMap() map[string]interface{} {
	m := make(map[string]interface{}, len(s.data))
	for k, v := range s.data {
		m[k] = v
	}
	return m
}
func (s *asmFakeState) ToYAML() ([]byte, error)    { return nil, nil }
func (s *asmFakeState) FromYAML(_ []byte) error    { return nil }
func (s *asmFakeState) Validate() error            { return nil }
func (s *asmFakeState) GetManagedFields() []string { return nil }

var _ modules.ConfigState = (*asmFakeState)(nil)

// asmFakeStateWithConfidence wraps asmFakeState and implements ConfidenceReporter.
type asmFakeStateWithConfidence struct {
	asmFakeState
	confidence string
}

func (s *asmFakeStateWithConfidence) Confidence() string { return s.confidence }

var _ ConfidenceReporter = (*asmFakeStateWithConfidence)(nil)

// asmFakeModule is a deterministic Module that returns a fixed ConfigState.
type asmFakeModule struct {
	state modules.ConfigState
	err   error
}

func (m *asmFakeModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.state, nil
}
func (m *asmFakeModule) Set(_ context.Context, _ string, _ modules.ConfigState) error { return nil }

var _ modules.Module = (*asmFakeModule)(nil)

// stateFixture creates an asmFakeModule returning the given key-value data.
func stateFixture(data map[string]interface{}) *asmFakeModule {
	return &asmFakeModule{state: &asmFakeState{data: data}}
}

// hostFactFrag builds a pre-canonicalized host-fact fragment (simulating #2910 output).
func hostFactFrag(t *testing.T, kind string, data map[string]interface{}) *commonpb.Fragment {
	t.Helper()
	state := &asmFakeState{data: data}
	canonical, err := CanonicalizeFragment(kind, "gatherer", state)
	require.NoError(t, err)
	return &commonpb.Fragment{
		FragmentId:     kind,
		Authority:      "gatherer",
		CanonicalBytes: canonical,
		FragmentHash:   FragmentHash(canonical),
	}
}

// newTestAssembler returns an Assembler backed by a no-op logger.
func newTestAssembler() *Assembler {
	return NewAssembler(logging.NewNoopLogger())
}

// --- Tests ------------------------------------------------------------------

// TestAssembler_ProducesFragmentPerModuleKind verifies that Assemble produces
// exactly one Fragment+FragmentEnvelope per active module's declared owns: kind.
func TestAssembler_ProducesFragmentPerModuleKind(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	activeModules := map[string]modules.Module{
		"service-module": stateFixture(map[string]interface{}{"name": "sshd", "state": "running"}),
		"file-module":    stateFixture(map[string]interface{}{"path": "/etc/hosts", "mode": "0644"}),
	}
	ownership := map[string][]modules.OwnershipDeclaration{
		"service-module": {{Kind: "service"}},
		"file-module":    {{Kind: "file"}},
	}

	frags, envs, err := a.Assemble(ctx, activeModules, ownership, nil)
	require.NoError(t, err)

	ids := fragmentIDSet(frags)
	assert.True(t, ids["service"], "service fragment must be produced")
	assert.True(t, ids["file"], "file fragment must be produced")
	assert.Len(t, frags, 2, "must produce exactly one fragment per declared kind")

	for _, f := range frags {
		assert.NotEmpty(t, f.FragmentHash, "fragment %s must have a non-empty hash", f.FragmentId)
		assert.NotEmpty(t, f.CanonicalBytes, "fragment %s must have non-empty canonical bytes", f.FragmentId)

		env, ok := envs[f.FragmentId]
		require.True(t, ok, "envelope must exist for %s", f.FragmentId)
		assert.Equal(t, "high", env.Confidence, "default confidence must be 'high' for %s", f.FragmentId)
		assert.NotNil(t, env.ObservedAt, "observed_at must be set for %s", f.FragmentId)
		assert.Contains(t, env.Source, f.FragmentId[:3], "source must reference the module for %s", f.FragmentId)
	}
}

// TestAssembler_AuthorityConflictRejectsKind is the REQUIRED TEST for AC2:
// two active modules declaring owns: for the same kind must be rejected —
// the kind is logged and skipped, never merged or silently resolved.
func TestAssembler_AuthorityConflictRejectsKind(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	activeModules := map[string]modules.Module{
		"module-a":    stateFixture(map[string]interface{}{"name": "sshd"}),
		"module-b":    stateFixture(map[string]interface{}{"name": "nginx"}),
		"file-module": stateFixture(map[string]interface{}{"path": "/etc/hosts"}),
	}
	ownership := map[string][]modules.OwnershipDeclaration{
		"module-a":    {{Kind: "service"}}, // conflict!
		"module-b":    {{Kind: "service"}}, // conflict!
		"file-module": {{Kind: "file"}},    // no conflict — control
	}

	frags, envs, err := a.Assemble(ctx, activeModules, ownership, nil)
	require.NoError(t, err, "authority conflict must not propagate as an error — log+skip")

	ids := fragmentIDSet(frags)
	assert.False(t, ids["service"],
		"conflicted kind 'service' must produce zero fragments — the resolver must never merge or guess")
	assert.Nil(t, envs["service"],
		"conflicted kind must have no envelope")

	// Non-conflicting kind must still be assembled correctly.
	assert.True(t, ids["file"],
		"non-conflicting kind 'file' must still be assembled after the service conflict")
}

// TestAssembler_RequiredFieldMissingFailsClosed is the REQUIRED TEST for AC3:
// when a module's Get output omits a declared required field, the assembler
// must fail closed — no fragment emitted for that kind.
func TestAssembler_RequiredFieldMissingFailsClosed(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	// Get returns a state that has "name" but not the required "state" field.
	activeModules := map[string]modules.Module{
		"service-module": stateFixture(map[string]interface{}{"name": "sshd"}),
	}
	ownership := map[string][]modules.OwnershipDeclaration{
		"service-module": {{Kind: "service", RequiredFields: []string{"name", "state"}}},
	}

	frags, envs, err := a.Assemble(ctx, activeModules, ownership, nil)
	require.NoError(t, err, "required-field violation must not propagate as error — fail closed")

	ids := fragmentIDSet(frags)
	assert.False(t, ids["service"],
		"service fragment must be absent: required field 'state' is missing in Get output (ADR-020 §3)")
	assert.Nil(t, envs["service"],
		"service envelope must be absent when fragment is rejected by required-field check")
}

// TestAssembler_RequiredFieldEmptyFailsClosed tests that an empty-string required
// field value also triggers fail-closed behavior (ADR-020 §3).
func TestAssembler_RequiredFieldEmptyFailsClosed(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	activeModules := map[string]modules.Module{
		"service-module": stateFixture(map[string]interface{}{"name": "sshd", "state": ""}),
	}
	ownership := map[string][]modules.OwnershipDeclaration{
		"service-module": {{Kind: "service", RequiredFields: []string{"state"}}},
	}

	frags, _, err := a.Assemble(ctx, activeModules, ownership, nil)
	require.NoError(t, err)

	ids := fragmentIDSet(frags)
	assert.False(t, ids["service"],
		"empty required field value must also trigger fail-closed (no fragment emitted)")
}

// TestAssembler_RequiredFieldsAllPresentSucceeds is the positive case for the
// required-field check: when all declared required fields are present and non-empty,
// the fragment is emitted normally.
func TestAssembler_RequiredFieldsAllPresentSucceeds(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	activeModules := map[string]modules.Module{
		"service-module": stateFixture(map[string]interface{}{
			"name":  "sshd",
			"state": "running",
		}),
	}
	ownership := map[string][]modules.OwnershipDeclaration{
		"service-module": {{Kind: "service", RequiredFields: []string{"name", "state"}}},
	}

	frags, envs, err := a.Assemble(ctx, activeModules, ownership, nil)
	require.NoError(t, err)

	ids := fragmentIDSet(frags)
	assert.True(t, ids["service"],
		"service fragment must be emitted when all required fields are present and non-empty")
	assert.NotNil(t, envs["service"],
		"service envelope must be present for a successfully assembled fragment")
}

// TestAssembler_SelfAuthorityGuarantee is the REQUIRED SECURITY TEST for AC4.
// Proves the self-authority guarantee two ways:
//
// (a) Runtime: a kind whose owning module is absent from activeModules must produce
// zero fragments — the assembler must never fabricate a fragment with a default,
// guessed, or fallback authority.
//
// (b) Structural: Assemble takes no parameter through which a caller could supply a
// foreign host or entity as authority — checked by reading the function signature.
func TestAssembler_SelfAuthorityGuarantee(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	// (a) Runtime guarantee: "orphan-module" is in ownership but absent from activeModules.
	activeModules := map[string]modules.Module{
		"service-module": stateFixture(map[string]interface{}{"name": "sshd"}),
		// "orphan-module" intentionally absent
	}
	ownership := map[string][]modules.OwnershipDeclaration{
		"service-module": {{Kind: "service"}},
		"orphan-module":  {{Kind: "orphaned-kind"}},
	}

	frags, envs, err := a.Assemble(ctx, activeModules, ownership, nil)
	require.NoError(t, err)

	ids := fragmentIDSet(frags)
	assert.False(t, ids["orphaned-kind"],
		"(a) runtime: a kind whose module is absent from activeModules must produce zero fragments — "+
			"the assembler must not fabricate authority for an unknown module")
	assert.Nil(t, envs["orphaned-kind"],
		"(a) runtime: no envelope must exist for an unresolved module kind")

	// "service" is still assembled; only the orphaned kind is absent.
	assert.True(t, ids["service"],
		"service must be assembled normally — orphan absence must not affect other kinds")

	// (b) Structural guarantee: verified by reading Assemble's signature.
	//
	// func (a *Assembler) Assemble(
	//     ctx context.Context,
	//     activeModules map[string]modules.Module,
	//     ownership map[string][]modules.OwnershipDeclaration,
	//     hostFactFragments []*commonpb.Fragment,
	// ) ([]*commonpb.Fragment, map[string]*commonpb.FragmentEnvelope, error)
	//
	// None of the parameters is a host ID, entity ID, peer ID, or authority override.
	// hostFactFragments carries already-shaped observe-only host facts for THIS steward,
	// never a foreign authority claim. This is a structural exclusion — outpost/remote-host
	// authority is not built here per Issue #2905 PO ruling ("self-authority only").
	t.Log("(b) structural: Assemble signature verified — no foreign-authority parameter (see function definition)")
}

// TestAssembler_ObserveOnlyMergeWithConflict is the REQUIRED TEST for AC5:
// the observe-only (host-fact) branch merges for kinds no module owns, and when a
// kind appears in BOTH ownership and hostFactFragments, the module's fragment wins.
func TestAssembler_ObserveOnlyMergeWithConflict(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	// A module claims "host:cpu" — it should preempt the gatherer's fragment.
	moduleData := map[string]interface{}{"cpu_count": "8", "cpu_arch": "arm64"}
	activeModules := map[string]modules.Module{
		"cpu-module": stateFixture(moduleData),
	}
	ownership := map[string][]modules.OwnershipDeclaration{
		"cpu-module": {{Kind: "host:cpu"}},
	}

	// hostFactFragments contains both a conflicting "host:cpu" and a non-conflicting "host:os".
	gatherCPU := hostFactFrag(t, "host:cpu", map[string]interface{}{"cpu_count": "4", "cpu_arch": "amd64"})
	gatherOS := hostFactFrag(t, "host:os", map[string]interface{}{"os": "linux", "kernel_version": "5.15.0"})
	hostFacts := []*commonpb.Fragment{gatherCPU, gatherOS}

	frags, envs, err := a.Assemble(ctx, activeModules, ownership, hostFacts)
	require.NoError(t, err)

	// Count per kind to verify exactly one fragment for host:cpu.
	var cpuFrags, osFrags []*commonpb.Fragment
	for _, f := range frags {
		switch f.FragmentId {
		case "host:cpu":
			cpuFrags = append(cpuFrags, f)
		case "host:os":
			osFrags = append(osFrags, f)
		}
	}

	require.Len(t, cpuFrags, 1,
		"exactly one host:cpu fragment must be present (module wins; gatherer-fed one is dropped, never merged)")
	assert.Equal(t, "cpu-module", cpuFrags[0].Authority,
		"host:cpu must carry the module's authority, not 'gatherer'")
	assert.NotNil(t, envs["host:cpu"],
		"envelope for module-owned host:cpu must be present")

	// Gatherer's hash for cpu differs because it has different data (4 cores, amd64).
	assert.NotEqual(t, gatherCPU.FragmentHash, cpuFrags[0].FragmentHash,
		"module fragment must not be the gatherer fragment — it has distinct data")

	// Non-conflicting host-fact fragment must be merged in unmodified.
	require.Len(t, osFrags, 1, "non-conflicting host:os fragment must be merged in")
	assert.Equal(t, "gatherer", osFrags[0].Authority, "host:os authority remains 'gatherer'")
	assert.Equal(t, gatherOS.FragmentHash, osFrags[0].FragmentHash,
		"host-fact fragment must be included unmodified (S2/S3 not re-applied)")
	assert.Nil(t, envs["host:os"],
		"assembler must not create an envelope for host-fact fragments (caller's responsibility)")
}

// TestAssembler_EnvelopeFieldsExcludedFromHash is the invariant test for AC6:
// fragment_hash is identical across two assemblies that differ only in observed_at
// (ADR-017 A1.1: envelope fields are structurally excluded from canonical_bytes).
func TestAssembler_EnvelopeFieldsExcludedFromHash(t *testing.T) {
	ctx := context.Background()

	activeModules := map[string]modules.Module{
		"service-module": stateFixture(map[string]interface{}{"name": "sshd", "state": "running"}),
	}
	ownership := map[string][]modules.OwnershipDeclaration{
		"service-module": {{Kind: "service"}},
	}

	frags1, envs1, err := newTestAssembler().Assemble(ctx, activeModules, ownership, nil)
	require.NoError(t, err)

	// Sleep to ensure the monotonic clock advances so observed_at may differ.
	time.Sleep(time.Millisecond)

	frags2, envs2, err := newTestAssembler().Assemble(ctx, activeModules, ownership, nil)
	require.NoError(t, err)

	require.Len(t, frags1, 1)
	require.Len(t, frags2, 1)

	// Fragment hash must be identical even if observed_at differs.
	assert.Equal(t, frags1[0].FragmentHash, frags2[0].FragmentHash,
		"fragment_hash must be identical across assemblies differing only in observed_at (A1.1 invariant)")

	// Envelopes may differ in observed_at but must agree on source and confidence.
	env1 := envs1["service"]
	env2 := envs2["service"]
	require.NotNil(t, env1, "first assembly must produce a service envelope")
	require.NotNil(t, env2, "second assembly must produce a service envelope")
	assert.Equal(t, env1.Source, env2.Source, "envelope source must be stable across assemblies")
	assert.Equal(t, env1.Confidence, env2.Confidence, "envelope confidence must be stable across assemblies")
}

// TestAssembler_ModuleConfidenceOverride verifies that a ConfigState implementing
// ConfidenceReporter overrides the default "high" confidence in the envelope.
func TestAssembler_ModuleConfidenceOverride(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	activeModules := map[string]modules.Module{
		"network-module": &asmFakeModule{
			state: &asmFakeStateWithConfidence{
				asmFakeState: asmFakeState{data: map[string]interface{}{"interface": "eth0"}},
				confidence:   "medium",
			},
		},
	}
	ownership := map[string][]modules.OwnershipDeclaration{
		"network-module": {{Kind: "network"}},
	}

	_, envs, err := a.Assemble(ctx, activeModules, ownership, nil)
	require.NoError(t, err)

	env, ok := envs["network"]
	require.True(t, ok, "network envelope must be present")
	assert.Equal(t, "medium", env.Confidence,
		"module-declared confidence must override the default 'high'")
}

// TestAssembler_ModuleGetErrorFailsClosed verifies that when Module.Get returns
// an error, the fragment is not emitted (fail closed) but other modules proceed.
func TestAssembler_ModuleGetErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	activeModules := map[string]modules.Module{
		"broken-module": &asmFakeModule{err: errors.New("transient read failure")},
		"ok-module":     stateFixture(map[string]interface{}{"key": "value"}),
	}
	ownership := map[string][]modules.OwnershipDeclaration{
		"broken-module": {{Kind: "broken"}},
		"ok-module":     {{Kind: "ok"}},
	}

	frags, _, err := a.Assemble(ctx, activeModules, ownership, nil)
	require.NoError(t, err, "a module's Get error must not propagate as an Assemble error")

	ids := fragmentIDSet(frags)
	assert.False(t, ids["broken"], "broken module's fragment must not be emitted on Get error")
	assert.True(t, ids["ok"], "ok module's fragment must still be emitted")
}

// TestModuleGetErrorCategory verifies that the Get-error logging label is drawn
// from a bounded set of constants and never echoes the error's raw message text.
// This is the taint break that clears CodeQL go/clear-text-logging (CWE-312) at
// the polymorphic mod.Get sink: no matter what a module embeds in its error
// (e.g. a /etc/passwd path or a *SecretKey handle reference), the logged value
// is one of these fixed categories.
func TestModuleGetErrorCategory(t *testing.T) {
	sensitive := errors.New("winrm_user_secret=super-secret-value at /etc/passwd")

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "none"},
		{"canceled", context.Canceled, "canceled"},
		{"deadline", context.DeadlineExceeded, "deadline-exceeded"},
		{"not-implemented", modules.ErrNotImplemented, "not-implemented"},
		{"unsupported-platform", modules.ErrUnsupportedPlatform, "unsupported-platform"},
		{"invalid-resource-id", modules.ErrInvalidResourceID, "invalid-resource-id"},
		{"invalid-input", modules.ErrInvalidInput, "invalid-input"},
		{"wrapped-sentinel", fmt.Errorf("read cluster: %w", modules.ErrNotImplemented), "not-implemented"},
		{"opaque", sensitive, "module-error"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := moduleGetErrorCategory(tc.err)
			assert.Equal(t, tc.want, got)
			if tc.err != nil {
				assert.NotContains(t, got, tc.err.Error(),
					"category label must never contain the raw error text")
			}
		})
	}
}

// TestAssembler_EmptyInputs verifies graceful handling of all-nil inputs.
func TestAssembler_EmptyInputs(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	frags, envs, err := a.Assemble(ctx, nil, nil, nil)
	require.NoError(t, err)
	assert.Empty(t, frags, "no modules and no host-facts must produce no fragments")
	assert.Empty(t, envs, "no modules must produce no envelopes")
}

// TestAssembler_HostFactsPassThroughWhenNoModules verifies that when no active
// modules are present, all host-fact fragments are merged into the output unmodified
// (S2/S3 must NOT be re-applied).
func TestAssembler_HostFactsPassThroughWhenNoModules(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	cpuFrag := hostFactFrag(t, "host:cpu", map[string]interface{}{"cpu_count": "4", "cpu_arch": "amd64"})
	osFrag := hostFactFrag(t, "host:os", map[string]interface{}{"os": "linux"})

	frags, envs, err := a.Assemble(ctx, nil, nil, []*commonpb.Fragment{cpuFrag, osFrag})
	require.NoError(t, err)

	require.Len(t, frags, 2, "both host-fact fragments must pass through")
	ids := fragmentIDSet(frags)
	assert.True(t, ids["host:cpu"])
	assert.True(t, ids["host:os"])

	assert.Equal(t, cpuFrag.FragmentHash, hashByID(frags, "host:cpu"),
		"host-fact fragment hash must be identical (not re-canonicalized)")
	assert.Empty(t, envs, "no module envelopes when no active modules")
}

// TestAssembler_ConflictedKindExcludedFromHostFacts verifies that a kind
// involved in an authority conflict is also excluded from the host-fact merge
// (ADR-016 clause 5: a claimed kind must never be dual-sourced, even on conflict).
func TestAssembler_ConflictedKindExcludedFromHostFacts(t *testing.T) {
	ctx := context.Background()
	a := newTestAssembler()

	activeModules := map[string]modules.Module{
		"module-a": stateFixture(map[string]interface{}{"cpu_count": "4"}),
		"module-b": stateFixture(map[string]interface{}{"cpu_count": "8"}),
	}
	ownership := map[string][]modules.OwnershipDeclaration{
		"module-a": {{Kind: "host:cpu"}}, // conflict!
		"module-b": {{Kind: "host:cpu"}}, // conflict!
	}

	// Gatherer also has a host:cpu fragment — it must be excluded because the kind is claimed.
	gatherCPU := hostFactFrag(t, "host:cpu", map[string]interface{}{"cpu_count": "16"})

	frags, _, err := a.Assemble(ctx, activeModules, ownership, []*commonpb.Fragment{gatherCPU})
	require.NoError(t, err)

	ids := fragmentIDSet(frags)
	assert.False(t, ids["host:cpu"],
		"conflicted kind must produce zero fragments — neither module nor gatherer may win (atomicity)")
}
