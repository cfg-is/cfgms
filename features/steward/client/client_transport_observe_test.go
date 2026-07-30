// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
//
// Tests for the Tier-2 whole-domain observe sweep (Issue #3104, ADR-024 Amendment 1).
//
// inMemoryModule, inMemoryConfigState, and inMemoryObserveModuleLoader are real,
// deterministic in-process implementations of their respective interfaces — not
// mocks. No framework, no expectation recording, no call verification. They
// provide the same guarantee the production implementations do: defined inputs
// produce defined outputs, consistently and without I/O.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// Real in-process test components (not mocks)
// ---------------------------------------------------------------------------

// inMemoryConfigState is a real, deterministic implementation of modules.ConfigState
// backed by a fixed AsMap value. Satisfies the ADR-016 clause 4 contract: identical
// state always produces identical AsMap output.
type inMemoryConfigState struct {
	data map[string]interface{}
}

var _ modules.ConfigState = (*inMemoryConfigState)(nil)

func (s *inMemoryConfigState) AsMap() map[string]interface{} {
	out := make(map[string]interface{}, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}
func (s *inMemoryConfigState) ToYAML() ([]byte, error)    { return nil, nil }
func (s *inMemoryConfigState) FromYAML(_ []byte) error    { return nil }
func (s *inMemoryConfigState) Validate() error            { return nil }
func (s *inMemoryConfigState) GetManagedFields() []string { return nil }

// inMemoryModule is a real, thread-safe implementation of modules.Module backed
// by a fixed ConfigState. Get always returns the same state; Set is a no-op.
type inMemoryModule struct {
	mu     sync.RWMutex
	state  map[string]interface{}
	getErr error
}

var _ modules.Module = (*inMemoryModule)(nil)

func (m *inMemoryModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	return &inMemoryConfigState{data: m.state}, nil
}

func (m *inMemoryModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

// inMemoryObserveModuleLoader is a real, thread-safe implementation of
// ObserveModuleLoader backed by a name→Module map. Returns a module-not-found
// error for any name absent from the map. No frameworks, no expectation recording.
type inMemoryObserveModuleLoader struct {
	mu      sync.RWMutex
	mods    map[string]modules.Module
	loadErr map[string]error
}

var _ ObserveModuleLoader = (*inMemoryObserveModuleLoader)(nil)

func newInMemoryLoader(mods map[string]modules.Module) *inMemoryObserveModuleLoader {
	return &inMemoryObserveModuleLoader{
		mods:    mods,
		loadErr: make(map[string]error),
	}
}

func (l *inMemoryObserveModuleLoader) LoadModule(name string) (modules.Module, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if err, ok := l.loadErr[name]; ok && err != nil {
		return nil, err
	}
	mod, ok := l.mods[name]
	if !ok {
		return nil, fmt.Errorf("module not found: %s", name)
	}
	return mod, nil
}

// ---------------------------------------------------------------------------
// Helper: build a TransportClient wired for observe tests
// ---------------------------------------------------------------------------

// newObserveTestClient builds a minimal TransportClient with an in-memory
// offline queue (for capturing published events), a test logger, and an
// observeSweepTick channel for cadence-test synchronisation.
func newObserveTestClient(t *testing.T) (*TransportClient, *OfflineQueue) {
	t.Helper()
	c, q := newClientWithOfflineQueue(t)
	// Buffer large enough that batch cadence tests can call checkAndTriggerObserveSweep
	// multiple times without blocking (sender never blocks, never drops for count ≤ 16).
	c.observeSweepTick = make(chan struct{}, 16)
	return c, q
}

// drainObserveSweepEvents drains all events from the offline queue and returns
// those of type EventObserveSweepRequest.
func drainObserveSweepEvents(q *OfflineQueue) []*cpTypes.Event {
	var result []*cpTypes.Event
	q.Drain(func(e *cpTypes.Event) error {
		if e.Type == cpTypes.EventObserveSweepRequest {
			result = append(result, e)
		}
		return nil
	})
	return result
}

// observeCmd builds a CommandObserveModules command carrying the given specs
// as a JSON-encoded "modules" param (the wire format the controller sends).
func observeCmd(t *testing.T, specs []cpTypes.ObserveModuleSpec) *cpTypes.Command {
	t.Helper()
	return observeCmdWithID(t, "cmd-obs-1", specs)
}

// observeCmdWithID is observeCmd with an explicit command ID. Overlapping
// sweeps arrive as commands with distinct IDs (replay de-duplication keys on
// the ID and therefore does not suppress them), so concurrency tests must be
// able to set the ID.
func observeCmdWithID(t *testing.T, id string, specs []cpTypes.ObserveModuleSpec) *cpTypes.Command {
	t.Helper()
	raw, err := json.Marshal(specs)
	require.NoError(t, err)
	return &cpTypes.Command{
		ID:        id,
		Type:      cpTypes.CommandObserveModules,
		StewardID: "steward-1",
		Params:    map[string]interface{}{"modules": string(raw)},
	}
}

// makeHostFact returns a Fragment that looks like a host-fact fragment
// (non-module-owned) with the given kind and a dummy CanonicalBytes.
func makeHostFact(kind string) *commonpb.Fragment {
	return &commonpb.Fragment{
		FragmentId:     kind,
		Authority:      "gatherer",
		CanonicalBytes: []byte(`{"kind":"` + kind + `"}`),
		FragmentHash:   kind + "-hash",
	}
}

// ---------------------------------------------------------------------------
// parseObserveModuleSpecs unit tests
// ---------------------------------------------------------------------------

func TestParseObserveModuleSpecs_NilInput(t *testing.T) {
	specs, err := parseObserveModuleSpecs(nil)
	require.NoError(t, err)
	assert.Empty(t, specs)
}

func TestParseObserveModuleSpecs_EmptyString(t *testing.T) {
	specs, err := parseObserveModuleSpecs("")
	require.NoError(t, err)
	assert.Empty(t, specs)
}

func TestParseObserveModuleSpecs_JSONString(t *testing.T) {
	raw := `[{"name":"hyperv","kind":"hyperv"}]`
	specs, err := parseObserveModuleSpecs(raw)
	require.NoError(t, err)
	require.Len(t, specs, 1)
	assert.Equal(t, "hyperv", specs[0].Name)
	assert.Equal(t, "hyperv", specs[0].Kind)
}

func TestParseObserveModuleSpecs_SliceInterface(t *testing.T) {
	raw := []interface{}{
		map[string]interface{}{"name": "hyperv", "kind": "vm"},
		map[string]interface{}{"name": "cluster", "kind": "cluster"},
	}
	specs, err := parseObserveModuleSpecs(raw)
	require.NoError(t, err)
	require.Len(t, specs, 2)
	assert.Equal(t, "hyperv", specs[0].Name)
	assert.Equal(t, "cluster", specs[1].Name)
}

func TestParseObserveModuleSpecs_NativeSlice(t *testing.T) {
	raw := []cpTypes.ObserveModuleSpec{{Name: "hyperv", Kind: "vm"}}
	specs, err := parseObserveModuleSpecs(raw)
	require.NoError(t, err)
	require.Len(t, specs, 1)
	assert.Equal(t, "vm", specs[0].Kind)
}

func TestParseObserveModuleSpecs_MissingName(t *testing.T) {
	raw := `[{"name":"","kind":"vm"}]`
	_, err := parseObserveModuleSpecs(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestParseObserveModuleSpecs_MissingKind(t *testing.T) {
	raw := `[{"name":"hyperv","kind":""}]`
	_, err := parseObserveModuleSpecs(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kind")
}

// ---------------------------------------------------------------------------
// handleObserveModules — AC2 and AC3
// ---------------------------------------------------------------------------

// TestHandleObserveModules_MergesFragmentIntoCurrentDNA verifies AC2 (module Get
// invoked) and AC3 (Get output merged into existing DNA fragment emission path).
// After handleObserveModules, currentDNAFragments must contain a fragment whose
// FragmentId matches the spec's Kind. This is the existing partial-sync emission
// path — setCurrentDNAFragments is the only write to currentDNAFragments.
func TestHandleObserveModules_MergesFragmentIntoCurrentDNA(t *testing.T) {
	c, _ := newObserveTestClient(t)

	// Wire a loader that returns a module with known, stable Get output.
	mod := &inMemoryModule{state: map[string]interface{}{"vm_count": 3, "cluster": "site-a"}}
	c.observeModuleLoader = newInMemoryLoader(map[string]modules.Module{"hyperv": mod})

	cmd := observeCmd(t, []cpTypes.ObserveModuleSpec{{Name: "hyperv", Kind: "hyperv"}})
	err := c.handleObserveModules(context.Background(), cmd)
	require.NoError(t, err)

	c.dnaMu.RLock()
	frags := c.currentDNAFragments
	c.dnaMu.RUnlock()

	require.NotEmpty(t, frags, "currentDNAFragments must be non-empty after observe sweep")
	var found bool
	for _, f := range frags {
		if f.GetFragmentId() == "hyperv" {
			found = true
			assert.NotEmpty(t, f.GetCanonicalBytes(), "fragment must have canonical bytes")
			assert.NotEmpty(t, f.GetFragmentHash(), "fragment must have a hash")
			assert.Equal(t, "hyperv", f.GetAuthority(), "module authority must be the module name")
		}
	}
	assert.True(t, found, "currentDNAFragments should contain a fragment with FragmentId=hyperv")
}

// TestHandleObserveModules_HostFactFragmentsPreserved verifies that pre-existing
// host-fact fragments for kinds NOT claimed by the observe module are preserved
// after handleObserveModules (Assembler phase 3: merge observe-only host facts).
func TestHandleObserveModules_HostFactFragmentsPreserved(t *testing.T) {
	c, _ := newObserveTestClient(t)

	// Seed an existing host-fact fragment for a different kind.
	hostFact := makeHostFact("host:network")
	c.dnaMu.Lock()
	c.currentDNAFragments = []*commonpb.Fragment{hostFact}
	c.dnaMu.Unlock()

	mod := &inMemoryModule{state: map[string]interface{}{"vm_count": 1}}
	c.observeModuleLoader = newInMemoryLoader(map[string]modules.Module{"hyperv": mod})

	cmd := observeCmd(t, []cpTypes.ObserveModuleSpec{{Name: "hyperv", Kind: "hyperv"}})
	err := c.handleObserveModules(context.Background(), cmd)
	require.NoError(t, err)

	c.dnaMu.RLock()
	frags := c.currentDNAFragments
	c.dnaMu.RUnlock()

	// Both the observe-module fragment AND the host-fact fragment must be present.
	kindSet := make(map[string]bool)
	for _, f := range frags {
		kindSet[f.GetFragmentId()] = true
	}
	assert.True(t, kindSet["hyperv"], "observe-module fragment must be present")
	assert.True(t, kindSet["host:network"], "pre-existing host-fact fragment must be preserved")
}

// TestHandleObserveModules_ModuleAuthorityPreemptsHostFact verifies ADR-016 clause 5:
// when the observe module claims a kind that was previously in a host-fact fragment,
// the module fragment wins and the host-fact fragment is dropped.
func TestHandleObserveModules_ModuleAuthorityPreemptsHostFact(t *testing.T) {
	c, _ := newObserveTestClient(t)

	// Seed a host-fact fragment for the SAME kind the module will claim.
	hostFact := makeHostFact("hyperv")
	c.dnaMu.Lock()
	c.currentDNAFragments = []*commonpb.Fragment{hostFact}
	c.dnaMu.Unlock()

	mod := &inMemoryModule{state: map[string]interface{}{"vm_count": 2}}
	c.observeModuleLoader = newInMemoryLoader(map[string]modules.Module{"hyperv": mod})

	cmd := observeCmd(t, []cpTypes.ObserveModuleSpec{{Name: "hyperv", Kind: "hyperv"}})
	err := c.handleObserveModules(context.Background(), cmd)
	require.NoError(t, err)

	c.dnaMu.RLock()
	frags := c.currentDNAFragments
	c.dnaMu.RUnlock()

	// There must be exactly one fragment for kind "hyperv" and its authority must
	// be the module (not the gatherer from the host-fact fragment).
	var hypervFrags []*commonpb.Fragment
	for _, f := range frags {
		if f.GetFragmentId() == "hyperv" {
			hypervFrags = append(hypervFrags, f)
		}
	}
	require.Len(t, hypervFrags, 1, "exactly one hyperv fragment must exist after authority preemption")
	assert.Equal(t, "hyperv", hypervFrags[0].GetAuthority(),
		"module authority must win over gatherer authority (ADR-016 clause 5)")
}

// TestHandleObserveModules_LoaderUnavailable verifies graceful handling when the
// module loader is nil (disabled). The call must succeed without panicking.
func TestHandleObserveModules_LoaderNil(t *testing.T) {
	c, _ := newObserveTestClient(t)
	c.observeModuleLoader = nil // explicitly disabled

	cmd := observeCmd(t, []cpTypes.ObserveModuleSpec{{Name: "hyperv", Kind: "hyperv"}})
	err := c.handleObserveModules(context.Background(), cmd)
	require.NoError(t, err, "nil loader must be a no-op, not an error")

	c.dnaMu.RLock()
	frags := c.currentDNAFragments
	c.dnaMu.RUnlock()
	assert.Empty(t, frags, "no fragments should be emitted when loader is nil")
}

// TestHandleObserveModules_ModuleLoadError verifies graceful handling when the
// loader returns an error for a specific module. The module is skipped; others
// in the spec list are still processed.
func TestHandleObserveModules_ModuleLoadError(t *testing.T) {
	c, _ := newObserveTestClient(t)

	goodMod := &inMemoryModule{state: map[string]interface{}{"disk_count": 4}}
	loader := newInMemoryLoader(map[string]modules.Module{"storage": goodMod})
	loader.loadErr["hyperv"] = fmt.Errorf("module binary not cached")
	c.observeModuleLoader = loader

	cmd := observeCmd(t, []cpTypes.ObserveModuleSpec{
		{Name: "hyperv", Kind: "hyperv"},   // fails to load
		{Name: "storage", Kind: "storage"}, // succeeds
	})
	err := c.handleObserveModules(context.Background(), cmd)
	require.NoError(t, err, "per-module load failure must be skipped, not propagated")

	c.dnaMu.RLock()
	frags := c.currentDNAFragments
	c.dnaMu.RUnlock()

	kindSet := make(map[string]bool)
	for _, f := range frags {
		kindSet[f.GetFragmentId()] = true
	}
	assert.True(t, kindSet["storage"], "successfully loaded module must produce a fragment")
	assert.False(t, kindSet["hyperv"], "failed module must not produce a fragment")
}

// TestHandleObserveModules_NoSpecs verifies that an empty spec list is a no-op.
func TestHandleObserveModules_NoSpecs(t *testing.T) {
	c, _ := newObserveTestClient(t)
	c.observeModuleLoader = newInMemoryLoader(nil)

	cmd := observeCmd(t, nil)
	err := c.handleObserveModules(context.Background(), cmd)
	require.NoError(t, err)

	c.dnaMu.RLock()
	frags := c.currentDNAFragments
	c.dnaMu.RUnlock()
	assert.Empty(t, frags)
}

// ---------------------------------------------------------------------------
// AC4 — Integration test: full Tier-2 cycle
// ---------------------------------------------------------------------------

// TestHandleObserveModules_FullCycle verifies AC4: one full Tier-2 cycle in terms
// of the steward side — baseline DNA is in currentDNAAttrs (carried to the
// controller via EventObserveSweepRequest), the controller resolves the module set
// and sends CommandObserveModules back, handleObserveModules runs Get and merges
// results, and currentDNAFragments contains the new module data through the same
// emission path (setCurrentDNAFragments).
//
// The controller-side resolution is not exercised here; this test verifies the
// steward-side fragment emission path end-to-end: baseline in → module loaded →
// Get called → fragment in currentDNAFragments.
func TestHandleObserveModules_FullCycle(t *testing.T) {
	c, _ := newObserveTestClient(t)

	// Seed baseline DNA (as if the DNA refresh loop already ran once).
	baselineDNA := map[string]string{
		"os":              "windows",
		"windows_feature": "Hyper-V",
	}
	c.dnaMu.Lock()
	c.currentDNAAttrs = baselineDNA
	c.dnaMu.Unlock()

	// Wire a loader for the "hyperv" module the controller resolved.
	mod := &inMemoryModule{state: map[string]interface{}{
		"vm_count":   2,
		"cluster":    "site-a",
		"hypervisor": "hyper-v",
	}}
	c.observeModuleLoader = newInMemoryLoader(map[string]modules.Module{"hyperv": mod})

	// Simulate the CommandObserveModules the controller would send.
	cmd := observeCmd(t, []cpTypes.ObserveModuleSpec{{Name: "hyperv", Kind: "hyperv"}})

	// Run handleObserveModules — this is the core of the Tier-2 sweep on the steward side.
	err := c.handleObserveModules(context.Background(), cmd)
	require.NoError(t, err)

	// Verify: currentDNAFragments contains the hyperv fragment, using the existing
	// setCurrentDNAFragments emission path (not a new channel — ADR-024 Amendment 1 §2).
	c.dnaMu.RLock()
	frags := c.currentDNAFragments
	root := c.currentDNAAggregateRoot
	c.dnaMu.RUnlock()

	require.NotEmpty(t, frags, "fragment set must be non-empty after full Tier-2 cycle")
	assert.NotEmpty(t, root, "aggregate root must be updated after fragment merge")

	var found bool
	for _, f := range frags {
		if f.GetFragmentId() == "hyperv" {
			found = true
			assert.NotEmpty(t, f.GetCanonicalBytes())
			assert.NotEmpty(t, f.GetFragmentHash())
		}
	}
	assert.True(t, found, "fragment set must contain hyperv module data after full Tier-2 cycle")
}

// ---------------------------------------------------------------------------
// AC1 — triggerObserveSweep publishes EventObserveSweepRequest
// ---------------------------------------------------------------------------

// TestTriggerObserveSweep_PublishesEventWithBaselineDNA verifies AC1: the
// triggerObserveSweep method publishes an EventObserveSweepRequest event that
// carries the current baseline DNA in the "baseline_dna" detail key.
func TestTriggerObserveSweep_PublishesEventWithBaselineDNA(t *testing.T) {
	c, q := newObserveTestClient(t)
	c.stewardID = "steward-1"
	c.tenantID = "tenant-1"

	baselineAttrs := map[string]string{
		"os":   "windows",
		"arch": "amd64",
	}
	c.dnaMu.Lock()
	c.currentDNAAttrs = baselineAttrs
	c.dnaMu.Unlock()

	c.triggerObserveSweep(context.Background())

	events := drainObserveSweepEvents(q)
	require.Len(t, events, 1, "exactly one EventObserveSweepRequest must be published")

	evt := events[0]
	assert.Equal(t, cpTypes.EventObserveSweepRequest, evt.Type)
	assert.Equal(t, "steward-1", evt.StewardID)

	rawDNA, ok := evt.Details["baseline_dna"].(string)
	require.True(t, ok, "baseline_dna detail must be a JSON string")

	var decoded map[string]string
	require.NoError(t, json.Unmarshal([]byte(rawDNA), &decoded))
	assert.Equal(t, baselineAttrs["os"], decoded["os"])
	assert.Equal(t, baselineAttrs["arch"], decoded["arch"])
}

// TestTriggerObserveSweep_NoopWhenNotRegistered verifies that triggerObserveSweep
// is a no-op when the steward is not yet registered (empty stewardID). No event
// should be published and no error should occur.
func TestTriggerObserveSweep_NoopWhenNotRegistered(t *testing.T) {
	c, q := newObserveTestClient(t)
	c.stewardID = "" // not registered

	c.triggerObserveSweep(context.Background())

	events := drainObserveSweepEvents(q)
	assert.Empty(t, events, "no event must be published when steward is not registered")
}

// ---------------------------------------------------------------------------
// AC5 — Cadence test: sweep fires only on Nth cycle
// ---------------------------------------------------------------------------

// TestObserveSweepCadence_FiresOnNthCycle verifies AC5: the whole-domain sweep
// fires exactly once every N convergence ticks, not on every tick.
//
// checkAndTriggerObserveSweep is called directly to isolate the counter logic
// from the wall-clock-based convergence ticker. The test drives N ticks,
// verifies the sweep fires once, then drives N-1 more ticks and confirms no
// second sweep fires prematurely.
func TestObserveSweepCadence_FiresOnNthCycle(t *testing.T) {
	const N = 3
	c, q := newObserveTestClient(t)
	c.stewardID = "steward-1"
	c.tenantID = "tenant-1"
	c.observeSweepN = N

	// Set some baseline DNA so triggerObserveSweep has something to publish.
	c.dnaMu.Lock()
	c.currentDNAAttrs = map[string]string{"os": "linux"}
	c.dnaMu.Unlock()

	ctx := context.Background()

	// Ticks 1 and 2: no sweep yet.
	c.checkAndTriggerObserveSweep(ctx)
	c.checkAndTriggerObserveSweep(ctx)
	assert.Empty(t, drainObserveSweepEvents(q), "sweep must not fire before Nth cycle")

	// Tick 3: sweep fires.
	c.checkAndTriggerObserveSweep(ctx)
	events := drainObserveSweepEvents(q)
	require.Len(t, events, 1, "sweep must fire exactly once on the Nth cycle")
	assert.Equal(t, cpTypes.EventObserveSweepRequest, events[0].Type)

	// Ticks 4 and 5: no sweep yet (counter reset to 0 after tick 3).
	c.checkAndTriggerObserveSweep(ctx)
	c.checkAndTriggerObserveSweep(ctx)
	assert.Empty(t, drainObserveSweepEvents(q), "sweep must not fire between Nth cycles")
}

// TestObserveSweepCadence_DisabledWhenZero verifies that setting ObserveSweepN=0
// disables the Tier-2 sweep entirely. No events must be published regardless of
// how many convergence ticks fire.
func TestObserveSweepCadence_DisabledWhenZero(t *testing.T) {
	c, q := newObserveTestClient(t)
	c.stewardID = "steward-1"
	c.observeSweepN = 0 // disabled

	c.dnaMu.Lock()
	c.currentDNAAttrs = map[string]string{"os": "linux"}
	c.dnaMu.Unlock()

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		c.checkAndTriggerObserveSweep(ctx)
	}
	assert.Empty(t, drainObserveSweepEvents(q), "sweep must never fire when ObserveSweepN=0")
}

// TestObserveSweepCadence_N1FiresEveryTick verifies that N=1 causes the sweep
// to fire on every convergence tick.
func TestObserveSweepCadence_N1FiresEveryTick(t *testing.T) {
	c, q := newObserveTestClient(t)
	c.stewardID = "steward-1"
	c.tenantID = "tenant-1"
	c.observeSweepN = 1

	c.dnaMu.Lock()
	c.currentDNAAttrs = map[string]string{"os": "linux"}
	c.dnaMu.Unlock()

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		c.checkAndTriggerObserveSweep(ctx)
	}
	events := drainObserveSweepEvents(q)
	assert.Len(t, events, 3, "with N=1 every convergence tick must trigger a sweep")
}

// TestNewObserveSweepEventID_UniqueUnderIdenticalTimestamp reproduces the
// Windows CI failure of TestObserveSweepCadence_N1FiresEveryTick: three
// tight-loop calls to triggerObserveSweep landed within the same clock tick
// (coarse timer resolution), so time.Now().UnixNano() alone produced three
// identical event IDs. The offline queue de-duplicates by event ID (see
// OfflineQueue.Add's seenIDs check), so only one of the three events survived
// draining even though three sweeps fired. Fixing this requires uniqueness
// that does not depend on clock resolution at all.
func TestNewObserveSweepEventID_UniqueUnderIdenticalTimestamp(t *testing.T) {
	const collidingTimestamp = int64(1234567890)

	seen := make(map[string]struct{})
	for seq := int64(1); seq <= 3; seq++ {
		id := newObserveSweepEventID(collidingTimestamp, seq)
		_, dup := seen[id]
		assert.False(t, dup, "event ID must be unique even when the timestamp component collides: %s", id)
		seen[id] = struct{}{}
	}
	assert.Len(t, seen, 3, "all three IDs must be distinct despite the identical timestamp")
}

// TestTriggerObserveSweep_RapidSuccessionProducesDistinctEvents drives
// triggerObserveSweep in a tight loop (no wall-clock gaps between calls,
// mirroring how checkAndTriggerObserveSweep is exercised in cadence tests)
// and confirms every call survives offline-queue de-duplication as a
// separate event.
func TestTriggerObserveSweep_RapidSuccessionProducesDistinctEvents(t *testing.T) {
	c, q := newObserveTestClient(t)
	c.stewardID = "steward-1"
	c.tenantID = "tenant-1"

	ctx := context.Background()
	const iterations = 25
	for i := 0; i < iterations; i++ {
		c.triggerObserveSweep(ctx)
	}

	events := drainObserveSweepEvents(q)
	assert.Len(t, events, iterations, "each triggerObserveSweep call must publish a distinct, undeduplicated event")
}

// ---------------------------------------------------------------------------
// observeSweepTick synchronisation (mirrors dnaRefreshTick pattern)
// ---------------------------------------------------------------------------

// TestCheckAndTriggerObserveSweep_SignalsTick verifies that checkAndTriggerObserveSweep
// always sends on observeSweepTick after completion, regardless of whether the
// sweep fired. This allows tests to observe each tick deterministically.
func TestCheckAndTriggerObserveSweep_SignalsTick(t *testing.T) {
	c, _ := newObserveTestClient(t)
	c.observeSweepN = 5 // won't fire within 3 calls
	tick := make(chan struct{}, 3)
	c.observeSweepTick = tick

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		c.checkAndTriggerObserveSweep(ctx)
	}

	assert.Equal(t, 3, len(tick),
		"observeSweepTick must receive one value per checkAndTriggerObserveSweep call")
}

// ---------------------------------------------------------------------------
// Overlapping sweeps: single-flight guard and shared-loader concurrency
// ---------------------------------------------------------------------------

// sweepProbeModule is a real modules.Module that records how many Get calls are
// in flight at once and can be held inside Get until released. It is the
// instrument the overlapping-sweep tests read: maxInFlight > 1 means two sweeps
// ran concurrently over the shared module loader.
type sweepProbeModule struct {
	calls       atomic.Int32
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	entered     chan struct{} // signalled once per Get entry (buffered)
	release     chan struct{} // Get blocks until closed; nil = never block
}

var _ modules.Module = (*sweepProbeModule)(nil)

func (m *sweepProbeModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	m.calls.Add(1)
	n := m.inFlight.Add(1)
	defer m.inFlight.Add(-1)
	for {
		high := m.maxInFlight.Load()
		if n <= high || m.maxInFlight.CompareAndSwap(high, n) {
			break
		}
	}
	if m.entered != nil {
		m.entered <- struct{}{}
	}
	if m.release != nil {
		<-m.release
	}
	return &inMemoryConfigState{data: map[string]interface{}{"vm_count": 1}}, nil
}

func (m *sweepProbeModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

// TestHandleObserveModules_OverlappingSweepIsDropped verifies the single-flight
// guard. The controller can issue a second observe_modules command while the
// first sweep is still inside a module Get (a Get slower than N convergence
// ticks is enough, and the two commands carry distinct IDs so replay
// de-duplication does not suppress the second). Without the guard both sweeps
// run concurrently over the same module loader, which for the production
// *factory.ModuleFactory is a concurrent map write — a fatal, unrecoverable
// process abort. The overlapping command must be dropped instead.
func TestHandleObserveModules_OverlappingSweepIsDropped(t *testing.T) {
	c, _ := newObserveTestClient(t)

	mod := &sweepProbeModule{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	c.observeModuleLoader = newInMemoryLoader(map[string]modules.Module{"hyperv": mod})

	specs := []cpTypes.ObserveModuleSpec{{Name: "hyperv", Kind: "hyperv"}}
	ctx := context.Background()

	// release unblocks every Get held in the module. Idempotent so the failure
	// path can unblock leaked sweeps without risking a double close.
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(mod.release) }) }
	t.Cleanup(release)

	// Sweep A: enters the module Get and stays there until released.
	first := make(chan error, 1)
	go func() {
		first <- c.handleObserveModules(ctx, observeCmdWithID(t, "cmd-obs-a", specs))
	}()
	<-mod.entered // sweep A is now inside Get — a sweep is definitively in flight

	// Sweep B arrives while A is in flight: it must return without touching the
	// loader. Racing its completion against a second Get entry keeps the
	// assertion deterministic — no timeout, no sleep. mod.entered has spare
	// buffer capacity, so an unguarded sweep B signals it and is detected here
	// rather than deadlocking the test.
	second := make(chan error, 1)
	go func() {
		second <- c.handleObserveModules(ctx, observeCmdWithID(t, "cmd-obs-b", specs))
	}()
	select {
	case err := <-second:
		require.NoError(t, err, "a dropped overlapping sweep is not a command failure")
	case <-mod.entered:
		release()
		t.Fatal("overlapping sweep ran against the shared module loader while a sweep was in flight")
	}
	assert.Equal(t, int32(1), mod.calls.Load(),
		"overlapping sweep must be dropped, not run against the shared module loader")

	release()
	require.NoError(t, <-first)
	assert.Equal(t, int32(1), mod.maxInFlight.Load(),
		"at most one observe sweep may be in flight at a time")

	// The guard is released once the sweep finishes: the next command runs.
	require.NoError(t, c.handleObserveModules(ctx, observeCmdWithID(t, "cmd-obs-c", specs)))
	assert.Equal(t, int32(2), mod.calls.Load(),
		"a sweep issued after the previous one completed must run")
}

// TestHandleObserveModules_ConcurrentCommandsWithRealFactory_NoDataRace runs
// concurrent observe_modules commands against the production module loader —
// the single long-lived *factory.ModuleFactory that cmd/steward wires into
// TransportConfig.ObserveModuleLoader — while other goroutines load modules
// from that same factory the way the convergence path does.
//
// Under -race this fails on any unsynchronized access to the factory's instance
// cache or injection-status map, which in production surfaces as
// "fatal error: concurrent map writes" and kills the steward process.
func TestHandleObserveModules_ConcurrentCommandsWithRealFactory_NoDataRace(t *testing.T) {
	c, _ := newObserveTestClient(t)

	loader := factory.NewWithStewardID(
		discovery.ModuleRegistry{},
		stewardconfig.ErrorHandlingConfig{ModuleLoadFailure: stewardconfig.ActionContinue},
		"steward-1",
		logging.NewNoopLogger(),
	)
	c.observeModuleLoader = loader

	specs := []cpTypes.ObserveModuleSpec{
		{Name: "file", Kind: "file"},
		{Name: "script", Kind: "script"},
		{Name: "user", Kind: "user"},
	}

	ctx := context.Background()
	const sweeps = 8
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < sweeps; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			cmd := observeCmdWithID(t, fmt.Sprintf("cmd-obs-%d", i), specs)
			if err := c.handleObserveModules(ctx, cmd); err != nil {
				t.Errorf("handleObserveModules: %v", err)
			}
		}(i)
	}

	// Concurrent module loads off the same factory, mirroring the convergence
	// executor running alongside the Tier-2 sweep.
	for i := 0; i < sweeps; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for _, spec := range specs {
				if _, err := loader.LoadModule(spec.Name); err != nil {
					t.Errorf("LoadModule(%s): %v", spec.Name, err)
				}
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.ElementsMatch(t, []string{"file", "script", "user"}, loader.GetLoadedModules(),
		"each module must be cached exactly once after concurrent sweeps and loads")
}

// ---------------------------------------------------------------------------
// NewTransportClient wiring: ObserveSweepN and ObserveModuleLoader
// ---------------------------------------------------------------------------

// TestNewTransportClient_WiresObserveSweepFields verifies that TransportConfig fields
// ObserveSweepN and ObserveModuleLoader are correctly threaded into the client struct
// by NewTransportClient.
func TestNewTransportClient_WiresObserveSweepFields(t *testing.T) {
	loader := newInMemoryLoader(nil)
	cfg := &TransportConfig{
		ControllerURL:       "controller:4433",
		Logger:              newTestLogger(t),
		ObserveSweepN:       7,
		ObserveModuleLoader: loader,
	}
	c, err := NewTransportClient(cfg)
	require.NoError(t, err)

	assert.Equal(t, 7, c.observeSweepN, "observeSweepN must be set from TransportConfig")
	assert.Equal(t, loader, c.observeModuleLoader, "observeModuleLoader must be set from TransportConfig")
}
