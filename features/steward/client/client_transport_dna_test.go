// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package client_test exercises the DNA-sync logic in TransportClient.
//
// These tests cover the pure, non-networked functions (delta computation,
// hash tracking), the Heartbeat DNAHash field contract, and the periodic
// DNA refresh loop (Issue #1915).
package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	dna "github.com/cfgis/cfgms/features/steward/dna"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Stub DNACollector for refresh-loop tests (Issue #1915)
// ---------------------------------------------------------------------------

// stubDNACollector satisfies DNACollector and returns the configured snapshot.
// Use setAttrs to safely change what CollectAttributes returns on the next tick;
// the mutex prevents data races when the loop goroutine and the test body
// access attrs concurrently.
type stubDNACollector struct {
	mu    sync.RWMutex
	attrs map[string]string
	err   error
}

func (s *stubDNACollector) CollectAttributes(_ context.Context) (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.err != nil {
		return nil, s.err
	}
	out := make(map[string]string, len(s.attrs))
	for k, v := range s.attrs {
		out[k] = v
	}
	return out, nil
}

func (s *stubDNACollector) setAttrs(attrs map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attrs = attrs
}

// newClientWithOfflineQueue returns a minimal TransportClient wired with an
// in-memory OfflineQueue so tests can observe events without a real control plane.
func newClientWithOfflineQueue(t *testing.T) (*TransportClient, *OfflineQueue) {
	t.Helper()
	logger := newTestLogger(t)
	q, err := NewOfflineQueue(OfflineQueueConfig{Logger: logger})
	require.NoError(t, err)
	c := &TransportClient{
		stewardID:          "steward-1",
		tenantID:           "tenant-1",
		heartbeatStop:      make(chan struct{}),
		convergenceStop:    make(chan struct{}),
		dnaRefreshStop:     make(chan struct{}),
		convergeInterval:   30 * time.Minute,
		dnaRefreshInterval: 10 * time.Millisecond,
		offlineQueue:       q,
		logger:             logger,
	}
	return c, q
}

// ---------------------------------------------------------------------------
// Minimal DataPlaneSession for sync_dna handler tests
// ---------------------------------------------------------------------------

// testDataPlaneSession satisfies dataplaneInterfaces.DataPlaneSession.
// It records the most recent SendDNA call and signals dnaSent when it fires.
type testDataPlaneSession struct {
	dnaSent chan *dpTypes.DNATransfer
}

var _ dataplaneInterfaces.DataPlaneSession = (*testDataPlaneSession)(nil)

func newTestSession() *testDataPlaneSession {
	return &testDataPlaneSession{dnaSent: make(chan *dpTypes.DNATransfer, 1)}
}

func (s *testDataPlaneSession) ID() string                    { return "test-session" }
func (s *testDataPlaneSession) PeerID() string                { return "controller-1" }
func (s *testDataPlaneSession) IsClosed() bool                { return false }
func (s *testDataPlaneSession) LocalAddr() string             { return "127.0.0.1:0" }
func (s *testDataPlaneSession) RemoteAddr() string            { return "127.0.0.1:1" }
func (s *testDataPlaneSession) Close(_ context.Context) error { return nil }
func (s *testDataPlaneSession) SendConfig(_ context.Context, _ *dpTypes.ConfigTransfer) error {
	return nil
}
func (s *testDataPlaneSession) ReceiveConfig(_ context.Context) (*dpTypes.ConfigTransfer, error) {
	return nil, nil
}
func (s *testDataPlaneSession) SendDNA(_ context.Context, dna *dpTypes.DNATransfer) error {
	s.dnaSent <- dna
	return nil
}
func (s *testDataPlaneSession) ReceiveDNA(_ context.Context) (*dpTypes.DNATransfer, error) {
	return nil, nil
}
func (s *testDataPlaneSession) SendBulk(_ context.Context, _ *dpTypes.BulkTransfer) error {
	return nil
}
func (s *testDataPlaneSession) ReceiveBulk(_ context.Context) (*dpTypes.BulkTransfer, error) {
	return nil, nil
}

func newTestLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewLogger("debug")
}

// ---------------------------------------------------------------------------
// computeDelta
// ---------------------------------------------------------------------------

func TestComputeDelta_NilOld(t *testing.T) {
	newAttrs := map[string]string{"a": "1", "b": "2"}
	delta := computeDelta(nil, newAttrs)
	require.NotNil(t, delta)
	assert.Equal(t, newAttrs, delta,
		"when no previous state exists all attributes are included in the delta")
}

func TestComputeDelta_EmptyOld(t *testing.T) {
	newAttrs := map[string]string{"a": "1"}
	delta := computeDelta(map[string]string{}, newAttrs)
	assert.Equal(t, newAttrs, delta,
		"when previous state is empty all attributes are included in the delta")
}

func TestComputeDelta_NoChanges(t *testing.T) {
	attrs := map[string]string{"a": "1", "b": "2"}
	same := map[string]string{"a": "1", "b": "2"}
	delta := computeDelta(attrs, same)
	assert.Empty(t, delta, "identical attributes should produce an empty delta")
}

func TestComputeDelta_ChangedValue(t *testing.T) {
	old := map[string]string{"a": "1", "b": "old"}
	new := map[string]string{"a": "1", "b": "new"}
	delta := computeDelta(old, new)
	assert.Equal(t, map[string]string{"b": "new"}, delta,
		"only the changed attribute should appear in the delta")
}

func TestComputeDelta_AddedKey(t *testing.T) {
	old := map[string]string{"a": "1"}
	new := map[string]string{"a": "1", "b": "2"}
	delta := computeDelta(old, new)
	assert.Equal(t, map[string]string{"b": "2"}, delta,
		"newly added keys should appear in the delta")
}

func TestComputeDelta_MultipleChanges(t *testing.T) {
	old := map[string]string{"a": "1", "b": "2", "c": "3"}
	new := map[string]string{"a": "99", "b": "2", "c": "99"}
	delta := computeDelta(old, new)
	assert.Equal(t, map[string]string{"a": "99", "c": "99"}, delta)
}

func TestComputeDelta_RemovedKey(t *testing.T) {
	old := map[string]string{"a": "1", "b": "2", "c": "3"}
	new := map[string]string{"a": "1", "c": "99"} // "b" was removed
	delta := computeDelta(old, new)
	// "b" must appear with empty-string sentinel so the controller can unset it.
	assert.Equal(t, map[string]string{"b": "", "c": "99"}, delta,
		"deleted keys must appear in the delta with an empty-string sentinel value")
}

func TestComputeDelta_IsolatesNewMap(t *testing.T) {
	old := map[string]string{}
	new := map[string]string{"k": "v"}
	delta := computeDelta(old, new)
	// Mutating delta must not affect new
	delta["extra"] = "injected"
	assert.NotContains(t, new, "extra",
		"delta should be an independent copy, not the same map reference")
}

// ---------------------------------------------------------------------------
// copyStringMap
// ---------------------------------------------------------------------------

func TestCopyStringMap_Nil(t *testing.T) {
	result := copyStringMap(nil)
	assert.Nil(t, result)
}

func TestCopyStringMap_Empty(t *testing.T) {
	result := copyStringMap(map[string]string{})
	require.NotNil(t, result)
	assert.Empty(t, result)
}

func TestCopyStringMap_DeepCopy(t *testing.T) {
	original := map[string]string{"k": "v"}
	copy := copyStringMap(original)
	assert.Equal(t, original, copy)
	// Mutate the copy — original must be unaffected
	copy["k"] = "changed"
	assert.Equal(t, "v", original["k"], "copyStringMap must return an independent copy")
}

// ---------------------------------------------------------------------------
// PublishDNAUpdate error paths
// ---------------------------------------------------------------------------

// newMinimalClient builds a TransportClient with no network connections for
// unit-testing state-only and error-path behaviour.
func newMinimalClient(t *testing.T) *TransportClient {
	t.Helper()
	c := &TransportClient{
		heartbeatStop:    make(chan struct{}),
		convergenceStop:  make(chan struct{}),
		convergeInterval: 30 * time.Minute,
		logger:           newTestLogger(t),
	}
	return c
}

func TestPublishDNAUpdate_ErrorNotRegistered(t *testing.T) {
	c := newMinimalClient(t)
	// stewardID is empty — not registered
	err := c.PublishDNAUpdate(context.TODO(), map[string]string{"k": "v"}, "", "")
	if err == nil {
		t.Fatal("expected error when steward is not registered")
	}
	if err.Error() != "not registered" {
		t.Fatalf("unexpected error message: %q", err.Error())
	}
}

func TestPublishDNAUpdate_ErrorControlPlaneNil(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-1"
	c.tenantID = "tenant-1"
	// controlPlane is nil and no offline queue — should error
	err := c.PublishDNAUpdate(context.TODO(), map[string]string{"k": "v"}, "", "")
	if err == nil {
		t.Fatal("expected error when control plane and offline queue are unavailable")
	}
}

func TestPublishDNAUpdate_NoDeltaSkipsPublish(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-1"
	c.tenantID = "tenant-1"
	// Seed state so delta is empty on second call.
	// Include steward.version because PublishDNAUpdate always enriches the
	// incoming attrs with the running version before computing the delta.
	c.dnaMu.Lock()
	c.lastPublishedDNA = map[string]string{"k": "v", "steward.version": version.Short()}
	c.currentDNAHash = "some-hash"
	c.dnaMu.Unlock()

	// controlPlane is nil but delta should be empty, so we never reach the publish call.
	// The function returns nil (not an error) when no delta is detected.
	err := c.PublishDNAUpdate(context.TODO(), map[string]string{"k": "v"}, "", "")
	// We do NOT reach the "control plane not connected" error because the early
	// return for empty delta fires first.
	if err != nil {
		t.Fatalf("expected nil error when delta is empty, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Heartbeat.DNAHash field contract
// ---------------------------------------------------------------------------

func TestHeartbeat_DNAHashField(t *testing.T) {
	hb := &cpTypes.Heartbeat{
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Status:    cpTypes.StatusHealthy,
		DNAHash:   "abc123",
	}
	assert.Equal(t, "abc123", hb.DNAHash,
		"Heartbeat.DNAHash must be readable after assignment")
}

func TestHeartbeat_DNAHashOmitempty(t *testing.T) {
	hb := &cpTypes.Heartbeat{StewardID: "s1", Status: cpTypes.StatusHealthy}
	assert.Empty(t, hb.DNAHash, "DNAHash must default to empty string")
}

// ---------------------------------------------------------------------------
// sync_dna command handler — happy path
// ---------------------------------------------------------------------------

func TestSyncDNAHandler_SendsFullDNAOverDataPlane(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-1"
	c.tenantID = "tenant-1"

	// Seed the last-published DNA that the handler will serialize and send.
	dnaAttrs := map[string]string{"os": "linux", "version": "1.2.3"}
	c.dnaMu.Lock()
	c.lastPublishedDNA = copyStringMap(dnaAttrs)
	c.dnaMu.Unlock()

	// Install a test data-plane session that records what SendDNA receives.
	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()

	// Build the command handler and dispatch a CommandSyncDNA command.
	handler, err := c.setupCommandHandler(context.Background(), "steward-1")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-sync-dna-1",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	// HandleCommand dispatches the handler in a goroutine. The handler only does
	// in-memory map reads and a channel write — 250 ms is ample for the scheduler.
	select {
	case transfer := <-sess.dnaSent:
		require.NotNil(t, transfer, "SendDNA must be called with a non-nil transfer")
		assert.Equal(t, "steward-1", transfer.StewardID)
		assert.Equal(t, "tenant-1", transfer.TenantID)
		assert.False(t, transfer.Delta, "full sync must set Delta=false")
		assert.NotEmpty(t, transfer.Attributes, "attributes payload must be non-empty")
		assert.Equal(t, "cmd-sync-dna-1", transfer.Metadata["command_id"])
		assert.Equal(t, "2", transfer.Metadata["attr_count"])
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for sync_dna handler to call SendDNA")
	}
}

// ---------------------------------------------------------------------------
// StartDNARefreshLoop (Issue #1915)
// ---------------------------------------------------------------------------

// TestDNARefreshLoop_NoDeltaSkipsPublish verifies that when the collector
// returns the same attributes as the last-published snapshot, the refresh
// loop does not enqueue any event.
func TestDNARefreshLoop_NoDeltaSkipsPublish(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	// Seed last-published DNA so the collector returns the same snapshot.
	// Include steward.version because PublishDNAUpdate enriches incoming attrs
	// with the running version; the seed must match to produce an empty delta.
	attrs := map[string]string{"hostname": "host-a", "os": "linux", "steward.version": version.Short()}
	c.dnaMu.Lock()
	c.lastPublishedDNA = copyStringMap(attrs)
	c.dnaMu.Unlock()

	stub := &stubDNACollector{attrs: attrs}
	c.mu.Lock()
	c.dnaCollector = stub
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.StartDNARefreshLoop(ctx)

	// Allow multiple ticks to fire; none should enqueue an event.
	time.Sleep(80 * time.Millisecond)
	cancel()

	assert.Equal(t, 0, q.Len(),
		"no event must be queued when the DNA delta is empty")
}

// TestDNARefreshLoop_ChangedAttributePublishesOne verifies that when the collector
// returns a single changed attribute, the refresh loop enqueues exactly one
// EventDNAChanged event carrying only that changed attribute in the delta.
func TestDNARefreshLoop_ChangedAttributePublishesOne(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	// Seed a prior snapshot; collector will return a single changed value.
	// Include steward.version so only the hostname change produces a delta.
	c.dnaMu.Lock()
	c.lastPublishedDNA = map[string]string{"hostname": "host-a", "os": "linux", "steward.version": version.Short()}
	c.dnaMu.Unlock()

	stub := &stubDNACollector{attrs: map[string]string{"hostname": "host-b", "os": "linux"}}
	c.mu.Lock()
	c.dnaCollector = stub
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.StartDNARefreshLoop(ctx)

	// Wait for at least one tick to fire and enqueue the event.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && q.Len() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	require.Equal(t, 1, q.Len(), "exactly one DNA event must be queued after a single attribute change")

	// Drain the queue and inspect the event.
	var captured *cpTypes.Event
	q.Drain(func(ev *cpTypes.Event) error {
		captured = ev
		return nil
	})
	require.NotNil(t, captured)
	assert.Equal(t, cpTypes.EventDNAChanged, captured.Type)

	delta, ok := captured.Details["dna"].(map[string]string)
	require.True(t, ok, "event details must contain a string-string delta map")
	assert.Equal(t, map[string]string{"hostname": "host-b"}, delta,
		"delta must contain only the changed attribute with its new value")
}

// TestDNARefreshLoop_StopsOnContextCancel verifies that cancelling the context
// stops the refresh loop within the existing 15-second graceful disconnect window.
func TestDNARefreshLoop_StopsOnContextCancel(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	// Seed prior state so the first tick produces no event (stable baseline).
	// Include steward.version to match what PublishDNAUpdate enriches the attrs with.
	initial := map[string]string{"os": "linux", "steward.version": version.Short()}
	c.dnaMu.Lock()
	c.lastPublishedDNA = copyStringMap(initial)
	c.dnaMu.Unlock()

	stub := &stubDNACollector{attrs: copyStringMap(initial)}
	c.mu.Lock()
	c.dnaCollector = stub
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())

	// Allow a few ticks to confirm the loop is running (no events = stable).
	c.StartDNARefreshLoop(ctx)
	time.Sleep(40 * time.Millisecond)
	assert.Equal(t, 0, q.Len(), "no events expected while DNA is unchanged")

	// Cancel and verify the loop has stopped: inject a change and confirm the
	// event is NOT published after cancellation.
	cancel()
	time.Sleep(20 * time.Millisecond) // let goroutine observe ctx.Done

	stub.setAttrs(map[string]string{"os": "linux", "hostname": "new"})

	time.Sleep(40 * time.Millisecond) // extra ticks after cancel
	assert.Equal(t, 0, q.Len(), "no events must be published after context cancellation")
}

// TestDNARefreshLoop_StopsOnDNARefreshStop verifies that closing dnaRefreshStop
// (via Disconnect) terminates the loop even when the context is still active.
func TestDNARefreshLoop_StopsOnDNARefreshStop(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	// Seed prior state so the first tick produces no event (stable baseline).
	// Include steward.version to match what PublishDNAUpdate enriches the attrs with.
	initial := map[string]string{"os": "linux", "steward.version": version.Short()}
	c.dnaMu.Lock()
	c.lastPublishedDNA = copyStringMap(initial)
	c.dnaMu.Unlock()

	stub := &stubDNACollector{attrs: copyStringMap(initial)}
	c.mu.Lock()
	c.dnaCollector = stub
	c.mu.Unlock()

	ctx := context.Background()
	c.StartDNARefreshLoop(ctx)
	time.Sleep(40 * time.Millisecond)
	assert.Equal(t, 0, q.Len(), "no events expected while DNA is unchanged")

	// Close the stop channel (mimics Disconnect) and verify the loop stops.
	close(c.dnaRefreshStop)
	time.Sleep(20 * time.Millisecond) // let goroutine observe channel close

	stub.setAttrs(map[string]string{"os": "linux", "hostname": "new"})

	time.Sleep(40 * time.Millisecond) // extra ticks after stop
	assert.Equal(t, 0, q.Len(), "no events must be published after dnaRefreshStop is closed")
}

// TestDNARefreshLoop_CollectorErrorSkipsTick verifies that a collection error
// does not terminate the loop — subsequent ticks still fire.
func TestDNARefreshLoop_CollectorErrorSkipsTick(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	// Start with an error-producing collector.
	errCollector := &stubDNACollector{err: errors.New("transient")}
	c.mu.Lock()
	c.dnaCollector = errCollector
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.StartDNARefreshLoop(ctx)

	// Give the loop several ticks to fail at collection; queue must stay empty.
	time.Sleep(60 * time.Millisecond)
	assert.Equal(t, 0, q.Len(), "collection errors must not enqueue events")

	// Now swap to a collector that produces a real change (no prior snapshot).
	goodCollector := &stubDNACollector{attrs: map[string]string{"os": "linux"}}
	c.mu.Lock()
	c.dnaCollector = goodCollector
	c.mu.Unlock()

	// Wait for the event to arrive — confirms the loop kept running after errors.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && q.Len() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	assert.Equal(t, 1, q.Len(),
		"loop must continue after a collection error and publish when a change is detected")
}

// ---------------------------------------------------------------------------
// RefreshCurrentDNA — Issue #2521
// ---------------------------------------------------------------------------

// TestRefreshCurrentDNA_PopulatesHashAfterReconnect asserts the required AC:
// a freshly-created TransportClient (zero currentDNAHash, nil lastPublishedDNA)
// reports a correct, non-empty DNAHash on its first heartbeat once
// RefreshCurrentDNA is called — matching what dna.ComputeHash would produce
// over the same freshly-collected attribute set.
func TestRefreshCurrentDNA_PopulatesHashAfterReconnect(t *testing.T) {
	c := newMinimalClient(t)

	rawAttrs := map[string]string{"hostname": "machine-1", "os": "linux", "arch": "amd64"}
	stub := &stubDNACollector{attrs: rawAttrs}
	c.mu.Lock()
	c.dnaCollector = stub
	c.mu.Unlock()

	// Pre-condition: no hash before the collect.
	c.dnaMu.RLock()
	assert.Empty(t, c.currentDNAHash, "currentDNAHash must be empty on a fresh client")
	c.dnaMu.RUnlock()

	require.NoError(t, c.RefreshCurrentDNA(context.Background()))

	// Compute the expected hash the same way RefreshCurrentDNA should — enrich
	// with steward.version then feed to dna.ComputeHash.
	enriched := make(map[string]string, len(rawAttrs)+1)
	for k, v := range rawAttrs {
		enriched[k] = v
	}
	enriched["steward.version"] = version.Short()
	wantHash := dna.ComputeHash(enriched)

	c.dnaMu.RLock()
	gotHash := c.currentDNAHash
	c.dnaMu.RUnlock()

	require.NotEmpty(t, gotHash, "currentDNAHash must be non-empty after RefreshCurrentDNA")
	assert.Equal(t, wantHash, gotHash,
		"currentDNAHash must equal dna.ComputeHash of the collected+enriched attributes")
}

// TestCurrentDNAHash_StableWhenUnchangedChangesOnDrift asserts the required AC:
// the reported hash is stable across heartbeats when machine state is unchanged,
// and changes when a collected attribute changes — consistent with
// dna.ComputeHash determinism.
func TestCurrentDNAHash_StableWhenUnchangedChangesOnDrift(t *testing.T) {
	c := newMinimalClient(t)

	attrs := map[string]string{"hostname": "box-1", "os": "linux"}
	stub := &stubDNACollector{attrs: attrs}
	c.mu.Lock()
	c.dnaCollector = stub
	c.mu.Unlock()

	// Collect N times with unchanged state — hash must be identical each time.
	const rounds = 3
	var hashes [rounds]string
	for i := 0; i < rounds; i++ {
		require.NoError(t, c.RefreshCurrentDNA(context.Background()))
		c.dnaMu.RLock()
		hashes[i] = c.currentDNAHash
		c.dnaMu.RUnlock()
	}
	require.NotEmpty(t, hashes[0], "hash must be non-empty after first collect")
	for i := 1; i < rounds; i++ {
		assert.Equal(t, hashes[0], hashes[i],
			"hash must be stable across repeated collects when attributes are unchanged")
	}

	// Mutate an attribute — hash must change on the next collect.
	stub.setAttrs(map[string]string{"hostname": "box-2", "os": "linux"})
	require.NoError(t, c.RefreshCurrentDNA(context.Background()))

	c.dnaMu.RLock()
	changedHash := c.currentDNAHash
	c.dnaMu.RUnlock()

	assert.NotEqual(t, hashes[0], changedHash,
		"hash must change when a collected attribute value changes")
}

// TestRefreshCurrentDNA_CollectorErrorPropagates asserts that when the collector
// returns an error, RefreshCurrentDNA wraps it as "DNA collection failed: %w" and
// leaves currentDNAHash untouched (no partial state is written on the error path).
func TestRefreshCurrentDNA_CollectorErrorPropagates(t *testing.T) {
	c := newMinimalClient(t)

	collectErr := errors.New("transient")
	stub := &stubDNACollector{err: collectErr}
	c.mu.Lock()
	c.dnaCollector = stub
	c.mu.Unlock()

	err := c.RefreshCurrentDNA(context.Background())

	require.Error(t, err, "RefreshCurrentDNA must return the collection error")
	assert.ErrorIs(t, err, collectErr, "returned error must wrap the underlying collector error")
	assert.Contains(t, err.Error(), "DNA collection failed",
		"returned error must carry the DNA collection failure context")

	c.dnaMu.RLock()
	gotHash := c.currentDNAHash
	c.dnaMu.RUnlock()
	assert.Empty(t, gotHash, "currentDNAHash must not be mutated when collection fails")
}

// TestRefreshCurrentDNA_EmptyAttrsLeavesHashUnchanged asserts that when the
// collector returns an empty attribute map, RefreshCurrentDNA returns nil without
// mutating currentDNAHash — so a transient empty collect cannot clobber a known
// good hash.
func TestRefreshCurrentDNA_EmptyAttrsLeavesHashUnchanged(t *testing.T) {
	c := newMinimalClient(t)

	stub := &stubDNACollector{attrs: map[string]string{"hostname": "box-1", "os": "linux"}}
	c.mu.Lock()
	c.dnaCollector = stub
	c.mu.Unlock()

	// Establish a known-good hash from a non-empty collect.
	require.NoError(t, c.RefreshCurrentDNA(context.Background()))
	c.dnaMu.RLock()
	seededHash := c.currentDNAHash
	c.dnaMu.RUnlock()
	require.NotEmpty(t, seededHash, "hash must be seeded by the initial non-empty collect")

	// Now return an empty map — RefreshCurrentDNA must no-op the hash.
	stub.setAttrs(map[string]string{})
	require.NoError(t, c.RefreshCurrentDNA(context.Background()),
		"an empty collect must not be treated as an error")

	c.dnaMu.RLock()
	afterHash := c.currentDNAHash
	c.dnaMu.RUnlock()
	assert.Equal(t, seededHash, afterHash,
		"currentDNAHash must be unchanged when the collector returns an empty map")
}

// TestStartDNARefreshLoop_NilCollectorWarns verifies that StartDNARefreshLoop
// logs a warning and returns immediately when no DNACollector is configured.
func TestStartDNARefreshLoop_NilCollectorWarns(t *testing.T) {
	capLog := &kvCapturingLogger{}
	c := &TransportClient{
		heartbeatStop:      make(chan struct{}),
		convergenceStop:    make(chan struct{}),
		dnaRefreshStop:     make(chan struct{}),
		convergeInterval:   30 * time.Minute,
		dnaRefreshInterval: 10 * time.Millisecond,
		logger:             capLog,
		// dnaCollector intentionally nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.StartDNARefreshLoop(ctx)

	// No goroutine is spawned; give the scheduler a moment to settle.
	time.Sleep(30 * time.Millisecond)

	found := false
	for _, e := range capLog.allEntries() {
		if e.msg == "DNA refresh loop started without a collector; DNA will not be refreshed periodically" {
			found = true
			break
		}
	}
	assert.True(t, found, "must log a warning when dnaCollector is nil")
}
