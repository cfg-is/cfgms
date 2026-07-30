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
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
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
// In-memory DNACollector for refresh-loop tests (Issue #1915)
// ---------------------------------------------------------------------------

// inMemoryDNACollector is a real, thread-safe implementation of the
// client-owned DNACollector interface backed by an in-memory attribute map. It
// is not a mock: there is no expectation recording, no call verification, and
// no framework — CollectAttributes returns a genuine defensive copy of the
// configured attributes, exactly as the production dnaCollectorAdapter returns
// a copy of the collected attribute set.
//
// The real dna.Collector (features/steward/dna) is deliberately NOT used here
// because it is non-deterministic by design: it stamps a fresh "timestamp"
// attribute on every Collect call and merges asynchronously-collected
// software/security attributes as its background goroutine completes. That
// makes the delta-detection logic under test (no-delta-skips-publish,
// single-attribute-change-publishes-one) impossible to assert against. This
// collector provides the deterministic attribute stream those assertions
// require while exercising the exact CollectAttributes contract the loop calls.
// Use setAttrs to change what the next tick observes; the mutex prevents data
// races between the loop goroutine and the test body.
type inMemoryDNACollector struct {
	mu    sync.RWMutex
	attrs map[string]string
	err   error
}

func (s *inMemoryDNACollector) CollectAttributes(_ context.Context) (map[string]string, error) {
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

func (s *inMemoryDNACollector) setAttrs(attrs map[string]string) {
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
		// dnaRefreshTick lets refresh-loop tests observe each fully-processed
		// tick deterministically (one value per completed collect+publish cycle),
		// replacing wall-clock sleeps. Unbuffered so a receive proves a tick
		// finished. StartDNARefreshLoop's notify send is guarded by ctx.Done and
		// dnaRefreshStop, so an un-drained channel never deadlocks the loop.
		dnaRefreshTick: make(chan struct{}),
	}
	return c, q
}

// ---------------------------------------------------------------------------
// In-process DataPlaneSession for sync_dna handler tests
// ---------------------------------------------------------------------------

// testDataPlaneSession is a real in-process implementation of
// dataplaneInterfaces.DataPlaneSession — not a mock. It follows the same
// convention as configTransferSession (client_transport_signature_test.go) and
// configTransferSessionDegraded (client_transport_degraded_test.go): every
// method is implemented explicitly with no expectation recording or framework.
//
// SendDNA delivers the DNATransfer over an in-process buffered channel that the
// test drains via <-dnaSent — the receiving half of the session. This exercises
// the exact SendDNA contract the sync_dna handler calls (serialization of the
// DNATransfer, metadata population) without standing up a QUIC/mTLS transport,
// which the grpc provider's Connect/AcceptConnection would require and which the
// handler-logic-under-test does not touch. The controller-side DNA handler tests
// (features/controller/transport/dna_handler_test.go) use the same in-process
// approach via testDNAStream rather than a live session.
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

	// Seed currentDNAAttrs (maintained by #2521) — the handler sources from
	// this snapshot, not lastPublishedDNA.
	dnaAttrs := map[string]string{"os": "linux", "version": "1.2.3"}
	c.dnaMu.Lock()
	c.currentDNAAttrs = copyStringMap(dnaAttrs)
	c.currentDNAHash = dna.ComputeHash(dnaAttrs)
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

// TestSyncDNAHandler_EmptyPublishCache_UsesCurrentAttrs verifies that the
// sync_dna handler streams the full currentDNAAttrs snapshot even when
// lastPublishedDNA is empty (i.e. no delta has been published yet).
// This is the required "empty-cache" case from Issue #2522.
func TestSyncDNAHandler_EmptyPublishCache_UsesCurrentAttrs(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-2"
	c.tenantID = "tenant-2"

	// Populate currentDNAAttrs but leave lastPublishedDNA nil, simulating a
	// steward that has collected DNA (#2521) but has not yet published a delta.
	dnaAttrs := map[string]string{
		"hostname":        "host-a",
		"os":              "linux",
		"steward.version": version.Short(),
	}
	expectedHash := dna.ComputeHash(dnaAttrs)
	c.dnaMu.Lock()
	c.currentDNAAttrs = copyStringMap(dnaAttrs)
	c.currentDNAHash = expectedHash
	// lastPublishedDNA deliberately left nil
	c.dnaMu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-2")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-sync-dna-empty-cache",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-2",
		TenantID:  "tenant-2",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	select {
	case transfer := <-sess.dnaSent:
		require.NotNil(t, transfer)
		assert.NotEmpty(t, transfer.Attributes,
			"handler must stream non-empty snapshot even with empty publish cache")
		assert.Equal(t, expectedHash, transfer.Metadata["dna_hash"],
			"streamed dna_hash must match the hash of the current snapshot")
		assert.Equal(t, "3", transfer.Metadata["attr_count"],
			"attr_count must reflect the full currentDNAAttrs snapshot")
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for sync_dna handler to call SendDNA with empty publish cache")
	}
}

// TestSyncDNAHandler_DNAHashMatchesHeartbeat asserts that the dna_hash field
// in the DNATransfer equals the hash the steward reports in heartbeats for the
// same collection, as required by Issue #2522.
func TestSyncDNAHandler_DNAHashMatchesHeartbeat(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-3"
	c.tenantID = "tenant-3"

	// Simulate what setCurrentDNAFromAttrs (#2521) produces.
	dnaAttrs := map[string]string{
		"hostname":        "my-host",
		"os":              "linux",
		"arch":            "amd64",
		"steward.version": version.Short(),
	}
	heartbeatHash := dna.ComputeHash(dnaAttrs)
	c.dnaMu.Lock()
	c.currentDNAAttrs = copyStringMap(dnaAttrs)
	c.currentDNAHash = heartbeatHash
	c.dnaMu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-3")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-hash-consistency",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-3",
		TenantID:  "tenant-3",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	select {
	case transfer := <-sess.dnaSent:
		assert.Equal(t, heartbeatHash, transfer.Metadata["dna_hash"],
			"dna_hash in DNATransfer must equal the hash reported in heartbeats for the same collection")
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for sync_dna handler")
	}
}

// TestSyncDNAHandler_EmptyCurrentAttrs_CollectorSucceeds covers the fallback
// branch of the sync_dna handler (client_transport.go) sub-path A:
// currentDNAAttrs is empty AND RefreshCurrentDNA succeeds — the handler must
// stream the freshly collected snapshot, not an empty transfer.
func TestSyncDNAHandler_EmptyCurrentAttrs_CollectorSucceeds(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-refresh-ok"
	c.tenantID = "tenant-refresh-ok"

	// currentDNAAttrs is nil (zero-value), lastPublishedDNA is nil — no prior state.
	// Install a collector so RefreshCurrentDNA can populate currentDNAAttrs.
	rawAttrs := map[string]string{"hostname": "box-ok", "os": "linux"}
	collector := &inMemoryDNACollector{attrs: rawAttrs}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-refresh-ok")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-refresh-ok",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-refresh-ok",
		TenantID:  "tenant-refresh-ok",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	select {
	case transfer := <-sess.dnaSent:
		require.NotNil(t, transfer)
		// The handler must have called RefreshCurrentDNA which enriches rawAttrs
		// with steward.version — so attr_count must be at least 3.
		require.NotEmpty(t, transfer.Attributes,
			"handler must send a non-empty snapshot when RefreshCurrentDNA succeeds")
		attrCount := transfer.Metadata["attr_count"]
		require.NotEqual(t, "0", attrCount,
			"attr_count must be > 0 after a successful refresh")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for sync_dna handler to call SendDNA after fallback refresh")
	}
}

// TestSyncDNAHandler_EmptyCurrentAttrs_CollectorFails covers the fallback
// branch of the sync_dna handler (client_transport.go) sub-path B:
// currentDNAAttrs is empty AND RefreshCurrentDNA fails — no snapshot can be
// produced. A full DNA sync must never send an empty attribute set (that would
// tell the controller the steward has no DNA and clobber its record), so the
// handler must fail the command and MUST NOT call SendDNA.
func TestSyncDNAHandler_EmptyCurrentAttrs_CollectorFails(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-refresh-fail"
	c.tenantID = "tenant-refresh-fail"

	// currentDNAAttrs is nil. Install a collector that always errors.
	collector := &inMemoryDNACollector{err: errors.New("collector unavailable")}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-refresh-fail")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-refresh-fail",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-refresh-fail",
		TenantID:  "tenant-refresh-fail",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	// The handler must return an error before reaching SendDNA. Assert no
	// DNATransfer is emitted within a window generous enough for the dispatch
	// goroutine to run collect-then-return.
	select {
	case transfer := <-sess.dnaSent:
		t.Fatalf("handler must not send DNA when no snapshot can be produced; got transfer %+v", transfer)
	case <-time.After(250 * time.Millisecond):
		// Expected: the handler failed the command and sent nothing.
	}
}

// TestSyncDNAHandler_EmptyCurrentAttrs_CollectorReturnsEmpty covers the fallback
// branch sub-path where RefreshCurrentDNA returns nil (no error) but the
// collector yields an empty attribute set, so currentDNAAttrs stays empty. The
// handler must still refuse to stream an empty full-DNA snapshot and fail the
// command instead.
func TestSyncDNAHandler_EmptyCurrentAttrs_CollectorReturnsEmpty(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-refresh-empty"
	c.tenantID = "tenant-refresh-empty"

	// Collector returns an empty map: RefreshCurrentDNA returns nil but does not
	// populate currentDNAAttrs (a transient empty collect must not clobber state).
	collector := &inMemoryDNACollector{attrs: map[string]string{}}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-refresh-empty")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-refresh-empty",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-refresh-empty",
		TenantID:  "tenant-refresh-empty",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	select {
	case transfer := <-sess.dnaSent:
		t.Fatalf("handler must not send an empty full-DNA snapshot; got transfer %+v", transfer)
	case <-time.After(250 * time.Millisecond):
		// Expected: the handler failed the command and sent nothing.
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

	collector := &inMemoryDNACollector{attrs: attrs}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := c.StartDNARefreshLoop(ctx)

	// Wait for three fully-processed ticks; each is a no-delta skip, so none
	// enqueues an event. Receiving proves the tick ran — no timing guess.
	for i := 0; i < 3; i++ {
		<-c.dnaRefreshTick
	}
	assert.Equal(t, 0, q.Len(),
		"no event must be queued when the DNA delta is empty")

	cancel()
	<-done // confirm the loop goroutine has exited
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

	collector := &inMemoryDNACollector{attrs: map[string]string{"hostname": "host-b", "os": "linux"}}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := c.StartDNARefreshLoop(ctx)

	// One fully-processed tick collects the changed attribute and enqueues the
	// event before signalling; waiting on the tick is deterministic.
	<-c.dnaRefreshTick
	cancel()
	<-done // confirm the loop goroutine has exited before inspecting the queue

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

	collector := &inMemoryDNACollector{attrs: copyStringMap(initial)}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())

	// Two fully-processed ticks confirm the loop is running; both are stable
	// (no delta), so the queue stays empty.
	done := c.StartDNARefreshLoop(ctx)
	<-c.dnaRefreshTick
	<-c.dnaRefreshTick
	assert.Equal(t, 0, q.Len(), "no events expected while DNA is unchanged")

	// Cancel and wait for the goroutine to actually exit. Only then inject a
	// change: because the loop has provably stopped, no tick can observe it.
	cancel()
	<-done

	collector.setAttrs(map[string]string{"os": "linux", "hostname": "new"})

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

	collector := &inMemoryDNACollector{attrs: copyStringMap(initial)}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	ctx := context.Background()
	done := c.StartDNARefreshLoop(ctx)

	// Two fully-processed stable ticks confirm the loop is running.
	<-c.dnaRefreshTick
	<-c.dnaRefreshTick
	assert.Equal(t, 0, q.Len(), "no events expected while DNA is unchanged")

	// Close the stop channel (mimics Disconnect) and wait for the goroutine to
	// exit. Only then inject a change: the loop has provably stopped, so no tick
	// can observe it.
	close(c.dnaRefreshStop)
	<-done

	collector.setAttrs(map[string]string{"os": "linux", "hostname": "new"})

	assert.Equal(t, 0, q.Len(), "no events must be published after dnaRefreshStop is closed")
}

// TestDNARefreshLoop_CollectorErrorSkipsTick verifies that a collection error
// does not terminate the loop — subsequent ticks still fire.
func TestDNARefreshLoop_CollectorErrorSkipsTick(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	// Start with an error-producing collector.
	errCollector := &inMemoryDNACollector{err: errors.New("transient")}
	c.mu.Lock()
	c.dnaCollector = errCollector
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := c.StartDNARefreshLoop(ctx)

	// Three fully-processed ticks all fail collection; the queue must stay empty
	// and the loop must not terminate.
	for i := 0; i < 3; i++ {
		<-c.dnaRefreshTick
	}
	assert.Equal(t, 0, q.Len(), "collection errors must not enqueue events")

	// Now swap to a collector that produces a real change (no prior snapshot).
	goodCollector := &inMemoryDNACollector{attrs: map[string]string{"os": "linux"}}
	c.mu.Lock()
	c.dnaCollector = goodCollector
	c.mu.Unlock()

	// Drain ticks until the recovered collector publishes — proves the loop kept
	// running after the errors. Each iteration consumes exactly one processed
	// tick, so the wait ends deterministically once the event is enqueued.
	for q.Len() == 0 {
		<-c.dnaRefreshTick
	}
	cancel()
	<-done

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
	collector := &inMemoryDNACollector{attrs: rawAttrs}
	c.mu.Lock()
	c.dnaCollector = collector
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
	collector := &inMemoryDNACollector{attrs: attrs}
	c.mu.Lock()
	c.dnaCollector = collector
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
	collector.setAttrs(map[string]string{"hostname": "box-2", "os": "linux"})
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
	collector := &inMemoryDNACollector{err: collectErr}
	c.mu.Lock()
	c.dnaCollector = collector
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

	collector := &inMemoryDNACollector{attrs: map[string]string{"hostname": "box-1", "os": "linux"}}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	// Establish a known-good hash from a non-empty collect.
	require.NoError(t, c.RefreshCurrentDNA(context.Background()))
	c.dnaMu.RLock()
	seededHash := c.currentDNAHash
	c.dnaMu.RUnlock()
	require.NotEmpty(t, seededHash, "hash must be seeded by the initial non-empty collect")

	// Now return an empty map — RefreshCurrentDNA must no-op the hash.
	collector.setAttrs(map[string]string{})
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

	// With no collector, StartDNARefreshLoop returns synchronously (before any
	// goroutine is spawned) and its done channel is already closed. Receiving
	// from it is the deterministic proof that no loop was started — no sleep.
	done := c.StartDNARefreshLoop(ctx)
	<-done

	found := false
	for _, e := range capLog.allEntries() {
		if e.msg == "DNA refresh loop started without a collector; DNA will not be refreshed periodically" {
			found = true
			break
		}
	}
	assert.True(t, found, "must log a warning when dnaCollector is nil")
}

// ---------------------------------------------------------------------------
// Partial-sync protocol tests (ADR-017 §7, Issue #2906)
// ---------------------------------------------------------------------------

// makeClientFragments builds test fragments and returns them along with the
// computed aggregate root, for seeding TransportClient fragment state.
func makeClientFragments(t *testing.T, n int) ([]*commonpb.Fragment, string) {
	t.Helper()
	frags := make([]*commonpb.Fragment, n)
	manifest := make([]*commonpb.ManifestEntry, n)
	for i := 0; i < n; i++ {
		canonical := []byte(fmt.Sprintf(`{"id":%d,"v":"val%d"}`, i, i))
		h := dna.FragmentHash(canonical)
		frags[i] = &commonpb.Fragment{
			FragmentId:     fmt.Sprintf("frag-%d", i),
			Authority:      "test",
			CanonicalBytes: canonical,
			FragmentHash:   h,
		}
		manifest[i] = &commonpb.ManifestEntry{FragmentId: frags[i].FragmentId, FragmentHash: h}
	}
	root, err := dna.AggregateRoot(manifest)
	require.NoError(t, err)
	return frags, root
}

// TestSetCurrentDNAFragments_SetsAggregateRoot verifies that setCurrentDNAFragments
// correctly computes and stores the aggregate root from the fragment manifest
// (ADR-017 §7 step 1). SendHeartbeat reads currentDNAAggregateRoot directly and
// includes it in the Heartbeat struct; this test verifies the field is populated.
func TestSetCurrentDNAFragments_SetsAggregateRoot(t *testing.T) {
	c := newMinimalClient(t)

	frags, expectedRoot := makeClientFragments(t, 3)
	c.setCurrentDNAFragments(frags)

	c.dnaMu.RLock()
	gotRoot := c.currentDNAAggregateRoot
	gotFrags := c.currentDNAFragments
	c.dnaMu.RUnlock()

	assert.Equal(t, expectedRoot, gotRoot,
		"setCurrentDNAFragments must store the AggregateRoot computed from the fragment manifest")
	require.Len(t, gotFrags, len(frags),
		"setCurrentDNAFragments must store all provided fragments")
}

// TestSyncDNAHandler_PartialSync_SendsFragmentDelta verifies that the sync_dna
// handler sends a fragment delta (Delta=true, Fragments populated) when the
// command carries fragment_ids and the steward has matching fragments.
func TestSyncDNAHandler_PartialSync_SendsFragmentDelta(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-partial"
	c.tenantID = "tenant-1"

	frags, _ := makeClientFragments(t, 3)
	c.dnaMu.Lock()
	c.currentDNAFragments = frags
	c.dnaMu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-partial")
	require.NoError(t, err)

	// Request all three fragment IDs.
	requestedIDs := []string{"frag-0", "frag-1", "frag-2"}
	idsJSON, err := json.Marshal(requestedIDs)
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-partial-1",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-partial",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{"fragment_ids": string(idsJSON)},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	select {
	case transfer := <-sess.dnaSent:
		require.NotNil(t, transfer)
		assert.True(t, transfer.Delta, "partial sync must set Delta=true")
		require.Len(t, transfer.Fragments, 3, "all requested fragments must be sent")
		assert.Equal(t, "cmd-partial-1", transfer.Metadata["command_id"])
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for partial sync_dna handler to call SendDNA")
	}
}

// TestSyncDNAHandler_NoFragmentIDs_FullSync_Regression verifies that SYNC_DNA
// without fragment_ids param still triggers the full-snapshot path (Delta=false).
// This is the regression guard ensuring the new partial-sync branch is additive.
func TestSyncDNAHandler_NoFragmentIDs_FullSync_Regression(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-regr"
	c.tenantID = "tenant-1"

	dnaAttrs := map[string]string{"os": "linux", "hostname": "host-1"}
	c.dnaMu.Lock()
	c.currentDNAAttrs = copyStringMap(dnaAttrs)
	c.currentDNAHash = dna.ComputeHash(dnaAttrs)
	c.dnaMu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-regr")
	require.NoError(t, err)

	// No fragment_ids → full sync.
	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-full-regr",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-regr",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{}, // no fragment_ids
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	select {
	case transfer := <-sess.dnaSent:
		assert.False(t, transfer.Delta, "full sync (no fragment_ids) must set Delta=false")
		assert.Nil(t, transfer.Fragments, "full sync must not carry fragments")
		assert.NotEmpty(t, transfer.Attributes, "full sync must carry attributes")
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for full sync_dna to call SendDNA")
	}
}

// TestSyncDNAHandler_PartialSync_NoFragmentState_FallsBackToFullSync verifies
// that when fragment_ids is present but the steward has no currentDNAFragments,
// the handler falls back to a full sync rather than failing.
func TestSyncDNAHandler_PartialSync_NoFragmentState_FallsBackToFullSync(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-fallback"
	c.tenantID = "tenant-1"

	dnaAttrs := map[string]string{"os": "linux"}
	c.dnaMu.Lock()
	c.currentDNAAttrs = copyStringMap(dnaAttrs)
	c.currentDNAHash = dna.ComputeHash(dnaAttrs)
	// currentDNAFragments is nil (no fragment collector).
	c.dnaMu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-fallback")
	require.NoError(t, err)

	idsJSON, err := json.Marshal([]string{"frag-0", "frag-1"})
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-fallback",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-fallback",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{"fragment_ids": string(idsJSON)},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	select {
	case transfer := <-sess.dnaSent:
		assert.False(t, transfer.Delta, "fallback must produce a full sync with Delta=false")
		assert.Nil(t, transfer.Fragments, "fallback must not carry fragments")
		assert.NotEmpty(t, transfer.Attributes)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for fallback to full sync")
	}
}

// ---------------------------------------------------------------------------
// FragmentCollector tests (ADR-017 §7, Issue #2906)
// ---------------------------------------------------------------------------

// fragmentAndAttrCollector is a real in-process implementation of both DNACollector
// and FragmentCollector. It returns pre-set attrs and fragments for deterministic
// test assertions without relying on any external component.
type fragmentAndAttrCollector struct {
	attrs     map[string]string
	fragments []*commonpb.Fragment
}

func (c *fragmentAndAttrCollector) CollectAttributes(_ context.Context) (map[string]string, error) {
	return c.attrs, nil
}

func (c *fragmentAndAttrCollector) CollectFragments(_ context.Context) ([]*commonpb.Fragment, error) {
	return c.fragments, nil
}

var _ DNACollector = (*fragmentAndAttrCollector)(nil)
var _ FragmentCollector = (*fragmentAndAttrCollector)(nil)

// TestRefreshCurrentDNA_FragmentCollector_SetsAggregateRoot verifies that when
// the wired DNACollector also implements FragmentCollector, RefreshCurrentDNA
// populates both currentDNAHash and currentDNAAggregateRoot (ADR-017 §7 step 1).
func TestRefreshCurrentDNA_FragmentCollector_SetsAggregateRoot(t *testing.T) {
	c := newMinimalClient(t)

	attrs := map[string]string{"hostname": "box-1", "os": "linux"}
	frags, expectedRoot := makeClientFragments(t, 3)

	collector := &fragmentAndAttrCollector{attrs: attrs, fragments: frags}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	require.NoError(t, c.RefreshCurrentDNA(context.Background()))

	c.dnaMu.RLock()
	gotHash := c.currentDNAHash
	gotRoot := c.currentDNAAggregateRoot
	gotFrags := c.currentDNAFragments
	c.dnaMu.RUnlock()

	assert.NotEmpty(t, gotHash, "RefreshCurrentDNA must populate currentDNAHash")
	assert.Equal(t, expectedRoot, gotRoot,
		"RefreshCurrentDNA must populate currentDNAAggregateRoot from the fragment manifest")
	require.Len(t, gotFrags, len(frags),
		"RefreshCurrentDNA must store all collected fragments")
}

// TestRefreshCurrentDNA_FragmentCollector_EmptyFragmentsLeavesRootUnchanged verifies
// that when CollectFragments returns zero fragments, RefreshCurrentDNA does not
// mutate currentDNAAggregateRoot (empty collect must not clobber a known-good root).
func TestRefreshCurrentDNA_FragmentCollector_EmptyFragmentsLeavesRootUnchanged(t *testing.T) {
	c := newMinimalClient(t)

	// Seed a known-good root via a non-empty collect.
	frags, expectedRoot := makeClientFragments(t, 2)
	c.setCurrentDNAFragments(frags)

	// Now run RefreshCurrentDNA with a collector that returns no fragments.
	collector := &fragmentAndAttrCollector{
		attrs:     map[string]string{"os": "linux"},
		fragments: nil, // empty — root must not change
	}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	require.NoError(t, c.RefreshCurrentDNA(context.Background()))

	c.dnaMu.RLock()
	gotRoot := c.currentDNAAggregateRoot
	c.dnaMu.RUnlock()
	assert.Equal(t, expectedRoot, gotRoot,
		"currentDNAAggregateRoot must be unchanged when CollectFragments returns empty")
}

// TestParseFragmentIDs covers every shape the control plane can deliver the
// fragment_ids param in, plus the rejection cases.
//
// The wire path is lossy in a way that matters: the controller marshals a JSON
// array into a string param, but the gRPC control-plane provider JSON-decodes
// any param value that is valid JSON on arrival, so the steward actually receives
// []interface{}. A handler that only accepts the string form silently disables
// partial sync on the real control plane.
func TestParseFragmentIDs(t *testing.T) {
	want := []string{"frag-0", "file:/etc/hosts", "service:sshd"}

	t.Run("json string as sent by the controller", func(t *testing.T) {
		raw, err := json.Marshal(want)
		require.NoError(t, err)
		got, err := parseFragmentIDs(string(raw))
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("interface slice as delivered over the real control plane", func(t *testing.T) {
		delivered := make([]interface{}, 0, len(want))
		for _, id := range want {
			delivered = append(delivered, id)
		}
		got, err := parseFragmentIDs(delivered)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("native string slice", func(t *testing.T) {
		got, err := parseFragmentIDs(want)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("absent and empty are not errors", func(t *testing.T) {
		got, err := parseFragmentIDs(nil)
		require.NoError(t, err)
		assert.Empty(t, got)

		got, err = parseFragmentIDs("")
		require.NoError(t, err)
		assert.Empty(t, got)

		got, err = parseFragmentIDs("[]")
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("rejects malformed input", func(t *testing.T) {
		_, err := parseFragmentIDs("not json")
		require.Error(t, err)

		_, err = parseFragmentIDs([]interface{}{"frag-0", 42})
		require.Error(t, err, "non-string elements must be rejected, not coerced")

		_, err = parseFragmentIDs([]interface{}{"frag-0", ""})
		require.Error(t, err, "empty fragment IDs must be rejected")

		_, err = parseFragmentIDs(map[string]interface{}{"frag-0": true})
		require.Error(t, err, "unsupported param types must be rejected")

		oversized := make([]string, maxRequestedFragmentIDs+1)
		for i := range oversized {
			oversized[i] = fmt.Sprintf("frag-%d", i)
		}
		_, err = parseFragmentIDs(oversized)
		require.Error(t, err, "an unbounded ID list must be rejected")
	})
}

// TestSyncDNAHandler_PartialSync_WireDecodedParams verifies the sync_dna handler
// takes the partial-sync path when fragment_ids arrives in the []interface{} form
// the real gRPC control plane produces. This is the regression guard for the bug
// an in-package fake control plane hid: the controller sends a JSON string, the
// provider re-parses it, and a string-only type assertion made every partial sync
// fall back to a full snapshot.
func TestSyncDNAHandler_PartialSync_WireDecodedParams(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-wireparams"
	c.tenantID = "tenant-1"

	frags, _ := makeClientFragments(t, 3)
	c.dnaMu.Lock()
	c.currentDNAFragments = frags
	// A full snapshot is also available, so a regression falls back silently
	// instead of erroring — the assertion below is what catches it.
	c.currentDNAAttrs = map[string]string{"os": "linux"}
	c.currentDNAHash = dna.ComputeHash(c.currentDNAAttrs)
	c.dnaMu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-wireparams")
	require.NoError(t, err)

	// Exactly what stringMapToInterfaceMap yields for a marshalled ID array.
	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-wireparams",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-wireparams",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"fragment_ids": []interface{}{"frag-0", "frag-1", "frag-2"},
		},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	select {
	case transfer := <-sess.dnaSent:
		require.NotNil(t, transfer)
		assert.True(t, transfer.Delta,
			"wire-decoded fragment_ids must still take the partial-sync path")
		require.Len(t, transfer.Fragments, 3)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for the partial sync_dna handler to call SendDNA")
	}
}

// TestSyncDNAHandler_PartialSync_MalformedFragmentIDs_NoSend verifies that a
// malformed fragment_ids param fails the command instead of silently degrading to
// a full snapshot: nothing is sent on the data plane, so the controller observes
// the failure and can retry with a full sync rather than believing a partial sync
// satisfied its request.
func TestSyncDNAHandler_PartialSync_MalformedFragmentIDs_NoSend(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-badparams"
	c.tenantID = "tenant-1"

	frags, _ := makeClientFragments(t, 2)
	c.dnaMu.Lock()
	c.currentDNAFragments = frags
	// A full snapshot IS available: a regression that ignores the malformed param
	// would happily send it, which is exactly what this test forbids.
	c.currentDNAAttrs = map[string]string{"os": "linux"}
	c.currentDNAHash = dna.ComputeHash(c.currentDNAAttrs)
	c.dnaMu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-badparams")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-badparams",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-badparams",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{"fragment_ids": []interface{}{"frag-0", 7}},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	select {
	case transfer := <-sess.dnaSent:
		t.Fatalf("no DNA may be sent for a malformed fragment_ids param, got delta=%v", transfer.Delta)
	case <-time.After(250 * time.Millisecond):
		// Nothing sent — the command failed as required.
	}
}
