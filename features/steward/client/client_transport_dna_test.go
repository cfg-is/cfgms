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
	"github.com/cfgis/cfgms/features/steward/execution"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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
	frags []*commonpb.Fragment // optional; set via setFrags for fragment-delta tests
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

// CollectFragments returns the configured fragment slice (Issue #3330). Tests
// that exercise fragment-delta publishing configure this via setFrags; attribute-
// only tests leave it nil so the fragment delta is always empty and publish is
// suppressed, which accurately reflects production behaviour before #3332 lands.
func (s *inMemoryDNACollector) CollectFragments(_ context.Context) []*commonpb.Fragment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.frags) == 0 {
		return nil
	}
	out := make([]*commonpb.Fragment, len(s.frags))
	copy(out, s.frags)
	return out
}

func (s *inMemoryDNACollector) setAttrs(attrs map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attrs = attrs
}

func (s *inMemoryDNACollector) setFrags(frags []*commonpb.Fragment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frags = frags
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
// computeFragmentDelta (Issue #3330)
// ---------------------------------------------------------------------------

// mustTestFragment creates a Fragment for delta-computation tests.
// Panics on error (test helper).
func mustTestFragment(t *testing.T, id string, fields map[string]interface{}) *commonpb.Fragment {
	t.Helper()
	f, err := dna.NewFragment(id, "test", dna.MapState(fields))
	require.NoError(t, err)
	return f
}

func TestComputeFragmentDelta_NilOld(t *testing.T) {
	fA := mustTestFragment(t, "svc:A", map[string]interface{}{"status": "running"})
	delta := computeFragmentDelta(nil, []*commonpb.Fragment{fA})
	require.Len(t, delta, 1, "when no previous state exists all fragments are in the delta")
	assert.Equal(t, "svc:A", delta[0].GetFragmentId())
}

func TestComputeFragmentDelta_EmptyOld(t *testing.T) {
	fA := mustTestFragment(t, "svc:A", map[string]interface{}{"status": "running"})
	delta := computeFragmentDelta([]*commonpb.Fragment{}, []*commonpb.Fragment{fA})
	require.Len(t, delta, 1, "when previous state is empty all fragments are in the delta")
}

func TestComputeFragmentDelta_NoChanges(t *testing.T) {
	fA := mustTestFragment(t, "svc:A", map[string]interface{}{"status": "running"})
	fB := mustTestFragment(t, "svc:B", map[string]interface{}{"status": "stopped"})
	delta := computeFragmentDelta([]*commonpb.Fragment{fA, fB}, []*commonpb.Fragment{fA, fB})
	assert.Empty(t, delta, "identical fragment sets must produce an empty delta")
}

func TestComputeFragmentDelta_ChangedHash(t *testing.T) {
	old := mustTestFragment(t, "svc:A", map[string]interface{}{"status": "running"})
	updated := mustTestFragment(t, "svc:A", map[string]interface{}{"status": "stopped"})
	delta := computeFragmentDelta([]*commonpb.Fragment{old}, []*commonpb.Fragment{updated})
	require.Len(t, delta, 1, "a changed fragment must appear in the delta")
	assert.Equal(t, "svc:A", delta[0].GetFragmentId())
	assert.NotEmpty(t, delta[0].GetFragmentHash())
}

func TestComputeFragmentDelta_AddedFragment(t *testing.T) {
	fA := mustTestFragment(t, "svc:A", map[string]interface{}{"status": "running"})
	fB := mustTestFragment(t, "svc:B", map[string]interface{}{"status": "running"})
	delta := computeFragmentDelta([]*commonpb.Fragment{fA}, []*commonpb.Fragment{fA, fB})
	require.Len(t, delta, 1, "newly added fragment must appear in the delta")
	assert.Equal(t, "svc:B", delta[0].GetFragmentId())
}

func TestComputeFragmentDelta_RemovedFragment(t *testing.T) {
	fA := mustTestFragment(t, "svc:A", map[string]interface{}{"status": "running"})
	fB := mustTestFragment(t, "svc:B", map[string]interface{}{"status": "running"})
	// fB removed from current
	delta := computeFragmentDelta([]*commonpb.Fragment{fA, fB}, []*commonpb.Fragment{fA})
	require.Len(t, delta, 1, "removed fragment must appear as sentinel in the delta")
	assert.Equal(t, "svc:B", delta[0].GetFragmentId(), "sentinel carries the removed fragment's ID")
	// Sentinel has no canonical bytes or hash — just the ID.
	assert.Empty(t, delta[0].GetCanonicalBytes(), "removal sentinel must have no canonical bytes")
}

func TestComputeFragmentDelta_BothNil(t *testing.T) {
	delta := computeFragmentDelta(nil, nil)
	assert.Empty(t, delta, "nil vs nil must produce an empty delta")
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
	// stewardID is empty — not registered.
	// Seed a fragment change so the empty-delta guard does not fire first.
	frag := mustTestFragment(t, "svc:A", map[string]interface{}{"status": "running"})
	c.dnaMu.Lock()
	c.currentDNAFragments = []*commonpb.Fragment{frag}
	// lastPublishedFragments left nil so fragment delta is non-empty.
	c.dnaMu.Unlock()

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
	// Seed a fragment change so the empty-delta guard does not fire first;
	// controlPlane is nil and no offline queue — should error at the publish step.
	frag := mustTestFragment(t, "svc:A", map[string]interface{}{"status": "running"})
	c.dnaMu.Lock()
	c.currentDNAFragments = []*commonpb.Fragment{frag}
	c.dnaMu.Unlock()

	err := c.PublishDNAUpdate(context.TODO(), map[string]string{"k": "v"}, "", "")
	if err == nil {
		t.Fatal("expected error when control plane and offline queue are unavailable")
	}
}

func TestPublishDNAUpdate_NoDeltaSkipsPublish(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-1"
	c.tenantID = "tenant-1"
	// Seed lastPublishedFragments with the same fragments that currentDNAFragments
	// holds so the fragment delta is empty and the publish is skipped.
	frag := mustTestFragment(t, "svc:A", map[string]interface{}{"status": "running"})
	c.dnaMu.Lock()
	c.currentDNAFragments = []*commonpb.Fragment{frag}
	c.lastPublishedFragments = []*commonpb.Fragment{frag} // same hash → empty delta
	c.dnaMu.Unlock()

	// controlPlane is nil but fragment delta should be empty, so we never reach
	// the publish call. The function returns nil when no delta is detected.
	err := c.PublishDNAUpdate(context.TODO(), map[string]string{"k": "v"}, "", "")
	if err != nil {
		t.Fatalf("expected nil error when fragment delta is empty, got: %v", err)
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
		assert.Nil(t, transfer.Attributes, "Attributes must not be populated on the wire (Issue #3322)")
		assert.Equal(t, "cmd-sync-dna-1", transfer.Metadata["command_id"])
		assert.Equal(t, "2", transfer.Metadata["attr_count"])
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for sync_dna handler to call SendDNA")
	}
}

// fragmentDNACollector is a real DNACollector that returns both attributes and
// ADR-017 fragments. It is not a mock: the fragments it returns are built by the
// production constructor dna.NewFragment (same code path *execution.Executor's
// CollectModuleFragments uses), so canonical bytes and fragment hash are genuine.
type fragmentDNACollector struct {
	attrs map[string]string
	frags []*commonpb.Fragment
}

func (f *fragmentDNACollector) CollectAttributes(_ context.Context) (map[string]string, error) {
	out := make(map[string]string, len(f.attrs))
	for k, v := range f.attrs {
		out[k] = v
	}
	return out, nil
}

func (f *fragmentDNACollector) CollectFragments(_ context.Context) []*commonpb.Fragment {
	return f.frags
}

// TestSyncDNAHandler_IncludesModuleFragments is the REQUIRED wiring test for
// #2908: the sync_dna handler must carry the collector's ADR-017 fragments on the
// DNATransfer. Before this wiring the full-sync path sent only flat attributes,
// so DNA.Fragments was never populated on the controller and the cluster registry
// (clusterregistry.BuildRegistry) was always empty in production.
func TestSyncDNAHandler_IncludesModuleFragments(t *testing.T) {
	// Build a genuine cluster fragment through the production constructor.
	frag, err := dna.NewFragment("cluster:cfg-lab", "hyperv",
		execution.NewConfigState(map[string]interface{}{
			"name":           "cfg-lab",
			"cno_owner_node": "CFG-70-02",
			"member_nodes":   []string{"CFG-70-02", "CFG-AB-02"},
			"resource_owner": map[string]string{"web-01": "CFG-70-02"},
		}))
	require.NoError(t, err)
	require.NotEmpty(t, frag.GetCanonicalBytes())

	c := newMinimalClient(t)
	c.stewardID = "steward-frag"
	c.tenantID = "tenant-frag"

	dnaAttrs := map[string]string{"hostname": "cfg-70-02", "os": "windows"}
	c.dnaMu.Lock()
	c.currentDNAAttrs = copyStringMap(dnaAttrs)
	c.currentDNAHash = dna.ComputeHash(dnaAttrs)
	c.dnaMu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	c.dnaCollector = &fragmentDNACollector{attrs: dnaAttrs, frags: []*commonpb.Fragment{frag}}
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-frag")
	require.NoError(t, err)

	require.NoError(t, handler.HandleCommand(context.Background(), &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        "cmd-sync-dna-frag",
			Type:      cpTypes.CommandSyncDNA,
			StewardID: "steward-frag",
			TenantID:  "tenant-frag",
			Timestamp: time.Now(),
			Params:    map[string]interface{}{},
		},
	}))

	select {
	case transfer := <-sess.dnaSent:
		require.NotNil(t, transfer)
		require.Len(t, transfer.FragmentBytes, 1,
			"the collector's fragment must ride the full-sync DNATransfer")
		assert.Equal(t, "1", transfer.Metadata["fragment_count"])

		// The wire bytes must proto-decode back to the exact fragment.
		got := &commonpb.Fragment{}
		require.NoError(t, proto.Unmarshal(transfer.FragmentBytes[0], got))
		assert.Equal(t, "cluster:cfg-lab", got.GetFragmentId())
		assert.Equal(t, "hyperv", got.GetAuthority())
		assert.Equal(t, frag.GetCanonicalBytes(), got.GetCanonicalBytes())
		assert.Equal(t, frag.GetFragmentHash(), got.GetFragmentHash())
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sync_dna handler to call SendDNA")
	}
}

// TestSyncDNAHandler_NilCollector_NoFragments: with no DNA collector wired the
// full sync still succeeds and simply carries no fragments (degrade-safe).
func TestSyncDNAHandler_NilCollector_NoFragments(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-nofrag"
	c.tenantID = "tenant-nofrag"

	dnaAttrs := map[string]string{"hostname": "h", "os": "linux"}
	c.dnaMu.Lock()
	c.currentDNAAttrs = copyStringMap(dnaAttrs)
	c.currentDNAHash = dna.ComputeHash(dnaAttrs)
	c.dnaMu.Unlock()

	sess := newTestSession()
	c.mu.Lock()
	c.dataPlaneSession = sess
	// dnaCollector intentionally nil
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-nofrag")
	require.NoError(t, err)

	require.NoError(t, handler.HandleCommand(context.Background(), &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        "cmd-sync-dna-nofrag",
			Type:      cpTypes.CommandSyncDNA,
			StewardID: "steward-nofrag",
			TenantID:  "tenant-nofrag",
			Timestamp: time.Now(),
			Params:    map[string]interface{}{},
		},
	}))

	select {
	case transfer := <-sess.dnaSent:
		require.NotNil(t, transfer)
		assert.Empty(t, transfer.FragmentBytes, "no collector means no fragments")
		assert.Equal(t, "0", transfer.Metadata["fragment_count"])
		assert.Nil(t, transfer.Attributes, "Attributes must not be populated on the wire (Issue #3322)")
	case <-time.After(2 * time.Second):
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
		assert.Nil(t, transfer.Attributes, "Attributes must not be populated on the wire (Issue #3322)")
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
		assert.Nil(t, transfer.Attributes, "Attributes must not be populated on the wire (Issue #3322)")
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
// produced. A full DNA sync must never send an empty transfer with no DNA state
// (that would tell the controller the steward has no DNA and clobber its
// record), so the handler must fail the command and MUST NOT call SendDNA.
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
// handler must still refuse to proceed with no DNA state and fail the command instead.
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
// returns the same fragments as the last-published snapshot, the refresh loop
// does not enqueue any event. (Issue #3330: fragment-based delta replaces flat-map diff)
func TestDNARefreshLoop_NoDeltaSkipsPublish(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	// Build a fragment and seed it as both "current" and "last published" so
	// the fragment delta is empty on every tick.
	frag := mustTestFragment(t, "host:os", map[string]interface{}{"os": "linux", "hostname": "host-a"})

	c.dnaMu.Lock()
	c.lastPublishedFragments = []*commonpb.Fragment{frag}
	c.dnaMu.Unlock()

	collector := &inMemoryDNACollector{
		attrs: map[string]string{"hostname": "host-a", "os": "linux"},
		frags: []*commonpb.Fragment{frag}, // same fragment → no delta
	}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := c.StartDNARefreshLoop(ctx)

	// Wait for three fully-processed ticks; each is a no-fragment-delta skip, so
	// none enqueues an event. Receiving proves the tick ran — no timing guess.
	for i := 0; i < 3; i++ {
		<-c.dnaRefreshTick
	}
	assert.Equal(t, 0, q.Len(),
		"no event must be queued when the fragment delta is empty")

	cancel()
	<-done // confirm the loop goroutine has exited
}

// TestDNARefreshLoop_ChangedFragmentPublishesOne verifies that when the collector
// returns a changed fragment, the refresh loop enqueues exactly one EventDNAChanged
// event whose "dna" detail carries the full current fragment set as a protojson
// JSON array. (Issue #3330: fragment-based delta replaces flat-map diff)
func TestDNARefreshLoop_ChangedFragmentPublishesOne(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	// Build initial and updated fragments — same ID, different hash (status changed).
	fragOld := mustTestFragment(t, "host:os", map[string]interface{}{"os": "linux", "hostname": "host-a"})
	fragNew := mustTestFragment(t, "host:os", map[string]interface{}{"os": "linux", "hostname": "host-b"})

	// Seed lastPublishedFragments with the OLD fragment so the FIRST tick sees a change.
	c.dnaMu.Lock()
	c.lastPublishedFragments = []*commonpb.Fragment{fragOld}
	c.dnaMu.Unlock()

	collector := &inMemoryDNACollector{
		attrs: map[string]string{"hostname": "host-b", "os": "linux"},
		frags: []*commonpb.Fragment{fragNew}, // changed hash → non-empty delta
	}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := c.StartDNARefreshLoop(ctx)

	// One fully-processed tick detects the changed fragment and enqueues the event.
	<-c.dnaRefreshTick
	cancel()
	<-done // confirm the loop goroutine has exited before inspecting the queue

	require.Equal(t, 1, q.Len(), "exactly one DNA event must be queued after a fragment change")

	// Drain the queue and inspect the event.
	var captured *cpTypes.Event
	q.Drain(func(ev *cpTypes.Event) error {
		captured = ev
		return nil
	})
	require.NotNil(t, captured)
	assert.Equal(t, cpTypes.EventDNAChanged, captured.Type)

	// Details["dna"] is the protojson JSON array string produced by marshalFragmentsToJSONString.
	// The event travels through the in-memory offline queue without transport encoding,
	// so the value is the plain string we set — parse it to verify fragment content.
	dnaPayload, ok := captured.Details["dna"].(string)
	require.True(t, ok, "event details must contain a JSON string for the fragment payload")
	require.NotEmpty(t, dnaPayload, "fragment payload must be non-empty")

	// Decode the JSON array and verify it contains the updated fragment.
	var rawElems []json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(dnaPayload), &rawElems),
		"fragment payload must be a valid JSON array")
	require.Len(t, rawElems, 1, "payload must contain exactly one fragment (the current set)")

	// Verify the fragment ID is the one we set.
	var fragObj map[string]interface{}
	require.NoError(t, json.Unmarshal(rawElems[0], &fragObj))
	assert.Equal(t, "host:os", fragObj["fragmentId"], "fragment ID must match the updated fragment")
}

// TestDNARefreshLoop_StopsOnContextCancel verifies that cancelling the context
// stops the refresh loop within the existing 15-second graceful disconnect window.
func TestDNARefreshLoop_StopsOnContextCancel(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	// Collector returns attrs only, no fragments. Since fragment delta drives the
	// publish decision (Issue #3330), nil frags → nil delta → no event queued,
	// so the queue stays empty for every tick while the loop is running.
	collector := &inMemoryDNACollector{attrs: map[string]string{"os": "linux"}}
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

	// Collector returns attrs only, no fragments. Since fragment delta drives the
	// publish decision (Issue #3330), nil frags → nil delta → no event queued,
	// so the queue stays empty for every tick while the loop is running.
	collector := &inMemoryDNACollector{attrs: map[string]string{"os": "linux"}}
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

	// Swap to a collector that returns a fragment. Since fragment delta drives the
	// publish decision (Issue #3330), a non-nil fragment with no prior snapshot
	// produces a non-empty delta → event queued.
	goodFrag := mustTestFragment(t, "host:os", map[string]interface{}{"os": "linux"})
	goodCollector := &inMemoryDNACollector{
		attrs: map[string]string{"os": "linux"},
		frags: []*commonpb.Fragment{goodFrag},
	}
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
		"loop must continue after a collection error and publish when a fragment change is detected")
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
		assert.Nil(t, transfer.Attributes, "Attributes must not be populated on the wire (Issue #3322)")
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
		assert.Nil(t, transfer.Attributes, "Attributes must not be populated on the wire (Issue #3322)")
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

func (c *fragmentAndAttrCollector) CollectFragmentsTracked(_ context.Context) ([]*commonpb.Fragment, error) {
	return c.fragments, nil
}

// CollectFragments satisfies DNACollector's best-effort fragment surface
// (used by the sync_dna full-sync path); CollectFragmentsTracked above
// satisfies the separate error-returning FragmentCollector extension.
func (c *fragmentAndAttrCollector) CollectFragments(_ context.Context) []*commonpb.Fragment {
	return c.fragments
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

// ---------------------------------------------------------------------------
// Issue #3332: gate-fix tests and production-adapter integration
// ---------------------------------------------------------------------------

// realHostFragmentCollector wraps the real dna.Collector and implements both
// DNACollector and FragmentCollector, mirroring the production dnaCollectorAdapter
// surface. It returns empty attrs (no module source) so the tests verify the
// fragment-only path activated for the first time by Issue #3332.
type realHostFragmentCollector struct {
	c *dna.Collector
}

func (r *realHostFragmentCollector) CollectAttributes(_ context.Context) (map[string]string, error) {
	return nil, nil
}

func (r *realHostFragmentCollector) CollectFragments(ctx context.Context) []*commonpb.Fragment {
	result, err := r.c.Collect(ctx)
	if err != nil {
		return nil
	}
	return result.Fragments
}

func (r *realHostFragmentCollector) CollectFragmentsTracked(ctx context.Context) ([]*commonpb.Fragment, error) {
	return r.CollectFragments(ctx), nil
}

var _ DNACollector = (*realHostFragmentCollector)(nil)
var _ FragmentCollector = (*realHostFragmentCollector)(nil)

// TestRefreshCurrentDNA_EmptyAttrsButFragments_SetsFragmentState verifies the
// gate fix (Issue #3332): RefreshCurrentDNA must proceed and update
// currentDNAFragments / currentDNAAggregateRoot when attrs is empty but
// fragments are present — a hardware-facts-only steward no longer silently
// skips all DNA state updates.
func TestRefreshCurrentDNA_EmptyAttrsButFragments_SetsFragmentState(t *testing.T) {
	c := newMinimalClient(t)

	frags, expectedRoot := makeClientFragments(t, 2)
	collector := &fragmentAndAttrCollector{
		attrs:     nil, // empty — hardware-facts-only steward
		fragments: frags,
	}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	require.NoError(t, c.RefreshCurrentDNA(context.Background()))

	c.dnaMu.RLock()
	gotFrags := c.currentDNAFragments
	gotRoot := c.currentDNAAggregateRoot
	c.dnaMu.RUnlock()

	require.Len(t, gotFrags, len(frags),
		"RefreshCurrentDNA must store fragments even when attrs is empty")
	assert.Equal(t, expectedRoot, gotRoot,
		"RefreshCurrentDNA must set currentDNAAggregateRoot even when attrs is empty")
}

// TestRefreshCurrentDNA_ProductionCollector_PopulatesFragmentState is the REQUIRED
// TEST for Issue #3332: the production DNA adapter (wrapping the real dna.Collector)
// populates currentDNAFragments and currentDNAAggregateRoot through RefreshCurrentDNA
// for the first time, proving ADR-017 §7 partial sync activates in production.
func TestRefreshCurrentDNA_ProductionCollector_PopulatesFragmentState(t *testing.T) {
	c := newMinimalClient(t)

	// Use the real dna.Collector — not a stub. This mirrors the production
	// dnaCollectorAdapter.CollectFragmentsTracked which calls Collect() and
	// returns result.Fragments (host:* fragments).
	realCollector := &realHostFragmentCollector{
		c: dna.NewCollector(logging.NewLogger("error")),
	}
	c.mu.Lock()
	c.dnaCollector = realCollector
	c.mu.Unlock()

	require.NoError(t, c.RefreshCurrentDNA(context.Background()))

	c.dnaMu.RLock()
	gotFrags := c.currentDNAFragments
	gotRoot := c.currentDNAAggregateRoot
	c.dnaMu.RUnlock()

	assert.NotEmpty(t, gotFrags,
		"currentDNAFragments must be non-empty when the real DNA collector provides host:* fragments")
	assert.NotEmpty(t, gotRoot,
		"currentDNAAggregateRoot must be computed when fragments are present")
}

// TestSyncDNAHandler_FullSync_EmptyAttrsFragmentsPresent_Succeeds verifies that
// the sync_dna full-sync handler (Issue #3332) no longer hard-fails when
// currentDNAAttrs is empty but fragments are present — a zero-managed-resource
// steward can complete a full sync via fragments alone.
func TestSyncDNAHandler_FullSync_EmptyAttrsFragmentsPresent_Succeeds(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-fragonly"
	c.tenantID = "tenant-1"

	// Seed fragment state (no attrs — hardware-facts-only steward).
	frags, _ := makeClientFragments(t, 2)

	// Wire a collector that returns empty attrs but non-empty fragments.
	// RefreshCurrentDNA (called by the handler fallback) will populate
	// currentDNAFragments via the gate-fixed path.
	collector := &fragmentAndAttrCollector{attrs: nil, fragments: frags}
	sess := newTestSession()
	c.mu.Lock()
	c.dnaCollector = collector
	c.dataPlaneSession = sess
	c.mu.Unlock()

	// Pre-seed currentDNAFragments so the handler can read them after
	// RefreshCurrentDNA populates them in the fallback path.
	c.dnaMu.Lock()
	c.currentDNAFragments = frags
	c.dnaMu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-fragonly")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-fragonly",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-fragonly",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
	}}

	require.NoError(t, handler.HandleCommand(context.Background(), cmd),
		"sync_dna must not fail when currentDNAAttrs is empty but fragments are present")

	select {
	case transfer := <-sess.dnaSent:
		assert.False(t, transfer.Delta, "must be a full sync")
		assert.NotEmpty(t, transfer.FragmentBytes,
			"transfer must include fragment bytes from the wired collector")
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for sync_dna handler to call SendDNA")
	}
}

// mutableFragmentAttrCollector is a real, thread-safe DNACollector whose
// attribute map and fragment set can be swapped while the DNA refresh loop is
// running. It is not a mock: there is no expectation recording and no
// framework — each Collect* call returns whatever was last configured, exactly
// as the production dnaCollectorAdapter returns whatever the underlying
// collector and module source produced on that cycle. The mutex is what makes
// it safe for the loop goroutine to read while the test body writes.
type mutableFragmentAttrCollector struct {
	mu        sync.RWMutex
	attrs     map[string]string
	fragments []*commonpb.Fragment
}

func (c *mutableFragmentAttrCollector) CollectAttributes(_ context.Context) (map[string]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.attrs == nil {
		return nil, nil
	}
	out := make(map[string]string, len(c.attrs))
	for k, v := range c.attrs {
		out[k] = v
	}
	return out, nil
}

func (c *mutableFragmentAttrCollector) CollectFragments(_ context.Context) []*commonpb.Fragment {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*commonpb.Fragment, len(c.fragments))
	copy(out, c.fragments)
	return out
}

func (c *mutableFragmentAttrCollector) setFragments(frags []*commonpb.Fragment) {
	c.mu.Lock()
	c.fragments = frags
	c.mu.Unlock()
}

var _ DNACollector = (*mutableFragmentAttrCollector)(nil)

// TestPublishCurrentDNA_EmptyAttrsButFragments_SetsFragmentState covers the
// fragment-only branch of PublishCurrentDNA (Issue #3332): a hardware-facts-only
// steward has an empty attribute map, so there is nothing to publish, but its
// host:* fragments must still populate currentDNAFragments /
// currentDNAAggregateRoot instead of the call returning early with no effect.
func TestPublishCurrentDNA_EmptyAttrsButFragments_SetsFragmentState(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	frags, expectedRoot := makeClientFragments(t, 3)
	collector := &mutableFragmentAttrCollector{attrs: nil, fragments: frags}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	require.NoError(t, c.PublishCurrentDNA(context.Background()))

	c.dnaMu.RLock()
	gotFrags := c.currentDNAFragments
	gotRoot := c.currentDNAAggregateRoot
	gotHash := c.currentDNAHash
	c.dnaMu.RUnlock()

	require.Len(t, gotFrags, len(frags),
		"PublishCurrentDNA must store fragments when attrs is empty")
	assert.Equal(t, expectedRoot, gotRoot,
		"PublishCurrentDNA must set currentDNAAggregateRoot from the collected fragments")
	assert.Empty(t, gotHash,
		"no attributes were collected, so no attribute hash may be recorded")
	assert.Equal(t, 0, q.Len(),
		"a fragment-only collect has nothing attribute-based to publish")
}

// TestPublishCurrentDNA_AttrsAndFragments_PublishesAndSetsFragmentState covers
// the both-present case: a steward with managed resources has a non-empty
// attribute map AND host:* fragments. The attribute delta must be published and
// the partial-sync fragment state must be updated in the same call — publishing
// must not leave currentDNAFragments stale.
func TestPublishCurrentDNA_AttrsAndFragments_PublishesAndSetsFragmentState(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	frags, expectedRoot := makeClientFragments(t, 2)
	collector := &mutableFragmentAttrCollector{
		attrs:     map[string]string{"hostname": "host-a", "os": "linux"},
		fragments: frags,
	}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	require.NoError(t, c.PublishCurrentDNA(context.Background()))

	c.dnaMu.RLock()
	gotFrags := c.currentDNAFragments
	gotRoot := c.currentDNAAggregateRoot
	gotHash := c.currentDNAHash
	c.dnaMu.RUnlock()

	require.Len(t, gotFrags, len(frags),
		"PublishCurrentDNA must store fragments when attrs is also present")
	assert.Equal(t, expectedRoot, gotRoot,
		"PublishCurrentDNA must set currentDNAAggregateRoot when attrs is also present")
	assert.NotEmpty(t, gotHash, "the attribute snapshot hash must be refreshed")
	assert.Equal(t, 1, q.Len(), "the attribute delta must still be published")
}

// TestDNARefreshLoop_EmptyAttrsButFragments_UpdatesFragmentState covers the
// fragment branch of runDNARefreshTick for a hardware-facts-only steward
// (Issue #3332): attrs is empty, so nothing is published, but each tick must
// still update currentDNAFragments / currentDNAAggregateRoot.
func TestDNARefreshLoop_EmptyAttrsButFragments_UpdatesFragmentState(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	frags, expectedRoot := makeClientFragments(t, 2)
	collector := &mutableFragmentAttrCollector{attrs: nil, fragments: frags}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := c.StartDNARefreshLoop(ctx)
	<-c.dnaRefreshTick // one fully-processed tick
	cancel()
	<-done // the loop goroutine has exited before state is inspected

	c.dnaMu.RLock()
	gotFrags := c.currentDNAFragments
	gotRoot := c.currentDNAAggregateRoot
	c.dnaMu.RUnlock()

	require.Len(t, gotFrags, len(frags),
		"a refresh tick must store fragments even when the attribute map is empty")
	assert.Equal(t, expectedRoot, gotRoot,
		"a refresh tick must set currentDNAAggregateRoot from the collected fragments")
	assert.Equal(t, 0, q.Len(),
		"an attribute-less tick has nothing to publish")
}

// TestDNARefreshLoop_AttrsAndFragments_UpdatesFragmentStatePerTick covers the
// both-present case in runDNARefreshTick: the attribute snapshot is refreshed
// AND the fragment state is updated, and a later tick picks up a changed
// fragment set (proving the fragment branch runs on every tick, not once).
func TestDNARefreshLoop_AttrsAndFragments_UpdatesFragmentStatePerTick(t *testing.T) {
	c, q := newClientWithOfflineQueue(t)

	// Seed lastPublishedFragments with the first fragment set so that tick 1
	// produces an empty fragment delta and no event. The primary assertions are
	// about DNA state (currentDNAAggregateRoot, currentDNAFragments), not about
	// the publish path. Tick 2 onwards will see the swapped secondFrags and fire
	// exactly one event (two new fragment IDs). (Issue #3330: fragment delta drives publish)
	attrs := map[string]string{"hostname": "host-a", "os": "linux"}
	firstFrags, firstRoot := makeClientFragments(t, 2)

	c.dnaMu.Lock()
	c.lastPublishedFragments = firstFrags
	c.dnaMu.Unlock()

	collector := &mutableFragmentAttrCollector{attrs: attrs, fragments: firstFrags}
	c.mu.Lock()
	c.dnaCollector = collector
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := c.StartDNARefreshLoop(ctx)

	<-c.dnaRefreshTick
	c.dnaMu.RLock()
	gotHash := c.currentDNAHash
	gotRoot := c.currentDNAAggregateRoot
	gotFrags := len(c.currentDNAFragments)
	c.dnaMu.RUnlock()

	assert.NotEmpty(t, gotHash, "the attribute branch must refresh the snapshot hash")
	assert.Equal(t, firstRoot, gotRoot, "the fragment branch must run alongside the attribute branch")
	assert.Equal(t, len(firstFrags), gotFrags, "all collected fragments must be stored")

	// Swap the fragment set; a subsequent tick must pick it up. Ticks are
	// counted rather than slept on: the collector swap can land after the next
	// tick has already read the collector, so up to two further ticks are
	// drained before the assertion.
	secondFrags, secondRoot := makeClientFragments(t, 4)
	collector.setFragments(secondFrags)

	var latestRoot string
	for i := 0; i < 3; i++ {
		<-c.dnaRefreshTick
		c.dnaMu.RLock()
		latestRoot = c.currentDNAAggregateRoot
		c.dnaMu.RUnlock()
		if latestRoot == secondRoot {
			break
		}
	}
	cancel()
	<-done

	assert.Equal(t, secondRoot, latestRoot,
		"each refresh tick must re-record the fragment state, not only the first")
	// Fragment delta drives the publish decision (Issue #3330): swapping from
	// firstFrags (2 entries) to secondFrags (4 entries) adds 2 new fragment IDs,
	// producing a non-empty delta and exactly one event on the first tick that
	// observes the new set.
	assert.Equal(t, 1, q.Len(),
		"a changed fragment set must publish exactly one delta event")
}
