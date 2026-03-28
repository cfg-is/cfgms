// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client_test exercises the DNA-sync logic in TransportClient.
//
// These tests cover the pure, non-networked functions (delta computation,
// hash tracking) and the Heartbeat DNAHash field contract.
package client

import (
	"context"
	"fmt"
	"testing"
	"time"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func (s *testDataPlaneSession) ID() string         { return "test-session" }
func (s *testDataPlaneSession) PeerID() string      { return "controller-1" }
func (s *testDataPlaneSession) IsClosed() bool      { return false }
func (s *testDataPlaneSession) LocalAddr() string   { return "127.0.0.1:0" }
func (s *testDataPlaneSession) RemoteAddr() string  { return "127.0.0.1:1" }
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
func (s *testDataPlaneSession) OpenStream(_ context.Context, _ dpTypes.StreamType) (dataplaneInterfaces.Stream, error) {
	return nil, fmt.Errorf("testDataPlaneSession: OpenStream not implemented")
}
func (s *testDataPlaneSession) AcceptStream(_ context.Context) (dataplaneInterfaces.Stream, dpTypes.StreamType, error) {
	return nil, "", fmt.Errorf("testDataPlaneSession: AcceptStream not implemented")
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
	// controlPlane is nil — not connected
	err := c.PublishDNAUpdate(context.TODO(), map[string]string{"k": "v"}, "", "")
	if err == nil {
		t.Fatal("expected error when control plane is not connected")
	}
	if err.Error() != "control plane not connected" {
		t.Fatalf("unexpected error message: %q", err.Error())
	}
}

func TestPublishDNAUpdate_NoDeltaSkipsPublish(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-1"
	c.tenantID = "tenant-1"
	// Seed state so delta is empty on second call.
	c.dnaMu.Lock()
	c.lastPublishedDNA = map[string]string{"k": "v"}
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

	cmd := &cpTypes.Command{
		ID:        "cmd-sync-dna-1",
		Type:      cpTypes.CommandSyncDNA,
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}
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
