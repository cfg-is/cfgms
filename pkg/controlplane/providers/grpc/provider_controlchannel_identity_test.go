// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMultiStewardEnv sets up a server and two clients connected with different CNs.
// clientA uses stewardID "steward-a"; clientB uses stewardID "steward-b".
type multiStewardEnv struct {
	server   *Provider
	clientA  *Provider
	clientB  *Provider
	registry registry.Registry
}

func newMultiStewardEnv(t *testing.T) *multiStewardEnv {
	t.Helper()

	tc := newTestCA(t)
	reg := registry.NewRegistry()

	server := New(ModeServer)
	err := server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	})
	require.NoError(t, err)
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(func() { forceStopServer(server) })

	listenAddr := server.listener.Addr().String()

	clientA := New(ModeClient)
	err = clientA.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": tc.clientTLSConfig(t, "steward-a"),
		"steward_id": "steward-a",
	})
	require.NoError(t, err)
	require.NoError(t, clientA.Start(context.Background()))
	t.Cleanup(func() { _ = clientA.Stop(context.Background()) })

	clientB := New(ModeClient)
	err = clientB.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": tc.clientTLSConfig(t, "steward-b"),
		"steward_id": "steward-b",
	})
	require.NoError(t, err)
	require.NoError(t, clientB.Start(context.Background()))
	t.Cleanup(func() { _ = clientB.Stop(context.Background()) })

	// Wait for both stewards to be registered
	require.Eventually(t, func() bool {
		return reg.Count() == 2
	}, 5*time.Second, 10*time.Millisecond, "both stewards should register")

	return &multiStewardEnv{
		server:   server,
		clientA:  clientA,
		clientB:  clientB,
		registry: reg,
	}
}

// TestControlChannel_Event_MatchingStewardID verifies that an Event with a
// payload StewardID matching the authenticated CN is dispatched normally and
// does not increment IdentityMismatches.
func TestControlChannel_Event_MatchingStewardID(t *testing.T) {
	env := newMultiStewardEnv(t)

	received := make(chan *types.Event, 1)
	require.NoError(t, env.server.SubscribeEvents(context.Background(), nil, func(_ context.Context, e *types.Event) error {
		received <- e
		return nil
	}))

	event := &types.Event{
		ID:        "evt-match",
		Type:      types.EventConfigApplied,
		StewardID: "steward-a",
		Timestamp: time.Now().Truncate(time.Microsecond),
		Severity:  "info",
	}
	require.NoError(t, env.clientA.PublishEvent(context.Background(), event))

	select {
	case got := <-received:
		assert.Equal(t, "evt-match", got.ID)
		assert.Equal(t, "steward-a", got.StewardID)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for matching event")
	}

	stats, err := env.server.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.IdentityMismatches)
}

// TestControlChannel_Event_EmptyStewardIDGetsCNStamped verifies that an Event
// with an empty payload StewardID is stamped with the authenticated CN before
// dispatch, and IdentityMismatches is not incremented.
func TestControlChannel_Event_EmptyStewardIDGetsCNStamped(t *testing.T) {
	env := newMultiStewardEnv(t)

	received := make(chan *types.Event, 1)
	require.NoError(t, env.server.SubscribeEvents(context.Background(), nil, func(_ context.Context, e *types.Event) error {
		received <- e
		return nil
	}))

	event := &types.Event{
		ID:        "evt-empty-id",
		Type:      types.EventConfigApplied,
		StewardID: "", // empty — should be stamped with CN
		Timestamp: time.Now().Truncate(time.Microsecond),
		Severity:  "info",
	}
	require.NoError(t, env.clientA.PublishEvent(context.Background(), event))

	select {
	case got := <-received:
		assert.Equal(t, "evt-empty-id", got.ID)
		assert.Equal(t, "steward-a", got.StewardID, "empty StewardID should be stamped with CN")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for stamped event")
	}

	stats, err := env.server.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.IdentityMismatches)
}

// TestControlChannel_Event_MismatchedStewardID verifies that an Event whose
// payload StewardID disagrees with the authenticated CN is rejected (not
// dispatched) and increments IdentityMismatches.
func TestControlChannel_Event_MismatchedStewardID(t *testing.T) {
	env := newMultiStewardEnv(t)

	dispatched := make(chan *types.Event, 5)
	require.NoError(t, env.server.SubscribeEvents(context.Background(), nil, func(_ context.Context, e *types.Event) error {
		dispatched <- e
		return nil
	}))

	// clientA (CN=steward-a) sends event claiming to be steward-b
	mismatch := &types.Event{
		ID:        "evt-mismatch",
		Type:      types.EventConfigApplied,
		StewardID: "steward-b",
		Timestamp: time.Now().Truncate(time.Microsecond),
		Severity:  "info",
	}
	require.NoError(t, env.clientA.PublishEvent(context.Background(), mismatch))

	// Mismatched event must not be dispatched
	require.Never(t, func() bool {
		return len(dispatched) > 0
	}, 300*time.Millisecond, 20*time.Millisecond, "mismatched event should not be dispatched")

	// IdentityMismatches must be 1
	require.Eventually(t, func() bool {
		stats, err := env.server.GetStats(context.Background())
		return err == nil && stats.IdentityMismatches == 1
	}, 3*time.Second, 50*time.Millisecond, "IdentityMismatches should be 1")
}

// TestControlChannel_Heartbeat_MatchingStewardID verifies that a Heartbeat with
// a matching payload StewardID is dispatched and does not increment mismatches.
func TestControlChannel_Heartbeat_MatchingStewardID(t *testing.T) {
	env := newMultiStewardEnv(t)

	received := make(chan *types.Heartbeat, 1)
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		received <- hb
		return nil
	}))

	hb := &types.Heartbeat{
		StewardID: "steward-a",
		Status:    types.StatusHealthy,
		Timestamp: time.Now().Truncate(time.Microsecond),
		Version:   "1.0.0",
	}
	require.NoError(t, env.clientA.SendHeartbeat(context.Background(), hb))

	select {
	case got := <-received:
		assert.Equal(t, "steward-a", got.StewardID)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for heartbeat")
	}

	stats, err := env.server.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.IdentityMismatches)
}

// TestControlChannel_Heartbeat_EmptyStewardIDGetsCNStamped verifies that a
// Heartbeat with an empty payload StewardID is stamped with the authenticated CN.
func TestControlChannel_Heartbeat_EmptyStewardIDGetsCNStamped(t *testing.T) {
	env := newMultiStewardEnv(t)

	received := make(chan *types.Heartbeat, 1)
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		received <- hb
		return nil
	}))

	hb := &types.Heartbeat{
		StewardID: "", // empty — should be stamped
		Status:    types.StatusHealthy,
		Timestamp: time.Now().Truncate(time.Microsecond),
		Version:   "1.0.0",
	}
	require.NoError(t, env.clientA.SendHeartbeat(context.Background(), hb))

	select {
	case got := <-received:
		assert.Equal(t, "steward-a", got.StewardID, "empty StewardID should be stamped with CN")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for stamped heartbeat")
	}

	stats, err := env.server.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.IdentityMismatches)
}

// TestControlChannel_Heartbeat_MismatchedStewardID verifies that a Heartbeat
// whose payload StewardID disagrees with the CN is rejected and counted.
func TestControlChannel_Heartbeat_MismatchedStewardID(t *testing.T) {
	env := newMultiStewardEnv(t)

	dispatched := make(chan *types.Heartbeat, 5)
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		dispatched <- hb
		return nil
	}))

	hb := &types.Heartbeat{
		StewardID: "steward-b", // CN is steward-a — mismatch
		Status:    types.StatusHealthy,
		Timestamp: time.Now().Truncate(time.Microsecond),
		Version:   "1.0.0",
	}
	require.NoError(t, env.clientA.SendHeartbeat(context.Background(), hb))

	require.Never(t, func() bool {
		return len(dispatched) > 0
	}, 300*time.Millisecond, 20*time.Millisecond, "mismatched heartbeat should not be dispatched")

	require.Eventually(t, func() bool {
		stats, err := env.server.GetStats(context.Background())
		return err == nil && stats.IdentityMismatches == 1
	}, 3*time.Second, 50*time.Millisecond, "IdentityMismatches should be 1")
}

// TestControlChannel_Response_MatchingStewardID verifies that a Response with a
// matching payload StewardID is dispatched normally.
func TestControlChannel_Response_MatchingStewardID(t *testing.T) {
	env := newMultiStewardEnv(t)

	// Subscribe to commands and reply so SendResponse is triggered via the
	// happy path. We validate via WaitForResponse that the response arrived.
	cmdID := "resp-match-cmd"
	require.NoError(t, env.clientA.SubscribeCommands(context.Background(), "steward-a", func(ctx context.Context, cmd *types.Command) error {
		return env.clientA.SendResponse(ctx, &types.Response{
			CommandID: cmd.ID,
			StewardID: "steward-a",
			Success:   true,
			Timestamp: time.Now(),
		})
	}))

	var respErr error
	gotResp := make(chan struct{})
	go func() {
		_, respErr = env.server.WaitForResponse(context.Background(), cmdID, 5*time.Second)
		close(gotResp)
	}()

	// Wait for the pending channel to register before sending
	require.Eventually(t, func() bool {
		env.server.responseMu.Lock()
		_, ok := env.server.pendingResponses[cmdID]
		env.server.responseMu.Unlock()
		return ok
	}, 5*time.Second, time.Millisecond)

	require.NoError(t, env.server.SendCommand(context.Background(), &types.Command{
		ID:        cmdID,
		Type:      types.CommandSyncConfig,
		StewardID: "steward-a",
		Timestamp: time.Now(),
	}))

	select {
	case <-gotResp:
		require.NoError(t, respErr)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for response")
	}

	stats, err := env.server.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.IdentityMismatches)
}

// TestControlChannel_Response_EmptyStewardIDGetsCNStamped verifies that a
// Response with an empty payload StewardID is stamped with the CN.
func TestControlChannel_Response_EmptyStewardIDGetsCNStamped(t *testing.T) {
	env := newMultiStewardEnv(t)

	cmdID := "resp-empty-cmd"
	require.NoError(t, env.clientA.SubscribeCommands(context.Background(), "steward-a", func(ctx context.Context, cmd *types.Command) error {
		return env.clientA.SendResponse(ctx, &types.Response{
			CommandID: cmd.ID,
			StewardID: "", // empty — should be stamped with CN
			Success:   true,
			Timestamp: time.Now(),
		})
	}))

	var gotResp *types.Response
	var respErr error
	done := make(chan struct{})
	go func() {
		gotResp, respErr = env.server.WaitForResponse(context.Background(), cmdID, 5*time.Second)
		close(done)
	}()

	require.Eventually(t, func() bool {
		env.server.responseMu.Lock()
		_, ok := env.server.pendingResponses[cmdID]
		env.server.responseMu.Unlock()
		return ok
	}, 5*time.Second, time.Millisecond)

	require.NoError(t, env.server.SendCommand(context.Background(), &types.Command{
		ID:        cmdID,
		Type:      types.CommandSyncConfig,
		StewardID: "steward-a",
		Timestamp: time.Now(),
	}))

	select {
	case <-done:
		require.NoError(t, respErr)
		assert.Equal(t, "steward-a", gotResp.StewardID, "empty StewardID should be stamped with CN")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for stamped response")
	}

	stats, err := env.server.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.IdentityMismatches)
}

// TestControlChannel_Response_MismatchedStewardID verifies that a Response whose
// payload StewardID disagrees with the CN is rejected and counted.
func TestControlChannel_Response_MismatchedStewardID(t *testing.T) {
	env := newMultiStewardEnv(t)

	cmdID := "resp-mismatch-cmd"
	require.NoError(t, env.clientA.SubscribeCommands(context.Background(), "steward-a", func(ctx context.Context, cmd *types.Command) error {
		return env.clientA.SendResponse(ctx, &types.Response{
			CommandID: cmd.ID,
			StewardID: "steward-b", // CN is steward-a — mismatch
			Success:   true,
			Timestamp: time.Now(),
		})
	}))

	var respErr error
	done := make(chan struct{})
	go func() {
		// Short timeout — response will never arrive because it's rejected
		_, respErr = env.server.WaitForResponse(context.Background(), cmdID, 500*time.Millisecond)
		close(done)
	}()

	require.Eventually(t, func() bool {
		env.server.responseMu.Lock()
		_, ok := env.server.pendingResponses[cmdID]
		env.server.responseMu.Unlock()
		return ok
	}, 5*time.Second, time.Millisecond)

	require.NoError(t, env.server.SendCommand(context.Background(), &types.Command{
		ID:        cmdID,
		Type:      types.CommandSyncConfig,
		StewardID: "steward-a",
		Timestamp: time.Now(),
	}))

	select {
	case <-done:
		// WaitForResponse must time out (response was rejected)
		require.Error(t, respErr, "WaitForResponse should time out when response is rejected")
	case <-time.After(5 * time.Second):
		t.Fatal("WaitForResponse goroutine did not return")
	}

	require.Eventually(t, func() bool {
		stats, err := env.server.GetStats(context.Background())
		return err == nil && stats.IdentityMismatches == 1
	}, 3*time.Second, 50*time.Millisecond, "IdentityMismatches should be 1")
}

// TestControlChannel_IdentityMismatches_MultipleRejections verifies that after
// N mismatches, GetStats returns IdentityMismatches == N (tested for N=1 and N=3).
func TestControlChannel_IdentityMismatches_MultipleRejections(t *testing.T) {
	env := newMultiStewardEnv(t)

	dispatched := make(chan *types.Event, 10)
	require.NoError(t, env.server.SubscribeEvents(context.Background(), nil, func(_ context.Context, e *types.Event) error {
		dispatched <- e
		return nil
	}))

	// Send 3 mismatched events from clientA claiming to be steward-b
	for i := 0; i < 3; i++ {
		require.NoError(t, env.clientA.PublishEvent(context.Background(), &types.Event{
			ID:        "evt-multi-mismatch",
			Type:      types.EventConfigApplied,
			StewardID: "steward-b",
			Timestamp: time.Now().Truncate(time.Microsecond),
			Severity:  "info",
		}))
	}

	// Wait for all 3 to be counted
	require.Eventually(t, func() bool {
		stats, err := env.server.GetStats(context.Background())
		return err == nil && stats.IdentityMismatches == 3
	}, 5*time.Second, 50*time.Millisecond, "IdentityMismatches should be 3")

	// No mismatched events should have been dispatched
	assert.Equal(t, 0, len(dispatched), "no mismatched events should be dispatched")

	// Confirm exact value
	stats, err := env.server.GetStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(3), stats.IdentityMismatches)
}

// TestControlChannel_StreamRemainsOpenAfterMismatch verifies that the stream is
// not torn down after a single mismatch — a subsequent valid message is dispatched.
func TestControlChannel_StreamRemainsOpenAfterMismatch(t *testing.T) {
	env := newMultiStewardEnv(t)

	dispatched := make(chan *types.Event, 5)
	require.NoError(t, env.server.SubscribeEvents(context.Background(), nil, func(_ context.Context, e *types.Event) error {
		dispatched <- e
		return nil
	}))

	// Send a mismatched event first
	require.NoError(t, env.clientA.PublishEvent(context.Background(), &types.Event{
		ID:        "evt-bad",
		Type:      types.EventConfigApplied,
		StewardID: "steward-b",
		Timestamp: time.Now().Truncate(time.Microsecond),
		Severity:  "warn",
	}))

	// Wait for the mismatch to be counted before sending the valid event
	require.Eventually(t, func() bool {
		stats, err := env.server.GetStats(context.Background())
		return err == nil && stats.IdentityMismatches == 1
	}, 3*time.Second, 20*time.Millisecond)

	// Now send a valid event — stream should still be alive
	require.NoError(t, env.clientA.PublishEvent(context.Background(), &types.Event{
		ID:        "evt-good",
		Type:      types.EventConfigApplied,
		StewardID: "steward-a",
		Timestamp: time.Now().Truncate(time.Microsecond),
		Severity:  "info",
	}))

	select {
	case got := <-dispatched:
		assert.Equal(t, "evt-good", got.ID, "valid event should be dispatched after mismatch")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out — stream should remain open after a single mismatch")
	}
}
