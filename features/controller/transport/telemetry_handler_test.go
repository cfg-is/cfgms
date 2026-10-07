// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// Test double for grpc.BidiStreamingServer[TelemetrySnapshot, TelemetryRequest]
// ---------------------------------------------------------------------------

// testTelemetryStream is a test double for the bidi stream from a steward.
// recvCh supplies snapshot frames; closing it signals EOF.
// Sent TelemetryRequests are captured in sent for assertion.
// sendNotify is signalled (non-blocking) on each Send call so tests can wait
// for the send goroutine instead of sleeping.
type testTelemetryStream struct {
	ctx    context.Context
	recvCh chan *transportpb.TelemetrySnapshot // close to signal EOF

	mu         sync.Mutex
	sent       []*transportpb.TelemetryRequest
	sendErr    error
	sendNotify chan struct{} // buffered; signalled on each Send
}

func newTestTelemetryStream(ctx context.Context) *testTelemetryStream {
	return &testTelemetryStream{
		ctx:        ctx,
		recvCh:     make(chan *transportpb.TelemetrySnapshot, 16),
		sendNotify: make(chan struct{}, 32),
	}
}

func (s *testTelemetryStream) Recv() (*transportpb.TelemetrySnapshot, error) {
	select {
	case snap, ok := <-s.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return snap, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *testTelemetryStream) Send(req *transportpb.TelemetryRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, req)
	select {
	case s.sendNotify <- struct{}{}:
	default:
	}
	return nil
}

func (s *testTelemetryStream) getSent() []*transportpb.TelemetryRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*transportpb.TelemetryRequest, len(s.sent))
	copy(out, s.sent)
	return out
}

func (s *testTelemetryStream) SetHeader(metadata.MD) error  { return nil }
func (s *testTelemetryStream) SendHeader(metadata.MD) error { return nil }
func (s *testTelemetryStream) SetTrailer(metadata.MD)       {}
func (s *testTelemetryStream) Context() context.Context     { return s.ctx }
func (s *testTelemetryStream) SendMsg(interface{}) error    { return nil }
func (s *testTelemetryStream) RecvMsg(interface{}) error    { return nil }

// Compile-time interface check.
var _ interface {
	Recv() (*transportpb.TelemetrySnapshot, error)
	Send(*transportpb.TelemetryRequest) error
	Context() context.Context
} = (*testTelemetryStream)(nil)

// ---------------------------------------------------------------------------
// Helper: run HandleGRPC in a goroutine and wait for it to register.
// ---------------------------------------------------------------------------

// startHandleGRPC starts HandleGRPC in a background goroutine and returns a
// function that waits for it to finish.
// It waits until activateStream has run (via onActivate hook) before returning
// so tests can safely subscribe browser clients.
func startHandleGRPC(t *testing.T, h *TelemetryHandler, stream *testTelemetryStream) (wait func() error) {
	t.Helper()
	activated := make(chan struct{})
	h.onActivate = func() { close(activated) }

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.HandleGRPC(stream)
	}()

	select {
	case <-activated:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleGRPC did not activate within deadline")
	}
	return func() error {
		select {
		case err := <-errCh:
			return err
		case <-time.After(3 * time.Second):
			t.Fatal("HandleGRPC did not return within deadline")
			return nil
		}
	}
}

// awaitSend waits for stream.sendNotify to signal that at least one Send call
// completed, or fails the test if the deadline expires.
func awaitSend(t *testing.T, stream *testTelemetryStream) {
	t.Helper()
	select {
	case <-stream.sendNotify:
	case <-time.After(2 * time.Second):
		t.Fatal("expected stream.Send to be called within deadline")
	}
}

// ---------------------------------------------------------------------------
// AC1: Exactly one upstream subscribe on the first browser subscriber;
//
//	no additional subscribe when a second browser subscribes.
//
// ---------------------------------------------------------------------------

// TestTelemetryHandler_FirstBrowserSubscriberTriggersExactlyOneSubscribe verifies
// that the controller sends exactly one TelemetryRequest{Subscribe: true} upstream
// when the first browser subscriber attaches, and no second subscribe when more
// browser clients join (reference-count correctness).
func TestTelemetryHandler_FirstBrowserSubscriberTriggersExactlyOneSubscribe(t *testing.T) {
	const stewardID = "steward-sub-test"
	ca := newTestCA(t)
	peerCtx := peerContextWithCA(t, ca, stewardID)
	peerCtx, peerCancel := context.WithTimeout(peerCtx, 5*time.Second)
	defer peerCancel()

	stream := newTestTelemetryStream(peerCtx)
	h := NewTelemetryHandler(logging.NewNoopLogger(), nil)

	waitDone := startHandleGRPC(t, h, stream)

	// First browser subscribes → must trigger exactly one upstream subscribe.
	sub1, ch1, _ := h.addSubscriber(stewardID)
	require.NotNil(t, ch1)

	// Wait for the send goroutine to deliver the subscribe request.
	awaitSend(t, stream)

	sent := stream.getSent()
	subscribeCount := countSubscribes(sent, true)
	assert.Equal(t, 1, subscribeCount, "first browser subscribe must trigger exactly one upstream subscribe")

	// Second browser subscribes → no additional upstream subscribe.
	_, ch2, _ := h.addSubscriber(stewardID)
	require.NotNil(t, ch2)

	// Allow a short window for any spurious send (none expected).
	select {
	case <-stream.sendNotify:
	case <-time.After(30 * time.Millisecond):
	}

	sent = stream.getSent()
	subscribeCount = countSubscribes(sent, true)
	assert.Equal(t, 1, subscribeCount, "second browser subscribe must NOT trigger a second upstream subscribe")

	// Clean up subscriber channels.
	_, _, _ = h.removeSubscriber(stewardID, sub1)
	close(stream.recvCh)
	assert.NoError(t, waitDone())
}

// ---------------------------------------------------------------------------
// AC2: Exactly one upstream unsubscribe when the last browser subscriber disconnects.
// ---------------------------------------------------------------------------

// TestTelemetryHandler_LastBrowserUnsubscribeTriggersExactlyOneUnsubscribe verifies
// that the controller sends exactly one TelemetryRequest{Subscribe: false} upstream
// when the last browser subscriber disconnects, and none when non-last subscribers leave.
func TestTelemetryHandler_LastBrowserUnsubscribeTriggersExactlyOneUnsubscribe(t *testing.T) {
	const stewardID = "steward-unsub-test"
	ca := newTestCA(t)
	peerCtx := peerContextWithCA(t, ca, stewardID)
	peerCtx, peerCancel := context.WithTimeout(peerCtx, 5*time.Second)
	defer peerCancel()

	stream := newTestTelemetryStream(peerCtx)
	h := NewTelemetryHandler(logging.NewNoopLogger(), nil)

	waitDone := startHandleGRPC(t, h, stream)

	// Add two browser subscribers.
	id1, ch1, _ := h.addSubscriber(stewardID)
	id2, ch2, _ := h.addSubscriber(stewardID)
	require.NotNil(t, ch1)
	require.NotNil(t, ch2)

	// Wait for the subscribe request from the first addSubscriber to be sent.
	awaitSend(t, stream)

	// Remove first subscriber (non-last) → no unsubscribe.
	isLast, sc, sd := h.removeSubscriber(stewardID, id1)
	assert.False(t, isLast, "removing first of two subscribers must not be the last")

	// Replicate the WS handler's defer logic: if isLast, send unsubscribe.
	if isLast && sc != nil {
		select {
		case sc <- &transportpb.TelemetryRequest{StewardId: stewardID, Subscribe: false}:
		case <-sd:
		default:
		}
	}

	// Allow a short window for any spurious send (none expected).
	select {
	case <-stream.sendNotify:
	case <-time.After(30 * time.Millisecond):
	}

	sent := stream.getSent()
	unsubCount := countSubscribes(sent, false)
	assert.Equal(t, 0, unsubCount, "removing non-last subscriber must NOT send unsubscribe")

	// Remove second subscriber (last) → must trigger exactly one upstream unsubscribe.
	isLast, sc, sd = h.removeSubscriber(stewardID, id2)
	assert.True(t, isLast, "removing second of two subscribers must be last")
	if isLast && sc != nil {
		select {
		case sc <- &transportpb.TelemetryRequest{StewardId: stewardID, Subscribe: false}:
		case <-sd:
		default:
		}
	}

	// Wait for the unsubscribe request to be delivered.
	awaitSend(t, stream)

	sent = stream.getSent()
	unsubCount = countSubscribes(sent, false)
	assert.Equal(t, 1, unsubCount, "removing last subscriber must send exactly one upstream unsubscribe")

	close(stream.recvCh)
	assert.NoError(t, waitDone())
}

// ---------------------------------------------------------------------------
// AC3: Steward mid-stream disconnect is surfaced to all browser subscribers.
// ---------------------------------------------------------------------------

// TestTelemetryHandler_StewardDisconnectSurfacedToAllBrowserSubscribers verifies
// that when the steward's gRPC stream ends (EOF), all browser subscriber channels
// receive a nil-snapshot disconnect signal within a reasonable deadline.
func TestTelemetryHandler_StewardDisconnectSurfacedToAllBrowserSubscribers(t *testing.T) {
	const stewardID = "steward-disconnect-test"
	ca := newTestCA(t)
	peerCtx := peerContextWithCA(t, ca, stewardID)
	peerCtx, peerCancel := context.WithTimeout(peerCtx, 5*time.Second)
	defer peerCancel()

	stream := newTestTelemetryStream(peerCtx)
	h := NewTelemetryHandler(logging.NewNoopLogger(), nil)

	waitDone := startHandleGRPC(t, h, stream)

	// Two browser subscribers.
	_, ch1, _ := h.addSubscriber(stewardID)
	_, ch2, _ := h.addSubscriber(stewardID)
	require.NotNil(t, ch1)
	require.NotNil(t, ch2)

	// Wait for the subscribe to be delivered before triggering disconnect.
	awaitSend(t, stream)

	// Trigger steward disconnect by closing the recv channel (→ EOF in Recv()).
	close(stream.recvCh)

	// Both browser channels must receive a disconnect message (nil snap).
	assertDisconnect := func(t *testing.T, ch chan snapshotOrDisconnect, label string) {
		t.Helper()
		select {
		case msg := <-ch:
			assert.Nil(t, msg.snap, "%s: disconnect message must have nil snapshot", label)
		case <-time.After(2 * time.Second):
			t.Errorf("%s: did not receive disconnect within deadline", label)
		}
	}

	assertDisconnect(t, ch1, "subscriber-1")
	assertDisconnect(t, ch2, "subscriber-2")

	assert.NoError(t, waitDone())
}

// ---------------------------------------------------------------------------
// AC4: Multiple browser subscribers all receive the same snapshot.
// ---------------------------------------------------------------------------

// TestTelemetryHandler_SnapshotFanOutToAllSubscribers verifies that a TelemetrySnapshot
// sent by the steward is delivered to every active browser subscriber.
func TestTelemetryHandler_SnapshotFanOutToAllSubscribers(t *testing.T) {
	const stewardID = "steward-fanout-test"
	ca := newTestCA(t)
	peerCtx := peerContextWithCA(t, ca, stewardID)
	peerCtx, peerCancel := context.WithTimeout(peerCtx, 5*time.Second)
	defer peerCancel()

	stream := newTestTelemetryStream(peerCtx)
	h := NewTelemetryHandler(logging.NewNoopLogger(), nil)

	waitDone := startHandleGRPC(t, h, stream)

	_, ch1, _ := h.addSubscriber(stewardID)
	_, ch2, _ := h.addSubscriber(stewardID)
	_, ch3, _ := h.addSubscriber(stewardID)

	// Wait for the subscribe to be delivered before sending the snapshot.
	awaitSend(t, stream)

	// Send a snapshot from the steward side.
	snap := &transportpb.TelemetrySnapshot{
		StewardId: stewardID,
		Timestamp: timestamppb.Now(),
		Processes: []*transportpb.ProcessSnapshot{
			{Name: "nginx", Pid: 1234, CpuPercent: 2.5},
		},
	}
	stream.recvCh <- snap

	// All three subscribers must receive the snapshot.
	deadline := 2 * time.Second
	for i, ch := range []chan snapshotOrDisconnect{ch1, ch2, ch3} {
		select {
		case msg := <-ch:
			require.NotNil(t, msg.snap, "subscriber %d: expected snapshot, got nil (disconnect)", i+1)
			assert.Equal(t, stewardID, msg.snap.GetStewardId())
			assert.Len(t, msg.snap.GetProcesses(), 1)
		case <-time.After(deadline):
			t.Errorf("subscriber %d: did not receive snapshot within %v", i+1, deadline)
		}
	}

	close(stream.recvCh)
	assert.NoError(t, waitDone())
}

// ---------------------------------------------------------------------------
// AC5: No upstream subscribe sent when no gRPC stream is active.
// ---------------------------------------------------------------------------

// TestTelemetryHandler_BrowserSubscribeWithNoActiveStream verifies that adding a
// browser subscriber when no steward gRPC stream is active does not panic and
// does not attempt to write to a nil channel.
func TestTelemetryHandler_BrowserSubscribeWithNoActiveStream(t *testing.T) {
	h := NewTelemetryHandler(logging.NewNoopLogger(), nil)

	// No HandleGRPC call yet — addSubscriber must not panic.
	id, ch, _ := h.addSubscriber("steward-no-stream")
	require.NotNil(t, ch)

	// removeSubscriber must not panic either.
	isLast, sendCh, _ := h.removeSubscriber("steward-no-stream", id)
	assert.True(t, isLast)
	assert.Nil(t, sendCh, "no sendCh when stream is inactive")
}

// ---------------------------------------------------------------------------
// AC6: HandleGRPC returns nil on clean EOF.
// ---------------------------------------------------------------------------

// TestTelemetryHandler_HandleGRPC_CleanEOF verifies that HandleGRPC returns nil
// (not an error) when the steward closes the stream cleanly (EOF).
func TestTelemetryHandler_HandleGRPC_CleanEOF(t *testing.T) {
	const stewardID = "steward-eof-test"
	ca := newTestCA(t)
	peerCtx := peerContextWithCA(t, ca, stewardID)

	stream := newTestTelemetryStream(peerCtx)
	close(stream.recvCh) // immediate EOF

	h := NewTelemetryHandler(logging.NewNoopLogger(), nil)
	err := h.HandleGRPC(stream)
	assert.NoError(t, err, "clean EOF must return nil")
}

// ---------------------------------------------------------------------------
// AC7: HandleGRPC rejects unauthenticated callers (no peer / no mTLS cert).
// ---------------------------------------------------------------------------

// TestTelemetryHandler_HandleGRPC_UnauthenticatedReturnsError verifies that
// HandleGRPC returns Unauthenticated when the stream context has no mTLS peer.
func TestTelemetryHandler_HandleGRPC_UnauthenticatedReturnsError(t *testing.T) {
	stream := newTestTelemetryStream(context.Background()) // no peer info
	h := NewTelemetryHandler(logging.NewNoopLogger(), nil)
	err := h.HandleGRPC(stream)
	require.Error(t, err, "unauthenticated caller must return an error")
}

// ---------------------------------------------------------------------------
// Unit tests for originAllowed
// ---------------------------------------------------------------------------

func TestOriginAllowed(t *testing.T) {
	h := NewTelemetryHandler(logging.NewNoopLogger(), []string{"allowed-host.example.com"})

	cases := []struct {
		name        string
		origin      string
		host        string
		allowedList []string
		want        bool
	}{
		{
			name:   "same-origin",
			origin: "https://app.example.com",
			host:   "app.example.com",
			want:   true,
		},
		{
			name:   "same-origin-case-insensitive",
			origin: "https://APP.EXAMPLE.COM",
			host:   "app.example.com",
			want:   true,
		},
		{
			name:   "in-allowed-list",
			origin: "https://allowed-host.example.com",
			host:   "other.example.com",
			want:   true,
		},
		{
			name:   "empty-origin-rejected",
			origin: "",
			host:   "app.example.com",
			want:   false,
		},
		{
			name:   "unparseable-origin-rejected",
			origin: "://bad-url",
			host:   "app.example.com",
			want:   false,
		},
		{
			name:   "different-host-not-in-list",
			origin: "https://evil.attacker.com",
			host:   "app.example.com",
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ws", nil)
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			assert.Equal(t, tc.want, h.originAllowed(req))
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests for marshalSnapshot
// ---------------------------------------------------------------------------

func TestMarshalSnapshot(t *testing.T) {
	t.Run("full-snapshot", func(t *testing.T) {
		snap := &transportpb.TelemetrySnapshot{
			StewardId: "steward-1",
			Timestamp: timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			Processes: []*transportpb.ProcessSnapshot{
				{
					FragmentId:     "frag-1",
					Pid:            42,
					Name:           "nginx",
					CpuPercent:     1.5,
					MemoryBytes:    1024,
					DiskReadBytes:  200,
					DiskWriteBytes: 300,
					NetRxBytes:     400,
					NetTxBytes:     500,
				},
			},
			Services: []*transportpb.ServiceSnapshot{
				{FragmentId: "frag-2", Name: "nginx", State: "running"},
			},
		}

		data, err := marshalSnapshot(snap)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))
		assert.Equal(t, "snapshot", out["type"])
		assert.Equal(t, "steward-1", out["steward_id"])
		assert.Equal(t, "2026-01-01T00:00:00Z", out["timestamp"])
	})

	t.Run("nil-timestamp-omitted", func(t *testing.T) {
		snap := &transportpb.TelemetrySnapshot{
			StewardId: "steward-2",
			Processes: nil,
			Services:  nil,
		}
		data, err := marshalSnapshot(snap)
		require.NoError(t, err)
		assert.NotContains(t, string(data), `"timestamp"`)
	})

	t.Run("empty-processes-and-services", func(t *testing.T) {
		snap := &transportpb.TelemetrySnapshot{StewardId: "s"}
		data, err := marshalSnapshot(snap)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"processes":[]`)
		assert.Contains(t, string(data), `"services":[]`)
	})
}

// ---------------------------------------------------------------------------
// ServeWebSocket basic path tests
// ---------------------------------------------------------------------------

// TestServeWebSocket_MissingIDReturns400 verifies that ServeWebSocket returns
// 400 when the {id} path variable is absent (no gorilla/mux context).
func TestServeWebSocket_MissingIDReturns400(t *testing.T) {
	h := NewTelemetryHandler(logging.NewNoopLogger(), nil)
	req := httptest.NewRequest("GET", "/telemetry/ws/", nil)
	rec := httptest.NewRecorder()
	h.ServeWebSocket(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestServeWebSocket_RejectedOriginReturns403 verifies that an Origin not matching
// the server's host or allowed list causes the WebSocket upgrade to fail with 403.
func TestServeWebSocket_RejectedOriginReturns403(t *testing.T) {
	h := NewTelemetryHandler(logging.NewNoopLogger(), nil)

	req := httptest.NewRequest("GET", "/telemetry/ws/steward-1", nil)
	req.Host = "app.example.com"
	req.Header.Set("Origin", "https://evil.attacker.com")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-Websocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-Websocket-Version", "13")
	// Inject the {id} path variable as gorilla/mux would.
	req = mux.SetURLVars(req, map[string]string{"id": "steward-1"})

	rec := httptest.NewRecorder()
	h.ServeWebSocket(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"mismatched Origin must cause Upgrader to reject with 403")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// countSubscribes returns the count of TelemetryRequest frames with Subscribe == wantSub.
func countSubscribes(reqs []*transportpb.TelemetryRequest, wantSub bool) int {
	n := 0
	for _, r := range reqs {
		if r.GetSubscribe() == wantSub {
			n++
		}
	}
	return n
}
