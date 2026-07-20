// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

const (
	// defaultTelemetryIntervalMs is the snapshot interval requested from the steward
	// on subscribe. The steward's minTelemetryIntervalMs floor (1 s) is authoritative.
	defaultTelemetryIntervalMs = 5000

	// wsWriteTimeout is the per-frame write deadline on browser WebSocket connections.
	wsWriteTimeout = 10 * time.Second

	// wsPingInterval is the heartbeat period for browser WebSocket connections.
	wsPingInterval = 54 * time.Second
)

// snapshotOrDisconnect is the message type delivered on each browser subscriber channel.
// A nil snap indicates the steward disconnected mid-stream.
type snapshotOrDisconnect struct {
	snap *transportpb.TelemetrySnapshot // nil when the steward disconnected
}

// stewardTelemetryState tracks the active gRPC stream and all browser subscriber
// channels for one steward. It is guarded by TelemetryHandler.mu.
type stewardTelemetryState struct {
	// sendCh carries TelemetryRequest frames to the HandleGRPC send goroutine.
	// Non-nil only while HandleGRPC is executing for this steward.
	sendCh chan *transportpb.TelemetryRequest
	// streamDone is closed by HandleGRPC when the gRPC stream exits. Browser goroutines
	// select on this to detect steward disconnect and avoid writing to a closed sendCh.
	streamDone chan struct{}
	// subs maps subscriber ID → delivery channel. Each browser WebSocket gets one entry.
	subs   map[int]chan snapshotOrDisconnect
	nextID int
}

// TelemetryHandler handles TelemetryStream bidi RPCs from stewards and fans out
// TelemetrySnapshot frames to browser WebSocket subscribers.
//
// Reference-counting ensures:
//   - The upstream subscribe TelemetryRequest is sent only on the 0→1 browser subscriber transition.
//   - The upstream unsubscribe TelemetryRequest is sent only on the 1→0 transition.
//
// If the steward disconnects while browsers are watching, all subscriber channels
// receive a nil-snapshot disconnect signal.
type TelemetryHandler struct {
	logger         logging.Logger
	allowedOrigins []string
	upgrader       websocket.Upgrader

	mu       sync.Mutex
	stewards map[string]*stewardTelemetryState

	// onActivate is called (without holding mu) after activateStream registers a
	// new stream. Nil in production; set in tests to signal readiness via a channel
	// instead of polling with time.Sleep.
	onActivate func()
}

// NewTelemetryHandler creates a TelemetryHandler. allowedOrigins contains
// additional allowed Origin hosts for WebSocket upgrade (same-origin always accepted).
func NewTelemetryHandler(logger logging.Logger, allowedOrigins []string) *TelemetryHandler {
	h := &TelemetryHandler{
		logger:         logger,
		allowedOrigins: allowedOrigins,
		stewards:       make(map[string]*stewardTelemetryState),
	}
	h.upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			return h.originAllowed(r)
		},
	}
	return h
}

// originAllowed returns true when the request's Origin host matches r.Host or
// appears in allowedOrigins. Absent or unparseable Origin is rejected.
func (h *TelemetryHandler) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	for _, a := range h.allowedOrigins {
		if strings.EqualFold(u.Host, a) {
			return true
		}
	}
	return false
}

// HandleGRPC processes a TelemetryStream bidi RPC.
//
//   - Receives TelemetrySnapshot frames from the steward.
//   - Sends TelemetryRequest frames to the steward (subscribe/unsubscribe/interval).
//   - On entry: if browser subscribers are already waiting, immediately sends subscribe.
//   - On steward disconnect: broadcasts a nil-snapshot disconnect to all browser channels.
func (h *TelemetryHandler) HandleGRPC(stream grpc.BidiStreamingServer[transportpb.TelemetrySnapshot, transportpb.TelemetryRequest]) error {
	ctx := stream.Context()

	// Extract steward identity via mTLS peer CN — fail closed if absent or empty.
	peerID, err := extractMTLSPeerID(ctx)
	if err != nil {
		return err
	}

	// Create the control channel and register this stream as active.
	sendCh := make(chan *transportpb.TelemetryRequest, 8)
	streamDone := make(chan struct{})
	existingSubCount := h.activateStream(peerID, sendCh, streamDone)

	defer func() {
		close(streamDone) // signal browser goroutines that the stream is gone
		h.deactivateStream(peerID, sendCh)
	}()

	// If browsers were already subscribed (race: browser connected before steward),
	// issue the upstream subscribe immediately.
	if existingSubCount > 0 {
		select {
		case sendCh <- &transportpb.TelemetryRequest{
			StewardId:  peerID,
			Subscribe:  true,
			IntervalMs: defaultTelemetryIntervalMs,
		}:
		default:
		}
	}

	// Goroutine: drain sendCh → stream.Send(). gRPC allows concurrent Send/Recv.
	sendErrCh := make(chan error, 1)
	go func() {
		for {
			select {
			case req, ok := <-sendCh:
				if !ok {
					sendErrCh <- nil
					return
				}
				if sendErr := stream.Send(req); sendErr != nil {
					sendErrCh <- sendErr
					return
				}
			case <-ctx.Done():
				sendErrCh <- nil
				return
			}
		}
	}()

	// Recv loop: fan out every received TelemetrySnapshot to all browser subscribers.
	var recvErr error
	for {
		snap, err := stream.Recv()
		if err != nil {
			recvErr = err
			break
		}
		h.broadcastSnapshot(peerID, snap)
	}

	// Notify all browser subscribers of the steward disconnect.
	h.broadcastDisconnect(peerID)

	if recvErr == io.EOF {
		return nil
	}
	return recvErr
}

// ServeWebSocket upgrades an HTTP request to a WebSocket connection and fans
// TelemetrySnapshot frames to the browser until the steward disconnects or the
// browser closes the connection.
//
// The {id} path variable (gorilla/mux) carries the steward ID. Tenant isolation
// and steward-existence checks are enforced by the API server wrapper before
// this handler is invoked; ServeWebSocket trusts that the caller is authorised.
func (h *TelemetryHandler) ServeWebSocket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]
	if stewardID == "" {
		http.Error(w, "missing steward id", http.StatusBadRequest)
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("telemetry: WebSocket upgrade failed",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", err)
		}
		return
	}
	defer conn.Close() //nolint:errcheck // conn.Close error in defer is unactionable; connection cleanup proceeds regardless

	// Subscribe to this steward's snapshot stream. On 0→1 the handler will send
	// a subscribe TelemetryRequest upstream automatically.
	subID, ch, streamDone := h.addSubscriber(stewardID)

	defer func() {
		// On 1→0 the removeSubscriber call returns the sendCh so we can send unsubscribe.
		isLast, sc, sd := h.removeSubscriber(stewardID, subID)
		if isLast && sc != nil {
			select {
			case sc <- &transportpb.TelemetryRequest{
				StewardId: stewardID,
				Subscribe: false,
			}:
			case <-sd:
				// stream already gone; nothing to send
			default:
			}
		}
	}()

	// Set up ping to keep the connection alive.
	conn.SetReadLimit(512)
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPingInterval + 10*time.Second))
	})
	_ = conn.SetReadDeadline(time.Now().Add(wsPingInterval + 10*time.Second))

	// Drain browser → controller direction (browsers only read; ignore input).
	browserGone := make(chan struct{})
	go func() {
		defer close(browserGone)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	}()

	pingTicker := time.NewTicker(wsPingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case <-browserGone:
			return

		case <-pingTicker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

		case msg, ok := <-ch:
			if !ok {
				// Channel closed externally (shouldn't happen normally).
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if msg.snap == nil {
				// Steward disconnected — send a disconnect event and close.
				payload, _ := json.Marshal(map[string]string{
					"type":   "disconnect",
					"reason": "steward disconnected",
				})
				_ = conn.WriteMessage(websocket.TextMessage, payload)
				return
			}
			payload, marshalErr := marshalSnapshot(msg.snap)
			if marshalErr != nil {
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				return
			}

		case <-streamDone:
			// Steward stream exited. The broadcastDisconnect will deliver via ch,
			// but if we race here first, close cleanly. The ch select above handles it.
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Internal state management
// ---------------------------------------------------------------------------

// activateStream registers sendCh and streamDone for stewardID and returns the
// current browser subscriber count. Called by HandleGRPC before the recv loop.
func (h *TelemetryHandler) activateStream(stewardID string, sendCh chan *transportpb.TelemetryRequest, streamDone chan struct{}) int {
	h.mu.Lock()
	st := h.getOrCreateState(stewardID)
	st.sendCh = sendCh
	st.streamDone = streamDone
	count := len(st.subs)
	h.mu.Unlock()
	if h.onActivate != nil {
		h.onActivate()
	}
	return count
}

// deactivateStream clears the sendCh for stewardID when HandleGRPC exits.
func (h *TelemetryHandler) deactivateStream(stewardID string, sendCh chan *transportpb.TelemetryRequest) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if st, ok := h.stewards[stewardID]; ok && st.sendCh == sendCh {
		st.sendCh = nil
		st.streamDone = nil
	}
}

// addSubscriber registers a new browser subscriber for stewardID. Returns the
// subscriber ID, the delivery channel, the stream-done channel (to detect
// steward disconnect), and whether this was the 0→1 subscriber transition.
// On 0→1, the caller should enqueue a subscribe TelemetryRequest on the sendCh.
func (h *TelemetryHandler) addSubscriber(stewardID string) (id int, ch chan snapshotOrDisconnect, streamDone chan struct{}) {
	h.mu.Lock()
	st := h.getOrCreateState(stewardID)
	id = st.nextID
	st.nextID++
	ch = make(chan snapshotOrDisconnect, 16)
	st.subs[id] = ch
	isFirst := len(st.subs) == 1
	sendCh := st.sendCh
	sd := st.streamDone
	h.mu.Unlock()

	// 0→1: trigger upstream subscribe if the steward stream is active.
	if isFirst && sendCh != nil {
		select {
		case sendCh <- &transportpb.TelemetryRequest{
			StewardId:  stewardID,
			Subscribe:  true,
			IntervalMs: defaultTelemetryIntervalMs,
		}:
		default:
		}
	}

	if sd == nil {
		// No active stream — return a never-closed placeholder so the caller's
		// select on streamDone never fires spuriously.
		sd = make(chan struct{})
	}
	return id, ch, sd
}

// removeSubscriber removes a browser subscriber and returns whether this was the
// last one (1→0), the active sendCh (or nil), and the streamDone channel. On
// 1→0 the caller should enqueue an unsubscribe TelemetryRequest on the sendCh.
func (h *TelemetryHandler) removeSubscriber(stewardID string, id int) (isLast bool, sendCh chan *transportpb.TelemetryRequest, streamDone chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, ok := h.stewards[stewardID]
	if !ok {
		return false, nil, nil
	}
	delete(st.subs, id)
	isLast = len(st.subs) == 0
	return isLast, st.sendCh, st.streamDone
}

// broadcastSnapshot delivers snap to every active browser subscriber of stewardID.
func (h *TelemetryHandler) broadcastSnapshot(stewardID string, snap *transportpb.TelemetrySnapshot) {
	h.mu.Lock()
	st, ok := h.stewards[stewardID]
	if !ok {
		h.mu.Unlock()
		return
	}
	// Collect channels while holding the lock, deliver without it.
	channels := make([]chan snapshotOrDisconnect, 0, len(st.subs))
	for _, ch := range st.subs {
		channels = append(channels, ch)
	}
	h.mu.Unlock()

	msg := snapshotOrDisconnect{snap: snap}
	for _, ch := range channels {
		select {
		case ch <- msg:
		default:
			// Drop rather than block if the subscriber is slow.
		}
	}
}

// broadcastDisconnect signals all browser subscribers of stewardID that the
// steward's gRPC stream ended. Sends a nil-snapshot message.
func (h *TelemetryHandler) broadcastDisconnect(stewardID string) {
	h.mu.Lock()
	st, ok := h.stewards[stewardID]
	if !ok {
		h.mu.Unlock()
		return
	}
	channels := make([]chan snapshotOrDisconnect, 0, len(st.subs))
	for _, ch := range st.subs {
		channels = append(channels, ch)
	}
	h.mu.Unlock()

	msg := snapshotOrDisconnect{snap: nil}
	for _, ch := range channels {
		select {
		case ch <- msg:
		default:
		}
	}
}

// getOrCreateState returns the stewardTelemetryState for stewardID, creating
// one if absent. Must be called with h.mu held.
func (h *TelemetryHandler) getOrCreateState(stewardID string) *stewardTelemetryState {
	if st, ok := h.stewards[stewardID]; ok {
		return st
	}
	st := &stewardTelemetryState{
		subs: make(map[int]chan snapshotOrDisconnect),
	}
	h.stewards[stewardID] = st
	return st
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// extractMTLSPeerID extracts the steward ID from the mTLS peer certificate in ctx.
// Returns Unauthenticated if the peer is absent, non-TLS, or has an empty CN.
func extractMTLSPeerID(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "mTLS certificate required")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "mTLS certificate required")
	}
	id, err := quictransport.PeerStewardID(tlsInfo.State)
	if err != nil || id == "" {
		return "", status.Error(codes.Unauthenticated, "mTLS certificate required")
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// JSON serialisation
// ---------------------------------------------------------------------------

// telemetrySnapshotJSON is the JSON wire type sent to browser WebSocket clients.
type telemetrySnapshotJSON struct {
	Type      string                `json:"type"`
	StewardID string                `json:"steward_id"`
	Processes []processSnapshotJSON `json:"processes"`
	Services  []serviceSnapshotJSON `json:"services"`
	Timestamp string                `json:"timestamp,omitempty"`
}

type processSnapshotJSON struct {
	FragmentID     string  `json:"fragment_id,omitempty"`
	PID            int32   `json:"pid"`
	Name           string  `json:"name"`
	CPUPercent     float64 `json:"cpu_percent"`
	MemoryBytes    uint64  `json:"memory_bytes"`
	DiskReadBytes  uint64  `json:"disk_read_bytes"`
	DiskWriteBytes uint64  `json:"disk_write_bytes"`
	NetRxBytes     uint64  `json:"net_rx_bytes"`
	NetTxBytes     uint64  `json:"net_tx_bytes"`
}

type serviceSnapshotJSON struct {
	FragmentID string `json:"fragment_id,omitempty"`
	Name       string `json:"name"`
	State      string `json:"state"`
}

func marshalSnapshot(snap *transportpb.TelemetrySnapshot) ([]byte, error) {
	procs := make([]processSnapshotJSON, len(snap.GetProcesses()))
	for i, p := range snap.GetProcesses() {
		procs[i] = processSnapshotJSON{
			FragmentID:     p.GetFragmentId(),
			PID:            p.GetPid(),
			Name:           p.GetName(),
			CPUPercent:     p.GetCpuPercent(),
			MemoryBytes:    p.GetMemoryBytes(),
			DiskReadBytes:  p.GetDiskReadBytes(),
			DiskWriteBytes: p.GetDiskWriteBytes(),
			NetRxBytes:     p.GetNetRxBytes(),
			NetTxBytes:     p.GetNetTxBytes(),
		}
	}
	svcs := make([]serviceSnapshotJSON, len(snap.GetServices()))
	for i, s := range snap.GetServices() {
		svcs[i] = serviceSnapshotJSON{
			FragmentID: s.GetFragmentId(),
			Name:       s.GetName(),
			State:      s.GetState(),
		}
	}
	ts := ""
	if t := snap.GetTimestamp(); t != nil {
		ts = t.AsTime().UTC().Format(time.RFC3339)
	}
	out := telemetrySnapshotJSON{
		Type:      "snapshot",
		StewardID: snap.GetStewardId(),
		Processes: procs,
		Services:  svcs,
		Timestamp: ts,
	}
	return json.Marshal(out)
}
