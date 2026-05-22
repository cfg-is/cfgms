// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package scriptrelay

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// StatusCallback is called to publish control-plane events to the controller.
// Same type as commands.StatusCallback to avoid cross-package imports.
type StatusCallback func(ctx context.Context, event *cpTypes.Event)

// Relay manages the per-execution socket / named-pipe for script API relay.
// It accepts HTTP requests from the script process, forwards them as
// EventRelayRequest events to the controller, and writes back the
// CommandRelayResponse it receives via DeliverRelayResponse.
//
// Only one connection is accepted at a time (scripts are single-threaded
// API callers). Each connection handles exactly one HTTP request-response
// cycle, then closes. Stop must be called after script execution completes.
type Relay struct {
	executionID string
	stewardID   string

	// socketPath is the path advertised to the script via CFGMS_API_SOCKET.
	socketPath string

	// publish sends EventRelayRequest events to the controller.
	publish StatusCallback

	// responseCh receives CommandRelayResponse from the command handler.
	responseCh chan *cpTypes.Command

	seq int64 // atomic; per-relay request sequence counter

	ln       net.Listener
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	logger logging.Logger
}

// NewRelay creates a Relay for the given execution. Call Start to begin
// accepting connections. The caller is responsible for calling Stop after
// script execution completes to clean up the socket directory.
func NewRelay(executionID, stewardID string, publish StatusCallback, logger logging.Logger) (*Relay, error) {
	if executionID == "" {
		return nil, fmt.Errorf("relay: executionID must not be empty")
	}
	r := &Relay{
		executionID: executionID,
		stewardID:   stewardID,
		publish:     publish,
		responseCh:  make(chan *cpTypes.Command, 1),
		stopCh:      make(chan struct{}),
		logger:      logger,
	}
	if err := initSocket(r); err != nil {
		return nil, fmt.Errorf("relay: init socket: %w", err)
	}
	return r, nil
}

// SocketPath returns the socket path that should be set in CFGMS_API_SOCKET.
func (r *Relay) SocketPath() string { return r.socketPath }

// ResponseCh returns the channel on which the command handler delivers
// CommandRelayResponse commands. The channel has buffer size 1.
func (r *Relay) ResponseCh() chan *cpTypes.Command { return r.responseCh }

// Start begins accepting connections in a background goroutine.
func (r *Relay) Start(ctx context.Context) error {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.serveLoop(ctx)
	}()
	return nil
}

// Stop signals the relay to stop accepting connections and cleans up the socket.
func (r *Relay) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopCh)
		if r.ln != nil {
			_ = r.ln.Close()
		}
		r.wg.Wait()
		cleanupSocket(r)
	})
}

// DeliverRelayResponse delivers a CommandRelayResponse to the waiting relay
// goroutine. Called by the command handler from its relay response dispatcher.
func (r *Relay) DeliverRelayResponse(cmd *cpTypes.Command) {
	select {
	case r.responseCh <- cmd:
	default:
		// Buffer full or relay already stopped — drop silently.
	}
}

// serveLoop accepts one connection at a time and handles each HTTP request.
func (r *Relay) serveLoop(ctx context.Context) {
	for {
		// Check for stop before each accept.
		select {
		case <-r.stopCh:
			return
		default:
		}

		// Accept with a deadline so we can check stopCh periodically.
		if dl, ok := r.ln.(interface{ SetDeadline(time.Time) error }); ok {
			_ = dl.SetDeadline(time.Now().Add(500 * time.Millisecond))
		}

		conn, err := r.ln.Accept()
		if err != nil {
			select {
			case <-r.stopCh:
				return
			default:
			}
			if isNetTimeout(err) {
				continue
			}
			r.logger.Debug("relay: accept error", "execution_id", r.executionID, "error", err)
			return
		}

		r.handleConn(ctx, conn)
	}
}

// handleConn reads one HTTP request, relays it to the controller, and writes
// the response back. Closes the connection on return.
func (r *Relay) handleConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		r.logger.Debug("relay: read request error", "execution_id", r.executionID, "error", err)
		return
	}
	defer func() { _ = req.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20)) // 1 MiB cap

	seq := atomic.AddInt64(&r.seq, 1)

	// Flatten headers to map[string]string (first value per header).
	headers := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}

	event := &cpTypes.Event{
		ID:        fmt.Sprintf("relay_%s_%d", r.executionID, seq),
		Type:      cpTypes.EventRelayRequest,
		StewardID: r.stewardID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id": r.executionID,
			"sequence":     seq,
			"method":       req.Method,
			"path":         req.URL.RequestURI(),
			"headers":      headers,
			"body":         base64.StdEncoding.EncodeToString(body),
		},
	}

	r.publish(ctx, event)

	// Wait for the controller's response.
	var responseCmd *cpTypes.Command
	select {
	case responseCmd = <-r.responseCh:
	case <-r.stopCh:
		writeHTTPError(conn, http.StatusServiceUnavailable, "relay stopped")
		return
	case <-ctx.Done():
		writeHTTPError(conn, http.StatusGatewayTimeout, "context cancelled")
		return
	case <-time.After(30 * time.Second):
		writeHTTPError(conn, http.StatusGatewayTimeout, "relay response timeout")
		return
	}

	writeRelayResponse(conn, responseCmd)
}

// writeRelayResponse serialises a CommandRelayResponse back to the script's connection.
func writeRelayResponse(conn net.Conn, cmd *cpTypes.Command) {
	statusCode := http.StatusOK
	if v, ok := cmd.Params["status"].(float64); ok && v > 0 {
		statusCode = int(v)
	}

	bodyB64, _ := cmd.Params["body"].(string)
	bodyBytes, _ := base64.StdEncoding.DecodeString(bodyB64)

	var headers map[string]interface{}
	if h, ok := cmd.Params["headers"].(map[string]interface{}); ok {
		headers = h
	}

	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	for k, v := range headers {
		if vStr, ok := v.(string); ok {
			_, _ = fmt.Fprintf(conn, "%s: %s\r\n", k, vStr)
		}
	}
	_, _ = fmt.Fprintf(conn, "Content-Length: %d\r\nConnection: close\r\n\r\n", len(bodyBytes))
	_, _ = conn.Write(bodyBytes)
}

// writeHTTPError writes a minimal HTTP error response to the connection.
func writeHTTPError(conn net.Conn, code int, msg string) {
	body := []byte(msg)
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), msg)
}

// isNetTimeout reports whether err is a net.Error timeout.
func isNetTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}
