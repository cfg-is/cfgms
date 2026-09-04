// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// egWatchProvider is the narrow interface from EntityGraphProvider that the
// cockpit-watch handler requires. *sqlite.SQLiteEntityGraphProvider satisfies it.
type egWatchProvider interface {
	Watch(ctx context.Context, filter eginterfaces.WatchFilter, cursor string) (<-chan eginterfaces.WatchEvent, error)
}

// watchWriteTimeout bounds a single frame write to a connected browser client.
const watchWriteTimeout = 10 * time.Second

// defaultWatchPongWait bounds how long the server waits for any frame from the
// client (a pong, or otherwise) before treating the connection as dead.
// Mirrors the terminal WebSocket handler's 60s keepalive window
// (features/terminal/websocket.go). A client that vanishes without a clean
// close frame — laptop sleep, network drop, browser crash — must have its
// read pump unblock and cancel the session context within a bounded time,
// or the derived ctx (and the provider's watchLoop polling goroutine it
// keeps alive) leaks until the controller process restarts.
const defaultWatchPongWait = 60 * time.Second

// defaultWatchPingInterval is how often the server sends a ping frame to refresh
// its own liveness signal to the client. Must stay below the pong wait so a
// healthy connection's deadline is renewed (via the pong handler) before it
// expires.
const defaultWatchPingInterval = 54 * time.Second

// setWatchKeepalive overrides this server's watch-session keepalive window.
// The window is per-Server state, not a process global: a WebSocket handler
// outlives the request that started it (an upgraded connection is hijacked, so
// http.Server shutdown does not wait for it), and a package-level knob mutated
// while such a handler is still reading it is an unsynchronized write/read pair
// on shared memory — a genuine data race, not a detector artefact.
//
// A non-positive argument selects the corresponding default. pingInterval must
// stay below pongWait so a healthy connection's read deadline is refreshed by a
// pong before it expires.
func (s *Server) setWatchKeepalive(pongWait, pingInterval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.watchPongWait = pongWait
	s.watchPingInterval = pingInterval
}

// watchKeepalive returns this server's pong-wait and ping-interval, falling back
// to the package defaults when unset. Read once per session by the handler so
// the values it uses are immutable locals for the life of the connection.
func (s *Server) watchKeepalive() (pongWait, pingInterval time.Duration) {
	s.mu.RLock()
	pongWait, pingInterval = s.watchPongWait, s.watchPingInterval
	s.mu.RUnlock()

	if pongWait <= 0 {
		pongWait = defaultWatchPongWait
	}
	if pingInterval <= 0 {
		pingInterval = defaultWatchPingInterval
	}
	return pongWait, pingInterval
}

// watchConnWriter serializes all writes to a single WebSocket connection.
// gorilla/websocket supports at most one concurrent writer per connection;
// the event-fan-out goroutine is the sole writer, but holding the mutex is
// cheap insurance and mirrors the pattern used by the terminal handler.
type watchConnWriter struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

// writeJSON serializes a JSON message frame under the write lock.
func (w *watchConnWriter) writeJSON(v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	// A failed deadline leaves WriteJSON unbounded, which is exactly the stall the
	// deadline exists to prevent — abort the write and surface the reason instead.
	if err := w.conn.SetWriteDeadline(time.Now().Add(watchWriteTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	return w.conn.WriteJSON(v)
}

// writePing serializes a ping control frame under the write lock.
func (w *watchConnWriter) writePing() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.conn.SetWriteDeadline(time.Now().Add(watchWriteTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	return w.conn.WriteMessage(websocket.PingMessage, nil)
}

// watchFrame is the JSON shape sent to browser clients on the watch WebSocket.
type watchFrame struct {
	Type      string `json:"type"`                 // "event" | "resync"
	Subject   string `json:"subject,omitempty"`    // EID string
	EventKind string `json:"event_kind,omitempty"` // "entity-updated" | "edge-updated" | "drift-updated"
	Version   int64  `json:"version,omitempty"`
	At        string `json:"at,omitempty"` // RFC 3339
}

// cockpitWatchUpgrader upgrades HTTP connections to WebSocket. Same-origin
// policy: the browser sends an Origin header matching the page host; both
// must match the request Host. An absent or cross-origin Origin is rejected.
var cockpitWatchUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin:     cockpitWatchOriginAllowed,
}

// cockpitWatchOriginAllowed accepts WebSocket upgrades from the same host as
// the request. An absent or unparseable Origin is rejected. This mirrors the
// guard used by the terminal WebSocket handler.
func cockpitWatchOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// pinnedEIDsForWatch extracts all EIDs referenced by a case's pins into a
// deduplicated slice for use as the WatchFilter.EIDs subscription set.
// Only kinds that carry a resolvable EID are included — observation-version
// and drift-record pins reference storage records, not graph entities.
func pinnedEIDsForWatch(pins []*business.Pin) []eginterfaces.EIDRef {
	seen := make(map[string]struct{})
	var eids []eginterfaces.EIDRef

	add := func(raw string) {
		if raw == "" {
			return
		}
		eid, err := egtypes.ParseEID(raw)
		if err != nil {
			return
		}
		key := eid.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		eids = append(eids, eid)
	}

	for _, p := range pins {
		switch p.Ref.Kind {
		case business.PinRefKindEID:
			add(p.Ref.EID)
		case business.PinRefKindSubjectTimeRange:
			add(p.Ref.Subject)
		case business.PinRefKindEdgeIdentity:
			// EdgeIdentity is stored as "edge_type|from_eid|to_eid" (edgeSubjectDelimiter).
			parts := strings.SplitN(p.Ref.EdgeIdentity, edgeSubjectDelimiter, 3)
			if len(parts) == 3 {
				add(parts[1])
				add(parts[2])
			}
		}
	}
	return eids
}

// handleCockpitWatch handles GET /api/v1/cases/{id}/watch.
// Upgrades to a WebSocket and streams WatchEvents scoped to the case's pinned
// EIDs and the caller's tenant subtree. The cursor feed begins from the current
// position (empty cursor); reconnects on the client side are needed for
// cursor-resume (MVP — follow-on story for backfill on reconnect).
func (s *Server) handleCockpitWatch(w http.ResponseWriter, r *http.Request) {
	if s.casesStore == nil {
		http.Error(w, "cases store unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.egWatchProv == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "case id is required", http.StatusBadRequest)
		return
	}

	// loadCallerCase applies the cross-tenant check; returns nil + error response on failure.
	c := s.loadCallerCase(w, r, id)
	if c == nil {
		return
	}

	// Extract EIDs from the case's pins for the subscription filter.
	eids := pinnedEIDsForWatch(c.Pins)

	// Build a lookup set for the handler's own tenant-safety filter.
	// WatchFilter.EIDs is passed to the provider as a hint; this set ensures that
	// a provider bug or bypass cannot deliver out-of-subscription events to the
	// connected browser client (a provider failure must not become a cross-tenant leak).
	eidSet := make(map[string]struct{}, len(eids))
	for _, eid := range eids {
		eidSet[eid.String()] = struct{}{}
	}

	// Upgrade the HTTP connection to a WebSocket before starting the provider
	// subscription, so connection failures are cleanly reported.
	conn, err := cockpitWatchUpgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("handleCockpitWatch: WebSocket upgrade failed",
			"case_id", logging.SanitizeLogValue(id),
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	defer func() { _ = conn.Close() }()

	cw := &watchConnWriter{conn: conn}

	// Derive a context tied to this WebSocket session.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Drain the read pump so control frames (ping/pong/close) are processed.
	// The client sends no application frames; close frames from the client cancel ctx.
	//
	// The initial deadline plus the pong handler's refresh are what bound a dead
	// connection: a client that disappears without a close frame — sleep, network
	// drop, crash — never sends a pong, so ReadMessage unblocks with a timeout
	// once pongWait elapses instead of hanging forever. Both must be set on
	// conn before this goroutine starts reading, since gorilla/websocket invokes
	// the pong handler synchronously from inside ReadMessage.
	//
	// The keepalive window is snapshotted once here: the pong handler and the
	// ping ticker below then close over immutable locals, so nothing this
	// session does reads server state concurrently with a later reconfiguration.
	pongWait, pingInterval := s.watchKeepalive()

	conn.SetReadLimit(256)
	if err := conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		s.logger.Warn("handleCockpitWatch: set initial read deadline failed",
			"case_id", logging.SanitizeLogValue(id),
			"error", logging.SanitizeLogValue(err.Error()))
	}
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	go func() {
		defer cancel()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	// The subscription is bounded by the CASE's tenant, not the caller's subtree:
	// a root/msp-a operator viewing a root/msp-a/client-1 case must not subscribe
	// across all of msp-a, and a global-scope caller (empty tenant) must not
	// subscribe to everything. loadCallerCase above remains the separate
	// authorisation step that proves the caller may see this case at all.
	events, err := s.egWatchProv.Watch(ctx, eginterfaces.WatchFilter{
		TenantFilter: c.TenantID,
		EIDs:         eids,
	}, "") // empty cursor = start from now
	if err != nil {
		if errors.Is(err, eginterfaces.ErrCursorExpired) {
			// Tell the client to resync via a fresh case + evidence read.
			_ = cw.writeJSON(watchFrame{Type: "resync"})
		} else {
			s.logger.Error("handleCockpitWatch: Watch failed",
				"case_id", logging.SanitizeLogValue(id),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return
	}

	s.logger.Info("handleCockpitWatch: WebSocket session opened",
		"case_id", logging.SanitizeLogValue(id))

	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pingTicker.C:
			if err := cw.writePing(); err != nil {
				s.logger.Warn("handleCockpitWatch: ping failed",
					"case_id", logging.SanitizeLogValue(id),
					"error", logging.SanitizeLogValue(err.Error()))
				return
			}
		case event, ok := <-events:
			if !ok {
				// Provider closed the channel; session ends.
				return
			}

			// Handler's own subscription filter: only forward events whose Subject
			// is in the case's pinned-EID set. The check is unconditional and
			// fails closed — an empty set (a case with no EID-bearing pins, which
			// is the state every case starts in) forwards nothing rather than
			// everything. Falling back to WatchFilter.TenantFilter here would leak:
			// the provider exempts edge-updated events from tenant filtering
			// (pkg/entitygraph/providers/sqlite/watch.go, watchFilterMatches), so a
			// pinless case would stream every tenant's edge events to the browser.
			// The socket stays open — resync frames and control frames still flow.
			if _, allowed := eidSet[event.Subject.String()]; !allowed {
				continue
			}

			frame := watchFrame{
				Type:      "event",
				Subject:   event.Subject.String(),
				EventKind: event.EventKind,
				Version:   event.Version,
				At:        event.At.UTC().Format(time.RFC3339),
			}
			if err := cw.writeJSON(frame); err != nil {
				s.logger.Warn("handleCockpitWatch: write failed",
					"case_id", logging.SanitizeLogValue(id),
					"error", logging.SanitizeLogValue(err.Error()))
				return
			}
		}
	}
}
