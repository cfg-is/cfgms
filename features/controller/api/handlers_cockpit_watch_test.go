// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// watchProbe wires the real *sqlite.SQLiteEntityGraphProvider — the provider the
// controller runs in production — into the handler, adding only the coordination
// the socket tests need. Every event, every filter decision and every error still
// comes from the real provider; this type synthesizes nothing:
//
//   - subscribed is closed once the real Watch call has returned. The provider
//     resolves its start cursor synchronously inside Watch, so any observation
//     committed after that point is guaranteed to be picked up by the poll loop.
//     Tests block on this signal instead of sleeping.
//   - filter records the WatchFilter the handler passed, so a test can assert the
//     subscription's tenant scope directly.
//   - bypassFilters strips WatchFilter.EIDs and WatchFilter.TenantFilter before
//     delegating. That reproduces the provider bug/bypass the handler's own
//     subscription filter exists to contain — the events themselves are still
//     real rows read off the real observation log.
//   - cursor, when non-empty, replaces the handler's empty cursor so the
//     provider's own cursor-expiry check runs against genuinely pruned log rows.
//
// This is the same real-components composition used by eidRoutedEGProvider in
// handlers_cases_test.go, not a stand-in implementation of Watch.
type watchProbe struct {
	*sqlite.SQLiteEntityGraphProvider

	subscribed chan struct{}
	once       sync.Once

	bypassFilters bool
	cursor        string

	mu         sync.Mutex
	lastFilter eginterfaces.WatchFilter
}

func newWatchProbe(t *testing.T) *watchProbe {
	t.Helper()
	return &watchProbe{
		SQLiteEntityGraphProvider: newTestEntityGraphProvider(t),
		subscribed:                make(chan struct{}),
	}
}

func (p *watchProbe) Watch(ctx context.Context, filter eginterfaces.WatchFilter, cursor string) (<-chan eginterfaces.WatchEvent, error) {
	p.mu.Lock()
	p.lastFilter = filter
	p.mu.Unlock()

	if p.bypassFilters {
		filter.EIDs = nil
		filter.TenantFilter = ""
	}
	if p.cursor != "" {
		cursor = p.cursor
	}

	ch, err := p.SQLiteEntityGraphProvider.Watch(ctx, filter, cursor)
	// Signal after the real Watch returns: at that point the provider has already
	// resolved its start cursor, so the caller may commit observations without
	// racing the subscription. Signalled on the error path too, so error tests
	// need no separate coordination.
	p.once.Do(func() { close(p.subscribed) })
	return ch, err
}

// waitSubscribed blocks until the handler has established its Watch subscription.
func (p *watchProbe) waitSubscribed(t *testing.T) {
	t.Helper()
	select {
	case <-p.subscribed:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not subscribe to the entity graph watch feed")
	}
}

// watchFilter returns the WatchFilter the handler passed into Watch.
func (p *watchProbe) watchFilter(t *testing.T) eginterfaces.WatchFilter {
	t.Helper()
	p.waitSubscribed(t)
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastFilter
}

// setupCockpitWatchServer creates a test server with a real CaseStore and the
// supplied watch provider wired in.
func setupCockpitWatchServer(t *testing.T, wp egWatchProvider) *Server {
	t.Helper()
	srv := setupTestServer(t)
	sm := pkgtesting.SetupTestStorage(t)
	cs := sm.GetCaseStore()
	require.NotNil(t, cs, "OSS composite storage must provide a CaseStore")
	srv.SetCasesStore(cs)
	srv.SetEntityGraphWatchProvider(wp)
	return srv
}

// dialWatchWS connects a WebSocket client to the watch endpoint on srv for
// the given caseID, using an API key scoped to callerTenant. Returns the
// connection and a teardown function that closes it.
func dialWatchWS(t *testing.T, srv *Server, caseID, callerTenant string) (*websocket.Conn, func()) {
	t.Helper()
	apiKey := NewEphemeralTestKey(t, srv, []string{"case:read"}, callerTenant, 5*time.Minute)

	ts := httptest.NewServer(srv.router)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/cases/" + caseID + "/watch"
	hdr := http.Header{
		"Authorization": []string{"Bearer " + apiKey},
		"Origin":        []string{ts.URL},
	}

	dialer := websocket.Dialer{}
	conn, resp, err := dialer.Dial(wsURL, hdr)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dialWatchWS: HTTP %d, err: %v", status, err)
	}
	return conn, func() { _ = conn.Close() }
}

// seedWatchCase creates a case owned by tenantID with one EID-kind pin.
// The EID uses the "cfgms" authority type (registered set).
func seedWatchCase(t *testing.T, cs business.CaseStore, tenantID string) (*business.Case, egtypes.EID) {
	t.Helper()
	eid := watchEID(t, "host/sql-primary")

	c := seedWatchCaseNoPins(t, cs, tenantID)
	pin := &business.Pin{
		ID:       c.ID + "-pin-001",
		CaseID:   c.ID,
		Ref:      business.PinRef{Kind: business.PinRefKindEID, EID: eid.String()},
		Author:   "operator",
		PinnedAt: time.Now().UTC(),
	}
	// CreateCase does not persist embedded Pins — call AddPin explicitly.
	require.NoError(t, cs.AddPin(context.Background(), c.ID, pin))
	c.Pins = []*business.Pin{pin}
	return c, eid
}

// seedWatchCaseNoPins creates a case with no pins at all — the state every case
// starts in (handleCreateCase initialises Pins to an empty slice).
func seedWatchCaseNoPins(t *testing.T, cs business.CaseStore, tenantID string) *business.Case {
	t.Helper()
	now := time.Now().UTC()
	c := &business.Case{
		// The tenant path is flattened: a '/' in the case ID would stop the router
		// matching /api/v1/cases/{id}/watch at all.
		ID:       "watch-case-" + strings.ReplaceAll(tenantID, "/", "-"),
		TenantID: tenantID,
		Status:   business.CaseStatusOpen,
		Ticket: business.Ticket{
			Title: business.TicketField{Value: "watch test case", Source: business.TicketFieldSourceOperator, Filled: true},
		},
		Pins:      []*business.Pin{},
		Content:   []*business.ContentEntry{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, cs.CreateCase(context.Background(), c))
	return c
}

// watchEID builds an EID in the registered "cfgms" authority namespace.
func watchEID(t *testing.T, localID string) egtypes.EID {
	t.Helper()
	eid, err := egtypes.NewEID("cfgms", "agent1", localID)
	require.NoError(t, err)
	return eid
}

// reportWatchObservation writes a real observation into the entity graph. This
// appends a row to eg_observation_log — the feed Watch actually reads — so the
// events the handler sees are produced end-to-end by real code. marker keeps each
// observation's content hash distinct so the provider's bit-identical dedup does
// not swallow a repeat report of the same subject.
func reportWatchObservation(t *testing.T, p *sqlite.SQLiteEntityGraphProvider, eid egtypes.EID, tenant, marker string, observedAt time.Time) {
	t.Helper()
	err := p.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: "test:watch-reporter",
		Observations: []egtypes.Observation{
			{
				Source:     "test:watch-reporter",
				ObservedAt: observedAt,
				RecordedAt: observedAt,
				Subject:    eid.String(),
				Kind:       egtypes.ObservationKindState,
				Confidence: egtypes.ConfidenceHigh,
				Payload: map[string]interface{}{
					"entity_kind":   "host",
					"owning_tenant": tenant,
					"hostname":      eid.String(),
					"marker":        marker,
				},
			},
		},
	})
	require.NoError(t, err, "reportWatchObservation: %s", eid.String())
}

// awaitLogPublished blocks until an independent subscription on the same real
// provider has delivered wantCount events, proving the observations are visible
// on the feed the handler is polling. Used as a barrier before asserting that
// the handler forwarded NOTHING, so the assertion cannot pass merely because the
// events had not been published yet.
func awaitLogPublished(t *testing.T, p *sqlite.SQLiteEntityGraphProvider, from string, wantCount int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := p.Watch(ctx, eginterfaces.WatchFilter{}, from)
	require.NoError(t, err)

	deadline := time.After(10 * time.Second)
	for got := 0; got < wantCount; got++ {
		select {
		case _, ok := <-ch:
			require.True(t, ok, "watch channel closed after %d of %d events", got, wantCount)
		case <-deadline:
			t.Fatalf("observation log published only %d of %d events", got, wantCount)
		}
	}
}

// readWatchFrame reads one JSON frame from the socket within timeout.
func readWatchFrame(t *testing.T, conn *websocket.Conn, timeout time.Duration) watchFrame {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(timeout)))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)

	var frame watchFrame
	require.NoError(t, json.Unmarshal(msg, &frame))
	return frame
}

// requireNoWatchFrame asserts that no frame arrives within timeout.
func requireNoWatchFrame(t *testing.T, conn *websocket.Conn, timeout time.Duration, msg string) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(timeout)))
	_, payload, err := conn.ReadMessage()
	require.Error(t, err, "%s, but received: %s", msg, string(payload))
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || isWebSocketTimeout(err),
		"%s, but the read failed for another reason: %v", msg, err)
}

// isWebSocketTimeout reports whether err is a network timeout, which is the
// underlying error when a WebSocket read deadline fires.
func isWebSocketTimeout(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout")
}

// ── No-store / no-provider 503 ─────────────────────────────────────────────

func TestHandleCockpitWatch_NoStore_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	// No SetCasesStore call — store is nil.
	apiKey := NewEphemeralTestKey(t, srv, []string{"case:read"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/cases/any-id/watch", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Origin", "https://localhost:8080")

	rr := httptest.NewRecorder()
	srv.router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestHandleCockpitWatch_NoWatchProvider_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	sm := pkgtesting.SetupTestStorage(t)
	srv.SetCasesStore(sm.GetCaseStore())
	// No SetEntityGraphWatchProvider — egWatchProv is nil.
	apiKey := NewEphemeralTestKey(t, srv, []string{"case:read"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/cases/any-id/watch", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Origin", "https://localhost:8080")

	rr := httptest.NewRecorder()
	srv.router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// ── Case not found / cross-tenant 404 ──────────────────────────────────────

func TestHandleCockpitWatch_CaseNotFound_Returns404(t *testing.T) {
	srv := setupCockpitWatchServer(t, newWatchProbe(t))
	apiKey := NewEphemeralTestKey(t, srv, []string{"case:read"}, "test-tenant", 5*time.Minute)

	ts := httptest.NewServer(srv.router)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/cases/nonexistent-id/watch"
	hdr := http.Header{
		"Authorization": []string{"Bearer " + apiKey},
		"Origin":        []string{ts.URL},
	}

	_, resp, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandleCockpitWatch_CrossTenant_Returns404(t *testing.T) {
	srv := setupCockpitWatchServer(t, newWatchProbe(t))
	cs := srv.CasesStore()

	// Seed a case under "other-tenant".
	seedCase(t, cs, "other-tenant")

	// Caller with key scoped to "test-tenant" tries to watch "other-tenant"'s case.
	cases, err := cs.ListCases(context.Background(), "other-tenant")
	require.NoError(t, err)
	require.NotEmpty(t, cases)
	caseID := cases[0].ID

	apiKey := NewEphemeralTestKey(t, srv, []string{"case:read"}, "test-tenant", 5*time.Minute)

	ts := httptest.NewServer(srv.router)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/cases/" + caseID + "/watch"
	hdr := http.Header{
		"Authorization": []string{"Bearer " + apiKey},
		"Origin":        []string{ts.URL},
	}

	_, resp, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ── ErrCursorExpired sends resync frame ────────────────────────────────────

// TestHandleCockpitWatch_CursorExpired_SendsResync drives the real provider's own
// cursor-expiry check: two observations are written with observed_at beyond the
// default 90-day history depth, retention GC prunes the unpinned older row, and
// the subscription then resumes from a cursor position that no longer exists.
// The ErrCursorExpired the handler reacts to is produced by real pruned rows.
func TestHandleCockpitWatch_CursorExpired_SendsResync(t *testing.T) {
	probe := newWatchProbe(t)
	probe.cursor = "1"

	eid := watchEID(t, "host/expired-cursor")
	old := time.Now().UTC().AddDate(0, 0, -200)
	reportWatchObservation(t, probe.SQLiteEntityGraphProvider, eid, "test-tenant", "first", old)
	reportWatchObservation(t, probe.SQLiteEntityGraphProvider, eid, "test-tenant", "second", old.AddDate(0, 0, 1))
	require.NoError(t, probe.RunRetentionGC(context.Background(), eginterfaces.RetentionPolicy{}))

	// Precondition: the first log row is really gone, so cursor "1" is expired.
	_, err := probe.SQLiteEntityGraphProvider.Watch(context.Background(), eginterfaces.WatchFilter{}, "1")
	require.ErrorIs(t, err, eginterfaces.ErrCursorExpired,
		"retention GC must have pruned the row cursor 1 refers to")

	srv := setupCockpitWatchServer(t, probe)
	c, _ := seedWatchCase(t, srv.CasesStore(), "test-tenant")

	conn, teardown := dialWatchWS(t, srv, c.ID, "test-tenant")
	defer teardown()

	frame := readWatchFrame(t, conn, 5*time.Second)
	assert.Equal(t, "resync", frame.Type)
}

// ── In-subscription event is forwarded; out-of-subscription event is filtered ──
//
// This is the load-bearing AC test: the handler's OWN filtering must prevent a
// provider bug or bypass from leaking events whose Subject is not in the case's
// pinned-EID set. The probe strips both WatchFilter.EIDs and
// WatchFilter.TenantFilter before delegating, so the real provider genuinely
// delivers an out-of-tenant, out-of-subscription event onto the same channel as
// the pinned one — and only the pinned one may reach the browser.

func TestHandleCockpitWatch_FiltersOutOfSubscriptionEvents(t *testing.T) {
	probe := newWatchProbe(t)
	probe.bypassFilters = true

	srv := setupCockpitWatchServer(t, probe)
	c, pinnedEID := seedWatchCase(t, srv.CasesStore(), "test-tenant")
	outsideEID := watchEID(t, "host/unrelated-host")

	conn, teardown := dialWatchWS(t, srv, c.ID, "test-tenant")
	defer teardown()

	// Block until the subscription is live; the provider resolves its start
	// cursor inside Watch, so observations committed after this point are seen.
	probe.waitSubscribed(t)

	// Emit out-of-subscription (and out-of-tenant) first, then in-subscription.
	// The provider preserves log order, so a handler that forwarded everything
	// would deliver the foreign event first.
	reportWatchObservation(t, probe.SQLiteEntityGraphProvider, outsideEID, "other-tenant", "outside", time.Now().UTC())
	reportWatchObservation(t, probe.SQLiteEntityGraphProvider, pinnedEID, "test-tenant", "inside", time.Now().UTC())

	frame := readWatchFrame(t, conn, 5*time.Second)
	assert.Equal(t, "event", frame.Type)
	assert.Equal(t, pinnedEID.String(), frame.Subject, "only the in-subscription event must reach the client")

	requireNoWatchFrame(t, conn, time.Second, "the out-of-subscription event must never be forwarded")
}

// TestHandleCockpitWatch_PinlessCaseForwardsNothing is the regression test for the
// fail-open subscription filter: a case with no EID-bearing pins (the state every
// case starts in) must forward zero event frames, not every event the provider
// emits. The probe strips the provider-side filters so the handler is the only
// thing standing between the feed and the browser — which is precisely the
// provider-bypass condition the handler filter exists for.
func TestHandleCockpitWatch_PinlessCaseForwardsNothing(t *testing.T) {
	probe := newWatchProbe(t)
	probe.bypassFilters = true

	srv := setupCockpitWatchServer(t, probe)
	c := seedWatchCaseNoPins(t, srv.CasesStore(), "test-tenant")

	conn, teardown := dialWatchWS(t, srv, c.ID, "test-tenant")
	defer teardown()

	probe.waitSubscribed(t)

	// One event in the case's own tenant and one from a foreign tenant. Edge and
	// entity events alike must stay off a pinless socket.
	reportWatchObservation(t, probe.SQLiteEntityGraphProvider, watchEID(t, "host/in-tenant"), "test-tenant", "in", time.Now().UTC())
	reportWatchObservation(t, probe.SQLiteEntityGraphProvider, watchEID(t, "host/foreign"), "other-tenant", "foreign", time.Now().UTC())

	// Barrier: both events are provably on the feed the handler is polling.
	awaitLogPublished(t, probe.SQLiteEntityGraphProvider, "0", 2)

	requireNoWatchFrame(t, conn, time.Second, "a case with no pins must receive no event frames")
}

// ── Event forwarded correctly ───────────────────────────────────────────────

func TestHandleCockpitWatch_ForwardsInSubscriptionEvent(t *testing.T) {
	probe := newWatchProbe(t)
	srv := setupCockpitWatchServer(t, probe)
	c, pinnedEID := seedWatchCase(t, srv.CasesStore(), "test-tenant")

	conn, teardown := dialWatchWS(t, srv, c.ID, "test-tenant")
	defer teardown()

	probe.waitSubscribed(t)

	observedAt := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	reportWatchObservation(t, probe.SQLiteEntityGraphProvider, pinnedEID, "test-tenant", "forwarded", observedAt)

	frame := readWatchFrame(t, conn, 5*time.Second)
	assert.Equal(t, "event", frame.Type)
	assert.Equal(t, pinnedEID.String(), frame.Subject)
	assert.Equal(t, "entity-updated", frame.EventKind)
	assert.Positive(t, frame.Version, "version carries the provider's log sequence")
	assert.Equal(t, "2026-08-01T12:00:00Z", frame.At)
}

// ── Subscription scope is the case's tenant, not the caller's subtree ──────

// TestHandleCockpitWatch_SubscriptionScopedToCaseTenant proves the subscription is
// bounded by the case it belongs to. A caller authorised for the whole "watch-msp"
// subtree who opens a case owned by "watch-msp/client-1" must not subscribe across
// the subtree — loadCallerCase stays the authorisation step, WatchFilter stays the
// scope of the feed.
func TestHandleCockpitWatch_SubscriptionScopedToCaseTenant(t *testing.T) {
	probe := newWatchProbe(t)
	srv := setupCockpitWatchServer(t, probe)
	c, _ := seedWatchCase(t, srv.CasesStore(), "watch-msp/client-1")

	_, teardown := dialWatchWS(t, srv, c.ID, "watch-msp")
	defer teardown()

	filter := probe.watchFilter(t)
	assert.Equal(t, "watch-msp/client-1", filter.TenantFilter,
		"the feed must be scoped to the case's tenant, not the caller's subtree")
}

// ── SetEntityGraphWatchProvider wiring round-trip ──────────────────────────

func TestSetEntityGraphWatchProvider_RoundTrip(t *testing.T) {
	srv := setupTestServer(t)
	assert.Nil(t, srv.EntityGraphWatchProvider())

	wp := newWatchProbe(t)
	srv.SetEntityGraphWatchProvider(wp)
	assert.Equal(t, wp, srv.EntityGraphWatchProvider())
}

// ── pinnedEIDsForWatch extraction ─────────────────────────────────────────

func TestPinnedEIDsForWatch(t *testing.T) {
	eid1, err := egtypes.NewEID("host", "agent1", "node-a")
	require.NoError(t, err)
	eid2, err := egtypes.NewEID("host", "agent1", "node-b")
	require.NoError(t, err)

	pins := []*business.Pin{
		{Ref: business.PinRef{Kind: business.PinRefKindEID, EID: eid1.String()}},
		{Ref: business.PinRef{Kind: business.PinRefKindEID, EID: eid1.String()}}, // duplicate
		{Ref: business.PinRef{Kind: business.PinRefKindEID, EID: eid2.String()}},
		{Ref: business.PinRef{Kind: business.PinRefKindObservationVersion, ObservationVersion: "obs-123"}},
		{Ref: business.PinRef{Kind: business.PinRefKindDriftRecord, DriftRecord: "drift-456"}},
	}

	got := pinnedEIDsForWatch(pins)
	require.Len(t, got, 2)

	set := make(map[string]struct{})
	for _, eid := range got {
		set[eid.String()] = struct{}{}
	}
	assert.Contains(t, set, eid1.String())
	assert.Contains(t, set, eid2.String())
}
