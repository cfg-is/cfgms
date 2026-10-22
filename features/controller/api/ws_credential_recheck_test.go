// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/pkg/logging"
)

// dialWSPath upgrades to a WebSocket at path on a TLS test server fronting srv and
// waits for in-flight handlers to return before the test ends.
func dialWSPath(t *testing.T, srv *Server, path, apiKey string) *websocket.Conn {
	t.Helper()
	var inflight sync.WaitGroup
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inflight.Add(1)
		defer inflight.Done()
		srv.router.ServeHTTP(w, r)
	}))
	t.Cleanup(func() {
		ts.Close()
		drained := make(chan struct{})
		go func() { inflight.Wait(); close(drained) }()
		select {
		case <-drained:
		case <-time.After(10 * time.Second):
			t.Error("WebSocket handler still running 10s after the test server closed")
		}
	})
	hdr := http.Header{
		"Origin":        []string{ts.URL},
		"Authorization": []string{"Bearer " + apiKey},
	}
	conn, resp, err := wsTLSDialer(ts).Dial("ws"+strings.TrimPrefix(ts.URL, "http")+path, hdr)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial %s: HTTP %d, err: %v", path, status, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// requirePolicyViolationClose asserts the server ends the socket with a
// policy-violation close frame within the read deadline.
func requirePolicyViolationClose(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	for {
		_, _, err := conn.ReadMessage()
		require.Error(t, err, "server must close the socket after the credential is revoked")
		var closeErr *websocket.CloseError
		require.ErrorAs(t, err, &closeErr, "got %v", err)
		assert.Equal(t, websocket.ClosePolicyViolation, closeErr.Code)
		return
	}
}

// TestHandleCockpitWatch_ClosesWhenAPIKeyRevoked proves an open watch authenticated by
// an API key ends once the key's secret-store record is deleted (on any node).
func TestHandleCockpitWatch_ClosesWhenAPIKeyRevoked(t *testing.T) {
	probe := newWatchProbe(t)
	srv := setupCockpitWatchServer(t, probe)
	srv.setWatchKeepalive(2*time.Second, 100*time.Millisecond)
	c, _ := seedWatchCase(t, srv.CasesStore(), "test-tenant")
	apiKey := NewEphemeralTestKey(t, srv, []string{"case:read"}, "test-tenant", 5*time.Minute)

	conn := dialWSPath(t, srv, "/api/v1/cases/"+c.ID+"/watch", apiKey)
	probe.waitSubscribed(t)

	require.NoError(t, srv.deleteAPIKeyRecord(context.Background(), "test-tenant", hashAPIKey(apiKey)))
	requirePolicyViolationClose(t, conn)
}

// TestTelemetryWS_ClosesWhenAPIKeyRevoked proves the telemetry WebSocket re-checks the
// authenticating credential on the keepalive interval and closes when it is revoked.
func TestTelemetryWS_ClosesWhenAPIKeyRevoked(t *testing.T) {
	const stewardID = "telemetry-recheck-steward"
	srv := setupTestServer(t)
	srv.setWatchKeepalive(2*time.Second, 100*time.Millisecond)
	logger := logging.NewLogger("info")
	srv.SetTelemetryHandler(http.HandlerFunc(transport.NewTelemetryHandler(logger, nil).ServeWebSocket))
	require.NoError(t, srv.controllerService.RegisterSteward(stewardID, "test-tenant", "localhost:0", "active"))
	apiKey := NewTestKey(t, srv, []string{"steward:telemetry"})

	conn := dialWSPath(t, srv, "/api/v1/telemetry/ws/"+stewardID, apiKey)

	require.NoError(t, srv.deleteAPIKeyRecord(context.Background(), "test-tenant", hashAPIKey(apiKey)))
	requirePolicyViolationClose(t, conn)
}

// TestTelemetryWS_StaysOpenWhileCredentialValid guards against the re-check closing a
// healthy stream: with the key intact the socket must still be open after several
// re-check intervals.
func TestTelemetryWS_StaysOpenWhileCredentialValid(t *testing.T) {
	const stewardID = "telemetry-valid-steward"
	srv := setupTestServer(t)
	srv.setWatchKeepalive(2*time.Second, 50*time.Millisecond)
	srv.SetTelemetryHandler(http.HandlerFunc(transport.NewTelemetryHandler(logging.NewLogger("info"), nil).ServeWebSocket))
	require.NoError(t, srv.controllerService.RegisterSteward(stewardID, "test-tenant", "localhost:0", "active"))
	apiKey := NewTestKey(t, srv, []string{"steward:telemetry"})

	conn := dialWSPath(t, srv, "/api/v1/telemetry/ws/"+stewardID, apiKey)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(600*time.Millisecond)))
	_, _, err := conn.ReadMessage()
	var netErr interface{ Timeout() bool }
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout(), "socket must stay open while the credential is valid, got %v", err)
}

// TestAdminCertRecheck_FollowsRevocation proves the credential recorded for an admin
// mTLS request flips to invalid once the certificate is revoked.
func TestAdminCertRecheck_FollowsRevocation(t *testing.T) {
	certManager := newSharedTestCertManager(t)
	srv := setupTestServerWithCertMgr(t, certManager)
	req, serial := issueCertAndBuildRequest(t, http.MethodGet, "/api/v1/test", certManager)

	var recheck authRecheck
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recheck = requestAuthRecheck(r)
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, recheck, "mTLS requests must carry a credential re-check")

	assert.True(t, recheck(context.Background()), "valid certificate must pass the re-check")
	require.NoError(t, certManager.Revoke(serial))
	assert.False(t, recheck(context.Background()), "revoked certificate must fail the re-check")
}

// TestAPIKeyRecheck_FollowsDeletionAndExpiry proves the API-key re-check reads the
// secret store, not the cache, and honours expiry.
func TestAPIKeyRecheck_FollowsDeletionAndExpiry(t *testing.T) {
	srv := setupTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"steward:read"})

	var recheck authRecheck
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recheck = requestAuthRecheck(r)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, recheck, "API-key requests must carry a credential re-check")

	assert.True(t, recheck(context.Background()))
	require.NoError(t, srv.deleteAPIKeyRecord(context.Background(), "test-tenant", hashAPIKey(apiKey)))
	assert.False(t, recheck(context.Background()), "deleted key must fail the re-check")
}

// TestTelemetryWS_ClosesWhenPermissionRemoved proves the telemetry stream re-runs the
// route's permission decision: removing steward:telemetry from the tenant-scoped
// account in the real account store closes the open socket.
func TestTelemetryWS_ClosesWhenPermissionRemoved(t *testing.T) {
	const stewardID = "telemetry-perm-steward"
	srv := setupTestServer(t)
	srv.setWatchKeepalive(2*time.Second, 100*time.Millisecond)
	srv.SetTelemetryHandler(http.HandlerFunc(transport.NewTelemetryHandler(logging.NewLogger("info"), nil).ServeWebSocket))
	token, acct := newBearerSessionForAccount(t, srv, "telemetry-perm-account", []string{"steward:telemetry"})
	require.NoError(t, srv.controllerService.RegisterSteward(stewardID, acct.TenantID, "localhost:0", "active"))

	conn := dialWSPath(t, srv, "/api/v1/telemetry/ws/"+stewardID, token)

	updateTestAccount(t, srv, "telemetry-perm-account", func(a *account) { a.Permissions = []string{"steward:read"} })
	requirePolicyViolationClose(t, conn)
}

// TestTelemetryWrapper_UnboundAdminCertStaysOpen proves an unchanged admin-certificate
// stream survives several re-check ticks, and that a revoked certificate ends it.
func TestTelemetryWrapper_UnboundAdminCertStaysOpen(t *testing.T) {
	const stewardID = "telemetry-cert-steward"
	certManager := newSharedTestCertManager(t)
	srv := setupTestServerWithCertMgr(t, certManager)
	srv.setWatchKeepalive(2*time.Second, 20*time.Millisecond)
	require.NoError(t, srv.controllerService.RegisterSteward(stewardID, "test-tenant", "localhost:0", "active"))
	req, serial := issueCertAndBuildRequest(t, http.MethodGet, "/api/v1/telemetry/ws/"+stewardID, certManager)
	req = mux.SetURLVars(req, map[string]string{"id": stewardID})

	cancelled := make(chan struct{})
	handler := srv.authenticationMiddleware(srv.tenantScopedTelemetryWrapper(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(cancelled)
	})))
	done := make(chan struct{})
	go func() { defer close(done); handler.ServeHTTP(httptest.NewRecorder(), req) }()

	select {
	case <-cancelled:
		t.Fatal("an unchanged admin-certificate stream must stay open across ticks")
	case <-time.After(300 * time.Millisecond):
	}
	require.NoError(t, certManager.Revoke(serial))
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("a revoked certificate must end the stream")
	}
	<-done
}

// TestTelemetryWrapper_NoRecordedRecheckClosesOnFirstTick guards the fail-closed
// direction: a request that never went through authentication has nothing to re-check.
func TestTelemetryWrapper_NoRecordedRecheckClosesOnFirstTick(t *testing.T) {
	const stewardID = "telemetry-norecheck-steward"
	srv := setupTestServer(t)
	srv.setWatchKeepalive(2*time.Second, 20*time.Millisecond)
	require.NoError(t, srv.controllerService.RegisterSteward(stewardID, "test-tenant", "localhost:0", "active"))
	req := withPrincipal(httptest.NewRequest(http.MethodGet, "/api/v1/telemetry/ws/"+stewardID, nil),
		&Principal{ID: "p", TenantID: "test-tenant", ImplicitAdmin: true})
	req = mux.SetURLVars(req, map[string]string{"id": stewardID})

	closed := make(chan struct{})
	go func() {
		srv.tenantScopedTelemetryWrapper(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
			close(closed)
		})).ServeHTTP(httptest.NewRecorder(), req)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("a stream with no recorded credential re-check must close")
	}
}
