// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordedReq struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

type crossingServer struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []recordedReq
}

func (s *crossingServer) requests() []recordedReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedReq(nil), s.reqs...)
}

// newCrossingServer records every request and answers with status/body.
func newCrossingServer(t *testing.T, status int, body string) *crossingServer {
	t.Helper()
	cs := &crossingServer{}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cs.mu.Lock()
		cs.reqs = append(cs.reqs, recordedReq{r.Method, r.URL.Path, r.Header.Clone(), b})
		cs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(cs.Close)
	return cs
}

const crossingJSON = `{"data":{"ID":"c-1","TenantID":"client-1","PrincipalID":"op-1","Kind":"grant","GrantedBy":"admin","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2999-01-01T00:00:00Z","RevokedAt":null}}`

func setupCrossingCmd(t *testing.T, url string) {
	t.Helper()
	origURL, origInsecure, origYes, origJSON := tenantAPIURL, tenantTLSInsecure, tenantCrossingYes, tenantJSONOutput
	origJust, origPrin, origDur := tenantBreakGlassJustification, tenantGrantPrincipal, tenantGrantDuration
	t.Cleanup(func() {
		tenantAPIURL, tenantTLSInsecure, tenantCrossingYes, tenantJSONOutput = origURL, origInsecure, origYes, origJSON
		tenantBreakGlassJustification, tenantGrantPrincipal, tenantGrantDuration = origJust, origPrin, origDur
	})
	t.Setenv("CFGMS_ADMIN_BUNDLE", "")
	tenantAPIURL = url
	tenantTLSInsecure = true
	tenantCrossingYes = true
	tenantJSONOutput = false
}

func TestBreakGlass_RequestShape(t *testing.T) {
	srv := newCrossingServer(t, http.StatusCreated, crossingJSON)
	setupCrossingCmd(t, srv.URL)
	tenantBreakGlassJustification = "P1 outage ticket 1234"

	out := captureStdout(t, func() {
		require.NoError(t, runTenantBreakGlass(tenantBreakGlassCmd, []string{"client-1"}))
	})

	reqs := srv.requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodPost, reqs[0].Method)
	assert.Equal(t, "/api/v1/tenants/client-1/break-glass", reqs[0].Path)
	assert.Equal(t, "P1 outage ticket 1234", reqs[0].Header.Get("X-Justification"))
	assert.Empty(t, reqs[0].Body)
	assert.Contains(t, out, "c-1")
	assert.Contains(t, out, "2999-01-01T00:00:00Z")
}

func TestBreakGlass_JustificationBounds(t *testing.T) {
	srv := newCrossingServer(t, http.StatusCreated, crossingJSON)
	setupCrossingCmd(t, srv.URL)

	for _, j := range []string{strings.Repeat("a", 9), strings.Repeat("a", 1001), "   short   "} {
		tenantBreakGlassJustification = j
		err := runTenantBreakGlass(tenantBreakGlassCmd, []string{"client-1"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "10-1000")
	}
	assert.Empty(t, srv.requests())
}

func TestGrant_DurationAndBody(t *testing.T) {
	srv := newCrossingServer(t, http.StatusCreated, crossingJSON)
	setupCrossingCmd(t, srv.URL)
	tenantGrantPrincipal = "op-1"

	tenantGrantDuration = "90m"
	_ = captureStdout(t, func() {
		require.NoError(t, runTenantGrant(tenantGrantCmd, []string{"client-1"}))
	})
	reqs := srv.requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodPost, reqs[0].Method)
	assert.Equal(t, "/api/v1/tenants/client-1/access-grants", reqs[0].Path)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(reqs[0].Body, &body))
	assert.Equal(t, "op-1", body["principal_id"])
	assert.EqualValues(t, 90, body["duration_minutes"])

	for _, d := range []string{"30s", "25h", "90m30s", "0m", "bogus"} {
		tenantGrantDuration = d
		require.Error(t, runTenantGrant(tenantGrantCmd, []string{"client-1"}), d)
	}
	assert.Len(t, srv.requests(), 1, "invalid durations must not reach the server")
}

func TestCrossingCommands_ErrorStatuses(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   string
	}{
		{401, `{"error":{"code":"UNAUTHORIZED","message":"session expired"}}`, "session expired"},
		{403, `{"error":{"code":"NOT_ROOT_SCOPED","message":"break-glass is only available to root-scoped callers"}}`, "root-scoped callers"},
		{404, `{"error":{"code":"TENANT_NOT_FOUND","message":"tenant not found"}}`, "tenant not found"},
	}
	runners := map[string]func() error{
		"break-glass": func() error {
			tenantBreakGlassJustification = "a long enough reason"
			return runTenantBreakGlass(tenantBreakGlassCmd, []string{"client-1"})
		},
		"grant": func() error {
			tenantGrantPrincipal, tenantGrantDuration = "op-1", "30m"
			return runTenantGrant(tenantGrantCmd, []string{"client-1"})
		},
		"crossings":    func() error { return runTenantCrossings(tenantCrossingsCmd, []string{"client-1"}) },
		"end-crossing": func() error { return runTenantEndCrossing(tenantEndCrossingCmd, []string{"client-1", "c-1"}) },
	}
	for name, run := range runners {
		for _, tc := range cases {
			srv := newCrossingServer(t, tc.status, tc.body)
			setupCrossingCmd(t, srv.URL)
			err := run()
			require.Error(t, err, name)
			assert.Contains(t, err.Error(), tc.want, name)
		}
	}
}

func TestCrossingError_ChallengeSuggestsBreakGlass(t *testing.T) {
	srv := newCrossingServer(t, http.StatusForbidden,
		`{"error":"tenant_crossing_required","required_assurance":"tenant-crossing","break_glass_endpoint":"/api/v1/tenants/client-1/break-glass"}`)
	setupCrossingCmd(t, srv.URL)
	err := runTenantCrossings(tenantCrossingsCmd, []string{"client-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_crossing_required")
	assert.Contains(t, err.Error(), "cfg tenant break-glass")
}

func TestCrossings_EmptyAndJSON(t *testing.T) {
	srv := newCrossingServer(t, http.StatusOK, `{"data":[]}`)
	setupCrossingCmd(t, srv.URL)

	out := captureStdout(t, func() {
		require.NoError(t, runTenantCrossings(tenantCrossingsCmd, []string{"client-1"}))
	})
	assert.Contains(t, out, "no active crossings")
	reqs := srv.requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodGet, reqs[0].Method)
	assert.Equal(t, "/api/v1/tenants/client-1/access-grants", reqs[0].Path)

	tenantJSONOutput = true
	out = captureStdout(t, func() {
		require.NoError(t, runTenantCrossings(tenantCrossingsCmd, []string{"client-1"}))
	})
	assert.JSONEq(t, `[]`, out)
}

func TestCrossings_ListsOnlyActive(t *testing.T) {
	var buf bytes.Buffer
	revoked := "2026-01-01T00:00:00Z"
	renderCrossings(&buf, []APITenantCrossing{
		{ID: "live", Kind: "grant", ExpiresAt: "2999-01-01T00:00:00Z"},
		{ID: "gone", Kind: "grant", ExpiresAt: "2999-01-01T00:00:00Z", RevokedAt: &revoked},
		{ID: "old", Kind: "break-glass", ExpiresAt: "2000-01-01T00:00:00Z"},
	}, time.Now())
	assert.Contains(t, buf.String(), "live")
	assert.NotContains(t, buf.String(), "gone")
	assert.NotContains(t, buf.String(), "old")
}

func TestCrossingMutations_RefuseWithoutYesOrTTY(t *testing.T) {
	srv := newCrossingServer(t, http.StatusCreated, crossingJSON)
	setupCrossingCmd(t, srv.URL)
	tenantCrossingYes = false
	tenantBreakGlassJustification = "a long enough reason"
	tenantGrantPrincipal, tenantGrantDuration = "op-1", "30m"

	assert.Error(t, runTenantBreakGlass(tenantBreakGlassCmd, []string{"client-1"}))
	assert.Error(t, runTenantGrant(tenantGrantCmd, []string{"client-1"}))
	assert.Error(t, runTenantEndCrossing(tenantEndCrossingCmd, []string{"client-1", "c-1"}))
	assert.Empty(t, srv.requests())
}

func TestEndCrossing_SendsDelete(t *testing.T) {
	srv := newCrossingServer(t, http.StatusOK, crossingJSON)
	setupCrossingCmd(t, srv.URL)

	out := captureStdout(t, func() {
		require.NoError(t, runTenantEndCrossing(tenantEndCrossingCmd, []string{"client-1", "c-1"}))
	})
	reqs := srv.requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodDelete, reqs[0].Method)
	assert.Equal(t, "/api/v1/tenants/client-1/access-grants/c-1", reqs[0].Path)
	assert.Contains(t, out, "crossing ended")
}

func TestBreakGlass_StepUpReplayKeepsJustification(t *testing.T) {
	var mu sync.Mutex
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		n := len(seen)
		mu.Unlock()
		if n == 1 {
			w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(crossingJSON))
	}))
	defer srv.Close()

	client, err := NewAPIClient(&APIClientConfig{
		BaseURL: srv.URL,
		OnStepUpRequired: func(_, _, _ string, _ []byte) (string, error) {
			return "presence-token", nil
		},
	})
	require.NoError(t, err)

	_, _, err = client.BreakGlassTenant(t.Context(), "client-1", "P1 outage ticket 1234")
	require.NoError(t, err)
	require.Len(t, seen, 2)
	assert.Equal(t, "P1 outage ticket 1234", seen[1].Get("X-Justification"))
	assert.Equal(t, "presence-token", seen[1].Get("X-Presence-Token"))
}
