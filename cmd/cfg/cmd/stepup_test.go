// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- parseStepUpHeader ---

func TestParseStepUpHeader(t *testing.T) {
	tests := []struct {
		name           string
		header         string
		wantRequired   string
		wantPresence   bool
		wantPermission string
	}{
		{
			name:           "full header with presence and permission",
			header:         `CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="module:approve"`,
			wantRequired:   "strong",
			wantPresence:   true,
			wantPermission: "module:approve",
		},
		{
			name:         "assurance only no presence",
			header:       `CFGMS-StepUp realm="cfgms", required="strong"`,
			wantRequired: "strong",
			wantPresence: false,
		},
		{
			name:         "elevated assurance level",
			header:       `CFGMS-StepUp required="elevated"`,
			wantRequired: "elevated",
			wantPresence: false,
		},
		{
			name:         "scheme only uses default",
			header:       `CFGMS-StepUp`,
			wantRequired: "strong",
			wantPresence: false,
		},
		{
			name:         "presence not required",
			header:       `CFGMS-StepUp realm="cfgms", required="strong", presence="discouraged"`,
			wantRequired: "strong",
			wantPresence: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotPresence, gotPermission := parseStepUpHeader(tt.header)
			assert.Equal(t, tt.wantRequired, got)
			assert.Equal(t, tt.wantPresence, gotPresence)
			assert.Equal(t, tt.wantPermission, gotPermission)
		})
	}
}

// --- Required test: non-interactive + CFGMS-StepUp → actionable error, no infinite retry ---

func TestStepUp_NonInteractive_ProducesActionableError(t *testing.T) {
	origTerm := isTerminalFn
	isTerminalFn = func() bool { return false }
	defer func() { isTerminalFn = origTerm }()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="module:approve"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	var client *APIClient
	cfg := &APIClientConfig{
		BaseURL:     server.URL,
		TLSInsecure: true,
		OnStepUpRequired: func(wwwAuth, method, path string, bodyBytes []byte) (string, error) {
			return defaultStepUpHandler(client)(wwwAuth, method, path, bodyBytes)
		},
	}
	var err error
	client, err = NewAPIClient(cfg)
	require.NoError(t, err)

	_, err = client.doRequest(context.Background(), "GET", "/api/v1/anything", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "step-up required")
	assert.Contains(t, err.Error(), "strong")
	assert.Contains(t, err.Error(), "mTLS-authenticated session")
	// Exactly one request — no retry loop, no hanging.
	assert.Equal(t, 1, requestCount, "must not retry after step-up error in non-interactive mode")
}

// --- Required test: plain 401 (no CFGMS-StepUp) falls through to onUnauthorized ---

func TestStepUp_Plain401_FallsToOnUnauthorized(t *testing.T) {
	fallbackCalled := false
	fallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalled = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tokens":[],"total":0}`))
	}))
	defer fallbackServer.Close()

	stepUpCalled := false
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Plain 401 with no WWW-Authenticate header — session expired/revoked path.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer primaryServer.Close()

	fallbackClient, err := NewAPIClient(&APIClientConfig{
		BaseURL:     fallbackServer.URL,
		TLSInsecure: true,
	})
	require.NoError(t, err)

	cfg := &APIClientConfig{
		BaseURL:     primaryServer.URL,
		TLSInsecure: true,
		OnUnauthorized: func() (*APIClient, error) {
			return fallbackClient, nil
		},
		OnStepUpRequired: func(wwwAuth, method, path string, bodyBytes []byte) (string, error) {
			stepUpCalled = true
			return "", nil
		},
	}
	client, err := NewAPIClient(cfg)
	require.NoError(t, err)

	_, err = client.ListTokens(context.Background(), "")
	require.NoError(t, err, "fallback client should succeed")
	assert.True(t, fallbackCalled, "onUnauthorized fallback must be used for plain 401")
	assert.False(t, stepUpCalled, "onStepUpRequired must not fire for a plain 401 without CFGMS-StepUp header")
}

// --- Interactive + presence required: browser flow is called, token is returned, request retried ---

func TestStepUp_Interactive_PresenceRequired_RetrigesWithToken(t *testing.T) {
	origTerm := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = origTerm }()

	const testToken = "test-presence-token-xyz"
	origFlow := presenceBrowserFlowFn
	presenceBrowserFlowFn = func(_ *APIClient, _, _ string, _ []byte, _ string) (string, error) {
		return testToken, nil
	}
	defer func() { presenceBrowserFlowFn = origFlow }()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.Header.Get("X-Presence-Token") == testToken {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tokens":[],"total":0}`))
			return
		}
		w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="module:approve"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	var client *APIClient
	cfg := &APIClientConfig{
		BaseURL:     server.URL,
		TLSInsecure: true,
		OnStepUpRequired: func(wwwAuth, method, path string, bodyBytes []byte) (string, error) {
			return defaultStepUpHandler(client)(wwwAuth, method, path, bodyBytes)
		},
	}
	var err error
	client, err = NewAPIClient(cfg)
	require.NoError(t, err)

	_, err = client.ListTokens(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, 2, requestCount, "must retry original request once with presence token")
}

// --- Interactive + no presence: assurance-level step-up fails with actionable error ---

func TestStepUp_Interactive_NoPresence_FailsWithActionableError(t *testing.T) {
	origTerm := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = origTerm }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No presence="required" — assurance-level challenge only.
		w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	var client *APIClient
	cfg := &APIClientConfig{
		BaseURL:     server.URL,
		TLSInsecure: true,
		OnStepUpRequired: func(wwwAuth, method, path string, bodyBytes []byte) (string, error) {
			return defaultStepUpHandler(client)(wwwAuth, method, path, bodyBytes)
		},
	}
	var err error
	client, err = NewAPIClient(cfg)
	require.NoError(t, err)

	_, err = client.doRequest(context.Background(), "GET", "/api/v1/anything", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "step-up required")
	assert.Contains(t, err.Error(), "strong")
	assert.Contains(t, err.Error(), "web UI")
}

// --- Interactive + presence required, but the challenge names no permission ---

func TestStepUp_Interactive_PresenceRequired_NoPermission_FailsWithActionableError(t *testing.T) {
	origTerm := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = origTerm }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// presence="required" but no permission= — an older controller, or a malformed
		// challenge. The relay cannot be lodged without knowing what it is lodging for.
		w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong", presence="required"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	var client *APIClient
	cfg := &APIClientConfig{
		BaseURL:     server.URL,
		TLSInsecure: true,
		OnStepUpRequired: func(wwwAuth, method, path string, bodyBytes []byte) (string, error) {
			return defaultStepUpHandler(client)(wwwAuth, method, path, bodyBytes)
		},
	}
	var err error
	client, err = NewAPIClient(cfg)
	require.NoError(t, err)

	_, err = client.doRequest(context.Background(), "GET", "/api/v1/anything", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not name a permission")
}

// --- runPresenceBrowserFlow: the real CLI presence relay, exercised end to end ---

// presenceRelayTestServer wires the lodge/collect endpoints the relay drives, plus a
// hook for the caller to inspect what was lodged and to control the collect response
// sequence.
type presenceRelayTestServer struct {
	server     *httptest.Server
	lodgedBody LodgeCliPresenceRequestBody
	// lodgedRaw is the exact JSON the CLI put on the wire, so a test can assert on
	// fields the typed body does not declare.
	lodgedRaw    []byte
	collectCalls int
	// collectResponses is served in order, one per collect call; the last entry
	// repeats for any call beyond len(collectResponses).
	collectResponses []func(w http.ResponseWriter)
}

func newPresenceRelayTestServer(t *testing.T, requestID, userCode string, collectResponses ...func(w http.ResponseWriter)) *presenceRelayTestServer {
	t.Helper()
	rts := &presenceRelayTestServer{collectResponses: collectResponses}
	rts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/cli-presence/lodge":
			raw, readErr := io.ReadAll(r.Body)
			require.NoError(t, readErr)
			rts.lodgedRaw = raw
			require.NoError(t, json.Unmarshal(raw, &rts.lodgedBody))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			resp := map[string]interface{}{
				"data": LodgeCliPresenceResponse{
					RequestID: requestID,
					UserCode:  userCode,
					ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/cli-presence/"+requestID+"/collect":
			idx := rts.collectCalls
			if idx >= len(rts.collectResponses) {
				idx = len(rts.collectResponses) - 1
			}
			rts.collectCalls++
			rts.collectResponses[idx](w)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(rts.server.Close)
	return rts
}

func jsonCollectResponse(status, token string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]string{"status": status, "presence_token": token},
		})
	}
}

func TestRunPresenceBrowserFlow_Success(t *testing.T) {
	origBrowser := presenceOpenBrowserFn
	var openedURL string
	presenceOpenBrowserFn = func(u string) error { openedURL = u; return nil }
	defer func() { presenceOpenBrowserFn = origBrowser }()

	rts := newPresenceRelayTestServer(t, "cli-presence-abc", "WXYZ-1234",
		jsonCollectResponse("pending", ""),
		jsonCollectResponse("collected", "the-real-presence-token"),
	)

	client, err := NewAPIClient(&APIClientConfig{BaseURL: rts.server.URL, TLSInsecure: true})
	require.NoError(t, err)

	origInterval := presencePollInterval
	presencePollInterval = 5 * time.Millisecond
	defer func() { presencePollInterval = origInterval }()

	token, err := runPresenceBrowserFlow(client, "POST", "/api/v1/modules/approvals/test/approve", []byte(`{}`), "module:approve")
	require.NoError(t, err)
	assert.Equal(t, "the-real-presence-token", token)

	assert.Equal(t, "POST", rts.lodgedBody.Method)
	assert.Equal(t, "/api/v1/modules/approvals/test/approve", rts.lodgedBody.Path)
	assert.Equal(t, "module:approve", rts.lodgedBody.Permission)
	assert.Equal(t, sha256Hex([]byte(`{}`)), rts.lodgedBody.BodyHash)

	// The lodge body carries the four bound values and no display text: the
	// confirmation page renders the action from the binding the controller persisted,
	// so the CLI never gets to describe one action while binding another.
	assert.NotContains(t, string(rts.lodgedRaw), "description",
		"lodge must not send caller-authored consent text")

	assert.Contains(t, openedURL, "cli-presence-abc", "the opened URL must reference the lodged request ID")
	assert.Contains(t, openedURL, "/cli/presence", "the opened URL must be the controller's own relay page")
}

func TestRunPresenceBrowserFlow_Gone(t *testing.T) {
	rts := newPresenceRelayTestServer(t, "cli-presence-gone", "WXYZ-1234", func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusGone)
	})
	client, err := NewAPIClient(&APIClientConfig{BaseURL: rts.server.URL, TLSInsecure: true})
	require.NoError(t, err)

	origBrowser := presenceOpenBrowserFn
	presenceOpenBrowserFn = func(string) error { return nil }
	defer func() { presenceOpenBrowserFn = origBrowser }()

	_, err = runPresenceBrowserFlow(client, "POST", "/api/v1/modules/approvals/test/approve", nil, "module:approve")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already collected")
}

func TestRunPresenceBrowserFlow_Expired(t *testing.T) {
	rts := newPresenceRelayTestServer(t, "cli-presence-expired", "WXYZ-1234", jsonCollectResponse("expired", ""))
	client, err := NewAPIClient(&APIClientConfig{BaseURL: rts.server.URL, TLSInsecure: true})
	require.NoError(t, err)

	origBrowser := presenceOpenBrowserFn
	presenceOpenBrowserFn = func(string) error { return nil }
	defer func() { presenceOpenBrowserFn = origBrowser }()

	_, err = runPresenceBrowserFlow(client, "POST", "/api/v1/modules/approvals/test/approve", nil, "module:approve")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out waiting")
}
