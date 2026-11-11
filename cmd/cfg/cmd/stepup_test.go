// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
// sequence. The handler goroutines can outlive the client call that triggered them
// (a cancelled poll abandons its in-flight request), so every field a handler writes
// is guarded by mu and tests read it through Lodged and CollectCalls.
type presenceRelayTestServer struct {
	server *httptest.Server

	mu         sync.Mutex
	lodgedBody LodgeCliPresenceRequestBody
	// lodgedRaw is the exact JSON the CLI put on the wire, so a test can assert on
	// fields the typed body does not declare.
	lodgedRaw    []byte
	collectCalls int

	// collectResponses is served in order, one per collect call; the last entry
	// repeats for any call beyond len(collectResponses).
	collectResponses []func(w http.ResponseWriter)
}

// Lodged returns a copy of the lodge body the CLI sent and the raw JSON it put on the wire.
func (rts *presenceRelayTestServer) Lodged() (LodgeCliPresenceRequestBody, []byte) {
	rts.mu.Lock()
	defer rts.mu.Unlock()
	return rts.lodgedBody, append([]byte(nil), rts.lodgedRaw...)
}

// CollectCalls returns the number of collect requests the handler has started serving.
func (rts *presenceRelayTestServer) CollectCalls() int {
	rts.mu.Lock()
	defer rts.mu.Unlock()
	return rts.collectCalls
}

func newPresenceRelayTestServer(t *testing.T, requestID, userCode string, collectResponses ...func(w http.ResponseWriter)) *presenceRelayTestServer {
	t.Helper()
	rts := &presenceRelayTestServer{collectResponses: collectResponses}
	rts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/cli-presence/lodge":
			raw, readErr := io.ReadAll(r.Body)
			require.NoError(t, readErr)
			var body LodgeCliPresenceRequestBody
			require.NoError(t, json.Unmarshal(raw, &body))
			rts.mu.Lock()
			rts.lodgedRaw = raw
			rts.lodgedBody = body
			rts.mu.Unlock()
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
			rts.mu.Lock()
			idx := rts.collectCalls
			if idx >= len(rts.collectResponses) {
				idx = len(rts.collectResponses) - 1
			}
			rts.collectCalls++
			rts.mu.Unlock()
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
	origTerm := isTerminalFn
	isTerminalFn = func() bool { return true }
	defer func() { isTerminalFn = origTerm }()

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

	lodgedBody, lodgedRaw := rts.Lodged()
	assert.Equal(t, "POST", lodgedBody.Method)
	assert.Equal(t, "/api/v1/modules/approvals/test/approve", lodgedBody.Path)
	assert.Equal(t, "module:approve", lodgedBody.Permission)
	assert.Equal(t, sha256Hex([]byte(`{}`)), lodgedBody.BodyHash)

	// The lodge body carries the four bound values and no display text: the
	// confirmation page renders the action from the binding the controller persisted,
	// so the CLI never gets to describe one action while binding another.
	assert.NotContains(t, string(lodgedRaw), "description",
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

// --- --no-browser: with a terminal, the URL and code are printed and no browser is launched ---

// captureStderr runs fn and returns what it wrote to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	func() {
		defer func() { os.Stderr = orig }()
		fn()
	}()
	require.NoError(t, w.Close())
	return <-done
}

// runTTYPresenceFlow runs the presence relay with a terminal and a recording browser
// opener, returning the stderr output and the URLs the opener was called with.
func runTTYPresenceFlow(t *testing.T) (stderr string, opened []string) {
	t.Helper()
	origTerm, origBrowser, origInterval := isTerminalFn, presenceOpenBrowserFn, presencePollInterval
	t.Cleanup(func() {
		isTerminalFn, presenceOpenBrowserFn, presencePollInterval = origTerm, origBrowser, origInterval
	})
	isTerminalFn = func() bool { return true }
	presenceOpenBrowserFn = func(u string) error { opened = append(opened, u); return nil }
	presencePollInterval = 5 * time.Millisecond

	rts := newPresenceRelayTestServer(t, "cli-presence-nobrowser", "WXYZ-1234",
		jsonCollectResponse("collected", "tok"))
	client, err := NewAPIClient(&APIClientConfig{BaseURL: rts.server.URL, TLSInsecure: true})
	require.NoError(t, err)

	stderr = captureStderr(t, func() {
		token, flowErr := runPresenceBrowserFlow(client, "POST", "/api/v1/modules/approvals/test/approve", []byte(`{}`), "module:approve")
		require.NoError(t, flowErr)
		assert.Equal(t, "tok", token)
	})
	return stderr, opened
}

func setPresenceNoBrowserFlag(t *testing.T, v bool) {
	t.Helper()
	orig := presenceNoBrowser
	t.Cleanup(func() { presenceNoBrowser = orig })
	presenceNoBrowser = v
}

func TestRunPresenceBrowserFlow_NoBrowserFlag_TTY_PrintsURLWithoutLaunch(t *testing.T) {
	setPresenceNoBrowserFlag(t, true)
	t.Setenv("CFGMS_NO_BROWSER", "")

	stderr, opened := runTTYPresenceFlow(t)

	assert.Empty(t, opened, "--no-browser must suppress the browser launch even with a terminal")
	assert.Contains(t, stderr, "Code: WXYZ-1234")
	assert.Contains(t, stderr, "Approve this action by visiting: ")
	assert.Contains(t, stderr, "cli-presence-nobrowser")
	assert.Contains(t, stderr, "/cli/presence")
}

func TestRunPresenceBrowserFlow_NoBrowserEnv_TTY_PrintsURLWithoutLaunch(t *testing.T) {
	setPresenceNoBrowserFlag(t, false)
	t.Setenv("CFGMS_NO_BROWSER", "1")

	stderr, opened := runTTYPresenceFlow(t)

	assert.Empty(t, opened, "CFGMS_NO_BROWSER must suppress the browser launch even with a terminal")
	assert.Contains(t, stderr, "Code: WXYZ-1234")
	assert.Contains(t, stderr, "Approve this action by visiting: ")
}

func TestRunPresenceBrowserFlow_NoBrowserNotSet_TTY_LaunchesBrowser(t *testing.T) {
	setPresenceNoBrowserFlag(t, false)
	t.Setenv("CFGMS_NO_BROWSER", "")

	stderr, opened := runTTYPresenceFlow(t)

	require.Len(t, opened, 1, "without the flag or env a terminal session still launches the browser")
	assert.Contains(t, opened[0], "cli-presence-nobrowser")
	assert.Contains(t, stderr, "Code: WXYZ-1234")
}

func TestPresenceBrowserSuppressed_EnvValues(t *testing.T) {
	setPresenceNoBrowserFlag(t, false)
	for value, want := range map[string]bool{"": false, "0": false, "1": true, "true": true, "yes": true} {
		t.Run("env="+value, func(t *testing.T) {
			t.Setenv("CFGMS_NO_BROWSER", value)
			assert.Equal(t, want, presenceBrowserSuppressed())
		})
	}
}

// The root persistent --no-browser flag and cfg login's own local --no-browser share a
// name; the local flag shadows the persistent one for login, so each command binds to its
// own variable.
func TestNoBrowserFlag_RootPersistentAndLoginLocalCoexist(t *testing.T) {
	pf := rootCmd.PersistentFlags().Lookup("no-browser")
	require.NotNil(t, pf, "root must declare a persistent --no-browser flag")

	t.Cleanup(func() {
		loginNoBrowser, presenceNoBrowser = false, false
		_ = loginCmd.Flags().Set("no-browser", "false")
		_ = rootCmd.PersistentFlags().Set("no-browser", "false")
	})

	require.NoError(t, loginCmd.ParseFlags([]string{"--no-browser"}))
	assert.True(t, loginNoBrowser, "cfg login --no-browser still sets login's own flag")
	assert.False(t, presenceNoBrowser, "the login-local flag shadows the root persistent one")

	require.NoError(t, rootCmd.PersistentFlags().Parse([]string{"--no-browser"}))
	assert.True(t, presenceNoBrowser, "the root persistent flag sets the presence relay flag")
}

// --- No terminal: the presence relay still runs, printing the URL and polling, never opening a browser ---

const noTTYPresenceToken = "collected-no-tty-token"

// noTTYPresenceClient wires one httptest server that serves both the presence relay
// endpoints (through a real presenceRelayTestServer) and a guarded endpoint that answers
// the presence challenge until a request carries noTTYPresenceToken. The client's
// step-up handler is defaultStepUpHandler. The test state is: no TTY, a browser opener
// that fails the test if called, and a short poll interval.
func noTTYPresenceClient(t *testing.T, collectResponses ...func(w http.ResponseWriter)) (client *APIClient, rts *presenceRelayTestServer, guardedCalls *atomic.Int32) {
	t.Helper()
	origTerm, origBrowser, origInterval := isTerminalFn, presenceOpenBrowserFn, presencePollInterval
	t.Cleanup(func() {
		isTerminalFn, presenceOpenBrowserFn, presencePollInterval = origTerm, origBrowser, origInterval
	})
	isTerminalFn = func() bool { return false }
	presenceOpenBrowserFn = func(u string) error {
		t.Errorf("a browser must not be launched without a terminal (url %q)", u)
		return nil
	}
	presencePollInterval = 5 * time.Millisecond

	rts = newPresenceRelayTestServer(t, "cli-presence-notty", "WXYZ-1234", collectResponses...)
	relayHandler := rts.server.Config.Handler
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/cli-presence/") {
			relayHandler.ServeHTTP(w, r)
			return
		}
		calls.Add(1)
		if r.Header.Get("X-Presence-Token") == noTTYPresenceToken {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tokens":[],"total":0}`))
			return
		}
		w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="module:approve"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	var err error
	client, err = NewAPIClient(&APIClientConfig{
		BaseURL:     server.URL,
		TLSInsecure: true,
		OnStepUpRequired: func(wwwAuth, method, path string, bodyBytes []byte) (string, error) {
			return defaultStepUpHandler(client)(wwwAuth, method, path, bodyBytes)
		},
	})
	require.NoError(t, err)
	return client, rts, calls
}

func TestStepUp_NoTTY_PresenceRequired_RunsRelayWithoutBrowser(t *testing.T) {
	client, rts, guardedCalls := noTTYPresenceClient(t,
		jsonCollectResponse("pending", ""),
		jsonCollectResponse("collected", noTTYPresenceToken),
	)

	_, err := client.ListTokens(context.Background(), "")
	require.NoError(t, err, "the original request is replayed with the collected token")

	assert.Equal(t, int32(2), guardedCalls.Load(), "the request is sent once, then replayed once with the collected token")
	lodgedBody, _ := rts.Lodged()
	assert.Equal(t, "module:approve", lodgedBody.Permission, "the presence request is lodged for the named permission")
	assert.Equal(t, 2, rts.CollectCalls(), "the relay polls until the request is confirmed")
	// A browser launch fails the test inside the presenceOpenBrowserFn the harness installs.
}

func TestStepUp_NoTTY_PresenceRequired_NoPermission_Errors(t *testing.T) {
	origTerm, origFlow := isTerminalFn, presenceBrowserFlowFn
	isTerminalFn = func() bool { return false }
	presenceBrowserFlowFn = func(*APIClient, string, string, []byte, string) (string, error) {
		t.Error("the relay must not start when the challenge names no permission")
		return "", nil
	}
	defer func() { isTerminalFn, presenceBrowserFlowFn = origTerm, origFlow }()

	_, err := defaultStepUpHandler(nil)(`CFGMS-StepUp realm="cfgms", required="strong", presence="required"`, "GET", "/api/v1/anything", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not name a permission")
}

func TestStepUp_NoTTY_NonPresenceStrong_KeepsNonInteractiveError(t *testing.T) {
	origTerm, origFlow := isTerminalFn, presenceBrowserFlowFn
	isTerminalFn = func() bool { return false }
	presenceBrowserFlowFn = func(*APIClient, string, string, []byte, string) (string, error) {
		t.Error("the relay must not start for a non-presence challenge")
		return "", nil
	}
	defer func() { isTerminalFn, presenceBrowserFlowFn = origTerm, origFlow }()

	_, err := defaultStepUpHandler(nil)(`CFGMS-StepUp realm="cfgms", required="strong"`, "GET", "/api/v1/anything", nil)
	require.Error(t, err)
	assert.EqualError(t, err, "step-up required: strong assurance needed for this action; re-run interactively or use an mTLS-authenticated session")
}

func TestStepUp_NoTTY_PresenceRequired_PollTimeout(t *testing.T) {
	client, rts, guardedCalls := noTTYPresenceClient(t, jsonCollectResponse("pending", ""))

	origWait := presenceWaitTimeout
	presenceWaitTimeout = 50 * time.Millisecond
	defer func() { presenceWaitTimeout = origWait }()

	_, err := client.ListTokens(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, errPresenceTimedOut)
	assert.Equal(t, int32(1), guardedCalls.Load(), "the request is not replayed without a collected token")
	assert.Positive(t, rts.CollectCalls(), "the relay polled before timing out")
}

func TestStepUp_NoTTY_PresenceRequired_PollCancelled(t *testing.T) {
	origSignal := presenceSignalContextFn
	var cancelPoll context.CancelFunc
	presenceSignalContextFn = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancelPoll = cancel
		return ctx, cancel
	}
	defer func() { presenceSignalContextFn = origSignal }()

	// The first collect call simulates an operator interrupt (Ctrl-C) mid-poll.
	client, _, guardedCalls := noTTYPresenceClient(t, func(w http.ResponseWriter) {
		cancelPoll()
		jsonCollectResponse("pending", "")(w)
	})

	_, err := client.ListTokens(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "presence ceremony interrupted")
	assert.Equal(t, int32(1), guardedCalls.Load(), "the guarded action is not retried after an interrupt")
}

// --- Tenant-crossing challenge: routed to the crossing remedy, never to step-up ---

// newCrossingChallengeClient builds a client wired to defaultStepUpHandler against a
// server answering every request with the controller's tenant-crossing 401 envelope.
func newCrossingChallengeClient(t *testing.T, body string) (*APIClient, *int) {
	t.Helper()
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="tenant-crossing"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	var client *APIClient
	var err error
	client, err = NewAPIClient(&APIClientConfig{
		BaseURL:     server.URL,
		TLSInsecure: true,
		OnStepUpRequired: func(wwwAuth, method, path string, bodyBytes []byte) (string, error) {
			return defaultStepUpHandler(client)(wwwAuth, method, path, bodyBytes)
		},
	})
	require.NoError(t, err)
	return client, &requestCount
}

func TestStepUp_TenantCrossing_NamesCrossingRemedy(t *testing.T) {
	const body = `{"error":"tenant_crossing_required","required_assurance":"tenant-crossing","break_glass_endpoint":"/api/v1/tenants/msp-a/break-glass","reason_categories":["account_recovery"]}`

	for _, interactive := range []bool{true, false} {
		origTerm, origFlow := isTerminalFn, presenceBrowserFlowFn
		isTerminalFn = func() bool { return interactive }
		flowCalled := false
		presenceBrowserFlowFn = func(*APIClient, string, string, []byte, string) (string, error) {
			flowCalled = true
			return "", nil
		}

		client, requestCount := newCrossingChallengeClient(t, body)
		_, err := client.doRequest(context.Background(), "GET", "/api/v1/anything", nil)
		isTerminalFn, presenceBrowserFlowFn = origTerm, origFlow

		require.Error(t, err, "interactive=%v", interactive)
		msg := err.Error()
		assert.Contains(t, msg, "tenant_crossing_required")
		assert.Contains(t, msg, "grant")
		assert.Contains(t, msg, "cfg tenant break-glass")
		assert.Contains(t, msg, "/api/v1/tenants/msp-a/break-glass")
		assert.NotContains(t, msg, "mTLS")
		assert.NotContains(t, msg, "web UI")
		assert.False(t, flowCalled, "presence relay must not run for a crossing challenge")
		assert.Equal(t, 1, *requestCount, "a crossing is not retried")
	}
}

func TestStepUp_TenantCrossing_WithoutBreakGlassEndpoint(t *testing.T) {
	for _, body := range []string{
		`{"error":"tenant_crossing_required","required_assurance":"tenant-crossing","reason_categories":[]}`,
		``,
		`not json`,
	} {
		origTerm := isTerminalFn
		isTerminalFn = func() bool { return true }
		client, _ := newCrossingChallengeClient(t, body)
		_, err := client.doRequest(context.Background(), "GET", "/api/v1/anything", nil)
		isTerminalFn = origTerm

		require.Error(t, err, "body %q", body)
		msg := err.Error()
		assert.Contains(t, msg, "grant", "body %q", body)
		assert.Contains(t, msg, "cfg tenant break-glass", "body %q", body)
		assert.NotContains(t, msg, "break-glass endpoint:", "body %q", body)
		for _, banned := range []string{"mTLS", "web UI", "log in again"} {
			assert.NotContains(t, msg, banned, "body %q", body)
		}
	}
}
