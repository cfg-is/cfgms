// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- parseStepUpHeader ---

func TestParseStepUpHeader(t *testing.T) {
	tests := []struct {
		name         string
		header       string
		wantRequired string
		wantPresence bool
	}{
		{
			name:         "full header with presence",
			header:       `CFGMS-StepUp realm="cfgms", required="strong", presence="required"`,
			wantRequired: "strong",
			wantPresence: true,
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
			got, gotPresence := parseStepUpHeader(tt.header)
			assert.Equal(t, tt.wantRequired, got)
			assert.Equal(t, tt.wantPresence, gotPresence)
		})
	}
}

// --- Required test: non-interactive + CFGMS-StepUp → actionable error, no infinite retry ---
//
// AC: "Non-interactive (no TTY): fails immediately with an actionable error naming the
// required assurance level — never hangs waiting for input."
// AC: "[REQUIRED TEST] a mocked 401 + CFGMS-StepUp response with a mocked non-interactive
// environment produces the expected error text and does not retry indefinitely or block."

func TestStepUp_NonInteractive_ProducesActionableError(t *testing.T) {
	origTerm := isTerminalFn
	isTerminalFn = func() bool { return false }
	defer func() { isTerminalFn = origTerm }()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong", presence="required"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	var client *APIClient
	cfg := &APIClientConfig{
		BaseURL:     server.URL,
		TLSInsecure: true,
		OnStepUpRequired: func(wwwAuth string) (string, error) {
			return defaultStepUpHandler(client)(wwwAuth)
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
//
// AC: "[REQUIRED TEST] a mocked 401 without the CFGMS-StepUp header still falls through
// to the existing onUnauthorized bundle-auth path unchanged (regression test for the
// untouched case)."

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
		OnStepUpRequired: func(wwwAuth string) (string, error) {
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
	presenceBrowserFlowFn = func(_ *APIClient) (string, error) {
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
		w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong", presence="required"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	var client *APIClient
	cfg := &APIClientConfig{
		BaseURL:     server.URL,
		TLSInsecure: true,
		OnStepUpRequired: func(wwwAuth string) (string, error) {
			return defaultStepUpHandler(client)(wwwAuth)
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
		OnStepUpRequired: func(wwwAuth string) (string, error) {
			return defaultStepUpHandler(client)(wwwAuth)
		},
	}
	var err error
	client, err = NewAPIClient(cfg)
	require.NoError(t, err)

	_, err = client.doRequest(context.Background(), "GET", "/api/v1/anything", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "step-up required")
	assert.Contains(t, err.Error(), "strong")
}
