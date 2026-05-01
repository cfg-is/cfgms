// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package saas

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGraphHTTPClient_WithinBurst_NoDelay(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// 10 requests within burst=20 — all fit in the token bucket; no rate-limiting delay
	client := NewGraphHTTPClient(10, 20)

	start := time.Now()
	for i := 0; i < 10; i++ {
		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	}
	assert.Less(t, time.Since(start), 500*time.Millisecond,
		"10 requests within burst=20 should complete without rate-limiting delay")
}

func TestNewGraphHTTPClient_ExceedBurst_DelaysRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// 100 rps, burst=5: 25 requests → first 5 free, next 20 at 100/s ≈ 200ms total delay
	client := NewGraphHTTPClient(100, 5)

	start := time.Now()
	for i := 0; i < 25; i++ {
		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	}
	elapsed := time.Since(start)
	// 20 extra requests at 100 rps = 200ms expected; assert at least 100ms as a conservative floor
	assert.Greater(t, elapsed, 100*time.Millisecond,
		"25 requests with burst=5 at 100 rps should be delayed by the rate limiter")
}

func TestNewGraphHTTPClient_HasTimeout(t *testing.T) {
	client := NewGraphHTTPClient(10, 20)
	assert.Greater(t, client.Timeout, time.Duration(0), "client must have a non-zero timeout")
}

func TestNewGraphHTTPClient_HasRateLimitedTransport(t *testing.T) {
	client := NewGraphHTTPClient(10, 20)
	_, ok := client.Transport.(*rateLimitedTransport)
	assert.True(t, ok, "client transport must be a *rateLimitedTransport")
}
