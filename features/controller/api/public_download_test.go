// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPublicDownloadGuardConfig(now func() time.Time) publicDownloadGuardConfig {
	return publicDownloadGuardConfig{
		requestsPerWindow: 100,
		window:            time.Minute,
		maxPerSource:      1,
		maxGlobal:         2,
		maxTrackedSources: 10,
		now:               now,
	}
}

func TestPublicDownloadLoadGuardRateAndConcurrencyBudgets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("rate budget resets only after window", func(t *testing.T) {
		cfg := testPublicDownloadGuardConfig(func() time.Time { return now })
		cfg.requestsPerWindow = 2
		guard := newPublicDownloadGuard(cfg)

		for range 2 {
			release, status, _ := guard.acquire("192.0.2.10")
			require.NotNil(t, release)
			assert.Zero(t, status)
			release()
		}
		release, status, retry := guard.acquire("192.0.2.10")
		assert.Nil(t, release)
		assert.Equal(t, http.StatusTooManyRequests, status)
		assert.Equal(t, 60, retry)

		now = now.Add(time.Minute)
		release, status, _ = guard.acquire("192.0.2.10")
		require.NotNil(t, release)
		assert.Zero(t, status)
		release()
	})

	t.Run("per-source and global inflight budgets are independent", func(t *testing.T) {
		guard := newPublicDownloadGuard(testPublicDownloadGuardConfig(func() time.Time { return now }))

		releaseA, _, _ := guard.acquire("192.0.2.1")
		require.NotNil(t, releaseA)
		defer releaseA()

		release, status, retry := guard.acquire("192.0.2.1")
		assert.Nil(t, release)
		assert.Equal(t, http.StatusTooManyRequests, status)
		assert.Equal(t, 1, retry)

		releaseB, _, _ := guard.acquire("192.0.2.2")
		require.NotNil(t, releaseB)
		defer releaseB()

		release, status, _ = guard.acquire("192.0.2.3")
		assert.Nil(t, release)
		assert.Equal(t, http.StatusTooManyRequests, status)
	})
}

func TestPublicDownloadGuardBoundsSourceTracking(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cfg := testPublicDownloadGuardConfig(func() time.Time { return now })
	cfg.maxTrackedSources = 2
	guard := newPublicDownloadGuard(cfg)

	for _, source := range []string{"192.0.2.1", "192.0.2.2"} {
		release, _, _ := guard.acquire(source)
		require.NotNil(t, release)
		release()
	}
	release, status, _ := guard.acquire("192.0.2.3")
	assert.Nil(t, release)
	assert.Equal(t, http.StatusTooManyRequests, status)

	now = now.Add(time.Minute)
	release, status, _ = guard.acquire("192.0.2.3")
	require.NotNil(t, release)
	assert.Zero(t, status)
	release()
	assert.LessOrEqual(t, len(guard.sources), cfg.maxTrackedSources)
}

func TestPublicDownloadLoadCacheCoalescesAndBoundsBuilds(t *testing.T) {
	cache := newPublicDownloadCache()
	cache.maxItem = 8
	cache.maxBytes = 12
	cache.maxEntries = 2

	var builds atomic.Int32
	start := make(chan struct{})
	build := func() (*publicDownloadAsset, error) {
		builds.Add(1)
		<-start
		return newPublicDownloadAsset([]byte("12345678"), "application/octet-stream", "", "no-cache"), nil
	}

	const callers = 16
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			asset, err := cache.getOrBuild(context.Background(), "same", build)
			if err == nil && string(asset.body) != "12345678" {
				err = assert.AnError
			}
			errs <- err
		}()
	}
	require.Eventually(t, func() bool { return builds.Load() == 1 }, time.Second, time.Millisecond)
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), builds.Load(), "one cache miss must perform one build")

	_, err := cache.getOrBuild(context.Background(), "too-large", func() (*publicDownloadAsset, error) {
		return newPublicDownloadAsset([]byte("123456789"), "application/octet-stream", "", "no-cache"), nil
	})
	require.ErrorIs(t, err, errPublicDownloadTooLarge)

	_, err = cache.getOrBuild(context.Background(), "nil-asset", func() (*publicDownloadAsset, error) {
		return nil, nil
	})
	require.EqualError(t, err, "public download builder returned no asset")

	failedBuilds := 0
	_, err = cache.getOrBuild(context.Background(), "failed-asset", func() (*publicDownloadAsset, error) {
		failedBuilds++
		return newPublicDownloadAsset([]byte("stale"), "application/octet-stream", "", "no-cache"), assert.AnError
	})
	require.ErrorIs(t, err, assert.AnError)
	_, err = cache.getOrBuild(context.Background(), "failed-asset", func() (*publicDownloadAsset, error) {
		failedBuilds++
		return newPublicDownloadAsset([]byte("fresh"), "application/octet-stream", "", "no-cache"), nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, failedBuilds, "a failed build must not populate the cache")

	_, err = cache.getOrBuild(context.Background(), "second", func() (*publicDownloadAsset, error) {
		return newPublicDownloadAsset([]byte("abcdef"), "application/octet-stream", "", "no-cache"), nil
	})
	require.NoError(t, err)
	cache.mu.Lock()
	assert.LessOrEqual(t, cache.totalBytes, cache.maxBytes)
	assert.LessOrEqual(t, len(cache.entries), cache.maxEntries)
	cache.mu.Unlock()
}

func TestServePublicDownloadValidatorsAndStrictRanges(t *testing.T) {
	asset := newPublicDownloadAsset(
		[]byte("0123456789"),
		"application/octet-stream",
		`attachment; filename="asset.bin"`,
		"public, max-age=300, must-revalidate",
	)

	t.Run("single range", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/asset", nil)
		req.Header.Set("Range", "bytes=2-5")
		rec := httptest.NewRecorder()
		servePublicDownload(rec, req, "asset.bin", asset)

		assert.Equal(t, http.StatusPartialContent, rec.Code)
		assert.Equal(t, "2345", rec.Body.String())
		assert.Equal(t, "bytes 2-5/10", rec.Header().Get("Content-Range"))
		assert.Equal(t, "bytes", rec.Header().Get("Accept-Ranges"))
	})

	t.Run("etag conditional", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/asset", nil)
		req.Header.Set("If-None-Match", asset.etag)
		rec := httptest.NewRecorder()
		servePublicDownload(rec, req, "asset.bin", asset)

		assert.Equal(t, http.StatusNotModified, rec.Code)
		assert.Empty(t, rec.Body.String())
	})

	for name, rangeValue := range map[string]string{
		"multiple":  "bytes=0-1,8-9",
		"malformed": "bytes=not-a-range",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/asset", nil)
			req.Header.Set("Range", rangeValue)
			rec := httptest.NewRecorder()
			servePublicDownload(rec, req, "asset.bin", asset)

			assert.Equal(t, http.StatusRequestedRangeNotSatisfiable, rec.Code)
			assert.NotEqual(t, "0123456789", rec.Body.String())
		})
	}
}

func TestPublicDownloadRoutesApplySuccessfulRequestBudget(t *testing.T) {
	server := setupTestServer(t)
	server.publicDownloadGuard.mu.Lock()
	server.publicDownloadGuard.cfg.requestsPerWindow = 1
	server.publicDownloadGuard.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/installer/download/linux/amd64", nil)
	first := httptest.NewRecorder()
	server.router.ServeHTTP(first, req)
	assert.Equal(t, http.StatusServiceUnavailable, first.Code)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/installer/download/linux/amd64", nil)
	second := httptest.NewRecorder()
	server.router.ServeHTTP(second, req)
	assert.Equal(t, http.StatusTooManyRequests, second.Code)
	assert.Equal(t, "60", second.Header().Get("Retry-After"))
	assert.Equal(t, "no-store", second.Header().Get("Cache-Control"))
}

func TestPublicDownloadTrustedProxyCannotRotateSpoofedLeftmostHop(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cfg := testPublicDownloadGuardConfig(func() time.Time { return now })
	cfg.requestsPerWindow = 1
	guard := newPublicDownloadGuard(cfg)

	_, trustedNet, err := net.ParseCIDR("192.168.1.0/24")
	require.NoError(t, err)
	handler := guard.middleware([]net.IPNet{*trustedNet}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	request := func(spoofed string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/download", nil)
		req.RemoteAddr = "192.168.1.10:443"
		req.Header.Set("X-Forwarded-For", spoofed+", 203.0.113.5")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	assert.Equal(t, http.StatusOK, request("198.51.100.1").Code)
	second := request("198.51.100.2")
	assert.Equal(t, http.StatusTooManyRequests, second.Code,
		"changing an attacker-controlled leftmost hop must not create a new source budget")
	assert.Equal(t, "no-store", second.Header().Get("Cache-Control"))
}
