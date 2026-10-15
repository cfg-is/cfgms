// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const userBody = `{"id":"u1","userPrincipalName":"a@example.com"}`

func TestHTTPClient_RetriesAfterRetryAfterHeader(t *testing.T) {
	var mu sync.Mutex
	var times []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		n := len(times)
		mu.Unlock()
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":"TooManyRequests","message":"slow down"}}`))
			return
		}
		_, _ = w.Write([]byte(userBody))
	}))
	defer srv.Close()

	c := NewRateLimitedHTTPClient(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	_, err := c.GetUser(context.Background(), testToken(), "a@example.com")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, times, 2)
	assert.GreaterOrEqual(t, times[1].Sub(times[0]), time.Second)
}

func TestHTTPClient_RateLimiterBoundsSustainedLoad(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		_, _ = w.Write([]byte(userBody))
	}))
	defer srv.Close()

	c := NewRateLimitedHTTPClient(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()),
		WithRateLimiter(NewTokenBucketRateLimiter(2, 10)))
	start := time.Now()
	for i := 0; i < 12; i++ {
		_, err := c.GetUser(context.Background(), testToken(), "a@example.com")
		require.NoError(t, err)
	}
	assert.Equal(t, int32(12), atomic.LoadInt32(&count))
	assert.GreaterOrEqual(t, time.Since(start), 800*time.Millisecond)
}

func TestHTTPClient_RetryAttemptsAreRateLimited(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&count, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(userBody))
	}))
	defer srv.Close()

	rl := &countingLimiter{}
	c := NewRateLimitedHTTPClient(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithRateLimiter(rl),
		WithRetryConfig(&RetryConfig{MaxRetries: 2, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond, BackoffMultiplier: 1}))
	_, err := c.GetUser(context.Background(), testToken(), "a@example.com")
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&rl.waits))
}

type countingLimiter struct{ waits int32 }

func (l *countingLimiter) Wait(ctx context.Context) error { atomic.AddInt32(&l.waits, 1); return nil }
func (l *countingLimiter) Allow() bool                    { return true }
func (l *countingLimiter) Reset()                         {}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, 5*time.Second, parseRetryAfter("5", now))
	assert.Equal(t, 30*time.Second, parseRetryAfter(now.Add(30*time.Second).Format(http.TimeFormat), now))
	assert.Zero(t, parseRetryAfter("", now))
	assert.Zero(t, parseRetryAfter("soon", now))
	assert.Zero(t, parseRetryAfter("-3", now))
	assert.Zero(t, parseRetryAfter(now.Add(-time.Hour).Format(http.TimeFormat), now))
}

func TestParseRetryAfter_CapsHugeValues(t *testing.T) {
	now := time.Now()
	assert.Equal(t, 24*time.Hour, parseRetryAfter("9223372036854775807", now))
}
