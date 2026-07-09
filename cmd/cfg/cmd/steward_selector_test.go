// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newResolveSelectorServer creates a test HTTP server that responds to
// POST /api/v1/fleet/resolve with the given steward list wrapped in the
// standard {"data": [...]} envelope.
func newResolveSelectorServer(t *testing.T, stewards []StewardInfo) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/fleet/resolve" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		envelope := struct {
			Data []StewardInfo `json:"data"`
		}{Data: stewards}
		if err := json.NewEncoder(w).Encode(envelope); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
}

// ---- resolveOrFailFast -------------------------------------------------------

func TestResolveOrFailFast_ZeroMatch_FailsWithClearError(t *testing.T) {
	srv := newResolveSelectorServer(t, []StewardInfo{})
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	_, err = resolveOrFailFast(context.Background(), client, "name:nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "matched no stewards")
	assert.Contains(t, err.Error(), `"name:nonexistent"`)
}

func TestResolveOrFailFast_NonZeroMatch_ReturnsMatches(t *testing.T) {
	fixtures := []StewardInfo{
		{ID: "s1", Status: "online"},
		{ID: "s2", Status: "online"},
	}
	srv := newResolveSelectorServer(t, fixtures)
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	matches, err := resolveOrFailFast(context.Background(), client, "all")
	require.NoError(t, err)
	require.Len(t, matches, 2)
	assert.Equal(t, "s1", matches[0].ID)
}

func TestResolveOrFailFast_ServerError_PropagatesError(t *testing.T) {
	// Verify that non-200 responses from the resolve endpoint surface as errors.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	_, err = resolveOrFailFast(context.Background(), client, "all")
	require.Error(t, err)
	// The error must not be silently swallowed.
	assert.NotEmpty(t, err.Error())
}

// ---- confirmMultiHost --------------------------------------------------------

func TestConfirmMultiHost(t *testing.T) {
	// Tests run in non-interactive environments (stdin is never a TTY),
	// so the non-TTY path is always exercised for multi-match cases.
	cases := []struct {
		name        string
		matches     []StewardInfo
		yes         bool
		wantErr     bool
		errContains []string
	}{
		{
			name:    "single match no-prompt",
			matches: []StewardInfo{{ID: "s1"}},
			yes:     false,
			wantErr: false,
		},
		{
			name:    "single match with yes no-prompt",
			matches: []StewardInfo{{ID: "s1"}},
			yes:     true,
			wantErr: false,
		},
		{
			name:    "zero matches no-op",
			matches: nil,
			yes:     false,
			wantErr: false,
		},
		{
			// AC4: --yes suppresses confirmation, never the 0-match error.
			// The 0-match error is owned by resolveOrFailFast; confirmMultiHost
			// with zero matches and yes=true is simply a no-op here.
			name:    "zero matches with yes no-op",
			matches: nil,
			yes:     true,
			wantErr: false,
		},
		{
			name:    "multi-match with yes flag proceeds on non-TTY",
			matches: []StewardInfo{{ID: "s1", TenantID: "acme"}, {ID: "s2", TenantID: "acme"}},
			yes:     true,
			wantErr: false,
		},
		{
			// A4: fails closed in non-interactive contexts without --yes.
			name:        "multi-match no-yes on non-TTY fails closed",
			matches:     []StewardInfo{{ID: "s1", TenantID: "acme"}, {ID: "s2", TenantID: "beta"}},
			yes:         false,
			wantErr:     true,
			errContains: []string{"2", "--yes"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := confirmMultiHost(tc.matches, tc.yes)
			if tc.wantErr {
				require.Error(t, err)
				for _, substr := range tc.errContains {
					assert.Contains(t, err.Error(), substr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ---- keyedOutput -------------------------------------------------------------

func TestKeyedOutput_MultiSteward_SuccessAndFailure(t *testing.T) {
	matches := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}
	payload := json.RawMessage(`{"detail":"ok"}`)
	results := map[string]fanOutResult{
		"host-a#s1": {Success: true, Payload: payload},
		"host-b#s2": {Success: false, Err: errors.New("connection refused")},
	}

	entries := keyedOutput(matches, results)
	require.Len(t, entries, 2)

	// Entries follow the same order as matches.
	assert.Equal(t, "host-a#s1", entries[0].Key)
	assert.True(t, entries[0].Success)
	assert.JSONEq(t, `{"detail":"ok"}`, string(entries[0].Payload))
	assert.Empty(t, entries[0].Error)

	assert.Equal(t, "host-b#s2", entries[1].Key)
	assert.False(t, entries[1].Success)
	assert.Equal(t, "connection refused", entries[1].Error)
}

func TestKeyedOutput_PartialFailure_AllRepresented(t *testing.T) {
	// Verify every steward entry appears in the output, success and failure alike.
	matches := []StewardInfo{{ID: "s1"}, {ID: "s2"}, {ID: "s3"}}
	results := map[string]fanOutResult{
		"#s1": {Success: true, Payload: json.RawMessage(`"done"`)},
		"#s2": {Success: false, Err: errors.New("timeout")},
		"#s3": {Success: true, Payload: json.RawMessage(`"done"`)},
	}

	entries := keyedOutput(matches, results)
	require.Len(t, entries, 3)

	var failures int
	for _, e := range entries {
		if !e.Success {
			failures++
		}
	}
	assert.Equal(t, 1, failures)
}

// ---- fanOutConcurrent --------------------------------------------------------

func TestFanOutConcurrent_ConcurrencyBound(t *testing.T) {
	// Verify that no more than fanOutConcurrencyBound goroutines execute the
	// action simultaneously. Uses a blocking channel receive to force
	// goroutines to remain in-flight while others try to start, giving
	// the Go scheduler a meaningful window to measure peak concurrency.
	const total = 50
	matches := make([]StewardInfo, total)
	for i := range matches {
		matches[i] = StewardInfo{ID: fmt.Sprintf("s%d", i)}
	}

	var inflight atomic.Int64
	var maxInflight atomic.Int64
	// unblock is closed once peak measurement is done so goroutines can finish.
	unblock := make(chan struct{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		fanOutConcurrent(context.Background(), matches, //nolint:errcheck
			func(ctx context.Context, s StewardInfo) (json.RawMessage, error) {
				current := inflight.Add(1)
				for {
					prev := maxInflight.Load()
					if current <= prev || maxInflight.CompareAndSwap(prev, current) {
						break
					}
				}
				// Block until the test signals unblock, holding the slot
				// and allowing other goroutines to pile up at the semaphore.
				select {
				case <-unblock:
				case <-ctx.Done():
				}
				inflight.Add(-1)
				return json.RawMessage(`"ok"`), nil
			})
	}()

	// Yield to let goroutines ramp up and saturate the semaphore.
	runtime.Gosched()
	// Give fan-out goroutines time to start; use a short busy-wait instead of
	// a fixed sleep so the test is fast on slow machines too.
	for i := 0; i < 1000 && maxInflight.Load() < int64(fanOutConcurrencyBound); i++ {
		runtime.Gosched()
	}

	// Unblock all goroutines so the test completes.
	close(unblock)
	<-done

	assert.LessOrEqual(t, maxInflight.Load(), int64(fanOutConcurrencyBound),
		"peak concurrency %d exceeded bound %d", maxInflight.Load(), fanOutConcurrencyBound)
}

func TestFanOutConcurrent_MixedResults_OverallErrNonNil(t *testing.T) {
	// One failing steward must produce a non-nil overallErr while still returning
	// all per-steward results.
	matches := []StewardInfo{
		{ID: "ok1"},
		{ID: "fail"},
		{ID: "ok2"},
	}

	results, overallErr := fanOutConcurrent(context.Background(), matches,
		func(_ context.Context, s StewardInfo) (json.RawMessage, error) {
			if s.ID == "fail" {
				return nil, errors.New("deliberate failure")
			}
			return json.RawMessage(`"success"`), nil
		})

	require.Error(t, overallErr, "overallErr must be non-nil when any steward action fails")
	assert.Len(t, results, 3)

	assert.True(t, results["#ok1"].Success)
	assert.True(t, results["#ok2"].Success)
	assert.False(t, results["#fail"].Success)
	assert.ErrorContains(t, results["#fail"].Err, "deliberate failure")
}

func TestFanOutConcurrent_AllSuccess_NilOverallErr(t *testing.T) {
	matches := []StewardInfo{{ID: "a"}, {ID: "b"}}
	results, overallErr := fanOutConcurrent(context.Background(), matches,
		func(_ context.Context, _ StewardInfo) (json.RawMessage, error) {
			return json.RawMessage(`"ok"`), nil
		})
	require.NoError(t, overallErr)
	assert.True(t, results["#a"].Success)
	assert.True(t, results["#b"].Success)
}

// ---- stewardKey --------------------------------------------------------------

func TestStewardKey_WithHostname(t *testing.T) {
	s := StewardInfo{ID: "abc123", DNA: &StewardInfoDNA{Hostname: "webserver-01"}}
	assert.Equal(t, "webserver-01#abc123", stewardKey(s))
}

func TestStewardKey_WithoutDNA(t *testing.T) {
	s := StewardInfo{ID: "abc123"}
	assert.Equal(t, "#abc123", stewardKey(s))
}
