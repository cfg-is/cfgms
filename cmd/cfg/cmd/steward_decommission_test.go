// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDecommissionMultiServer creates a test server that handles:
//   - POST /api/v1/fleet/resolve → returns stewards
//   - DELETE /api/v1/stewards/{id} → calls perSteward(id) for status + body
func newDecommissionMultiServer(t *testing.T, stewards []StewardInfo, perSteward func(id string) (int, interface{})) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve" {
			if err := json.NewEncoder(w).Encode(struct {
				Data []StewardInfo `json:"data"`
			}{Data: stewards}); err != nil {
				t.Errorf("encode resolve: %v", err)
			}
			return
		}
		// DELETE /api/v1/stewards/{id}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/stewards/") {
			parts := strings.Split(r.URL.Path, "/")
			id := parts[len(parts)-1]
			status, body := perSteward(id)
			w.WriteHeader(status)
			if err := json.NewEncoder(w).Encode(body); err != nil {
				t.Errorf("encode decommission response: %v", err)
			}
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
}

// setStewardDecommissionFlags sets global steward flags for decommission tests.
func setStewardDecommissionFlags(t *testing.T, serverURL string, yes, jsonOut bool) {
	t.Helper()
	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origYes := stewardYes
	origJSON := stewardDecommissionJSONOutput
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardYes = origYes
		stewardDecommissionJSONOutput = origJSON
	})
	stewardURL = serverURL
	stewardTLSInsecure = true
	stewardYes = yes
	stewardDecommissionJSONOutput = jsonOut
}

// ---- multi-match all-success ------------------------------------------------

func TestStewardDecommissionSelector_MultiMatch_AllSuccess(t *testing.T) {
	stewards := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	srv := newDecommissionMultiServer(t, stewards, func(_ string) (int, interface{}) {
		return http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "deregistered"}}
	})
	t.Cleanup(srv.Close)
	setStewardDecommissionFlags(t, srv.URL, true, false)

	output := captureStdout(t, func() {
		err := runStewardDecommission(stewardDecommissionCmd, []string{"group:old"})
		require.NoError(t, err)
	})

	// Both stewards appear as decommissioned.
	assert.Contains(t, output, "s1")
	assert.Contains(t, output, "s2")
	assert.Contains(t, output, "decommissioned")
}

func TestStewardDecommissionSelector_MultiMatch_AllSuccess_JSONOutput(t *testing.T) {
	stewards := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	srv := newDecommissionMultiServer(t, stewards, func(_ string) (int, interface{}) {
		return http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "deregistered"}}
	})
	t.Cleanup(srv.Close)
	setStewardDecommissionFlags(t, srv.URL, true, true)

	output := captureStdout(t, func() {
		err := runStewardDecommission(stewardDecommissionCmd, []string{"group:old"})
		require.NoError(t, err)
	})

	// Output must be a valid JSON array with one entry per steward.
	var entries []KeyedOutputEntry
	require.NoError(t, json.Unmarshal([]byte(output), &entries), "output must be a valid JSON array")
	require.Len(t, entries, 2)

	keys := make(map[string]bool)
	for _, e := range entries {
		keys[e.Key] = true
		assert.True(t, e.Success, "entry %s should be successful", e.Key)
		assert.Empty(t, e.Error)
	}
	assert.True(t, keys["host-a#s1"], "host-a#s1 must appear in output")
	assert.True(t, keys["host-b#s2"], "host-b#s2 must appear in output")
}

// ---- multi-match partial failure --------------------------------------------

func TestStewardDecommissionSelector_MultiMatch_PartialFailure_HumanOutput(t *testing.T) {
	stewards := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	srv := newDecommissionMultiServer(t, stewards, func(id string) (int, interface{}) {
		if id == "s2" {
			return http.StatusNotFound, map[string]interface{}{"error": "steward not found"}
		}
		return http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "deregistered"}}
	})
	t.Cleanup(srv.Close)
	setStewardDecommissionFlags(t, srv.URL, true, false)

	var runErr error
	output := captureStdout(t, func() {
		runErr = runStewardDecommission(stewardDecommissionCmd, []string{"group:old"})
	})

	// Command must exit non-zero when any host fails.
	require.Error(t, runErr, "partial failure must make RunE return non-nil error")

	// Successful steward still appears in human output.
	assert.Contains(t, output, "s1")
	assert.Contains(t, output, "decommissioned")
}

func TestStewardDecommissionSelector_MultiMatch_PartialFailure_JSONOutput(t *testing.T) {
	stewards := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	srv := newDecommissionMultiServer(t, stewards, func(id string) (int, interface{}) {
		if id == "s2" {
			return http.StatusForbidden, map[string]interface{}{"error": "insufficient permissions"}
		}
		return http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "deregistered"}}
	})
	t.Cleanup(srv.Close)
	setStewardDecommissionFlags(t, srv.URL, true, true)

	var runErr error
	output := captureStdout(t, func() {
		runErr = runStewardDecommission(stewardDecommissionCmd, []string{"group:old"})
	})

	// Non-zero exit even with --json.
	require.Error(t, runErr, "partial failure must make RunE return non-nil error")

	// Output is still valid JSON with both entries.
	var entries []KeyedOutputEntry
	require.NoError(t, json.Unmarshal([]byte(output), &entries), "output must be a valid JSON array even on partial failure")
	require.Len(t, entries, 2)

	byKey := make(map[string]KeyedOutputEntry, len(entries))
	for _, e := range entries {
		byKey[e.Key] = e
	}

	s1 := byKey["host-a#s1"]
	assert.True(t, s1.Success)
	assert.Empty(t, s1.Error)

	s2 := byKey["host-b#s2"]
	assert.False(t, s2.Success)
	assert.NotEmpty(t, s2.Error)
}

// ---- selector resolves to single match (no confirm gate) --------------------

func TestStewardDecommissionSelector_SingleMatch_NoConfirmNeeded(t *testing.T) {
	stewards := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-a"}},
	}

	srv := newDecommissionMultiServer(t, stewards, func(_ string) (int, interface{}) {
		return http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "deregistered"}}
	})
	t.Cleanup(srv.Close)
	setStewardDecommissionFlags(t, srv.URL, false, false) // yes=false

	output := captureStdout(t, func() {
		err := runStewardDecommission(stewardDecommissionCmd, []string{"s1"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "s1")
	assert.Contains(t, output, "decommissioned")
}

// ---- --json flag registered -------------------------------------------------

func TestStewardDecommissionCmd_JSONFlagRegistered(t *testing.T) {
	assert.NotNil(t, stewardDecommissionCmd.Flags().Lookup("json"), "--json flag must be registered on steward decommission")
}
