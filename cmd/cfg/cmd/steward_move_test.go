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

// newMoveMultiServer creates a test server that handles:
//   - POST /api/v1/fleet/resolve → returns stewards
//   - POST /api/v1/stewards/{id}/move → calls perSteward(id) for status + body
func newMoveMultiServer(t *testing.T, stewards []StewardInfo, perSteward func(id string) (int, interface{})) *httptest.Server {
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
		// /api/v1/stewards/{id}/move
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/move") {
			parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/move"), "/")
			id := parts[len(parts)-1]
			status, body := perSteward(id)
			w.WriteHeader(status)
			if err := json.NewEncoder(w).Encode(body); err != nil {
				t.Errorf("encode move response: %v", err)
			}
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
}

// setStewardMoveFlags sets the global steward flags for move tests and restores them
// on cleanup.
func setStewardMoveFlags(t *testing.T, serverURL, toTenant string, yes, jsonOut bool) {
	t.Helper()
	origURL := stewardURL
	origInsecure := stewardTLSInsecure
	origToTenant := stewardMoveToTenant
	origYes := stewardYes
	origJSON := stewardMoveJSONOutput
	t.Cleanup(func() {
		stewardURL = origURL
		stewardTLSInsecure = origInsecure
		stewardMoveToTenant = origToTenant
		stewardYes = origYes
		stewardMoveJSONOutput = origJSON
	})
	stewardURL = serverURL
	stewardTLSInsecure = true
	stewardMoveToTenant = toTenant
	stewardYes = yes
	stewardMoveJSONOutput = jsonOut
}

// successMoveBody returns a standard 200 move response body.
func successMoveBody(id, prevTenant, destTenant string) interface{} {
	return map[string]interface{}{
		"data": map[string]interface{}{
			"steward_id":      id,
			"tenant_id":       destTenant,
			"previous_tenant": prevTenant,
			"status":          "moved",
		},
	}
}

// ---- multi-match all-success ------------------------------------------------

func TestStewardMoveSelector_MultiMatch_AllSuccess(t *testing.T) {
	stewards := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	srv := newMoveMultiServer(t, stewards, func(id string) (int, interface{}) {
		return http.StatusOK, successMoveBody(id, "src-tenant", "dest-tenant")
	})
	t.Cleanup(srv.Close)
	setStewardMoveFlags(t, srv.URL, "dest-tenant", true, false)

	output := captureStdout(t, func() {
		err := runStewardMove(stewardMoveCmd, []string{"group:prod"})
		require.NoError(t, err)
	})

	// Both stewards appear in output as moved.
	assert.Contains(t, output, "s1")
	assert.Contains(t, output, "s2")
	assert.Contains(t, output, "dest-tenant")
}

func TestStewardMoveSelector_MultiMatch_AllSuccess_JSONOutput(t *testing.T) {
	stewards := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	srv := newMoveMultiServer(t, stewards, func(id string) (int, interface{}) {
		return http.StatusOK, successMoveBody(id, "src-tenant", "dest-tenant")
	})
	t.Cleanup(srv.Close)
	setStewardMoveFlags(t, srv.URL, "dest-tenant", true, true)

	output := captureStdout(t, func() {
		err := runStewardMove(stewardMoveCmd, []string{"group:prod"})
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

func TestStewardMoveSelector_MultiMatch_PartialFailure_HumanOutput(t *testing.T) {
	stewards := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	srv := newMoveMultiServer(t, stewards, func(id string) (int, interface{}) {
		if id == "s2" {
			return http.StatusForbidden, map[string]interface{}{"error": "insufficient scope"}
		}
		return http.StatusOK, successMoveBody(id, "src-tenant", "dest-tenant")
	})
	t.Cleanup(srv.Close)
	setStewardMoveFlags(t, srv.URL, "dest-tenant", true, false)

	var runErr error
	output := captureStdout(t, func() {
		runErr = runStewardMove(stewardMoveCmd, []string{"group:prod"})
	})

	// Command must exit non-zero when any host fails.
	require.Error(t, runErr, "partial failure must make RunE return non-nil error")

	// Successful steward still appears in human output.
	assert.Contains(t, output, "s1")
}

func TestStewardMoveSelector_MultiMatch_PartialFailure_JSONOutput(t *testing.T) {
	stewards := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-a"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-b"}},
	}

	srv := newMoveMultiServer(t, stewards, func(id string) (int, interface{}) {
		if id == "s2" {
			return http.StatusNotFound, map[string]interface{}{"error": "not found"}
		}
		return http.StatusOK, successMoveBody(id, "src-tenant", "dest-tenant")
	})
	t.Cleanup(srv.Close)
	setStewardMoveFlags(t, srv.URL, "dest-tenant", true, true)

	var runErr error
	output := captureStdout(t, func() {
		runErr = runStewardMove(stewardMoveCmd, []string{"group:prod"})
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

func TestStewardMoveSelector_SingleMatch_NoConfirmNeeded(t *testing.T) {
	// A single match should succeed without --yes.
	stewards := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-a"}},
	}

	srv := newMoveMultiServer(t, stewards, func(id string) (int, interface{}) {
		return http.StatusOK, successMoveBody(id, "src-tenant", "dest-tenant")
	})
	t.Cleanup(srv.Close)
	setStewardMoveFlags(t, srv.URL, "dest-tenant", false, false) // yes=false

	output := captureStdout(t, func() {
		err := runStewardMove(stewardMoveCmd, []string{"s1"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "s1")
}

// ---- --json flag registered -------------------------------------------------

func TestStewardMoveCmd_JSONFlagRegistered(t *testing.T) {
	assert.NotNil(t, stewardMoveCmd.Flags().Lookup("json"), "--json flag must be registered on steward move")
}
