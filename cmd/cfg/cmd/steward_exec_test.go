// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// saveExecGlobals saves all run globals (via saveStewardRunGlobals) plus
// stewardYes, which is needed for multi-host confirm tests.
func saveExecGlobals(t *testing.T) {
	t.Helper()
	saveStewardRunGlobals(t)
	origYes := stewardYes
	t.Cleanup(func() {
		stewardYes = origYes
	})
}

// newExecTestServer builds a minimal fake controller that handles the full exec
// flow:
//
//   - POST /api/v1/fleet/resolve  → resolveMatches wrapped in {"data": [...]}
//   - POST /api/v1/runs/command   → {"data": {"run_id": runID}}
//   - GET  /api/v1/runs/<runID>   → completed run status
//   - GET  /api/v1/runs/<runID>/jobs → jobRecords wrapped in {"data": [...]}
//
// If capturedTarget is non-nil, the "target" field from the command POST body
// is written there so the caller can assert it.
func newExecTestServer(
	t *testing.T,
	runID string,
	resolveMatches []StewardInfo,
	jobRecords []map[string]interface{},
	capturedTarget *string,
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": resolveMatches,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/runs/command":
			if capturedTarget != nil {
				b, _ := io.ReadAll(r.Body)
				var body map[string]interface{}
				_ = json.Unmarshal(b, &body)
				if target, ok := body["target"].(string); ok {
					*capturedTarget = target
				}
			}
			writeRunAPIResponse(w, map[string]string{"run_id": runID})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runs/"+runID:
			writeRunAPIResponse(w, map[string]interface{}{
				"run_id":         runID,
				"status":         "completed",
				"job_count":      len(jobRecords),
				"completed_jobs": len(jobRecords),
				"failed_jobs":    0,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runs/"+runID+"/jobs":
			writeRunAPIResponse(w, jobRecords)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// ---------------------------------------------------------------------------
// [REQUIRED TEST] regression: id: prepend bug (#2257)
// ---------------------------------------------------------------------------

// TestExec_NoPrepend_BareSelector_SendsRawTarget is a regression test for
// issue #2257: a bare hostname passed as the selector must not have "id:"
// prepended before dispatch. The target field in the POST body must be the
// raw selector string.
func TestExec_NoPrepend_BareSelector_SendsRawTarget(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	var capturedTarget string
	srv := newExecTestServer(t, "bare-run-id",
		[]StewardInfo{{ID: "host-abc", DNA: &StewardInfoDNA{Hostname: "host-abc"}}},
		[]map[string]interface{}{
			{"job_id": "j1", "device_id": "host-abc", "status": "completed", "output": "ok\n", "exit_code": 0},
		},
		&capturedTarget,
	)
	defer srv.Close()

	saveExecGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardExecCommand = "hostname"
	stewardExecShell = "bash"
	stewardExecTimeout = 30 * time.Second
	runWaitPollInterval = time.Millisecond

	_ = captureStdout(t, func() {
		err := runRunCommandSingle(stewardExecCmd, []string{"host-abc"})
		require.NoError(t, err)
	})

	// "host-abc" must reach the server verbatim — not as "id:host-abc".
	assert.Equal(t, "host-abc", capturedTarget, "bare selector must not be prepended with id:")
}

// TestExec_NoPrepend_IDPrefixedArg_NoDoubleID is a regression test for #2257:
// when the caller already passes "id:steward-X", the CLI must not prepend
// another "id:" — the target must remain exactly "id:steward-X".
func TestExec_NoPrepend_IDPrefixedArg_NoDoubleID(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	var capturedTarget string
	srv := newExecTestServer(t, "id-run-id",
		[]StewardInfo{{ID: "steward-xyz", DNA: &StewardInfoDNA{Hostname: "steward-xyz"}}},
		[]map[string]interface{}{
			{"job_id": "j1", "device_id": "steward-xyz", "status": "completed", "output": "ok\n", "exit_code": 0},
		},
		&capturedTarget,
	)
	defer srv.Close()

	saveExecGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardExecCommand = "hostname"
	stewardExecShell = "bash"
	stewardExecTimeout = 30 * time.Second
	runWaitPollInterval = time.Millisecond

	_ = captureStdout(t, func() {
		err := runRunCommandSingle(stewardExecCmd, []string{"id:steward-xyz"})
		require.NoError(t, err)
	})

	// "id:steward-xyz" must stay "id:steward-xyz", never "id:id:steward-xyz".
	assert.Equal(t, "id:steward-xyz", capturedTarget,
		"id:-prefixed selector must not gain a second id: prefix")
}

// ---------------------------------------------------------------------------
// [REQUIRED TEST] multi-match dispatch
// ---------------------------------------------------------------------------

// TestExec_MultiMatch_HumanOutput_HostPrefixed verifies that a selector
// matching 2 stewards produces one host-prefixed output block per steward
// in human (non-JSON) mode.
func TestExec_MultiMatch_HumanOutput_HostPrefixed(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	matches := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-one"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-two"}},
	}
	jobs := []map[string]interface{}{
		{"job_id": "j1", "device_id": "s1", "status": "completed", "output": "output from s1\n", "exit_code": 0},
		{"job_id": "j2", "device_id": "s2", "status": "completed", "output": "output from s2\n", "exit_code": 0},
	}
	srv := newExecTestServer(t, "multi-run-id", matches, jobs, nil)
	defer srv.Close()

	saveExecGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardExecCommand = "hostname"
	stewardExecShell = "bash"
	stewardExecTimeout = 30 * time.Second
	runWaitPollInterval = time.Millisecond
	stewardYes = true // suppress multi-host confirm prompt

	output := captureStdout(t, func() {
		err := runRunCommandSingle(stewardExecCmd, []string{"glob:host-*"})
		require.NoError(t, err)
	})

	// Both stewards must appear with host-prefixed keys in the output.
	assert.Contains(t, output, "host-one#s1")
	assert.Contains(t, output, "host-two#s2")
	assert.Contains(t, output, "output from s1")
	assert.Contains(t, output, "output from s2")
}

// TestExec_MultiMatch_JSONOutput_KeyedBySteward verifies that --json output
// from a multi-match exec is a keyed-by-steward array (story 4 schema)
// rather than a raw []runJobRecord dump.
func TestExec_MultiMatch_JSONOutput_KeyedBySteward(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	matches := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-one"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-two"}},
	}
	jobs := []map[string]interface{}{
		{"job_id": "j1", "device_id": "s1", "status": "completed", "output": "s1-result\n", "exit_code": 0},
		{"job_id": "j2", "device_id": "s2", "status": "completed", "output": "s2-result\n", "exit_code": 0},
	}
	srv := newExecTestServer(t, "json-run-id", matches, jobs, nil)
	defer srv.Close()

	saveExecGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardExecCommand = "hostname"
	stewardExecShell = "bash"
	stewardExecTimeout = 30 * time.Second
	runWaitPollInterval = time.Millisecond
	stewardExecJSONOutput = true
	stewardYes = true

	output := captureStdout(t, func() {
		err := runRunCommandSingle(stewardExecCmd, []string{"glob:host-*"})
		require.NoError(t, err)
	})

	// Output must be a JSON array with keyed entries.
	var entries []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(output), &entries), "output must be valid JSON")
	require.Len(t, entries, 2, "must have one entry per matched steward")

	keys := make(map[string]bool)
	for _, e := range entries {
		key, ok := e["key"].(string)
		require.True(t, ok, "each entry must have a string 'key' field")
		keys[key] = true
		_, hasSuccess := e["success"]
		assert.True(t, hasSuccess, "each entry must have a 'success' field")
		// Must not be a raw job record (no job_id at the top level).
		assert.Nil(t, e["job_id"], "keyed output must not expose raw job_id fields")
	}
	assert.True(t, keys["host-one#s1"], "output must contain key 'host-one#s1'")
	assert.True(t, keys["host-two#s2"], "output must contain key 'host-two#s2'")
}

// ---------------------------------------------------------------------------
// Missing job-record branch coverage
// ---------------------------------------------------------------------------

// TestExec_MissingJobRecord_HumanMode verifies that when the API returns fewer
// job records than resolved stewards, the human-mode output path prints a
// warning to stderr and continues without panicking.
func TestExec_MissingJobRecord_HumanMode(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	// Two stewards resolved, but only one job record returned.
	matches := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-one"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-two"}},
	}
	jobs := []map[string]interface{}{
		{"job_id": "j1", "device_id": "s1", "status": "completed", "output": "output from s1\n", "exit_code": 0},
		// s2 intentionally omitted
	}
	srv := newExecTestServer(t, "missing-job-run-id", matches, jobs, nil)
	defer srv.Close()

	saveExecGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardExecCommand = "hostname"
	stewardExecShell = "bash"
	stewardExecTimeout = 30 * time.Second
	runWaitPollInterval = time.Millisecond
	stewardYes = true

	output := captureStdout(t, func() {
		err := runRunCommandSingle(stewardExecCmd, []string{"glob:host-*"})
		require.NoError(t, err)
	})

	// s1 output must be present; s2 must not appear (no job record, only a stderr warning).
	assert.Contains(t, output, "host-one#s1")
	assert.Contains(t, output, "output from s1")
	assert.NotContains(t, output, "host-two#s2")
}

// TestExec_MissingJobRecord_JSONMode verifies that when the API returns fewer
// job records than resolved stewards, the --json output marks the missing
// steward with success=false and an error string.
func TestExec_MissingJobRecord_JSONMode(t *testing.T) {
	dir := t.TempDir()
	bundleFile := generateTestBundleWithRSA(t, dir)

	matches := []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "host-one"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "host-two"}},
	}
	jobs := []map[string]interface{}{
		{"job_id": "j1", "device_id": "s1", "status": "completed", "output": "s1-result\n", "exit_code": 0},
		// s2 intentionally omitted
	}
	srv := newExecTestServer(t, "missing-json-run-id", matches, jobs, nil)
	defer srv.Close()

	saveExecGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	bundlePath = bundleFile
	stewardExecCommand = "hostname"
	stewardExecShell = "bash"
	stewardExecTimeout = 30 * time.Second
	runWaitPollInterval = time.Millisecond
	stewardExecJSONOutput = true
	stewardYes = true

	output := captureStdout(t, func() {
		err := runRunCommandSingle(stewardExecCmd, []string{"glob:host-*"})
		require.NoError(t, err)
	})

	var entries []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(output), &entries), "output must be valid JSON")
	require.Len(t, entries, 2)

	entryByKey := make(map[string]map[string]interface{})
	for _, e := range entries {
		if k, ok := e["key"].(string); ok {
			entryByKey[k] = e
		}
	}

	s1 := entryByKey["host-one#s1"]
	require.NotNil(t, s1, "s1 entry must be present")
	assert.Equal(t, true, s1["success"], "s1 with a job record must be success=true")

	s2 := entryByKey["host-two#s2"]
	require.NotNil(t, s2, "s2 entry must be present even with no job record")
	assert.Equal(t, false, s2["success"], "s2 missing a job record must be success=false")
	assert.NotEmpty(t, s2["error"], "s2 must carry an error message")
}
