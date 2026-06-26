// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupAuditTestServer creates a test server and wires the controller URL to it.
// Returns a cleanup function and a channel that receives the last request URL.
func setupAuditTestServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	origURL := healthURL
	origInsecure := controllerTLSInsecure
	origAPIKey := healthAPIKey
	t.Cleanup(func() {
		healthURL = origURL
		controllerTLSInsecure = origInsecure
		healthAPIKey = origAPIKey
	})
	healthURL = srv.URL
	controllerTLSInsecure = true
	healthAPIKey = "test-key"
}

// resetAuditFlags restores default values for audit list command flags.
func resetAuditFlags(t *testing.T) {
	t.Helper()
	origSince := auditSince
	origUntil := auditUntil
	origLimit := auditLimit
	origOffset := auditOffset
	origSeverity := auditSeverity
	origAction := auditAction
	origEventType := auditEventType
	origUserID := auditUserID
	origResult := auditResult
	origModule := auditModule
	origFormat := healthFormat
	t.Cleanup(func() {
		auditSince = origSince
		auditUntil = origUntil
		auditLimit = origLimit
		auditOffset = origOffset
		auditSeverity = origSeverity
		auditAction = origAction
		auditEventType = origEventType
		auditUserID = origUserID
		auditResult = origResult
		auditModule = origModule
		healthFormat = origFormat
	})
	auditSince = ""
	auditUntil = ""
	auditLimit = 50
	auditOffset = 0
	auditSeverity = ""
	auditAction = ""
	auditEventType = ""
	auditUserID = ""
	auditResult = ""
	auditModule = ""
	healthFormat = "text"
}

func TestControllerAuditList_TabularOutput(t *testing.T) {
	resetAuditFlags(t)

	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	entries := []auditEntry{
		{
			ID:        "entry-1",
			TenantID:  "tenant-a",
			Timestamp: ts,
			Action:    "create",
			UserID:    "alice",
			Severity:  "low",
			Result:    "success",
		},
	}

	setupAuditTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": entries})
	})

	output := captureStdout(t, func() {
		err := runControllerAuditList(controllerAuditListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "TIMESTAMP", "tabular header must include TIMESTAMP")
	assert.Contains(t, output, "SEVERITY", "tabular header must include SEVERITY")
	assert.Contains(t, output, "ACTION", "tabular header must include ACTION")
	assert.Contains(t, output, "USER", "tabular header must include USER")
	assert.Contains(t, output, "RESULT", "tabular header must include RESULT")
	assert.Contains(t, output, "alice")
	assert.Contains(t, output, "create")
	assert.Contains(t, output, "success")
}

func TestControllerAuditList_JSONFormat(t *testing.T) {
	resetAuditFlags(t)
	healthFormat = "json"

	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	entries := []auditEntry{
		{
			ID:        "entry-json",
			TenantID:  "tenant-a",
			Timestamp: ts,
			Action:    "delete",
			UserID:    "bob",
			Severity:  "high",
			Result:    "success",
		},
	}

	setupAuditTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": entries})
	})

	output := captureStdout(t, func() {
		err := runControllerAuditList(controllerAuditListCmd, []string{})
		require.NoError(t, err)
	})

	var parsed []auditEntry
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed),
		"--format=json output must be a valid JSON array; got: %s", output)
	require.Len(t, parsed, 1)
	assert.Equal(t, "entry-json", parsed[0].ID)
	assert.Equal(t, "bob", parsed[0].UserID)
}

func TestControllerAuditList_EmptyResultMessage(t *testing.T) {
	resetAuditFlags(t)

	setupAuditTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []interface{}{}})
	})

	output := captureStdout(t, func() {
		err := runControllerAuditList(controllerAuditListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "No audit entries found")
}

func TestControllerAuditList_OffsetAndLimitForwardedAsQueryParams(t *testing.T) {
	resetAuditFlags(t)
	auditLimit = 25
	auditOffset = 100

	var capturedQuery string
	setupAuditTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []interface{}{}})
	})

	output := captureStdout(t, func() {
		err := runControllerAuditList(controllerAuditListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, capturedQuery, "limit=25", "limit must be forwarded as query param")
	assert.Contains(t, capturedQuery, "offset=100", "offset must be forwarded as query param")
	assert.Contains(t, output, "No audit entries found")
}

func TestControllerAuditList_HTTPErrorPropagates(t *testing.T) {
	resetAuditFlags(t)

	setupAuditTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"AUDIT_NOT_AVAILABLE"}}`))
	})

	err := runControllerAuditList(controllerAuditListCmd, []string{})
	require.Error(t, err, "non-OK HTTP response must propagate as an error")
	assert.Contains(t, err.Error(), "503")
}
