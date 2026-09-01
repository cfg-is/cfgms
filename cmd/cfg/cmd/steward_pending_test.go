// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newStewardPendingServer creates a test HTTP server that serves the given
// stewards on GET /api/v1/stewards and dispatches GET
// /api/v1/registration/pending to pendingHandler, so each test controls the
// pending-list response independently of the steward listing.
func newStewardPendingServer(t *testing.T, stewards []map[string]interface{}, pendingHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/registration/pending" {
			pendingHandler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data":      stewards,
			"timestamp": time.Now().UTC(),
		})
	}))
}

func pendingEntry(pendingID, stewardID, tenantID, sourceIP string) map[string]interface{} {
	return map[string]interface{}{
		"pending_id":    pendingID,
		"steward_id":    stewardID,
		"tenant_id":     tenantID,
		"source_ip":     sourceIP,
		"registered_at": time.Now().UTC().Format(time.RFC3339),
	}
}

func TestStewardList_AppendsPendingCountLine_WhenNonZero(t *testing.T) {
	stewards := []map[string]interface{}{
		{"id": "steward-abc", "status": "connected", "last_seen": time.Now().UTC().Format(time.RFC3339)},
	}
	pending := []map[string]interface{}{
		pendingEntry("p1", "steward-1", "root/msp-a", "10.0.0.1"),
		pendingEntry("p2", "steward-2", "root/msp-a", "10.0.0.2"),
		pendingEntry("p3", "steward-3", "root/msp-a", "10.0.0.3"),
	}

	server := newStewardPendingServer(t, stewards, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(pending)
	})
	t.Cleanup(server.Close)
	setStewardListFlags(t, server.URL)

	output := captureStdout(t, func() {
		err := runStewardList(stewardListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "steward-abc")
	assert.Contains(t, output, "3 pending registration(s)")
	assert.Contains(t, output, "cfg registration pending")

	// Count only: the surface must not leak pending_id / steward_id / source_ip
	// details, which stay behind `cfg registration pending`.
	assert.NotContains(t, output, "p1")
	assert.NotContains(t, output, "steward-1")
	assert.NotContains(t, output, "10.0.0.1")
}

func TestStewardList_PendingLineOmitted_On403(t *testing.T) {
	stewards := []map[string]interface{}{
		{"id": "steward-abc", "status": "connected", "last_seen": time.Now().UTC().Format(time.RFC3339)},
	}

	server := newStewardPendingServer(t, stewards, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: missing registration:list-pending"})
	})
	t.Cleanup(server.Close)
	setStewardListFlags(t, server.URL)

	output := captureStdout(t, func() {
		err := runStewardList(stewardListCmd, []string{})
		require.NoError(t, err, "a 403 on the pending call must not fail cfg steward list")
	})

	assert.Contains(t, output, "steward-abc")
	assert.NotContains(t, output, "pending registration")
	assert.NotContains(t, output, "0 pending")
}

func TestStewardList_PendingLineOmitted_WhenZero(t *testing.T) {
	stewards := []map[string]interface{}{
		{"id": "steward-abc", "status": "connected", "last_seen": time.Now().UTC().Format(time.RFC3339)},
	}

	server := newStewardPendingServer(t, stewards, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]interface{}{})
	})
	t.Cleanup(server.Close)
	setStewardListFlags(t, server.URL)

	output := captureStdout(t, func() {
		err := runStewardList(stewardListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "steward-abc")
	assert.NotContains(t, output, "pending registration")
}

func TestStewardList_PendingCount_TenantScoped(t *testing.T) {
	// The server is the sole source of tenant scoping (same endpoint backing
	// `cfg registration pending`); this fixture stands in for a caller whose
	// tenant subtree has 2 pending stewards while a sibling tenant has more
	// that never appear in this response. The CLI must report exactly what
	// the (already tenant-scoped) response contains, with no separate
	// aggregation that could leak across tenants.
	stewards := []map[string]interface{}{
		{"id": "steward-abc", "status": "connected", "last_seen": time.Now().UTC().Format(time.RFC3339)},
	}
	callerTenantPending := []map[string]interface{}{
		pendingEntry("p1", "steward-1", "root/msp-a/client-1", "10.0.0.1"),
		pendingEntry("p2", "steward-2", "root/msp-a/client-1", "10.0.0.2"),
	}

	server := newStewardPendingServer(t, stewards, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Simulates the server already having scoped the response to the
		// caller's tenant subtree; a sibling tenant's pending stewards are
		// simply absent from this payload.
		_ = json.NewEncoder(w).Encode(callerTenantPending)
	})
	t.Cleanup(server.Close)
	setStewardListFlags(t, server.URL)

	output := captureStdout(t, func() {
		err := runStewardList(stewardListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "2 pending registration(s)")
	assert.NotContains(t, output, "3 pending registration(s)")
}

func TestStewardList_EmptyStewards_StillShowsPendingCount(t *testing.T) {
	// Regression coverage for the incident this issue traces to: 8 stewards
	// registered successfully and sat in quarantine while `cfg steward list`
	// showed "No stewards registered.", producing a fictitious network defect.
	pending := []map[string]interface{}{
		pendingEntry("p1", "steward-1", "root/msp-a", "10.0.0.1"),
	}

	server := newStewardPendingServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(pending)
	})
	t.Cleanup(server.Close)
	setStewardListFlags(t, server.URL)

	output := captureStdout(t, func() {
		err := runStewardList(stewardListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "No stewards registered.")
	assert.Contains(t, output, "1 pending registration(s)")
}
