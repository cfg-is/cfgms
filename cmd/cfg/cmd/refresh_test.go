// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pendingRefreshHandler returns a handler that serves a fixed list of pending
// refresh entries. It records the received requests for assertion.
func pendingRefreshHandler(t *testing.T, entries []APIPendingRefreshEntry) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(entries); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}
}

func TestListPendingRefreshes_Empty(t *testing.T) {
	srv := httptest.NewServer(pendingRefreshHandler(t, nil))
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	entries, err := client.ListPendingRefreshes(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestListPendingRefreshes_WithEntries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := []APIPendingRefreshEntry{
		{
			PendingID: "refresh-001",
			DeviceID:  "aabbccddeeff0011",
			TenantID:  "acme-corp",
			SourceIP:  "10.0.0.1",
			Status:    "pending",
			CreatedAt: now,
			ExpiresAt: now.Add(7 * 24 * time.Hour),
		},
		{
			PendingID: "refresh-002",
			DeviceID:  "aabbccddeeff0022",
			TenantID:  "acme-corp",
			SourceIP:  "10.0.0.2",
			Status:    "pending",
			CreatedAt: now,
			ExpiresAt: now.Add(7 * 24 * time.Hour),
		},
	}

	srv := httptest.NewServer(pendingRefreshHandler(t, fixture))
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	entries, err := client.ListPendingRefreshes(context.Background(), "acme-corp")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, "refresh-001", entries[0].PendingID)
	assert.Equal(t, "acme-corp", entries[0].TenantID)
}

func TestApproveRefresh_Success(t *testing.T) {
	pendingID := "refresh-approve-test"
	response := APIApproveRefreshResponse{
		Status:     "approved",
		PendingID:  pendingID,
		ClientCert: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
		ClientKey:  "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
		CACert:     "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, pendingID)
		assert.Contains(t, r.URL.Path, "/approve")
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	result, err := client.ApproveRefresh(context.Background(), pendingID)
	require.NoError(t, err)
	assert.Equal(t, "approved", result.Status)
	assert.Equal(t, pendingID, result.PendingID)
	assert.NotEmpty(t, result.ClientCert)
}

func TestApproveRefresh_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "pending refresh not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	_, err = client.ApproveRefresh(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestRejectRefresh_Success(t *testing.T) {
	pendingID := "refresh-reject-test"
	var capturedReason string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, pendingID)
		assert.Contains(t, r.URL.Path, "/reject")

		var body struct {
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			capturedReason = body.Reason
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	err = client.RejectRefresh(context.Background(), pendingID, "Device decommissioned")
	require.NoError(t, err)
	assert.Equal(t, "Device decommissioned", capturedReason)
}

func TestRejectRefresh_NoReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	err = client.RejectRefresh(context.Background(), "refresh-no-reason", "")
	require.NoError(t, err)
}

func TestGetRefreshPolicy_Success(t *testing.T) {
	days := 90
	expected := APIRefreshPolicyResponse{
		TenantID:        "acme-corp",
		Mode:            "auto_accept",
		MaxDormancyDays: &days,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Contains(t, r.URL.Path, "acme-corp")
		assert.Contains(t, r.URL.Path, "refresh-policy")
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(expected); err != nil {
			t.Errorf("failed to encode: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	policy, err := client.GetRefreshPolicy(context.Background(), "acme-corp")
	require.NoError(t, err)
	assert.Equal(t, "acme-corp", policy.TenantID)
	assert.Equal(t, "auto_accept", policy.Mode)
	require.NotNil(t, policy.MaxDormancyDays)
	assert.Equal(t, 90, *policy.MaxDormancyDays)
}

func TestSetRefreshPolicy_Success(t *testing.T) {
	var capturedMode string
	var capturedDormancy *int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Contains(t, r.URL.Path, "acme-corp")
		assert.Contains(t, r.URL.Path, "refresh-policy")

		var body struct {
			Mode            string `json:"mode"`
			MaxDormancyDays *int   `json:"max_dormancy_days,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			capturedMode = body.Mode
			capturedDormancy = body.MaxDormancyDays
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(APIRefreshPolicyResponse{
			TenantID: "acme-corp",
			Mode:     body.Mode,
		}); err != nil {
			t.Errorf("failed to encode: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	days := 60
	err = client.SetRefreshPolicy(context.Background(), "acme-corp", "require_approval", &days)
	require.NoError(t, err)
	assert.Equal(t, "require_approval", capturedMode)
	require.NotNil(t, capturedDormancy)
	assert.Equal(t, 60, *capturedDormancy)
}

func TestSetRefreshPolicy_NoDormancy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(APIRefreshPolicyResponse{
			TenantID: "acme-corp",
			Mode:     "reject",
		}); err != nil {
			t.Errorf("failed to encode: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := newClientFromFlags(srv.URL, "test-key", "", false)
	require.NoError(t, err)

	err = client.SetRefreshPolicy(context.Background(), "acme-corp", "reject", nil)
	require.NoError(t, err)
}
