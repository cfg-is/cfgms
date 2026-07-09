// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build integration

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManualReviewFlow_RegisterPollApprove is the end-to-end integration test for the
// manual-review registration flow (Issue #1899).
//
// Scenario:
//  1. Register → controller returns HTTP 202 (pending manual approval)
//  2. Pending ID is persisted to disk so restarts resume the same record
//  3. pollForApproval polls the status endpoint: first call returns "pending",
//     second call returns "claimed" with cert fields
//  4. approvedRegistration is returned with the full cert data
//  5. Pending state file is cleared after approval
//
// "Successful connect" here means the approval cycle completes and the steward
// receives the cert bundle required to establish a gRPC transport connection.
// The actual gRPC dial is out of scope for this test (requires a live controller).
func TestManualReviewFlow_RegisterPollApprove(t *testing.T) {
	const pendingID = "pending-manual-abc123"
	logger := logging.NewLogger("error")

	// Simulate certificate fields returned by the controller on approval.
	approvedBody := registration.RegistrationStatusResponse{
		Status:           "claimed",
		StewardID:        "steward-integration-test",
		TenantID:         "tenant-test",
		Group:            "default",
		TransportAddress: "ctrl.example.com:4433",
		ClientCert:       "-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----",
		ClientKey:        "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
		CACert:           "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
		ServerCert:       "-----BEGIN CERTIFICATE-----\nSERVER\n-----END CERTIFICATE-----",
	}
	approvedJSON, err := json.Marshal(approvedBody)
	require.NoError(t, err)

	var statusCallCount atomic.Int32

	// httptest.Server simulates the controller's status endpoint.
	// First call returns "pending"; second call returns "claimed" with certs.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		n := statusCallCount.Add(1)
		if n == 1 {
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		} else {
			_, _ = w.Write(approvedJSON)
		}
	}))
	defer srv.Close()

	httpClient, err := registration.NewHTTPClient(&registration.HTTPConfig{
		ControllerURL: srv.URL,
		Logger:        logger,
	})
	require.NoError(t, err)

	// === Phase 1: Receive 202 (simulate by calling Register which would return pending) ===
	// We drive the poll loop directly here since Register needs a full controller.
	// The pending ID persistence is tested via savePendingState/loadPendingState round-trip.

	certStoreDir := t.TempDir()

	// Persist the pending ID (as registerAndConnect would after receiving 202).
	require.NoError(t, savePendingState(certStoreDir, PendingState{PendingID: pendingID}))

	// Verify persistence: a simulated restart can load the same pending ID.
	loaded, err := loadPendingState(certStoreDir)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, pendingID, loaded.PendingID, "persisted pending ID must survive restart")

	// === Phase 2: Poll for approval — pending then claimed ===
	result, pollErr := pollForApproval(
		context.Background(),
		httpClient,
		pendingID,
		"reg-token-abc",
		30*time.Second,
		0, // skip sleep in test
		0,
		logger,
	)

	require.NoError(t, pollErr)
	require.NotNil(t, result, "approvedRegistration must be non-nil on successful approval")

	// === Phase 3: Assert successful cert receipt (the "successful connect" AC) ===
	assert.Equal(t, "steward-integration-test", result.StewardID)
	assert.Equal(t, "tenant-test", result.TenantID)
	assert.Equal(t, "ctrl.example.com:4433", result.TransportAddress)
	assert.NotEmpty(t, result.ClientCert, "client cert must be populated on approval")
	assert.NotEmpty(t, result.ClientKey, "client key must be populated on approval")
	assert.NotEmpty(t, result.CACert, "CA cert must be populated on approval")

	assert.Equal(t, int32(2), statusCallCount.Load(),
		"must poll exactly twice: once for pending, once for claimed")

	// === Phase 4: Clear pending state after approval ===
	require.NoError(t, clearPendingState(certStoreDir))
	cleared, err := loadPendingState(certStoreDir)
	require.NoError(t, err)
	assert.Nil(t, cleared, "pending state must be cleared after approval")
}

// TestManualReviewFlow_RestartResumesPendingID verifies that a steward restart loads the
// persisted pending_id and resumes polling rather than creating a new pending record.
func TestManualReviewFlow_RestartResumesPendingID(t *testing.T) {
	const pendingID = "pending-restart-xyz"
	logger := logging.NewLogger("error")

	// Simulate immediate approval on first poll (restart scenario — was pending when it died).
	approvedBody := registration.RegistrationStatusResponse{
		Status:           "claimed",
		StewardID:        "steward-restarted",
		TenantID:         "tenant-restart",
		TransportAddress: "ctrl.example.com:4433",
		ClientCert:       "CLIENT-CERT",
		ClientKey:        "CLIENT-KEY",
		CACert:           "CA-CERT",
	}
	approvedJSON, err := json.Marshal(approvedBody)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the steward is polling the correct pending ID.
		assert.Contains(t, r.URL.Path, pendingID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(approvedJSON)
	}))
	defer srv.Close()

	httpClient, err := registration.NewHTTPClient(&registration.HTTPConfig{
		ControllerURL: srv.URL,
		Logger:        logger,
	})
	require.NoError(t, err)

	// Simulate previous run: save pending state to disk.
	certStoreDir := t.TempDir()
	require.NoError(t, savePendingState(certStoreDir, PendingState{PendingID: pendingID}))

	// Simulate restart: load the pending state.
	loaded, err := loadPendingState(certStoreDir)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Resume polling with the loaded pending ID (no new registration call).
	result, pollErr := pollForApproval(
		context.Background(),
		httpClient,
		loaded.PendingID,
		"reg-token-restart",
		30*time.Second,
		0, 0,
		logger,
	)

	require.NoError(t, pollErr)
	require.NotNil(t, result)
	assert.Equal(t, "steward-restarted", result.StewardID)
	assert.Equal(t, "CLIENT-CERT", result.ClientCert)
}

// TestManualReviewFlow_Denied_ExitsWithClearMessage verifies that a "denied" response
// from the controller causes pollForApproval to return an error with a clear message.
func TestManualReviewFlow_Denied_ExitsWithClearMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"denied"}`))
	}))
	defer srv.Close()

	httpClient, err := registration.NewHTTPClient(&registration.HTTPConfig{
		ControllerURL: srv.URL,
		Logger:        logging.NewLogger("error"),
	})
	require.NoError(t, err)

	result, pollErr := pollForApproval(
		context.Background(),
		httpClient,
		"pending-denied",
		"reg-token",
		5*time.Second,
		0, 0,
		logging.NewLogger("error"),
	)

	require.Error(t, pollErr)
	assert.Nil(t, result)
	assert.Contains(t, pollErr.Error(), "denied", "error must clearly state registration was denied")
}

// TestManualReviewFlow_PendingIDExpired_ReRegisters verifies that HTTP 410 Gone (pending
// record expired) causes pollForApproval to return (nil, nil) so the caller can re-register.
func TestManualReviewFlow_PendingIDExpired_ReRegisters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	httpClient, err := registration.NewHTTPClient(&registration.HTTPConfig{
		ControllerURL: srv.URL,
		Logger:        logging.NewLogger("error"),
	})
	require.NoError(t, err)

	certStoreDir := t.TempDir()
	require.NoError(t, savePendingState(certStoreDir, PendingState{PendingID: "pending-expired-id"}))

	result, pollErr := pollForApproval(
		context.Background(),
		httpClient,
		"pending-expired-id",
		"reg-token",
		5*time.Second,
		0, 0,
		logging.NewLogger("error"),
	)

	// nil result + nil error signals caller to re-register.
	assert.NoError(t, pollErr)
	assert.Nil(t, result, "nil result must signal re-registration is needed")
}
