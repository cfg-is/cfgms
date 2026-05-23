// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
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

// newRegistrationServer creates an httptest server serving canned registration API responses.
func newRegistrationServer(t *testing.T) *httptest.Server {
	t.Helper()

	registeredAt := time.Now().UTC()
	pending := []APIPendingRegistration{
		{
			PendingID:    "pending-1234567890",
			StewardID:    "steward-1234567890",
			TenantID:     "test-tenant",
			SourceIP:     "10.0.0.1",
			RegisteredAt: registeredAt,
		},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/registration/pending":
			_ = json.NewEncoder(w).Encode(pending)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/approve"):
			w.WriteHeader(http.StatusOK)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/deny"):
			w.WriteHeader(http.StatusOK)
		case r.Method == "POST" && r.URL.Path == "/api/v1/registration/approve-all":
			_, _ = w.Write([]byte(`{"approved":1}`))
		case r.Method == "POST" && r.URL.Path == "/api/v1/registration/approve-by-cidr":
			_, _ = w.Write([]byte(`{"approved":1}`))
		case r.Method == "POST" && r.URL.Path == "/api/v1/registration/ip-trust":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/api/v1/registration/ip-trust/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestRegistrationPendingCommand(t *testing.T) {
	t.Run("text output with results", func(t *testing.T) {
		server := newRegistrationServer(t)
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		origJSON := registrationJSONOutput
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
			registrationJSONOutput = origJSON
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true
		registrationJSONOutput = false

		output := captureStdout(t, func() {
			err := runRegistrationPending(registrationPendingCmd, nil)
			require.NoError(t, err)
		})

		assert.Contains(t, output, "pending-1234567890", "PENDING ID column must appear")
		assert.Contains(t, output, "steward-1234567890", "STEWARD ID column must appear")
		assert.Contains(t, output, "test-tenant")
		assert.Contains(t, output, "10.0.0.1")
		assert.Contains(t, output, "RDNS", "RDNS column header must appear")
		assert.Contains(t, output, "Pending registrations")
	})

	t.Run("JSON output", func(t *testing.T) {
		server := newRegistrationServer(t)
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		origJSON := registrationJSONOutput
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
			registrationJSONOutput = origJSON
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true
		registrationJSONOutput = true

		output := captureStdout(t, func() {
			err := runRegistrationPending(registrationPendingCmd, nil)
			require.NoError(t, err)
		})

		var parsed []APIPendingRegistration
		require.NoError(t, json.Unmarshal([]byte(output), &parsed), "output must be valid JSON")
		require.Len(t, parsed, 1)
		assert.Equal(t, "pending-1234567890", parsed[0].PendingID)
		assert.Equal(t, "steward-1234567890", parsed[0].StewardID)
		assert.Equal(t, "test-tenant", parsed[0].TenantID)
	})

	t.Run("empty queue shows message", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]APIPendingRegistration{})
		}))
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		origJSON := registrationJSONOutput
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
			registrationJSONOutput = origJSON
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true
		registrationJSONOutput = false

		output := captureStdout(t, func() {
			err := runRegistrationPending(registrationPendingCmd, nil)
			require.NoError(t, err)
		})

		assert.Contains(t, output, "No pending registrations")
	})

	t.Run("API error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal error"}`))
		}))
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true

		err := runRegistrationPending(registrationPendingCmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to list pending registrations")
	})
}

func TestRegistrationApproveCommand(t *testing.T) {
	t.Run("happy path - approval succeeds", func(t *testing.T) {
		server := newRegistrationServer(t)
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true

		output := captureStdout(t, func() {
			err := runRegistrationApprove(registrationApproveCmd, []string{"pending-1234567890"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "Registration approved")
		assert.Contains(t, output, "pending-1234567890")
	})

	t.Run("not found returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"steward not found in pending queue"}`))
		}))
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true

		err := runRegistrationApprove(registrationApproveCmd, []string{"nonexistent-steward"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to approve registration")
		assert.Contains(t, err.Error(), "nonexistent-steward")
	})

	t.Run("API error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal error"}`))
		}))
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true

		err := runRegistrationApprove(registrationApproveCmd, []string{"steward-xyz"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to approve registration")
	})
}

func TestRegistrationDenyCommand(t *testing.T) {
	t.Run("happy path - denial succeeds", func(t *testing.T) {
		server := newRegistrationServer(t)
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		origReason := registrationDenyReason
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
			registrationDenyReason = origReason
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true
		registrationDenyReason = ""

		output := captureStdout(t, func() {
			err := runRegistrationDeny(registrationDenyCmd, []string{"pending-1234567890"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "Registration denied")
		assert.Contains(t, output, "pending-1234567890")
	})

	t.Run("deny with reason", func(t *testing.T) {
		var capturedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/deny") {
				// Capture request body to verify reason was sent
				buf := make([]byte, 1024)
				n, _ := r.Body.Read(buf)
				capturedBody = string(buf[:n])
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		origReason := registrationDenyReason
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
			registrationDenyReason = origReason
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true
		registrationDenyReason = "Unauthorized deployment"

		output := captureStdout(t, func() {
			err := runRegistrationDeny(registrationDenyCmd, []string{"pending-1234567890"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "Registration denied")
		assert.Contains(t, capturedBody, "Unauthorized deployment")
	})

	t.Run("not found returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"steward not found in pending queue"}`))
		}))
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		origReason := registrationDenyReason
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
			registrationDenyReason = origReason
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true
		registrationDenyReason = ""

		err := runRegistrationDeny(registrationDenyCmd, []string{"nonexistent-steward"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deny registration")
		assert.Contains(t, err.Error(), "nonexistent-steward")
	})

	t.Run("API error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal error"}`))
		}))
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true

		err := runRegistrationDeny(registrationDenyCmd, []string{"steward-xyz"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deny registration")
	})
}

func TestRegistrationApproveAllCommand(t *testing.T) {
	t.Run("approve-all prints count", func(t *testing.T) {
		server := newRegistrationServer(t)
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true

		output := captureStdout(t, func() {
			err := runRegistrationApproveAll(registrationApproveAllCmd, nil)
			require.NoError(t, err)
		})

		assert.Contains(t, output, "Approved 1 registrations")
	})

	t.Run("API error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"store unavailable"}`))
		}))
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true

		err := runRegistrationApproveAll(registrationApproveAllCmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to approve all registrations")
	})
}

func TestRegistrationApproveByCIDRCommand(t *testing.T) {
	t.Run("approve-by-cidr prints count", func(t *testing.T) {
		server := newRegistrationServer(t)
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true

		output := captureStdout(t, func() {
			err := runRegistrationApproveByCIDR(registrationApproveByCIDRCmd, []string{"10.0.0.0/8"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "Approved 1 registrations")
	})

	t.Run("API error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid CIDR"}`))
		}))
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true

		err := runRegistrationApproveByCIDR(registrationApproveByCIDRCmd, []string{"not-a-cidr"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to approve registrations by CIDR")
	})
}

func TestRegistrationIPTrustAddCommand(t *testing.T) {
	t.Run("ip-trust add prints confirmation", func(t *testing.T) {
		server := newRegistrationServer(t)
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		origTenantID := registrationIPTrustTenantID
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
			registrationIPTrustTenantID = origTenantID
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true
		registrationIPTrustTenantID = "acme"

		output := captureStdout(t, func() {
			err := runRegistrationIPTrustAdd(registrationIPTrustAddCmd, []string{"10.0.0.0/8"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "IP trust range added")
		assert.Contains(t, output, "10.0.0.0/8")
		assert.Contains(t, output, "acme")
	})

	t.Run("API error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"ip-trust store unavailable"}`))
		}))
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		origTenantID := registrationIPTrustTenantID
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
			registrationIPTrustTenantID = origTenantID
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true
		registrationIPTrustTenantID = "acme"

		err := runRegistrationIPTrustAdd(registrationIPTrustAddCmd, []string{"10.0.0.0/8"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to add IP trust range")
	})
}

func TestRegistrationIPTrustRevokeCommand(t *testing.T) {
	t.Run("ip-trust revoke prints confirmation", func(t *testing.T) {
		server := newRegistrationServer(t)
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		origTenantID := registrationIPTrustTenantID
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
			registrationIPTrustTenantID = origTenantID
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true
		registrationIPTrustTenantID = "acme"

		output := captureStdout(t, func() {
			err := runRegistrationIPTrustRevoke(registrationIPTrustRevokeCmd, []string{"10.0.0.0/8"})
			require.NoError(t, err)
		})

		assert.Contains(t, output, "IP trust range revoked")
		assert.Contains(t, output, "10.0.0.0/8")
		assert.Contains(t, output, "acme")
	})

	t.Run("not found returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"ip trust entry not found"}`))
		}))
		defer server.Close()

		origAPIURL := registrationAPIURL
		origTLSInsecure := registrationTLSInsecure
		origTenantID := registrationIPTrustTenantID
		t.Cleanup(func() {
			registrationAPIURL = origAPIURL
			registrationTLSInsecure = origTLSInsecure
			registrationIPTrustTenantID = origTenantID
		})

		registrationAPIURL = server.URL
		registrationTLSInsecure = true
		registrationIPTrustTenantID = "acme"

		err := runRegistrationIPTrustRevoke(registrationIPTrustRevokeCmd, []string{"10.0.0.0/8"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to revoke IP trust range")
	})
}
