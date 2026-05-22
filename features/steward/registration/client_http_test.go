// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegister_202_ReturnsPendingResponse verifies that the real HTTPClient (the CFGMS component
// under test) correctly parses a 202 Accepted response and returns a non-nil
// *RegistrationPendingResponse with PendingID populated. The httptest.Server is a standard
// Go HTTP fixture — not a mock of a CFGMS component — used here because the steward package
// cannot import the controller package without inverting the dependency direction.
func TestRegister_202_ReturnsPendingResponse(t *testing.T) {
	pending := RegistrationPendingResponse{
		PendingID: "pending-1234567890",
		StewardID: "steward-abc",
		TenantID:  "test-tenant",
		Group:     "prod",
		Status:    "pending",
	}
	body, err := json.Marshal(pending)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		ControllerURL: srv.URL,
		Logger:        logging.NewLogger("debug"),
	})
	require.NoError(t, err)

	regResp, pendingResp, err := client.Register(context.Background(), "test-token")
	require.NoError(t, err)
	assert.Nil(t, regResp, "RegistrationResponse must be nil on 202")
	require.NotNil(t, pendingResp, "RegistrationPendingResponse must be non-nil on 202")
	assert.Equal(t, "pending-1234567890", pendingResp.PendingID, "PendingID must be populated")
	assert.Equal(t, "test-tenant", pendingResp.TenantID)
	assert.Equal(t, "pending", pendingResp.Status)
}

// TestRegister_ErrorStatus_ReturnsError verifies that the HTTP client surfaces a non-nil
// error when the controller returns a non-200/202 status (e.g., 403 Forbidden on reject,
// 401 Unauthorized on invalid token). Neither RegistrationResponse nor
// RegistrationPendingResponse should be returned.
func TestRegister_ErrorStatus_ReturnsError(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "403 Forbidden", statusCode: http.StatusForbidden, body: "Registration rejected\n"},
		{name: "401 Unauthorized", statusCode: http.StatusUnauthorized, body: "Invalid or expired registration token\n"},
		{name: "500 InternalServerError", statusCode: http.StatusInternalServerError, body: "Server misconfiguration\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, tc.body, tc.statusCode)
			}))
			defer srv.Close()

			client, err := NewHTTPClient(&HTTPConfig{
				ControllerURL: srv.URL,
				Logger:        logging.NewLogger("debug"),
			})
			require.NoError(t, err)

			regResp, pendingResp, err := client.Register(context.Background(), "test-token")
			require.Error(t, err, "non-200/202 status must return an error")
			assert.Nil(t, regResp, "RegistrationResponse must be nil on error status")
			assert.Nil(t, pendingResp, "RegistrationPendingResponse must be nil on error status")
			assert.Contains(t, err.Error(), "registration failed with status")
		})
	}
}

// TestRegistrationResponse_JSONFieldNames is a regression guard that ensures
// the wire format of RegistrationResponse has not changed. The JSON field names
// client_cert, client_key, and ca_cert are consumed by stewards in production;
// any rename would silently break existing deployments.
func TestRegistrationResponse_JSONFieldNames(t *testing.T) {
	resp := RegistrationResponse{
		ClientCert: "cert-pem",
		ClientKey:  "key-pem",
		CACert:     "ca-pem",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Contains(t, raw, "client_cert", "wire field client_cert must not be renamed")
	assert.Contains(t, raw, "client_key", "wire field client_key must not be renamed")
	assert.Contains(t, raw, "ca_cert", "wire field ca_cert must not be renamed")
	assert.Equal(t, "cert-pem", raw["client_cert"])
	assert.Equal(t, "key-pem", raw["client_key"])
	assert.Equal(t, "ca-pem", raw["ca_cert"])
}

func TestNewHTTPClientAlwaysVerifiesTLS(t *testing.T) {
	logger := logging.NewLogger("debug")

	t.Run("empty CACertPath uses system roots with nil TLSClientConfig", func(t *testing.T) {
		client, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "https://controller.example.com",
			Logger:        logger,
		})
		require.NoError(t, err)

		transport, ok := client.httpClient.Transport.(*http.Transport)
		require.True(t, ok, "transport must be *http.Transport")
		assert.Nil(t, transport.TLSClientConfig, "nil TLSClientConfig means system root CAs are used")
	})

	t.Run("valid CACertPath populates RootCAs and never sets InsecureSkipVerify", func(t *testing.T) {
		tmpDir := t.TempDir()

		ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
			Organization: "Test CA",
			Country:      "US",
			ValidityDays: 365,
		})
		require.NoError(t, err)
		require.NoError(t, ca.Initialize(nil))

		caPEM, err := ca.GetCACertificate()
		require.NoError(t, err)

		caPath := filepath.Join(tmpDir, "ca.crt")
		require.NoError(t, os.WriteFile(caPath, caPEM, 0600))

		client, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "https://controller.example.com",
			CACertPath:    caPath,
			Logger:        logger,
		})
		require.NoError(t, err)

		transport, ok := client.httpClient.Transport.(*http.Transport)
		require.True(t, ok, "transport must be *http.Transport")
		require.NotNil(t, transport.TLSClientConfig, "TLSClientConfig must be set when CACertPath is provided")
		assert.NotNil(t, transport.TLSClientConfig.RootCAs, "RootCAs must be populated from the CA cert file")
		assert.False(t, transport.TLSClientConfig.InsecureSkipVerify, "InsecureSkipVerify must never be true")
	})

	t.Run("missing CACertPath file returns error", func(t *testing.T) {
		_, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "https://controller.example.com",
			CACertPath:    "/nonexistent/path/ca.crt",
			Logger:        logger,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read CA cert")
	})

	t.Run("invalid PEM in CACertPath file returns error", func(t *testing.T) {
		tmpDir := t.TempDir()
		caPath := filepath.Join(tmpDir, "ca.crt")
		require.NoError(t, os.WriteFile(caPath, []byte("not-valid-pem"), 0600))

		_, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "https://controller.example.com",
			CACertPath:    caPath,
			Logger:        logger,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create TLS config")
	})

	t.Run("empty ControllerURL returns error", func(t *testing.T) {
		_, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "",
			Logger:        logger,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "controller URL is required")
	})

	t.Run("nil Logger returns error", func(t *testing.T) {
		_, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "https://controller.example.com",
			Logger:        nil,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})
}
