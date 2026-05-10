// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package registration

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
