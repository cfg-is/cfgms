// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package registration

import (
	"net/http"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewLogger("info")
}

// TestNewHTTPClientAlwaysVerifiesTLS asserts that NewHTTPClient always produces
// a transport with nil TLSClientConfig, meaning Go's default TLS verification
// (always-verify) applies. This is the compile-time enforcement guarantee:
// no config field or env var can produce InsecureSkipVerify=true.
func TestNewHTTPClientAlwaysVerifiesTLS(t *testing.T) {
	client, err := NewHTTPClient(&HTTPConfig{
		ControllerURL: "https://controller.example.com",
		Timeout:       5 * time.Second,
		Logger:        newTestLogger(t),
	})
	require.NoError(t, err)
	require.NotNil(t, client)

	transport, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok, "underlying transport must be *http.Transport")

	// nil TLSClientConfig is the structural proof: Go's default behavior is to
	// verify TLS certificates. Any TLSClientConfig override would be required to
	// set InsecureSkipVerify=true — its absence means TLS is always enforced.
	assert.Nil(t, transport.TLSClientConfig,
		"TLSClientConfig must be nil — TLS verification is compile-time enforced")
}

// TestNewHTTPClientRequiresControllerURL verifies validation on missing URL.
func TestNewHTTPClientRequiresControllerURL(t *testing.T) {
	_, err := NewHTTPClient(&HTTPConfig{
		ControllerURL: "",
		Logger:        newTestLogger(t),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "controller URL is required")
}

// TestNewHTTPClientRequiresLogger verifies validation on missing logger.
func TestNewHTTPClientRequiresLogger(t *testing.T) {
	_, err := NewHTTPClient(&HTTPConfig{
		ControllerURL: "https://controller.example.com",
		Logger:        nil,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}
