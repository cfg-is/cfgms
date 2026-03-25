// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestHelper provides utilities for transport integration testing.
// Uses HTTP API for registration and health checks; gRPC transport is
// internal between controller and steward (not directly accessible from tests).
type TestHelper struct {
	httpClient *http.Client
	baseURL    string
}

// NewTestHelper creates a new test helper.
// Uses CFGMS_TEST_HTTP_ADDR environment variable if set, otherwise defaults to baseURL parameter.
func NewTestHelper(baseURL string) *TestHelper {
	if envURL := os.Getenv("CFGMS_TEST_HTTP_ADDR"); envURL != "" {
		baseURL = envURL
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test helper
	}

	return &TestHelper{
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		baseURL: baseURL,
	}
}

// CreateToken returns a pre-created reusable test token.
// The controller pre-creates test tokens on startup when transport is enabled.
//
// NOTE: tenantID and group parameters are currently ignored — all registrations
// use the same shared token with pre-configured metadata. Multi-tenant isolation
// tests verify unique steward IDs but do NOT validate per-tenant token boundaries.
// Per-tenant tokens require seeding distinct tokens in the controller test setup.
func (h *TestHelper) CreateToken(_ *testing.T, _, _ string) string {
	return "integration_reusable"
}

// RegisterSteward registers a steward via HTTP API and returns the response.
func (h *TestHelper) RegisterSteward(t *testing.T, token string) *RegistrationResponse {
	t.Helper()

	reqBody := map[string]string{"token": token}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal registration request: %v", err)
	}

	url := fmt.Sprintf("%s/api/v1/register", h.baseURL)
	resp, err := h.httpClient.Post(url, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		t.Fatalf("HTTP registration request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	var regResp RegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		t.Fatalf("Failed to parse registration response: %v", err)
	}

	return &regResp
}

// RegistrationResponse represents the registration API response.
type RegistrationResponse struct {
	StewardID        string `json:"steward_id"`
	TenantID         string `json:"tenant_id"`
	Group            string `json:"group"`
	ControllerURL    string `json:"controller_url"`
	TransportAddress string `json:"transport_address"`
	ClientCert       string `json:"client_cert,omitempty"`
	ClientKey        string `json:"client_key,omitempty"`
	CACert           string `json:"ca_cert,omitempty"`
}

// GetTLSConfigFromRegistration registers a steward and returns TLS config from the response.
func (h *TestHelper) GetTLSConfigFromRegistration(t *testing.T, tenantID, group string) (*tls.Config, string) {
	t.Helper()

	token := h.CreateToken(t, tenantID, group)
	resp := h.RegisterSteward(t, token)

	if resp.ClientCert == "" || resp.ClientKey == "" || resp.CACert == "" {
		t.Fatalf("Registration did not return certificates (ClientCert=%v, ClientKey=%v, CACert=%v)",
			resp.ClientCert != "", resp.ClientKey != "", resp.CACert != "")
	}

	certDir := t.TempDir()

	clientCertPath := fmt.Sprintf("%s/client.crt", certDir)
	clientKeyPath := fmt.Sprintf("%s/client.key", certDir)
	caCertPath := fmt.Sprintf("%s/ca.crt", certDir)

	if err := os.WriteFile(clientCertPath, []byte(resp.ClientCert), 0600); err != nil {
		t.Fatalf("Failed to save client certificate: %v", err)
	}
	if err := os.WriteFile(clientKeyPath, []byte(resp.ClientKey), 0600); err != nil {
		t.Fatalf("Failed to save client key: %v", err)
	}
	if err := os.WriteFile(caCertPath, []byte(resp.CACert), 0600); err != nil {
		t.Fatalf("Failed to save CA certificate: %v", err)
	}

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("Failed to load client certificate: %v", err)
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		t.Fatal("Failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   "localhost",
	}

	return tlsConfig, resp.StewardID
}

// WaitForCondition polls a condition until it is true or the timeout expires.
func WaitForCondition(t *testing.T, timeout time.Duration, checkInterval time.Duration, condition func() bool, description string) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(checkInterval)
	}

	t.Logf("Timeout waiting for: %s", description)
	return false
}

// GetTestHTTPAddr returns the HTTP address for testing.
// Uses CFGMS_TEST_HTTP_ADDR environment variable if set.
func GetTestHTTPAddr(defaultAddr string) string {
	if envAddr := os.Getenv("CFGMS_TEST_HTTP_ADDR"); envAddr != "" {
		return envAddr
	}
	return defaultAddr
}

// GetTestTransportAddr returns the gRPC transport address for testing.
// Uses CFGMS_TEST_TRANSPORT_ADDR environment variable if set.
func GetTestTransportAddr(defaultAddr string) string {
	if envAddr := os.Getenv("CFGMS_TEST_TRANSPORT_ADDR"); envAddr != "" {
		return envAddr
	}
	return defaultAddr
}
