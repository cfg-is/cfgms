// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package mqtt_quic

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// TestHelper provides utilities for MQTT+QUIC integration testing
type TestHelper struct {
	httpClient *http.Client
	baseURL    string
}

// NewTestHelper creates a new test helper
// Uses CFGMS_TEST_HTTP_ADDR environment variable if set, otherwise defaults to baseURL parameter
func NewTestHelper(baseURL string) *TestHelper {
	// Allow override via environment variable for Docker integration
	if envURL := os.Getenv("CFGMS_TEST_HTTP_ADDR"); envURL != "" {
		baseURL = envURL
	}

	// Create HTTP client that skips SSL verification for test certificates
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &TestHelper{
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		baseURL: baseURL,
	}
}

// CreateToken creates a test registration token
// NOTE: For integration tests against real controller, this returns a pre-created token
// that exists in the controller's token store. The controller pre-creates test tokens
// when MQTT is enabled (see features/controller/server/server.go)
func (h *TestHelper) CreateToken(t *testing.T, tenantID, group string) string {
	t.Helper()

	// Use pre-created reusable token from controller
	// This token is created by the controller on startup when MQTT is enabled
	return "cfgms_reg_integration_reusable"
}

// RegisterSteward registers a steward via HTTP API
func (h *TestHelper) RegisterSteward(t *testing.T, token string) *RegistrationResponse {
	t.Helper()

	reqBody := map[string]string{
		"token": token,
	}
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

// RegistrationResponse represents the registration API response
type RegistrationResponse struct {
	StewardID     string `json:"steward_id"`
	TenantID      string `json:"tenant_id"`
	Group         string `json:"group"`
	ControllerURL string `json:"controller_url"`
	MQTTBroker    string `json:"mqtt_broker"`
	QUICAddress   string `json:"quic_address"`
	ClientCert    string `json:"client_cert,omitempty"`
	ClientKey     string `json:"client_key,omitempty"`
	CACert        string `json:"ca_cert,omitempty"`
}

// WaitForCondition waits for a condition with timeout
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

// GetTestHTTPAddr returns the HTTP address for testing
// Uses CFGMS_TEST_HTTP_ADDR environment variable if set, otherwise returns default
func GetTestHTTPAddr(defaultAddr string) string {
	if envAddr := os.Getenv("CFGMS_TEST_HTTP_ADDR"); envAddr != "" {
		return envAddr
	}
	return defaultAddr
}

// GetTestMQTTAddr returns the MQTT broker address for testing
// Uses CFGMS_TEST_MQTT_ADDR environment variable if set, otherwise returns default
func GetTestMQTTAddr(defaultAddr string) string {
	if envAddr := os.Getenv("CFGMS_TEST_MQTT_ADDR"); envAddr != "" {
		return envAddr
	}
	return defaultAddr
}

// GetTestQUICAddr returns the QUIC server address for testing
// Uses CFGMS_TEST_QUIC_ADDR environment variable if set, otherwise returns default
func GetTestQUICAddr(defaultAddr string) string {
	if envAddr := os.Getenv("CFGMS_TEST_QUIC_ADDR"); envAddr != "" {
		return envAddr
	}
	return defaultAddr
}

// GetTestCertsPath returns the path to test certificates directory
// Uses CFGMS_TEST_CERTS_PATH environment variable if set, otherwise returns default
func GetTestCertsPath(defaultPath string) string {
	if envPath := os.Getenv("CFGMS_TEST_CERTS_PATH"); envPath != "" {
		return envPath
	}
	return defaultPath
}

// LoadTLSConfig loads TLS configuration for MQTT client testing
// This function loads the CA certificate, client certificate, and client key
// from the test certificates directory for mTLS authentication
func LoadTLSConfig(t *testing.T, certsPath string) *tls.Config {
	t.Helper()

	// Load CA certificate (prefer controller-ca.pem if available, fall back to ca-cert.pem)
	caCertPath := filepath.Join(certsPath, "controller-ca.pem")
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		// Fallback to static test CA if controller CA not available
		caCertPath = filepath.Join(certsPath, "ca-cert.pem")
		caCert, err = os.ReadFile(caCertPath)
		if err != nil {
			t.Fatalf("Failed to read CA certificate: %v", err)
		}
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		t.Fatal("Failed to parse CA certificate")
	}

	// Load client certificate and key
	clientCertPath := filepath.Join(certsPath, "client-cert.pem")
	clientKeyPath := filepath.Join(certsPath, "client-key.pem")
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("Failed to load client certificate: %v", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
		// Use localhost as ServerName since we connect via 127.0.0.1:1886
		// The server certificate is valid for "localhost" and "cfgms-mqtt-server"
		InsecureSkipVerify: false,
		ServerName:         "localhost",
	}

	return tlsConfig
}

// LoadInvalidTLSConfig loads invalid TLS configuration for negative testing
// certType can be: "expired", "selfsigned", "wrong-ca"
func LoadInvalidTLSConfig(t *testing.T, certsPath string, certType string) *tls.Config {
	t.Helper()

	// Load CA certificate (same for all)
	caCertPath := filepath.Join(certsPath, "ca-cert.pem")
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		t.Fatal("Failed to parse CA certificate")
	}

	// Load invalid client certificate based on type
	var clientCertPath, clientKeyPath string
	switch certType {
	case "expired":
		clientCertPath = filepath.Join(certsPath, "expired-cert.pem")
		clientKeyPath = filepath.Join(certsPath, "expired-key.pem")
	case "selfsigned":
		clientCertPath = filepath.Join(certsPath, "selfsigned-cert.pem")
		clientKeyPath = filepath.Join(certsPath, "selfsigned-key.pem")
	case "wrong-ca":
		clientCertPath = filepath.Join(certsPath, "wrong-ca-client-cert.pem")
		clientKeyPath = filepath.Join(certsPath, "wrong-ca-client-key.pem")
	default:
		t.Fatalf("Unknown invalid cert type: %s", certType)
	}

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("Failed to load invalid client certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caCertPool,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
		ServerName:         "controller-standalone",
	}

	return tlsConfig
}

// LoadTLSConfigFromPEM creates a TLS config from PEM-encoded certificate data
// This is used when certificates are received from the registration endpoint
func LoadTLSConfigFromPEM(caCertPEM, clientCertPEM, clientKeyPEM []byte) (*tls.Config, error) {
	// Load CA certificate
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Load client certificate and key
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
		// Use localhost as ServerName since we connect via 127.0.0.1:1886
		ServerName: "localhost",
	}

	return tlsConfig, nil
}

// CreateMQTTClientOptions creates MQTT client options with TLS support
// If tlsConfig is nil, creates a non-TLS connection
func CreateMQTTClientOptions(brokerAddr string, clientID string, tlsConfig *tls.Config) *mqtt.ClientOptions {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(brokerAddr)
	opts.SetClientID(clientID)
	opts.SetConnectTimeout(10 * time.Second)
	opts.SetAutoReconnect(false)

	// Add TLS config if provided
	if tlsConfig != nil {
		opts.SetTLSConfig(tlsConfig)
	}

	return opts
}

// GetTLSConfigFromRegistration registers a steward and returns TLS config with certificates
// This helper enables tests to use production certificate flow instead of static test certs
// Story #294: Migrate tests to use registration API for certificate distribution
func (h *TestHelper) GetTLSConfigFromRegistration(t *testing.T, tenantID, group string) (*tls.Config, string) {
	t.Helper()

	// Register steward to obtain certificates
	token := h.CreateToken(t, tenantID, group)
	resp := h.RegisterSteward(t, token)

	if resp.ClientCert == "" || resp.ClientKey == "" || resp.CACert == "" {
		t.Fatalf("Registration did not return certificates (ClientCert=%v, ClientKey=%v, CACert=%v)",
			resp.ClientCert != "", resp.ClientKey != "", resp.CACert != "")
	}

	// Save certificates to temporary directory
	certDir := t.TempDir()
	clientCertPath := filepath.Join(certDir, "client.crt")
	clientKeyPath := filepath.Join(certDir, "client.key")
	caCertPath := filepath.Join(certDir, "ca.crt")

	if err := os.WriteFile(clientCertPath, []byte(resp.ClientCert), 0600); err != nil {
		t.Fatalf("Failed to save client certificate: %v", err)
	}
	if err := os.WriteFile(clientKeyPath, []byte(resp.ClientKey), 0600); err != nil {
		t.Fatalf("Failed to save client key: %v", err)
	}
	if err := os.WriteFile(caCertPath, []byte(resp.CACert), 0600); err != nil {
		t.Fatalf("Failed to save CA certificate: %v", err)
	}

	// Load client certificate
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("Failed to load client certificate: %v", err)
	}

	// Load CA certificate for server verification
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		t.Fatal("Failed to parse CA certificate")
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   "localhost", // Controller cert is valid for localhost
	}

	return tlsConfig, resp.StewardID
}
