// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
// Attempts to extract the CA cert from the controller-standalone Docker container for TLS
// verification; falls back to the system root pool when Docker is unavailable.
func NewTestHelper(baseURL string) *TestHelper {
	if envURL := os.Getenv("CFGMS_TEST_HTTP_ADDR"); envURL != "" {
		baseURL = envURL
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if caCertPEM, err := GetCACertFromContainer("controller-standalone"); err == nil {
		caCertPool := x509.NewCertPool()
		if caCertPool.AppendCertsFromPEM(caCertPEM) {
			tlsConfig.RootCAs = caCertPool
		}
	}

	return &TestHelper{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		baseURL: baseURL,
	}
}

// Client returns the underlying HTTP client for direct use in tests.
func (h *TestHelper) Client() *http.Client {
	return h.httpClient
}

// BaseURL returns the base URL for direct use in tests.
func (h *TestHelper) BaseURL() string {
	return h.baseURL
}

// CreateToken returns the pre-seeded reusable integration test token.
//
// The controller only seeds this token when started with CFGMS_SEED_TEST_TOKENS=1.
// Integration test environments (Docker Compose, CI) must set that variable on
// the controller process before it starts; see docker-compose.test.yml.
//
// NOTE: tenantID and group parameters are currently ignored — all registrations
// use the same shared token with pre-configured metadata. Multi-tenant isolation
// tests verify unique steward IDs but do NOT validate per-tenant token boundaries.
// Per-tenant tokens require seeding distinct tokens in the controller test setup.
//
// It takes no *testing.T: suites call it from worker goroutines, where the
// testing package forbids Fatal-family calls, so no test handle is handed out.
func (h *TestHelper) CreateToken(_, _ string) string {
	return "integration_reusable" //nolint:gosec // test-only token, requires CFGMS_SEED_TEST_TOKENS=1 on the controller
}

// generateTestDeviceIdentity generates a fresh Ed25519 key pair for integration test device identity.
// Each call produces unique credentials to prevent DeviceID conflicts within the same tenant.
// It returns an error instead of failing the test so that callers running on a
// goroutine other than the test goroutine can propagate the failure back.
func generateTestDeviceIdentity() (deviceID, identityKeyPub string, err error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate Ed25519 key for device identity: %w", err)
	}
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:]), base64.StdEncoding.EncodeToString(pub), nil
}

// generateTestRegistrationKeypairAndCSR generates a fresh ECDSA P-256 keypair and a
// self-signed PEM CERTIFICATE REQUEST over its public key, mirroring
// features/steward/registration/client_http.go's generateStewardKeypair /
// buildRegistrationCSR (Issue #3780). Returns the PKCS8 PEM-encoded private key
// (held only by the caller, never transmitted) and the CSR PEM to submit.
func generateTestRegistrationKeypairAndCSR() (keyPEM, csrPEM string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate registration keypair: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal registration private key: %w", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "integration-test-steward"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, priv)
	if err != nil {
		return "", "", fmt.Errorf("create registration CSR: %w", err)
	}
	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	return keyPEM, csrPEM, nil
}

// RegisterSteward registers a steward via HTTP API and returns the response.
//
// It reports failures as an error rather than calling t.Fatalf. The testing
// package requires FailNow/Fatal/Fatalf to be called only from the goroutine
// running the test function; several suites register stewards concurrently from
// their own goroutines, so this helper must be safe to call from any goroutine.
// Callers assert on the returned error from the test goroutine.
func (h *TestHelper) RegisterSteward(token string) (*RegistrationResponse, error) {
	deviceID, identityKeyPub, err := generateTestDeviceIdentity()
	if err != nil {
		return nil, err
	}

	// Generate the steward's mTLS keypair locally and submit only the public half
	// as a CSR (Issue #3780); clientKeyPEM never leaves this process.
	clientKeyPEM, csrPEM, err := generateTestRegistrationKeypairAndCSR()
	if err != nil {
		return nil, err
	}

	reqBody := map[string]string{
		"token":            token,
		"device_id":        deviceID,
		"identity_key_pub": identityKeyPub,
		"csr_pem":          csrPEM,
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal registration request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/register", h.baseURL)
	resp, err := h.httpClient.Post(url, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("HTTP registration request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read registration response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	var regResp RegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, fmt.Errorf("parse registration response: %w", err)
	}
	// No client_key field exists on the wire response (Issue #3780): the
	// controller never generates or sees a private key for this credential.
	// ClientKey is populated here from the keypair generated locally above,
	// combined with the controller-issued certificate.
	regResp.ClientKey = clientKeyPEM

	return &regResp, nil
}

// RegisterStewardRawBody performs the same registration request as RegisterSteward
// but returns the raw, unparsed HTTP response body — used by wire-contract tests
// that must inspect the literal JSON rather than the typed response, e.g. to prove
// no client_key field is ever present on the wire (Issue #3780).
func (h *TestHelper) RegisterStewardRawBody(token string) ([]byte, error) {
	deviceID, identityKeyPub, err := generateTestDeviceIdentity()
	if err != nil {
		return nil, err
	}
	_, csrPEM, err := generateTestRegistrationKeypairAndCSR()
	if err != nil {
		return nil, err
	}

	reqBody := map[string]string{
		"token":            token,
		"device_id":        deviceID,
		"identity_key_pub": identityKeyPub,
		"csr_pem":          csrPEM,
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal registration request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/register", h.baseURL)
	resp, err := h.httpClient.Post(url, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("HTTP registration request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read registration response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// RegistrationResponse represents the registration API response. ClientKey is
// never read off the wire (Issue #3780) — see RegisterSteward.
type RegistrationResponse struct {
	StewardID        string `json:"steward_id"`
	TenantID         string `json:"tenant_id"`
	Group            string `json:"group"`
	ControllerURL    string `json:"controller_url"`
	TransportAddress string `json:"transport_address"`
	ClientCert       string `json:"client_cert,omitempty"`
	ClientKey        string `json:"-"`
	CACert           string `json:"ca_cert,omitempty"`
}

// GetTLSConfigFromRegistration registers a steward and returns TLS config from the response.
func (h *TestHelper) GetTLSConfigFromRegistration(t *testing.T, tenantID, group string) (*tls.Config, string) {
	t.Helper()

	token := h.CreateToken(tenantID, group)
	resp, err := h.RegisterSteward(token)
	if err != nil {
		t.Fatalf("Failed to register steward: %v", err)
	}

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
