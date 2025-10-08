package mqtt_quic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
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

	return &TestHelper{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
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
