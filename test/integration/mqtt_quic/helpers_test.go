package mqtt_quic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/registration"
)

// TestHelper provides utilities for MQTT+QUIC integration testing
type TestHelper struct {
	httpClient *http.Client
	baseURL    string
	tokenStore *registration.MemoryStore
}

// NewTestHelper creates a new test helper
func NewTestHelper(baseURL string) *TestHelper {
	return &TestHelper{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		baseURL:    baseURL,
		tokenStore: registration.NewMemoryStore(),
	}
}

// CreateToken creates a test registration token
func (h *TestHelper) CreateToken(t *testing.T, tenantID, group string) string {
	t.Helper()

	token := &registration.Token{
		Token:         fmt.Sprintf("cfgms_reg_test_%d", time.Now().UnixNano()),
		TenantID:      tenantID,
		ControllerURL: "mqtt://localhost:1883",
		Group:         group,
		CreatedAt:     time.Now(),
		SingleUse:     true,
		Revoked:       false,
	}

	ctx := context.Background()
	if err := h.tokenStore.SaveToken(ctx, token); err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	return token.Token
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
	defer resp.Body.Close()

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
