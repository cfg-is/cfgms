// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// validFleetContainers is the allowlist of permitted container names.
var validFleetContainers = map[string]bool{
	"fleet-controller": true,
	"fleet-steward-1":  true,
	"fleet-steward-2":  true,
}

// FleetTestSuite holds shared state for the fleet walkthrough test sequence.
type FleetTestSuite struct {
	controllerURL string
	httpClient    *http.Client      // mTLS client (admin bundle) for authenticated endpoints
	noAuthClient  *http.Client      // CA-only client for unauthenticated test endpoints
	stewardIDs    map[string]string // container name → steward ID
}

// adminBundle mirrors the YAML structure of /etc/cfgms/admin.bundle.yaml.
type adminBundle struct {
	CertPEM       string `yaml:"cert_pem"`
	KeyPEM        string `yaml:"key_pem"`
	CAPEM         string `yaml:"ca_pem"`
	ControllerURL string `yaml:"controller_url"`
}

// stewardAPIResponse is the data envelope from GET /api/v1/stewards/{id}.
type stewardAPIResponse struct {
	Data struct {
		ID              string `json:"id"`
		ConnectionState string `json:"connection_state"`
	} `json:"data"`
}

// setupFleetSuite initialises the fleet test suite.
// Immediately skips if CFGMS_FLEET_TEST=1 is not set.
func setupFleetSuite(t *testing.T) *FleetTestSuite {
	t.Helper()

	if os.Getenv("CFGMS_FLEET_TEST") != "1" {
		t.Skip("Fleet E2E tests require CFGMS_FLEET_TEST=1 (run via: make test-e2e-fleet)")
	}

	s := &FleetTestSuite{
		controllerURL: "https://localhost:8090",
		stewardIDs:    make(map[string]string),
	}

	for _, name := range []string{"fleet-controller", "fleet-steward-1", "fleet-steward-2"} {
		if !s.waitForContainerHealthy(t, name, 90*time.Second) {
			t.Fatalf("container %s did not reach healthy state within 90s", name)
		}
	}

	if err := s.rebuildClients(t); err != nil {
		t.Fatalf("failed to build HTTP clients: %v", err)
	}

	for _, name := range []string{"fleet-steward-1", "fleet-steward-2"} {
		id, err := s.getStewardIDFromLogs(t, name)
		if err != nil {
			t.Fatalf("failed to get steward ID from %s: %v", name, err)
		}
		s.stewardIDs[name] = id
		t.Logf("Fleet suite: %s → steward ID %s", name, id)
	}

	return s
}

// rebuildClients re-extracts the admin bundle from fleet-controller and rebuilds both clients.
// Call this after a controller restart (the admin bundle changes on every init).
func (s *FleetTestSuite) rebuildClients(t *testing.T) error {
	t.Helper()

	bundleYAML, err := s.dockerExec(t, "fleet-controller", "cat", "/etc/cfgms/admin.bundle.yaml")
	if err != nil {
		return fmt.Errorf("read admin bundle: %w", err)
	}

	var bundle adminBundle
	if err := yaml.Unmarshal([]byte(bundleYAML), &bundle); err != nil {
		return fmt.Errorf("parse admin bundle: %w", err)
	}
	if bundle.CertPEM == "" || bundle.KeyPEM == "" || bundle.CAPEM == "" {
		return fmt.Errorf("admin bundle incomplete (cert=%v key=%v ca=%v)",
			bundle.CertPEM != "", bundle.KeyPEM != "", bundle.CAPEM != "")
	}

	clientCert, err := tls.X509KeyPair([]byte(bundle.CertPEM), []byte(bundle.KeyPEM))
	if err != nil {
		return fmt.Errorf("load admin cert/key pair: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(bundle.CAPEM)) {
		return fmt.Errorf("parse CA cert from admin bundle")
	}

	s.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}

	s.noAuthClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	return nil
}

// validateFleetContainer returns an error if name is not in the fleet allowlist.
func validateFleetContainer(name string) error {
	if !validFleetContainers[name] {
		return fmt.Errorf("container %q not in fleet allowlist", name)
	}
	return nil
}

// dockerExec runs args in a named container and returns stdout output.
func (s *FleetTestSuite) dockerExec(t *testing.T, container string, args ...string) (string, error) {
	t.Helper()
	if err := validateFleetContainer(container); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmdArgs := append([]string{"exec", container}, args...)
	out, err := exec.CommandContext(ctx, "docker", cmdArgs...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker exec %s %v: %w (output: %s)", container, args, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// getStewardIDFromLogs extracts the steward ID from /tmp/cfgms log files in the container.
// Uses the same grep pattern as test/integration/transport/module_helpers.go.
func (s *FleetTestSuite) getStewardIDFromLogs(t *testing.T, container string) (string, error) {
	t.Helper()
	if err := validateFleetContainer(container); err != nil {
		return "", err
	}

	for attempt := 1; attempt <= 30; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, "docker", "exec", container, "sh", "-c",
			`ls -t /tmp/cfgms/cfgms-*.log 2>/dev/null | head -1 | xargs cat 2>/dev/null | grep -o '"steward_id":"[^"]*"' | tail -1 | cut -d'"' -f4`)
		out, err := cmd.CombinedOutput()
		cancel()
		if id := strings.TrimSpace(string(out)); err == nil && id != "" {
			return id, nil
		}
		if attempt%5 == 0 {
			t.Logf("Waiting for steward ID in %s logs (attempt %d/30)...", container, attempt)
		}
		time.Sleep(1 * time.Second)
	}
	return "", fmt.Errorf("steward ID not found in %s logs after 30 attempts", container)
}

// waitForContainerHealthy polls docker ps until the container reports healthy or timeout expires.
func (s *FleetTestSuite) waitForContainerHealthy(t *testing.T, container string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, "docker", "ps",
			"--filter", "name="+container,
			"--filter", "health=healthy",
			"--format", "{{.Names}}").CombinedOutput()
		cancel()
		if err == nil && strings.Contains(string(out), container) {
			t.Logf("Container %s is healthy", container)
			return true
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("Container %s did not reach healthy within %v", container, timeout)
	return false
}

// waitForConvergence polls GET /api/v1/stewards/{id} until connection_state == "connected".
func (s *FleetTestSuite) waitForConvergence(t *testing.T, stewardID string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := s.getStewardConnectionState(t, stewardID)
		if err == nil && state == "connected" {
			t.Logf("Steward %s: connection_state=connected", stewardID)
			return true
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("Steward %s did not reach connected state within %v", stewardID, timeout)
	return false
}

// getStewardConnectionState returns connection_state from GET /api/v1/stewards/{id}.
func (s *FleetTestSuite) getStewardConnectionState(t *testing.T, stewardID string) (string, error) {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/stewards/%s", s.controllerURL, stewardID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var apiResp stewardAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", fmt.Errorf("decode steward response: %w", err)
	}
	return apiResp.Data.ConnectionState, nil
}

// uploadConfig reads configPath, patches the steward ID, and sends to the test endpoint.
// The test endpoint (PUT /api/v1/test/stewards/{id}/config) bypasses authentication
// when CFGMS_ENABLE_TEST_ENDPOINTS=true, which is set in the fleet docker-compose profile.
func (s *FleetTestSuite) uploadConfig(t *testing.T, stewardID, configPath string) error {
	t.Helper()

	rawYAML, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath, err)
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal(rawYAML, &cfg); err != nil {
		return fmt.Errorf("parse config YAML: %w", err)
	}

	if section, ok := cfg["steward"].(map[string]interface{}); ok {
		section["id"] = stewardID
	}

	body, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config to JSON: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/test/stewards/%s/config", s.controllerURL, stewardID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.noAuthClient.Do(req)
	if err != nil {
		return fmt.Errorf("PUT test config: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("config upload returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	t.Logf("Config uploaded for steward %s", stewardID)
	return nil
}

// containerRestart restarts a fleet container and waits for it to reach healthy.
func (s *FleetTestSuite) containerRestart(t *testing.T, container string, healthTimeout time.Duration) {
	t.Helper()
	if err := validateFleetContainer(container); err != nil {
		t.Fatalf("containerRestart: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "restart", container).CombinedOutput(); err != nil {
		t.Fatalf("docker restart %s: %v (output: %s)", container, err, strings.TrimSpace(string(out)))
	}
	t.Logf("Restarted %s; waiting for healthy...", container)
	if !s.waitForContainerHealthy(t, container, healthTimeout) {
		t.Fatalf("container %s did not reach healthy after restart", container)
	}
}

// TestFleetWalkthrough is the single ordered entry point for all fleet walkthrough scenarios.
// Scenarios execute in definition order via t.Run so each is individually identified in output.
func TestFleetWalkthrough(t *testing.T) {
	suite := setupFleetSuite(t)
	cfg := "configs/fleet-config.yaml"

	t.Run("VanillaState", func(t *testing.T) { suite.testVanillaState(t) })
	t.Run("ConfigUploadAndConvergence", func(t *testing.T) { suite.testConfigUploadAndConvergence(t, cfg) })
	t.Run("IdempotentReUpload", func(t *testing.T) { suite.testIdempotentReUpload(t, cfg) })
	t.Run("PerModuleConvergence", func(t *testing.T) { suite.testPerModuleConvergence(t) })
	t.Run("ControllerRestart", func(t *testing.T) { suite.testControllerRestart(t, cfg) })
	t.Run("StewardRestart", func(t *testing.T) { suite.testStewardRestart(t, cfg) })
	t.Run("DeferredConfig", func(t *testing.T) { suite.testDeferredConfig(t, cfg) })
}
