// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/test/integration/testutil"
)

// ControllerTestSuite tests in-process controller with real components.
// Creates a real controller (not a mock) and validates lifecycle, health, and registration.
type ControllerTestSuite struct {
	suite.Suite
	env      *testutil.TestEnv
	httpAddr string
}

func (s *ControllerTestSuite) SetupSuite() {
	// Use a unique HTTP port to avoid conflicts with Docker containers
	s.httpAddr = "127.0.0.1:19080"
	s.T().Setenv("CFGMS_HTTP_LISTEN_ADDR", s.httpAddr)

	// Create a real test environment (real controller, real cert manager, real storage)
	s.env = testutil.NewTestEnv(s.T())

	// Start the controller (real in-process startup)
	ctx := s.env.GetContext()
	err := s.env.Controller.Start(ctx)
	require.NoError(s.T(), err, "Failed to start controller")

	// Poll until HTTP API is ready (replaces hardcoded sleep)
	s.waitForHTTPReady()
}

func (s *ControllerTestSuite) waitForHTTPReady() {
	client := s.tlsClient()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(fmt.Sprintf("https://%s/api/v1/health", s.httpAddr))
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.T().Log("Warning: HTTP API may not be ready yet")
}

// tlsClient returns an HTTP client that skips TLS verification for self-signed test certs.
func (s *ControllerTestSuite) tlsClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 — test-only, self-signed cert
		},
	}
}

func (s *ControllerTestSuite) TearDownSuite() {
	if s.env != nil {
		_ = s.env.Controller.Stop(s.env.GetContext())
		s.env.Cleanup()
	}
}

func (s *ControllerTestSuite) SetupTest() {
	s.env.Reset()
}

// TestControllerStartup verifies the controller started and is serving
func (s *ControllerTestSuite) TestControllerStartup() {
	// Verify controller has a listen address (proves server bound to a port)
	addr := s.env.Controller.GetListenAddr()
	s.NotEmpty(addr, "Controller should have a listen address")

	// Verify cert manager is initialized (proves real startup completed)
	certMgr := s.env.Controller.GetCertificateManager()
	s.NotNil(certMgr, "Controller should have an initialized certificate manager")
}

// TestControllerHealthEndpoint verifies the health API responds with real status
func (s *ControllerTestSuite) TestControllerHealthEndpoint() {
	resp, err := s.tlsClient().Get(fmt.Sprintf("https://%s/api/v1/health", s.httpAddr))
	require.NoError(s.T(), err, "Health endpoint should be reachable")
	defer func() { _ = resp.Body.Close() }()

	// Health endpoint returns 200 (healthy) or 503 (degraded) - both prove it's running
	s.True(resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusServiceUnavailable,
		"Health endpoint should return 200 or 503, got %d", resp.StatusCode)

	var health map[string]any
	err = json.NewDecoder(resp.Body).Decode(&health)
	require.NoError(s.T(), err, "Health response should be valid JSON")

	// Response may wrap status in a "data" field or at top level
	var status any
	if data, ok := health["data"].(map[string]any); ok {
		status = data["status"]
	} else {
		status = health["status"]
	}
	s.NotNil(status, "Health response should contain a status field")

	s.T().Logf("Health status: %v", status)
}

// TestStewardRegistration tests the full registration flow with a real token and real API
func (s *ControllerTestSuite) TestStewardRegistration() {
	// Get the registration token store from the running controller
	tokenStoreIface := s.env.Controller.GetRegistrationTokenStore()
	require.NotNil(s.T(), tokenStoreIface, "Controller should have a registration token store")

	tokenStore, ok := tokenStoreIface.(registration.Store)
	require.True(s.T(), ok, "Token store should implement registration.Store")

	// Create a real registration token
	token, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID:      "test-tenant",
		ControllerURL: fmt.Sprintf("quic://%s", s.env.Controller.GetListenAddr()),
		Group:         "test-group",
		ExpiresIn:     "1h",
		SingleUse:     false,
	})
	require.NoError(s.T(), err, "Should create registration token")

	// Save token to the controller's store
	ctx := context.Background()
	err = tokenStore.SaveToken(ctx, token)
	require.NoError(s.T(), err, "Should save registration token")

	// Call the registration API endpoint
	reqBody, err := json.Marshal(map[string]string{"token": token.Token})
	require.NoError(s.T(), err)

	resp, err := s.tlsClient().Post(
		fmt.Sprintf("https://%s/api/v1/register", s.httpAddr),
		"application/json",
		bytes.NewReader(reqBody),
	)
	require.NoError(s.T(), err, "Registration request should reach the controller")
	defer func() { _ = resp.Body.Close() }()

	// Parse the registration response
	var regResp map[string]any
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	require.NoError(s.T(), err, "Registration response should be valid JSON")

	// Verify registration succeeded - response must contain a steward_id
	s.Contains(regResp, "steward_id", "Registration response should contain steward_id")
	s.NotEmpty(regResp["steward_id"], "Steward ID should not be empty")

	// Verify tenant info is correct
	s.Equal("test-tenant", regResp["tenant_id"], "Response should contain correct tenant_id")

	// Verify certificates were provided (proves cert manager is working)
	s.Contains(regResp, "ca_cert", "Registration response should contain CA certificate")
	s.Contains(regResp, "client_cert", "Registration response should contain client certificate")

	s.T().Logf("Registration successful: steward_id=%v, tenant_id=%v", regResp["steward_id"], regResp["tenant_id"])
}

func TestControllerIntegration(t *testing.T) {
	suite.Run(t, new(ControllerTestSuite))
}
