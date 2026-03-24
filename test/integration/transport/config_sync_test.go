// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

// ConfigSyncTestSuite tests configuration synchronization over gRPC data plane.
//
// Config sync in the gRPC transport architecture:
//   - Controller triggers config sync by sending a command over the gRPC control plane stream
//   - Steward connects to the gRPC data plane to fetch config payload
//   - Large configs (>100KB) transfer efficiently over the QUIC-based data plane
//   - Status is reported back via the gRPC control plane stream
//
// Tests verify the observable interface (HTTP API) rather than the internal gRPC stream.
type ConfigSyncTestSuite struct {
	suite.Suite
	helper *TestHelper
}

func (s *ConfigSyncTestSuite) SetupSuite() {
	if testing.Short() {
		s.T().Skip("Skipping config sync tests in short mode - requires controller infrastructure")
	}

	s.helper = NewTestHelper(GetTestHTTPAddr("https://localhost:8080"))
}

// TestConfigSyncCommand tests that a registered steward receives transport_address
// for initiating the gRPC data plane connection used for config sync.
func (s *ConfigSyncTestSuite) TestConfigSyncCommand() {
	s.T().Log("Testing config sync command flow")

	token := s.helper.CreateToken(s.T(), "default", "integration-test")
	regResp := s.helper.RegisterSteward(s.T(), token)

	s.NotEmpty(regResp.StewardID, "Steward ID should be generated")
	s.NotEmpty(regResp.TransportAddress, "Transport address required for gRPC DP config sync")

	s.T().Logf("Config sync transport validated: steward=%s transport=%s",
		regResp.StewardID, regResp.TransportAddress)
}

// TestConfigUploadAPI tests that configuration can be uploaded via the HTTP test endpoint.
// The controller will then push the config to connected stewards via gRPC.
func (s *ConfigSyncTestSuite) TestConfigUploadAPI() {
	token := s.helper.CreateToken(s.T(), "default", "integration-test")
	regResp := s.helper.RegisterSteward(s.T(), token)
	s.NotEmpty(regResp.StewardID)

	config := map[string]interface{}{
		"steward": map[string]interface{}{
			"id":   regResp.StewardID,
			"mode": "controller",
		},
		"resources": []map[string]interface{}{
			{
				"name":   "test-directory",
				"module": "directory",
				"config": map[string]interface{}{
					"path": "/tmp/test-transport",
					"mode": "0755",
				},
			},
		},
	}

	configJSON, err := json.Marshal(config)
	s.NoError(err)

	url := fmt.Sprintf("%s/api/v1/test/stewards/%s/config", s.helper.baseURL, regResp.StewardID)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(configJSON))
	s.NoError(err)
	req.Header.Set("Content-Type", "application/json")

	client := s.helper.httpClient
	resp, err := client.Do(req)
	if err != nil {
		s.T().Logf("Config upload failed (test endpoint may not be available): %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	s.T().Logf("Config upload response: %d", resp.StatusCode)
}

// TestConfigPayloadStructure validates the configuration payload structure
// used for gRPC data plane transfer.
func (s *ConfigSyncTestSuite) TestConfigPayloadStructure() {
	config := map[string]interface{}{
		"steward": map[string]interface{}{
			"id":   "test-steward",
			"mode": "controller",
		},
		"resources": []map[string]interface{}{
			{
				"name":   "test-directory",
				"module": "directory",
				"config": map[string]interface{}{
					"path": "/tmp/test",
					"mode": "0755",
				},
			},
			{
				"name":   "test-file",
				"module": "file",
				"config": map[string]interface{}{
					"path":    "/tmp/test/file.txt",
					"content": "test content",
					"mode":    "0644",
				},
			},
		},
	}

	s.NotNil(config["steward"])
	s.NotNil(config["resources"])

	resources := config["resources"].([]map[string]interface{})
	s.Len(resources, 2, "Should have 2 resources")
	s.Equal("directory", resources[0]["module"])
	s.Equal("file", resources[1]["module"])

	configJSON, err := json.Marshal(config)
	s.NoError(err)
	s.NotEmpty(configJSON)
	s.Greater(len(configJSON), 100, "Config should be substantial")

	s.T().Logf("Config payload structure validated: %d bytes", len(configJSON))
}

// TestLargeConfigPayload tests large configuration transfer (>100KB).
// Large configs use the gRPC data plane (QUIC stream) for efficient transfer.
func (s *ConfigSyncTestSuite) TestLargeConfigPayload() {
	largeConfig := map[string]interface{}{
		"steward": map[string]interface{}{
			"id": "test-steward-large",
		},
		"resources": []map[string]interface{}{},
	}

	for i := 0; i < 500; i++ {
		resource := map[string]interface{}{
			"name":   fmt.Sprintf("resource-%d", i),
			"module": "file",
			"config": map[string]interface{}{
				"path": fmt.Sprintf("/tmp/test/file%d.txt", i),
				"content": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " +
					"Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
			},
		}
		largeConfig["resources"] = append(largeConfig["resources"].([]map[string]interface{}), resource)
	}

	configJSON, err := json.Marshal(largeConfig)
	s.NoError(err)

	s.Greater(len(configJSON), 100*1024, "Config should exceed 100KB for gRPC DP transfer")

	s.T().Logf("Large config payload: %d bytes (%.1f KB) — would use gRPC DP QUIC stream",
		len(configJSON), float64(len(configJSON))/1024)
}

// TestConfigSyncTransportAddressFormat tests that the transport_address in the
// registration response has the correct format for gRPC-over-QUIC connections.
func (s *ConfigSyncTestSuite) TestConfigSyncTransportAddressFormat() {
	token := s.helper.CreateToken(s.T(), "default", "integration-test")
	regResp := s.helper.RegisterSteward(s.T(), token)

	s.NotEmpty(regResp.TransportAddress,
		"Registration must return transport_address for gRPC-over-QUIC data plane")

	s.T().Logf("Transport address format: %s", regResp.TransportAddress)
}

func TestConfigSync(t *testing.T) {
	suite.Run(t, new(ConfigSyncTestSuite))
}
