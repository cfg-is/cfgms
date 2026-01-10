// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package integration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/pkg/mqtt/types"
)

// MQTTQUICFlowTestSuite tests the MQTT+QUIC communication flow.
// These are API compatibility and message structure tests (Story #198).
// Full integration tests with running controller/steward are in docker_test.go.
type MQTTQUICFlowTestSuite struct {
	suite.Suite
}

// TestConfigStatusReportStructure verifies the ConfigStatusReport message structure.
func (s *MQTTQUICFlowTestSuite) TestConfigStatusReportStructure() {
	report := types.ConfigStatusReport{
		StewardID:     "test-steward",
		ConfigVersion: "v1.0.0",
		Status:        "OK",
		Message:       "Configuration applied successfully",
		Modules: map[string]types.ModuleStatus{
			"file": {
				Name:      "file",
				Status:    "OK",
				Message:   "File module applied successfully",
				Timestamp: time.Now(),
			},
			"firewall": {
				Name:      "firewall",
				Status:    "ERROR",
				Message:   "Failed to apply firewall rules",
				Timestamp: time.Now(),
			},
		},
		Timestamp:       time.Now(),
		ExecutionTimeMs: 1500,
	}

	s.Equal("test-steward", report.StewardID)
	s.Equal("v1.0.0", report.ConfigVersion)
	s.Equal(2, len(report.Modules))
	s.Equal("OK", report.Modules["file"].Status)
	s.Equal("ERROR", report.Modules["firewall"].Status)
}

// TestValidationRequestResponseStructure verifies the validation message structures.
func (s *MQTTQUICFlowTestSuite) TestValidationRequestResponseStructure() {
	request := types.ValidationRequest{
		RequestID: "val_123456",
		StewardID: "test-steward",
		Config:    []byte(`{"steward":{"id":"test"}}`),
		Version:   "v1.0.0",
		Timestamp: time.Now(),
	}

	s.Equal("val_123456", request.RequestID)
	s.Equal("test-steward", request.StewardID)
	s.NotEmpty(request.Config)

	response := types.ValidationResponse{
		RequestID: "val_123456",
		Valid:     false,
		Errors:    []string{"Invalid module configuration", "Missing required field"},
		Timestamp: time.Now(),
	}

	s.Equal("val_123456", response.RequestID)
	s.False(response.Valid)
	s.Equal(2, len(response.Errors))
}

func TestMQTTQUICFlow(t *testing.T) {
	suite.Run(t, new(MQTTQUICFlowTestSuite))
}
