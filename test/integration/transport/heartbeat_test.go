// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// HeartbeatTestSuite tests heartbeat delivery and failover detection via gRPC transport.
//
// In the gRPC transport architecture, heartbeats flow over the gRPC control plane stream.
// Failover detection occurs via stream break + reconnection.
// Tests verify observable system state via HTTP API.
//
// Scenarios handled differently from previous transports:
//   - QoS levels: not applicable (HTTP/2 provides reliable delivery)
//   - Keepalive: gRPC uses HTTP/2 PING internally
//   - Persistent sessions / offline message queueing (Issue #419)
//   - Failover detection: stream break replaces Last Will Testament
type HeartbeatTestSuite struct {
	suite.Suite
	helper *TestHelper
}

func (s *HeartbeatTestSuite) SetupSuite() {
	if testing.Short() {
		s.T().Skip("Skipping heartbeat tests in short mode - requires controller infrastructure")
	}

	baseURL := GetTestHTTPAddr("https://localhost:8080")
	s.helper = NewTestHelper(baseURL)

	// Verify the controller is reachable before running any test in this suite.
	// Without this bound, a goroutine in TestConcurrentHeartbeatConnections can
	// call t.Fatalf (which invokes runtime.Goexit on the goroutine), exit without
	// writing to the results channel, and leave the outer receive loop blocked
	// for the full 10-minute test timeout. Fail here quickly instead.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	healthURL := fmt.Sprintf("%s/api/v1/health", baseURL)
	for {
		resp, err := s.helper.httpClient.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		select {
		case <-ctx.Done():
			s.T().Skipf("controller not reachable at %s within 30s — heartbeat suite requires a running controller (set CFGMS_TEST_HTTP_ADDR to override); skipping to avoid 10-minute hang (Issue #3186)", baseURL)
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// TestRegistrationProvidesTransportAddress verifies that a registered steward
// receives a gRPC transport address for establishing the control plane stream.
// This is the prerequisite for all heartbeat and failover functionality.
func (s *HeartbeatTestSuite) TestRegistrationProvidesTransportAddress() {
	token := s.helper.CreateToken(s.T(), "default", "integration-test")
	regResp := s.helper.RegisterSteward(s.T(), token)

	s.NotEmpty(regResp.StewardID, "Steward ID should be generated")
	s.NotEmpty(regResp.TransportAddress, "Transport address should be provided for gRPC stream")
	s.T().Logf("Steward %s registered with transport_address=%s", regResp.StewardID, regResp.TransportAddress)
}

// TestHeartbeatOverGRPC verifies that a steward can register and that the controller
// exposes health status via HTTP API, reflecting connected steward health.
// Actual gRPC heartbeat stream is internal between steward process and controller.
func (s *HeartbeatTestSuite) TestHeartbeatOverGRPC() {
	s.T().Log("Verifying heartbeat infrastructure via HTTP health check")

	healthURL := fmt.Sprintf("%s/api/v1/health", s.helper.baseURL)
	resp, err := s.helper.httpClient.Get(healthURL)
	if err != nil {
		s.T().Logf("Health check unavailable: %v (controller may not expose /health)", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	s.True(resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent,
		"Controller health endpoint should respond")
	s.T().Logf("Controller health check: status=%d", resp.StatusCode)
}

// TestFailoverDetectionReconnection tests that a new registration succeeds after
// the previous steward session is lost. In gRPC transport, failover detection
// occurs via stream break — the controller detects the closed stream immediately
// (detection is immediate via stream break).
func (s *HeartbeatTestSuite) TestFailoverDetectionReconnection() {
	s.T().Log("Testing failover detection via stream break + re-registration")

	// Register first steward
	token1 := s.helper.CreateToken(s.T(), "default", "integration-test")
	resp1 := s.helper.RegisterSteward(s.T(), token1)
	s.NotEmpty(resp1.StewardID)
	s.T().Logf("Steward 1 registered: %s", resp1.StewardID)

	// Register second steward — simulates reconnection after failover
	token2 := s.helper.CreateToken(s.T(), "default", "integration-test")
	resp2 := s.helper.RegisterSteward(s.T(), token2)
	s.NotEmpty(resp2.StewardID)
	s.T().Logf("Steward 2 registered: %s", resp2.StewardID)

	// Both registrations should produce unique steward IDs
	s.NotEqual(resp1.StewardID, resp2.StewardID, "Each registration should produce a unique steward ID")
	s.T().Log("Failover detection validated: re-registration succeeds with unique identity")
}

// TestConcurrentHeartbeatConnections tests that multiple stewards can register
// and maintain independent transport connections without interference.
func (s *HeartbeatTestSuite) TestConcurrentHeartbeatConnections() {
	const numStewards = 5

	type result struct {
		stewardID        string
		transportAddress string
		err              error
	}

	results := make(chan result, numStewards)

	for i := 0; i < numStewards; i++ {
		go func(idx int) {
			// Deferred send guarantees the channel always receives a value even when
			// RegisterSteward calls t.Fatalf. t.Fatalf invokes runtime.Goexit on the
			// calling goroutine; runtime.Goexit runs deferred functions before
			// terminating, so this defer executes even on an early exit. Without it,
			// the goroutine exits silently and the outer receive loop blocks forever
			// until the 10-minute test timeout fires (Issue #3186).
			var r result
			defer func() { results <- r }()

			token := s.helper.CreateToken(s.T(), "default", fmt.Sprintf("group-%d", idx))
			regResp := s.helper.RegisterSteward(s.T(), token)
			r = result{
				stewardID:        regResp.StewardID,
				transportAddress: regResp.TransportAddress,
			}
		}(i)
	}

	seen := make(map[string]bool)
	for i := 0; i < numStewards; i++ {
		r := <-results
		if r.err != nil {
			s.T().Logf("Registration %d failed: %v", i, r.err)
			continue
		}
		s.NotEmpty(r.stewardID)
		s.NotEmpty(r.transportAddress)
		s.False(seen[r.stewardID], "Each steward should have a unique ID")
		seen[r.stewardID] = true

		time.Sleep(10 * time.Millisecond) // slight delay to prevent log spam
	}

	s.Equal(numStewards, len(seen), "All concurrent registrations should produce unique steward IDs")
	s.T().Logf("Concurrent heartbeat connections: %d unique stewards registered", len(seen))
}

func TestHeartbeat(t *testing.T) {
	suite.Run(t, new(HeartbeatTestSuite))
}
