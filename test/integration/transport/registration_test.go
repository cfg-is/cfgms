// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

// RegistrationTestSuite tests end-to-end registration flow with gRPC transport.
// AC1: HTTP registration returns transport_address
// AC2: Invalid/expired/revoked tokens rejected with 401
// AC3: Concurrent registrations return unique steward IDs
type RegistrationTestSuite struct {
	suite.Suite
	helper *TestHelper
}

func (s *RegistrationTestSuite) SetupSuite() {
	if testing.Short() {
		s.T().Skip("Skipping registration tests in short mode - requires controller")
	}

	s.helper = NewTestHelper(GetTestHTTPAddr("https://localhost:8080"))
}

func (s *RegistrationTestSuite) TearDownSuite() {}

// TestHTTPRegistrationEndpoint tests the HTTP registration endpoint returns transport_address.
func (s *RegistrationTestSuite) TestHTTPRegistrationEndpoint() {
	token := s.helper.CreateToken("", "")
	expectedTenantID := "test-tenant-integration"
	expectedGroup := "production"

	s.T().Logf("Using test token: %s", token)

	regResp, err := s.helper.RegisterSteward(token)
	s.Require().NoError(err, "Steward registration should succeed")

	s.NotEmpty(regResp.StewardID, "Steward ID should be generated")
	s.Equal(expectedTenantID, regResp.TenantID, "Tenant ID should match")
	s.Equal(expectedGroup, regResp.Group, "Group should match")
	s.NotEmpty(regResp.TransportAddress, "Transport address should be provided (gRPC-over-QUIC)")

	s.T().Logf("Registration successful: steward_id=%s, tenant_id=%s, transport_address=%s",
		regResp.StewardID, regResp.TenantID, regResp.TransportAddress)
}

// TestInvalidToken tests registration with invalid token returns 401.
func (s *RegistrationTestSuite) TestInvalidToken() {
	reqBody := map[string]string{"token": "invalid_token_12345"}
	reqJSON, err := json.Marshal(reqBody)
	s.NoError(err)

	registrationURL := fmt.Sprintf("%s/api/v1/register", s.helper.baseURL)
	resp, err := s.helper.httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
	s.NoError(err)
	defer func() { _ = resp.Body.Close() }()

	s.Equal(http.StatusUnauthorized, resp.StatusCode, "Invalid token should return 401")
}

// TestExpiredToken tests registration with expired token returns 401.
func (s *RegistrationTestSuite) TestExpiredToken() {
	reqBody := map[string]string{"token": "integration_expired"}
	reqJSON, err := json.Marshal(reqBody)
	s.NoError(err)

	registrationURL := fmt.Sprintf("%s/api/v1/register", s.helper.baseURL)
	resp, err := s.helper.httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
	s.NoError(err)
	defer func() { _ = resp.Body.Close() }()

	s.Equal(http.StatusUnauthorized, resp.StatusCode, "Expired token should return 401")
}

// TestRevokedToken tests registration with revoked token returns 401.
func (s *RegistrationTestSuite) TestRevokedToken() {
	reqBody := map[string]string{"token": "integration_revoked"}
	reqJSON, err := json.Marshal(reqBody)
	s.NoError(err)

	registrationURL := fmt.Sprintf("%s/api/v1/register", s.helper.baseURL)
	resp, err := s.helper.httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
	s.NoError(err)
	defer func() { _ = resp.Body.Close() }()

	s.Equal(http.StatusUnauthorized, resp.StatusCode, "Revoked token should return 401")
}

// TestPerennialToken tests that perennial tokens can be used multiple times (Issue #1690).
func (s *RegistrationTestSuite) TestPerennialToken() {
	registrationURL := fmt.Sprintf("%s/api/v1/register", s.helper.baseURL)
	for i := 0; i < 3; i++ {
		// Each registration needs a unique DeviceID to avoid 409 conflict within the tenant.
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		s.NoError(err)
		h := sha256.Sum256(pub)
		reqBody := map[string]string{
			"token":            "integration_reusable",
			"device_id":        hex.EncodeToString(h[:]),
			"identity_key_pub": base64.StdEncoding.EncodeToString(pub),
		}
		reqJSON, err := json.Marshal(reqBody)
		s.NoError(err)
		resp, postErr := s.helper.httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
		s.NoError(postErr)
		_ = resp.Body.Close()
		s.Equal(http.StatusOK, resp.StatusCode, "Registration #%d with perennial token must succeed", i+1)
	}
}

// TestStewardIDUniqueness tests that each registration produces a unique steward ID.
func (s *RegistrationTestSuite) TestStewardIDUniqueness() {
	const numStewards = 3
	stewardIDs := make([]string, 0, numStewards)

	for i := 0; i < numStewards; i++ {
		token := s.helper.CreateToken("test-tenant-integration", "production")
		regResp, err := s.helper.RegisterSteward(token)
		s.Require().NoErrorf(err, "Registration #%d should succeed", i+1)

		s.Equal("test-tenant-integration", regResp.TenantID, "Response should have correct tenant ID")
		stewardIDs = append(stewardIDs, regResp.StewardID)
	}

	seen := make(map[string]bool)
	for _, stewardID := range stewardIDs {
		s.False(seen[stewardID], "Steward IDs should be unique")
		seen[stewardID] = true
	}

	s.T().Logf("Verified steward ID uniqueness: %d unique steward IDs generated", len(stewardIDs))
}

// TestConcurrentRegistrations tests multiple simultaneous registrations.
func (s *RegistrationTestSuite) TestConcurrentRegistrations() {
	const numConcurrent = 50

	results := make(chan error, numConcurrent)
	stewardIDs := make(chan string, numConcurrent)

	token := "integration_reusable"

	for i := 0; i < numConcurrent; i++ {
		go func(idx int) {
			// Each concurrent registration needs a unique DeviceID to avoid 409 conflicts.
			pub, _, genErr := ed25519.GenerateKey(rand.Reader)
			if genErr != nil {
				results <- genErr
				return
			}
			h := sha256.Sum256(pub)
			reqBody := map[string]string{
				"token":            token,
				"device_id":        hex.EncodeToString(h[:]),
				"identity_key_pub": base64.StdEncoding.EncodeToString(pub),
			}
			reqJSON, marshalErr := json.Marshal(reqBody)
			if marshalErr != nil {
				results <- marshalErr
				return
			}

			registrationURL := fmt.Sprintf("%s/api/v1/register", s.helper.baseURL)
			resp, err := s.helper.httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
			if err != nil {
				results <- err
				return
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				results <- fmt.Errorf("registration %d failed with status %d", idx, resp.StatusCode)
				return
			}

			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				results <- fmt.Errorf("registration %d: read body: %w", idx, readErr)
				return
			}
			var regResp struct {
				StewardID string `json:"steward_id"`
			}
			if unmarshalErr := json.Unmarshal(body, &regResp); unmarshalErr != nil {
				results <- fmt.Errorf("registration %d: unmarshal response: %w", idx, unmarshalErr)
				return
			}

			stewardIDs <- regResp.StewardID
			results <- nil
		}(i)
	}

	successCount := 0
	uniqueIDs := make(map[string]bool)

	for i := 0; i < numConcurrent; i++ {
		err := <-results
		if err == nil {
			successCount++
			stewardID := <-stewardIDs
			uniqueIDs[stewardID] = true
		}
	}

	s.Equal(numConcurrent, successCount, "All concurrent registrations should succeed")
	s.Equal(numConcurrent, len(uniqueIDs), "All steward IDs should be unique")

	s.T().Logf("Concurrent registrations: %d successful, %d unique steward IDs", successCount, len(uniqueIDs))
}

func TestRegistration(t *testing.T) {
	suite.Run(t, new(RegistrationTestSuite))
}
