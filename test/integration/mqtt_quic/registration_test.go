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

	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/pkg/registration"
)

// RegistrationTestSuite tests end-to-end registration flow
// AC1: End-to-end registration test (HTTP → MQTT subscribe → QUIC session → steward ID)
type RegistrationTestSuite struct {
	suite.Suite
	helper *TestHelper
}

func (s *RegistrationTestSuite) SetupSuite() {
	// Connect to Docker controller (assumes docker-compose.test.yml is running)
	s.helper = NewTestHelper(GetTestHTTPAddr("http://localhost:8080"))
}

func (s *RegistrationTestSuite) TearDownSuite() {
	// No cleanup needed - Docker containers persist
}

// TestHTTPRegistrationEndpoint tests the HTTP registration endpoint
func (s *RegistrationTestSuite) TestHTTPRegistrationEndpoint() {
	// Create a test registration token
	tenantID := "test-tenant"
	group := "production"
	token := s.helper.CreateToken(s.T(), tenantID, group)

	s.T().Logf("Created test token: %s", token)

	// Register steward
	regResp := s.helper.RegisterSteward(s.T(), token)

	// Verify response fields
	s.NotEmpty(regResp.StewardID, "Steward ID should be generated")
	s.Equal(tenantID, regResp.TenantID, "Tenant ID should match")
	s.Equal(group, regResp.Group, "Group should match")
	s.NotEmpty(regResp.MQTTBroker, "MQTT broker address should be provided")
	s.NotEmpty(regResp.QUICAddress, "QUIC address should be provided")

	s.T().Logf("Registration successful: steward_id=%s, tenant_id=%s, mqtt=%s, quic=%s",
		regResp.StewardID, regResp.TenantID, regResp.MQTTBroker, regResp.QUICAddress)
}

// TestInvalidToken tests registration with invalid token
func (s *RegistrationTestSuite) TestInvalidToken() {
	reqBody := map[string]string{
		"token": "cfgms_reg_invalid_token_12345",
	}
	reqJSON, err := json.Marshal(reqBody)
	s.NoError(err)

	registrationURL := fmt.Sprintf("%s/api/v1/register", s.helper.baseURL)
	resp, err := s.helper.httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
	s.NoError(err)
	defer resp.Body.Close()

	// Should return 401 Unauthorized for invalid token
	s.Equal(http.StatusUnauthorized, resp.StatusCode, "Invalid token should return 401")
}

// TestExpiredToken tests registration with expired token
func (s *RegistrationTestSuite) TestExpiredToken() {
	// Create expired token
	ctx := context.Background()
	expiredTime := time.Now().Add(-1 * time.Hour)
	token := &registration.Token{
		Token:         "cfgms_reg_expired_test",
		TenantID:      "test-tenant",
		ControllerURL: "mqtt://localhost:1883",
		Group:         "production",
		CreatedAt:     time.Now().Add(-2 * time.Hour),
		ExpiresAt:     &expiredTime,
		SingleUse:     true,
		Revoked:       false,
	}

	err := s.helper.tokenStore.SaveToken(ctx, token)
	s.NoError(err)

	// Try to register with expired token
	reqBody := map[string]string{
		"token": token.Token,
	}
	reqJSON, err := json.Marshal(reqBody)
	s.NoError(err)

	registrationURL := fmt.Sprintf("%s/api/v1/register", s.helper.baseURL)
	resp, err := s.helper.httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
	s.NoError(err)
	defer resp.Body.Close()

	// Should return 401 Unauthorized
	s.Equal(http.StatusUnauthorized, resp.StatusCode, "Expired token should return 401")
}

// TestRevokedToken tests registration with revoked token
func (s *RegistrationTestSuite) TestRevokedToken() {
	ctx := context.Background()

	// Create revoked token
	now := time.Now()
	token := &registration.Token{
		Token:         "cfgms_reg_revoked_test",
		TenantID:      "test-tenant",
		ControllerURL: "mqtt://localhost:1883",
		Group:         "production",
		CreatedAt:     now,
		SingleUse:     true,
		Revoked:       true,
		RevokedAt:     &now,
	}

	err := s.helper.tokenStore.SaveToken(ctx, token)
	s.NoError(err)

	// Try to register with revoked token
	reqBody := map[string]string{
		"token": token.Token,
	}
	reqJSON, err := json.Marshal(reqBody)
	s.NoError(err)

	registrationURL := fmt.Sprintf("%s/api/v1/register", s.helper.baseURL)
	resp, err := s.helper.httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
	s.NoError(err)
	defer resp.Body.Close()

	// Should return 401 Unauthorized
	s.Equal(http.StatusUnauthorized, resp.StatusCode, "Revoked token should return 401")
}

// TestSingleUseToken tests that single-use tokens can only be used once
func (s *RegistrationTestSuite) TestSingleUseToken() {
	// Create single-use token
	token := s.helper.CreateToken(s.T(), "test-tenant", "production")

	// First registration should succeed
	reqBody := map[string]string{
		"token": token,
	}
	reqJSON, err := json.Marshal(reqBody)
	s.NoError(err)

	registrationURL := fmt.Sprintf("%s/api/v1/register", s.helper.baseURL)
	resp1, err := s.helper.httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
	s.NoError(err)
	defer resp1.Body.Close()

	s.Equal(http.StatusOK, resp1.StatusCode, "First registration should succeed")

	// Second registration with same token should fail
	resp2, err := s.helper.httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
	s.NoError(err)
	defer resp2.Body.Close()

	s.Equal(http.StatusUnauthorized, resp2.StatusCode, "Second registration with single-use token should fail")
}

// TestTenantIsolation tests that steward IDs include tenant prefix for isolation
func (s *RegistrationTestSuite) TestTenantIsolation() {
	// Register stewards for different tenants
	tenants := []string{"tenant-alpha", "tenant-beta", "tenant-gamma"}
	stewardIDs := make(map[string]string)

	for _, tenantID := range tenants {
		token := s.helper.CreateToken(s.T(), tenantID, "production")
		regResp := s.helper.RegisterSteward(s.T(), token)

		s.Equal(tenantID, regResp.TenantID, "Response should have correct tenant ID")
		stewardIDs[tenantID] = regResp.StewardID
	}

	// Verify each steward ID is unique
	seen := make(map[string]bool)
	for _, stewardID := range stewardIDs {
		s.False(seen[stewardID], "Steward IDs should be unique")
		seen[stewardID] = true
	}

	s.T().Logf("Verified tenant isolation: %d unique steward IDs generated", len(stewardIDs))
}

// TestConcurrentRegistrations tests multiple simultaneous registrations
func (s *RegistrationTestSuite) TestConcurrentRegistrations() {
	const numConcurrent = 50

	results := make(chan error, numConcurrent)
	stewardIDs := make(chan string, numConcurrent)

	// Launch concurrent registrations
	for i := 0; i < numConcurrent; i++ {
		go func(idx int) {
			token := s.helper.CreateToken(s.T(), fmt.Sprintf("tenant-%d", idx), "production")

			reqBody := map[string]string{
				"token": token,
			}
			reqJSON, _ := json.Marshal(reqBody)

			registrationURL := fmt.Sprintf("%s/api/v1/register", s.helper.baseURL)
			resp, err := s.helper.httpClient.Post(registrationURL, "application/json", bytes.NewBuffer(reqJSON))
			if err != nil {
				results <- err
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				results <- fmt.Errorf("registration %d failed with status %d", idx, resp.StatusCode)
				return
			}

			body, _ := io.ReadAll(resp.Body)
			var regResp struct {
				StewardID string `json:"steward_id"`
			}
			json.Unmarshal(body, &regResp)

			stewardIDs <- regResp.StewardID
			results <- nil
		}(i)
	}

	// Collect results
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

	// All registrations should succeed
	s.Equal(numConcurrent, successCount, "All concurrent registrations should succeed")

	// All steward IDs should be unique
	s.Equal(numConcurrent, len(uniqueIDs), "All steward IDs should be unique")

	s.T().Logf("Concurrent registrations: %d successful, %d unique steward IDs", successCount, len(uniqueIDs))
}

func TestRegistration(t *testing.T) {
	suite.Run(t, new(RegistrationTestSuite))
}
