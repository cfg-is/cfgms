// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package integration contains integration tests that validate CFGMS deployment scenarios
// as documented in QUICK_START.md. These tests ensure that the documented workflows
// actually work as described.
package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// CertificateRegistrationTestSuite tests the certificate provisioning flow
// that occurs when a steward registers with a valid token.
//
// This test suite validates:
//  1. Registration token validation logic
//  2. Certificate generation during registration
//  3. Token lifecycle (expiration, revocation, single-use)
//  4. Certificate chain validity
//
// Philosophy: "Test what you ship, ship what you test"
type CertificateRegistrationTestSuite struct {
	suite.Suite
	tempDir                 string
	certManager             *cert.Manager
	tokenStore              business.RegistrationTokenStore
	adapter                 *registration.StorageAdapter
	certProvisioningService *service.CertificateProvisioningService
	logger                  logging.Logger
}

func (s *CertificateRegistrationTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "cfgms-cert-registration-*")
	require.NoError(s.T(), err)

	s.logger = logging.NewNoopLogger()

	// Initialize certificate manager
	certStoragePath := filepath.Join(s.tempDir, "certs")
	err = os.MkdirAll(certStoragePath, 0755)
	require.NoError(s.T(), err)

	s.certManager, err = cert.NewManager(&cert.ManagerConfig{
		StoragePath: certStoragePath,
		CAConfig: &cert.CAConfig{
			Organization:       "CFGMS Test CA",
			Country:            "US",
			State:              "Test",
			City:               "Test",
			OrganizationalUnit: "Integration Tests",
			ValidityDays:       365,
			KeySize:            2048,
		},
		LoadExistingCA:       false,
		RenewalThresholdDays: 30,
	})
	require.NoError(s.T(), err)

	// Initialize registration token store (sqlite-based)
	tokenStorePath := filepath.Join(s.tempDir, "tokens")
	require.NoError(s.T(), os.MkdirAll(tokenStorePath, 0755))
	s.tokenStore, err = interfaces.CreateRegistrationTokenStoreFromConfig(
		"sqlite",
		map[string]interface{}{"path": filepath.Join(tokenStorePath, "tokens.db")},
	)
	require.NoError(s.T(), err)
	s.T().Cleanup(func() { _ = s.tokenStore.Close() })

	ctx := context.Background()
	err = s.tokenStore.Initialize(ctx)
	require.NoError(s.T(), err)

	s.adapter = registration.NewStorageAdapter(s.tokenStore)

	// Initialize certificate provisioning service
	s.certProvisioningService = service.NewCertificateProvisioningService(s.certManager, s.logger)
}

func (s *CertificateRegistrationTestSuite) TearDownSuite() {
	if s.tokenStore != nil {
		_ = s.tokenStore.Close()
	}
	if s.tempDir != "" {
		_ = os.RemoveAll(s.tempDir)
	}
}

func (s *CertificateRegistrationTestSuite) SetupTest() {
	// Clean up tokens between tests
	ctx := context.Background()
	tokens, err := s.tokenStore.ListTokens(ctx, nil)
	if err == nil {
		for _, token := range tokens {
			_ = s.tokenStore.DeleteToken(ctx, token.Token)
		}
	}
}

// TestTokenValidation validates registration token lifecycle
func (s *CertificateRegistrationTestSuite) TestTokenValidation() {
	ctx := context.Background()

	// Create a valid token
	token := &registration.Token{
		Token:         "cfgms_reg_valid_test_001",
		TenantID:      "test-tenant",
		ControllerURL: "tcp://localhost:1883",
		Group:         "test-group",
		CreatedAt:     time.Now(),
		SingleUse:     false,
		Revoked:       false,
	}
	err := s.adapter.SaveToken(ctx, token)
	require.NoError(s.T(), err)

	// Retrieve and validate token
	retrieved, err := s.adapter.GetToken(ctx, token.Token)
	require.NoError(s.T(), err)
	assert.True(s.T(), retrieved.IsValid(), "Token should be valid")
	assert.Equal(s.T(), "test-tenant", retrieved.TenantID)
	assert.Equal(s.T(), "test-group", retrieved.Group)

	s.T().Log("Token validation passed")
}

// TestExpiredTokenInvalid validates that expired tokens are invalid
func (s *CertificateRegistrationTestSuite) TestExpiredTokenInvalid() {
	ctx := context.Background()

	// Create an expired token
	pastExpiry := time.Now().Add(-1 * time.Hour)
	token := &registration.Token{
		Token:         "cfgms_reg_expired_test_001",
		TenantID:      "test-tenant",
		ControllerURL: "tcp://localhost:1883",
		CreatedAt:     time.Now().Add(-2 * time.Hour),
		ExpiresAt:     &pastExpiry,
		SingleUse:     false,
		Revoked:       false,
	}
	err := s.adapter.SaveToken(ctx, token)
	require.NoError(s.T(), err)

	// Retrieve and check validity
	retrieved, err := s.adapter.GetToken(ctx, token.Token)
	require.NoError(s.T(), err)
	assert.False(s.T(), retrieved.IsValid(), "Expired token should be invalid")

	s.T().Log("Expired token correctly marked as invalid")
}

// TestRevokedTokenInvalid validates that revoked tokens are invalid
func (s *CertificateRegistrationTestSuite) TestRevokedTokenInvalid() {
	ctx := context.Background()

	// Create and revoke a token
	token := &registration.Token{
		Token:         "cfgms_reg_revoked_test_001",
		TenantID:      "test-tenant",
		ControllerURL: "tcp://localhost:1883",
		CreatedAt:     time.Now(),
		SingleUse:     false,
	}
	token.Revoke()
	err := s.adapter.SaveToken(ctx, token)
	require.NoError(s.T(), err)

	// Retrieve and check validity
	retrieved, err := s.adapter.GetToken(ctx, token.Token)
	require.NoError(s.T(), err)
	assert.True(s.T(), retrieved.Revoked, "Token should be revoked")
	assert.False(s.T(), retrieved.IsValid(), "Revoked token should be invalid")
	assert.NotNil(s.T(), retrieved.RevokedAt, "Revocation time should be set")

	s.T().Log("Revoked token correctly marked as invalid")
}

// TestSingleUseTokenBecomesInvalidAfterUse validates single-use token behavior
func (s *CertificateRegistrationTestSuite) TestSingleUseTokenBecomesInvalidAfterUse() {
	ctx := context.Background()

	// Create a single-use token
	token := &registration.Token{
		Token:         "cfgms_reg_single_use_test_001",
		TenantID:      "test-tenant",
		ControllerURL: "tcp://localhost:1883",
		CreatedAt:     time.Now(),
		SingleUse:     true,
		Revoked:       false,
	}
	err := s.adapter.SaveToken(ctx, token)
	require.NoError(s.T(), err)

	// Token should be valid initially
	retrieved, err := s.adapter.GetToken(ctx, token.Token)
	require.NoError(s.T(), err)
	assert.True(s.T(), retrieved.IsValid(), "Single-use token should be valid initially")

	// Mark as used
	retrieved.MarkUsed("steward-001")
	err = s.adapter.UpdateToken(ctx, retrieved)
	require.NoError(s.T(), err)

	// Token should now be invalid
	afterUse, err := s.adapter.GetToken(ctx, token.Token)
	require.NoError(s.T(), err)
	assert.False(s.T(), afterUse.IsValid(), "Single-use token should be invalid after use")
	assert.Equal(s.T(), "steward-001", afterUse.UsedBy, "UsedBy should be set")
	assert.NotNil(s.T(), afterUse.UsedAt, "UsedAt should be set")

	s.T().Log("Single-use token enforcement working correctly")
}

// TestMultiUseTokenRemainsValidAfterUse validates multi-use tokens stay valid
func (s *CertificateRegistrationTestSuite) TestMultiUseTokenRemainsValidAfterUse() {
	ctx := context.Background()

	// Create a multi-use token
	token := &registration.Token{
		Token:         "cfgms_reg_multi_use_test_001",
		TenantID:      "test-tenant",
		ControllerURL: "tcp://localhost:1883",
		CreatedAt:     time.Now(),
		SingleUse:     false,
		Revoked:       false,
	}
	err := s.adapter.SaveToken(ctx, token)
	require.NoError(s.T(), err)

	// Mark as used (would happen during registration)
	retrieved, err := s.adapter.GetToken(ctx, token.Token)
	require.NoError(s.T(), err)
	retrieved.MarkUsed("steward-001")
	err = s.adapter.UpdateToken(ctx, retrieved)
	require.NoError(s.T(), err)

	// Token should still be valid (multi-use)
	afterUse, err := s.adapter.GetToken(ctx, token.Token)
	require.NoError(s.T(), err)
	assert.True(s.T(), afterUse.IsValid(), "Multi-use token should remain valid after use")

	s.T().Log("Multi-use token allows multiple uses")
}

// TestCertificateProvisioning validates certificate generation for steward
func (s *CertificateRegistrationTestSuite) TestCertificateProvisioning() {
	// Provision a certificate for a steward
	req := &service.CertificateProvisioningRequest{
		StewardID:    "test-steward-001",
		CommonName:   "test-steward-001",
		Organization: "CFGMS Test Stewards",
		ValidityDays: 365,
	}

	resp, err := s.certProvisioningService.ProvisionCertificate(req)
	require.NoError(s.T(), err)
	require.True(s.T(), resp.Success, "Provisioning should succeed: %s", resp.Message)

	// Validate response contains all required fields
	assert.NotEmpty(s.T(), resp.CertificatePEM, "Should have client certificate")
	assert.NotEmpty(s.T(), resp.PrivateKeyPEM, "Should have private key")
	assert.NotEmpty(s.T(), resp.CACertificatePEM, "Should have CA certificate")
	assert.NotEmpty(s.T(), resp.SerialNumber, "Should have serial number")
	assert.True(s.T(), resp.ExpiresAt.After(time.Now()), "Certificate should not be expired")

	s.T().Logf("Certificate provisioned: serial=%s, expires=%s",
		resp.SerialNumber, resp.ExpiresAt.Format(time.RFC3339))
}

// TestCertificateContentsValidation validates generated certificate has correct attributes
func (s *CertificateRegistrationTestSuite) TestCertificateContentsValidation() {
	stewardID := "cert-validation-steward"

	// Provision certificate
	req := &service.CertificateProvisioningRequest{
		StewardID:    stewardID,
		Organization: "CFGMS Test Stewards",
		ValidityDays: 365,
	}

	resp, err := s.certProvisioningService.ProvisionCertificate(req)
	require.NoError(s.T(), err)
	require.True(s.T(), resp.Success)

	// Parse and validate certificate
	block, _ := pem.Decode(resp.CertificatePEM)
	require.NotNil(s.T(), block, "Should have valid PEM block")
	require.Equal(s.T(), "CERTIFICATE", block.Type)

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(s.T(), err, "Should parse X.509 certificate")

	// Validate certificate fields
	assert.Equal(s.T(), stewardID, x509Cert.Subject.CommonName, "CN should match steward ID")
	// Check that at least one organization contains "CFGMS"
	orgContainsCFGMS := false
	for _, org := range x509Cert.Subject.Organization {
		if strings.Contains(org, "CFGMS") {
			orgContainsCFGMS = true
			break
		}
	}
	assert.True(s.T(), orgContainsCFGMS, "Organization should contain CFGMS, got: %v", x509Cert.Subject.Organization)
	assert.True(s.T(), x509Cert.NotAfter.After(time.Now()), "Certificate should not be expired")
	assert.True(s.T(), x509Cert.NotBefore.Before(time.Now()), "Certificate should be valid now")

	// Validate key usage
	assert.True(s.T(), x509Cert.KeyUsage&x509.KeyUsageDigitalSignature != 0,
		"Should have digital signature usage")

	// Validate extended key usage for client auth
	hasClientAuth := false
	for _, usage := range x509Cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	assert.True(s.T(), hasClientAuth, "Should have client auth extended key usage")

	s.T().Logf("Certificate validation passed: CN=%s, ValidUntil=%s",
		x509Cert.Subject.CommonName, x509Cert.NotAfter.Format(time.RFC3339))
}

// TestCAChainValidation validates that CA can verify client certificate
func (s *CertificateRegistrationTestSuite) TestCAChainValidation() {
	// Provision certificate
	req := &service.CertificateProvisioningRequest{
		StewardID:    "ca-chain-steward",
		ValidityDays: 365,
	}

	resp, err := s.certProvisioningService.ProvisionCertificate(req)
	require.NoError(s.T(), err)
	require.True(s.T(), resp.Success)

	// Parse client certificate
	clientBlock, _ := pem.Decode(resp.CertificatePEM)
	require.NotNil(s.T(), clientBlock)
	clientCert, err := x509.ParseCertificate(clientBlock.Bytes)
	require.NoError(s.T(), err)

	// Parse CA certificate
	caBlock, _ := pem.Decode(resp.CACertificatePEM)
	require.NotNil(s.T(), caBlock, "Should have CA certificate")
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	require.NoError(s.T(), err)

	// Create certificate pool with CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify client certificate against CA
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, err = clientCert.Verify(opts)
	assert.NoError(s.T(), err, "Client certificate should be signed by CA")

	s.T().Log("CA chain validation passed")
}

// TestPrivateKeyMatchesCertificate validates the private key matches the certificate
func (s *CertificateRegistrationTestSuite) TestPrivateKeyMatchesCertificate() {
	// Provision certificate
	req := &service.CertificateProvisioningRequest{
		StewardID:    "key-match-steward",
		ValidityDays: 365,
	}

	resp, err := s.certProvisioningService.ProvisionCertificate(req)
	require.NoError(s.T(), err)
	require.True(s.T(), resp.Success)

	// Validate key pair using cert package utility
	err = cert.ValidateKeyPair(resp.CertificatePEM, resp.PrivateKeyPEM)
	assert.NoError(s.T(), err, "Private key should match certificate")

	s.T().Log("Private key matches certificate")
}

// TestCertificateProvisioningWithDefaults validates provisioning uses defaults
func (s *CertificateRegistrationTestSuite) TestCertificateProvisioningWithDefaults() {
	// Provision with minimal request (rely on defaults)
	req := &service.CertificateProvisioningRequest{
		StewardID: "defaults-steward",
	}

	resp, err := s.certProvisioningService.ProvisionCertificate(req)
	require.NoError(s.T(), err)
	require.True(s.T(), resp.Success, "Provisioning with defaults should succeed")

	// Certificate should use steward ID as common name
	block, _ := pem.Decode(resp.CertificatePEM)
	require.NotNil(s.T(), block)
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), "defaults-steward", x509Cert.Subject.CommonName,
		"CN should default to steward ID")

	s.T().Log("Certificate provisioning with defaults works correctly")
}

// TestCertificateProvisioningMissingStewardID validates error handling
func (s *CertificateRegistrationTestSuite) TestCertificateProvisioningMissingStewardID() {
	// Attempt to provision without steward ID
	req := &service.CertificateProvisioningRequest{
		StewardID: "",
	}

	resp, err := s.certProvisioningService.ProvisionCertificate(req)
	assert.Error(s.T(), err, "Should fail without steward ID")
	assert.False(s.T(), resp.Success, "Response should indicate failure")

	s.T().Log("Missing steward ID correctly rejected")
}

// TestCertificateProvisioningNilRequest validates nil request handling
func (s *CertificateRegistrationTestSuite) TestCertificateProvisioningNilRequest() {
	resp, err := s.certProvisioningService.ProvisionCertificate(nil)
	assert.Error(s.T(), err, "Should fail with nil request")
	assert.False(s.T(), resp.Success, "Response should indicate failure")

	s.T().Log("Nil request correctly rejected")
}

// TestTokenWithFutureExpiry validates tokens with future expiry are valid
func (s *CertificateRegistrationTestSuite) TestTokenWithFutureExpiry() {
	ctx := context.Background()

	// Create a token with future expiry
	futureExpiry := time.Now().Add(24 * time.Hour)
	token := &registration.Token{
		Token:         "cfgms_reg_future_expiry_test_001",
		TenantID:      "future-expiry-tenant",
		ControllerURL: "tcp://localhost:1883",
		CreatedAt:     time.Now(),
		ExpiresAt:     &futureExpiry,
		SingleUse:     false,
		Revoked:       false,
	}
	err := s.adapter.SaveToken(ctx, token)
	require.NoError(s.T(), err)

	// Token should be valid
	retrieved, err := s.adapter.GetToken(ctx, token.Token)
	require.NoError(s.T(), err)
	assert.True(s.T(), retrieved.IsValid(), "Token with future expiry should be valid")

	s.T().Log("Token with future expiry works correctly")
}

// TestTokenListByTenant validates token listing by tenant
func (s *CertificateRegistrationTestSuite) TestTokenListByTenant() {
	ctx := context.Background()

	// Create tokens for different tenants
	token1 := &registration.Token{
		Token:         "cfgms_reg_tenant_a_001",
		TenantID:      "tenant-a",
		ControllerURL: "tcp://localhost:1883",
		CreatedAt:     time.Now(),
	}
	token2 := &registration.Token{
		Token:         "cfgms_reg_tenant_a_002",
		TenantID:      "tenant-a",
		ControllerURL: "tcp://localhost:1883",
		CreatedAt:     time.Now(),
	}
	token3 := &registration.Token{
		Token:         "cfgms_reg_tenant_b_001",
		TenantID:      "tenant-b",
		ControllerURL: "tcp://localhost:1883",
		CreatedAt:     time.Now(),
	}

	require.NoError(s.T(), s.adapter.SaveToken(ctx, token1))
	require.NoError(s.T(), s.adapter.SaveToken(ctx, token2))
	require.NoError(s.T(), s.adapter.SaveToken(ctx, token3))

	// List tokens for tenant-a
	tenantATokens, err := s.adapter.ListTokens(ctx, "tenant-a")
	require.NoError(s.T(), err)
	assert.Len(s.T(), tenantATokens, 2, "Should have 2 tokens for tenant-a")

	// List tokens for tenant-b
	tenantBTokens, err := s.adapter.ListTokens(ctx, "tenant-b")
	require.NoError(s.T(), err)
	assert.Len(s.T(), tenantBTokens, 1, "Should have 1 token for tenant-b")

	s.T().Log("Token listing by tenant works correctly")
}

// TestRegistrationFlowIntegration validates the complete registration flow
func (s *CertificateRegistrationTestSuite) TestRegistrationFlowIntegration() {
	ctx := context.Background()

	// Step 1: Create registration token (admin action)
	token := &registration.Token{
		Token:         "cfgms_reg_integration_test_001",
		TenantID:      "integration-tenant",
		ControllerURL: "tcp://localhost:1883",
		Group:         "production",
		CreatedAt:     time.Now(),
		SingleUse:     true,
		Revoked:       false,
	}
	err := s.adapter.SaveToken(ctx, token)
	require.NoError(s.T(), err)

	// Step 2: Validate token (as controller would during registration)
	retrieved, err := s.adapter.GetToken(ctx, token.Token)
	require.NoError(s.T(), err)
	require.True(s.T(), retrieved.IsValid(), "Token should be valid")

	// Step 3: Generate steward ID (as controller does)
	stewardID := "steward-integration-test-001"

	// Step 4: Provision certificate (as controller does during registration)
	certResp, err := s.certProvisioningService.ProvisionCertificate(&service.CertificateProvisioningRequest{
		StewardID:    stewardID,
		Organization: "CFGMS Integration Test",
		ValidityDays: 365,
	})
	require.NoError(s.T(), err)
	require.True(s.T(), certResp.Success)

	// Step 5: Mark token as used (for single-use tokens)
	retrieved.MarkUsed(stewardID)
	err = s.adapter.UpdateToken(ctx, retrieved)
	require.NoError(s.T(), err)

	// Step 6: Verify token is now invalid (single-use)
	afterUse, err := s.adapter.GetToken(ctx, token.Token)
	require.NoError(s.T(), err)
	assert.False(s.T(), afterUse.IsValid(), "Single-use token should be invalid after use")
	assert.Equal(s.T(), stewardID, afterUse.UsedBy)

	// Step 7: Verify certificate is valid
	err = cert.ValidateKeyPair(certResp.CertificatePEM, certResp.PrivateKeyPEM)
	require.NoError(s.T(), err)

	s.T().Logf("Registration flow completed successfully: steward=%s, tenant=%s, group=%s",
		stewardID, retrieved.TenantID, retrieved.Group)
}

func TestCertificateRegistration(t *testing.T) {
	t.Parallel()

	suite.Run(t, new(CertificateRegistrationTestSuite))
}
