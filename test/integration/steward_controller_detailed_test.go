// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	controllerapi "github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/test/integration/testutil"
)

// DetailedIntegrationTestSuite provides comprehensive steward-controller integration tests.
//
// Architecture note: the controller and transport client run in the same Go process.
// The gRPC data plane provider is a process-level singleton; when the controller starts
// it in server mode, the transport client cannot start it again in client mode. Full
// QUIC connection testing therefore lives in the E2E suite (test/e2e/), where controller
// and steward run in separate processes. These tests focus on the parts that can be
// exercised in-process: controller startup, certificate configuration, transport client
// creation, and error resilience.
type DetailedIntegrationTestSuite struct {
	suite.Suite
	env *testutil.TestEnv
}

func (s *DetailedIntegrationTestSuite) SetupSuite() {
	s.env = testutil.NewTestEnv(s.T())
}

func (s *DetailedIntegrationTestSuite) TearDownSuite() {
	s.env.Cleanup()
}

func (s *DetailedIntegrationTestSuite) SetupTest() {
	s.env.Reset()
}

// TestHeartbeatProcessing validates the controller-side infrastructure that heartbeats
// depend on: the controller starts, transport client is created without error, and the
// connection attempt exercises the TLS / control-plane initialization path.
//
// Full heartbeat round-trip (steward → controller) requires separate processes and is
// covered by the E2E test suite.
func (s *DetailedIntegrationTestSuite) TestHeartbeatProcessing() {
	// Start controller
	s.env.Start()

	// Allow initialization to settle
	time.Sleep(2 * time.Second)

	// Stop components
	s.env.Stop()

	// The transport client was created and a connection was attempted.
	// Verify the controller was running (has a certificate manager initialized).
	certMgr := s.env.CertManager
	s.NotNil(certMgr, "Controller certificate manager should be initialized")

	// No panic or fatal log should have occurred during the connection attempt
	errorLogs := s.env.Logger.GetLogs("error")
	for _, log := range errorLogs {
		s.NotContains(log.Message, "panic", "No panics should occur during connection attempt")
		s.NotContains(log.Message, "fatal", "No fatal errors should occur during connection attempt")
	}
}

// TestDNASynchronization validates that the transport layer infrastructure needed for
// DNA sync is present. DNA collection runs in the standalone steward convergence loop;
// reporting to the controller uses the gRPC data plane transport.
//
// This test verifies: controller starts, transport client is created with the correct
// CA so TLS verification would succeed in a separate-process scenario.
func (s *DetailedIntegrationTestSuite) TestDNASynchronization() {
	// Start controller and create transport client
	s.env.Start()

	// Allow initialization
	time.Sleep(1 * time.Second)

	// Stop components
	s.env.Stop()

	// Verify certificate setup is valid — this is the prerequisite for DNA sync TLS
	err := s.env.ValidateCertificateSetup()
	s.NoError(err, "Certificate setup should be valid (prerequisite for DNA sync TLS)")

	// TransportClient was created — verify it was constructed
	// (Start() fatals the test if creation fails, so reaching here means it succeeded)
	s.T().Log("TransportClient created successfully — DNA sync transport infrastructure is available")
}

// TestMTLSAuthentication validates that mTLS certificates are correctly configured.
// The transport client is created with the CA cert from the controller's cert manager,
// meaning it would successfully verify the controller's server cert in a separate-process
// scenario. In-process QUIC connection is not possible because the global data plane
// provider is already in server mode (started by the controller).
func (s *DetailedIntegrationTestSuite) TestMTLSAuthentication() {
	// Verify certificates are properly configured
	err := s.env.ValidateCertificateSetup()
	s.NoError(err, "Certificate setup should be valid for mTLS authentication")

	// Start controller
	s.env.Start()

	// Allow time for initialization
	time.Sleep(500 * time.Millisecond)

	// Stop components
	s.env.Stop()

	// Verify CA, server, and client certs are all present and valid
	caCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeCA)
	s.NoError(err, "Should be able to query CA certificates")
	s.NotEmpty(caCerts, "CA certificate should be present")

	serverCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeInternalServer)
	s.NoError(err, "Should be able to query internal server certificates")
	s.NotEmpty(serverCerts, "Internal server certificate should be present")

	clientCerts, err := s.env.GetCertificateInfo(cert.CertificateTypeClient)
	s.NoError(err, "Should be able to query client certificates")
	s.NotEmpty(clientCerts, "Client certificate should be present for mTLS")

	// Confirm no TLS-related errors logged
	errorLogs := s.env.Logger.GetLogs("error")
	for _, log := range errorLogs {
		s.NotContains(log.Message, "Certificate verification failed",
			"No certificate verification failures expected")
		s.NotContains(log.Message, "TLS handshake failed",
			"No TLS handshake failures expected")
	}
}

// TestErrorHandlingAndResilience validates that the controller survives a start/stop/start cycle.
func (s *DetailedIntegrationTestSuite) TestErrorHandlingAndResilience() {
	// Cycle 1: normal startup and shutdown
	s.env.Start()
	s.env.Stop()

	// Cycle 2: restart after clean stop
	s.env.Reset()
	s.env.Start()
	s.env.Stop()

	// Verify no panic or fatal errors occurred across both cycles
	errorLogs := s.env.Logger.GetLogs("error")
	for _, log := range errorLogs {
		s.NotContains(log.Message, "panic")
		s.NotContains(log.Message, "fatal")
	}
}

func TestDetailedIntegration(t *testing.T) {
	suite.Run(t, new(DetailedIntegrationTestSuite))
}

// newAdminPeerCert mints a self-signed client certificate carrying the CFGMS admin marker
// extension. Injected into req.TLS.PeerCertificates, it makes extractAdminPrincipal produce
// an admin principal. Chain verification is a TLS-layer concern (production uses
// VerifyClientCertIfGiven + ClientCAs) and is intentionally not exercised here — the handler
// under test only inspects the admin-marker extension.
func newAdminPeerCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "integration-admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cert.SetAdminMarker(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return parsed
}

// TestStewardDecommissionCycle_FullControllerStack exercises the complete steward
// decommission cycle across the real controller REST stack (Issue #2408). A DELETE
// /api/v1/stewards/{id} carried by an admin mTLS principal is driven through the production
// router — authentication middleware → Tier-3 mTLS gate → permission check → handler — and
// every effect is asserted against real providers (no mocks):
//
//  1. durable tombstone      — flat-file steward store record flips to "deregistered"
//  2. in-memory status update — controller service record reflects "deregistered"
//  3. audit                   — a high-severity steward.decommissioned event is written
//
// The active-connection drop (registry.Unregister on decommission) is owned by the
// unit test TestHandleDecommissionSteward_RegistryConnectionDropped in the api package.
// It is deliberately not re-exercised here: the decommission path never calls the
// connection's transport sender, so a registry entry adds no full-stack coverage and
// would require standing up a bespoke transport sender purely to satisfy the struct field.
func TestStewardDecommissionCycle_FullControllerStack(t *testing.T) {
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

	ctx := context.Background()
	logger := logging.NewNoopLogger()

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	// Real durable storage (flat-file steward + audit stores, in-memory SQLite for RBAC/tenant).
	storageManager := pkgtesting.SetupTestStorage(t)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(ctx))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	server, err := controllerapi.New(
		cfg, logger, controllerService, configService, nil, rbacService,
		nil, tenantManager, rbacManager,
		nil, nil, nil, "", nil, auditMgr, nil, nil, nil,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Close(closeCtx)
	})

	// Wire the durable fleet store.
	stewardStore := storageManager.GetStewardStore()
	require.NotNil(t, stewardStore, "OSS storage manager must provide a steward store")
	server.SetStewardStore(stewardStore)

	const stewardID = "s-decomm-integration"
	const tenantID = "integration-tenant"

	// Seed the durable and in-memory representations of a registered steward.
	require.NoError(t, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
		ID:       stewardID,
		TenantID: tenantID,
		Status:   business.StewardStatusActive,
	}))
	require.NoError(t, controllerService.RegisterSteward(stewardID, tenantID, "10.0.0.5:7443", "active"))

	// Drive the DELETE through the production router with an admin mTLS principal.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/stewards/"+stewardID, nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{newAdminPeerCert(t)}}
	rec := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "admin decommission must succeed: %s", rec.Body.String())
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data["id"])
	assert.Equal(t, "deregistered", resp.Data["status"])

	// (1) Durable tombstone — record retained, status flipped to deregistered.
	got, err := stewardStore.GetSteward(ctx, stewardID)
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusDeregistered, got.Status, "durable record must be tombstoned")

	// (2) In-memory status update — record retained for audit, status deregistered.
	info, ok := controllerService.GetStewardInfo(stewardID)
	require.True(t, ok, "in-memory record must still exist after decommission (retained for audit)")
	assert.Equal(t, string(business.StewardStatusDeregistered), info.Status, "in-memory status must be deregistered")

	// (3) Audit — a high-severity steward.decommissioned event is durably written.
	require.NoError(t, auditMgr.Flush(ctx))
	entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{Actions: []string{"steward.decommissioned"}})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "a steward.decommissioned audit entry must be written")
	e := entries[0]
	assert.Equal(t, business.AuditSeverityHigh, e.Severity)
	assert.Equal(t, "steward", e.ResourceType)
	assert.Equal(t, stewardID, e.ResourceID)
	assert.Equal(t, business.AuditResultSuccess, e.Result)
}
