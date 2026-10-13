// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerapi "github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// alwaysCopyProvenance is a ProvenanceChecker implementation that classifies
// every connection as a copy of the approved device.
type alwaysCopyProvenance struct{}

func (alwaysCopyProvenance) CheckProvenance(context.Context, string, map[string]string) grpcCP.ProvenanceAssessment {
	return grpcCP.ProvenanceAssessment{Decision: grpcCP.ProvenanceCopy}
}

// pointAtCopyRefusingController starts a real gRPC control plane, trusted by the
// fixture's CA, that refuses the stored identity as a copy (IDENTITY_IN_USE), and
// points the stored identity's transport address at it.
func (f *storedIdentityFixture) pointAtCopyRefusingController(t *testing.T) {
	t.Helper()
	serverCert := f.serverCert(t)
	serverTLS, err := cert.CreateServerTLSConfig(serverCert.CertificatePEM, serverCert.PrivateKeyPEM, []byte(f.caPEM), tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}

	server := grpcCP.New(grpcCP.ModeServer, grpcCP.WithProvenanceChecker(alwaysCopyProvenance{}))
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": serverTLS, "registry": registry.NewRegistry(),
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	id, err := loadIdentity(f.certStoreDir)
	require.NoError(t, err)
	id.TransportAddress = server.ListenAddr()
	require.NoError(t, saveIdentity(f.certStoreDir, *id))
}

// quarantineAllHook sends every registration to the operator approval queue.
type quarantineAllHook struct{}

func (quarantineAllHook) Evaluate(context.Context, controllerapi.RegistrationInput) (controllerapi.ApprovalDecision, string, error) {
	return controllerapi.DecisionQuarantine, "test quarantine", nil
}

// cloneTestController is the real controller API server (real token, steward and
// pending-registration stores) behind an httptest listener that counts refresh
// and registration requests.
type cloneTestController struct {
	server       *httptest.Server
	pending      business.PendingRegistrationStore
	refreshHits  atomic.Int32
	registerHits atomic.Int32
}

func newCloneTestController(t *testing.T, originalStewardID string) *cloneTestController {
	t.Helper()
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "true")
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())
	t.Setenv("CFGMS_SECRETS_KEY_FILE", writeSecretsKeyFile(t))

	tokenBackend, err := interfaces.CreateRegistrationTokenStoreFromConfig("sqlite", map[string]interface{}{"path": ":memory:"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tokenBackend.Close() })
	require.NoError(t, tokenBackend.Initialize(context.Background()))
	tokenStore := registration.NewStorageAdapter(tokenBackend)

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false
	if cfg.Transport != nil {
		cfg.Transport.ExternalAddress = "localhost"
	}
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	rbacManager := rbac.NewManagerWithStorage(sm.GetAuditStore(), sm.GetRBACStore())
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(ctx)
	})
	tenantManager := tenant.NewManager(tenant.NewStorageAdapter(sm.GetTenantStore()), rbacManager)
	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, sm, controllerService)
	auditMgr, err := audit.NewManager(sm.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	api, err := controllerapi.New(cfg, logger, controllerService, configService, nil, service.NewRBACService(rbacManager),
		nil, tenantManager, rbacManager, nil, nil, tokenStore, "", nil, auditMgr, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = api.Close(ctx)
	})
	c := &cloneTestController{pending: sm.GetPendingRegistrationStore()}
	api.SetPendingStore(c.pending)
	api.SetStewardStore(sm.GetStewardStore())
	api.SetApprovalHook(quarantineAllHook{})

	require.NoError(t, sm.GetStewardStore().RegisterSteward(context.Background(), &business.StewardRecord{
		ID: originalStewardID, TenantID: "default", Hostname: "original", Platform: "linux", Arch: "amd64",
		Version: "1", Status: business.StewardStatusActive,
	}))
	require.NoError(t, tokenStore.SaveToken(context.Background(), &registration.Token{
		Token: "cfgms_reg_clone_test", TenantID: "default", ControllerURL: "grpc://controller:7443",
	}))

	handler := api.GetRouter()
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/refresh/"):
			c.refreshHits.Add(1)
		case strings.HasSuffix(r.URL.Path, "/api/v1/register"):
			c.registerHits.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(c.server.Close)
	return c
}

func writeSecretsKeyFile(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "controller-secrets.key")
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	return path
}

func skipWithoutHostAttributes(t *testing.T) {
	t.Helper()
	// The controller only classifies a connection as a copy when the steward
	// sent host attributes; a host that exposes none cannot exercise the path.
	if len(hostAttributes()) == 0 {
		t.Skip("host exposes no provenance attributes; the copy refusal cannot be triggered")
	}
}

func TestRegisterAndConnect_IdentityInUse_ReKeysAndRegistersWithCloneOf(t *testing.T) {
	skipWithoutHostAttributes(t)
	f := newStoredIdentityFixture(t, "placeholder")
	f.pointAtCopyRefusingController(t)
	controller := newCloneTestController(t, f.stewardID)
	ks := newReadmitKeyStore(t)
	deviceBefore := ks.DeviceID()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := registerAndConnect(ctx, "cfgms_reg_clone_test", controller.server.URL, trustSourceCompileBaked, "", ks, false, logging.NewLogger("error"))
	require.Error(t, err, "approval never comes, so the poll ends with the context")

	assert.NotEqual(t, deviceBefore, ks.DeviceID(), "the steward must become a different device")
	assert.Zero(t, controller.refreshHits.Load(), "a copy must not use the re-admission path")
	assert.Equal(t, int32(1), controller.registerHits.Load())

	entries, listErr := controller.pending.ListPending(context.Background(), "default")
	require.NoError(t, listErr)
	require.Len(t, entries, 1)
	assert.Equal(t, f.stewardID, entries[0].CloneOf)
	assert.Equal(t, ks.DeviceID(), entries[0].DeviceID, "registered with the regenerated key")

	stored, loadErr := loadIdentity(f.certStoreDir)
	require.NoError(t, loadErr)
	assert.Nil(t, stored, "the original's stored identity is discarded")
	marker, markerErr := loadCloneMarker(f.certStoreDir)
	require.NoError(t, markerErr)
	require.NotNil(t, marker, "the marker stays until the new identity is connected")
	assert.Equal(t, f.stewardID, marker.CloneOf)
}

// TestRegisterAndConnect_IdentityInUse_CrashAfterReKeyResumesWithNewKey kills the
// steward between key regeneration and registration: the next start registers
// with the new key as clone_of the original and never presents the old identity.
func TestRegisterAndConnect_IdentityInUse_CrashAfterReKeyResumesWithNewKey(t *testing.T) {
	f := newStoredIdentityFixture(t, "placeholder")
	// A stored identity is still on disk (crash before it was cleared); its
	// transport is a refusing control plane that must never be dialled.
	controller := newCloneTestController(t, f.stewardID)
	ks := newReadmitKeyStore(t)
	oldDevice := ks.DeviceID()

	require.NoError(t, saveCloneMarker(f.certStoreDir, f.stewardID))
	_, _, err := ks.Regenerate(context.Background())
	require.NoError(t, err)
	newDevice := ks.DeviceID()
	require.NotEqual(t, oldDevice, newDevice)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err = registerAndConnect(ctx, "cfgms_reg_clone_test", controller.server.URL, trustSourceCompileBaked, "", ks, false, logging.NewLogger("error"))
	require.Error(t, err)

	assert.Zero(t, controller.refreshHits.Load(), "never falls back to re-admitting the old identity")
	entries, listErr := controller.pending.ListPending(context.Background(), "default")
	require.NoError(t, listErr)
	require.Len(t, entries, 1)
	assert.Equal(t, newDevice, entries[0].DeviceID)
	assert.Equal(t, f.stewardID, entries[0].CloneOf)
}

func TestCloneMarker_RoundTripAndStaleDrop(t *testing.T) {
	dir := t.TempDir()
	m, err := loadCloneMarker(dir)
	require.NoError(t, err)
	assert.Nil(t, m)
	require.NoError(t, saveCloneMarker(dir, "steward-a"))
	m, err = loadCloneMarker(dir)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, "steward-a", m.CloneOf)
	require.NoError(t, clearCloneMarker(dir))
	m, err = loadCloneMarker(dir)
	require.NoError(t, err)
	assert.Nil(t, m)
}
