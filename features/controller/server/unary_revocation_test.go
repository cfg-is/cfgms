// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	controllercreds "github.com/cfgis/cfgms/features/controller/credentials"
	"github.com/cfgis/cfgms/features/controller/service"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

const unaryRevocationTenant = "tenant-unary-revocation"

type credentialRevocationEnv struct {
	mgr    *cert.Manager
	addr   string
	pool   *x509.CertPool
	ctrl   *service.ControllerService
	cfgSvc *service.ConfigurationServiceV2
}

// startCredentialRevocationServer serves the real StewardTransport composite
// with a real CredentialHandler (real credential store, SOPS secret store and
// configuration service) behind mTLS from a real cert.Manager and the same
// unary interceptor chain the controller installs.
func startCredentialRevocationServer(t *testing.T, checker streamRevocationChecker) *credentialRevocationEnv {
	t.Helper()
	logger := logging.NewNoopLogger()

	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 30},
	})
	require.NoError(t, err)
	if checker == nil {
		checker = mgr
	}

	sm := pkgtesting.SetupTestStorage(t)
	ctrl := service.NewControllerService(logger)
	cfgSvc := service.NewConfigurationServiceV2(logger, sm, ctrl)
	require.NoError(t, sm.GetTenantStore().CreateTenant(ctxkeys.WithSystem(context.Background()),
		&business.TenantData{ID: unaryRevocationTenant, Name: unaryRevocationTenant, Status: business.TenantStatusActive}))

	base := t.TempDir()
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	keyPath := filepath.Join(base, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	secrets, err := secretsif.CreateSecretStoreFromConfig("sops", map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": filepath.Join(base, "data")},
		"cache_enabled":    false,
		"key_file":         keyPath,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = secrets.Close() })

	credStore, err := controllercreds.NewStore(sm.GetConfigStore(), secrets)
	require.NoError(t, err)
	credSvc, err := controllercreds.NewService(credStore, controllercreds.ConfigBindingChecker{Store: sm.GetConfigStore()}, logger)
	require.NoError(t, err)

	composite := newCompositeTransportServer(transportpb.UnimplementedStewardTransportServer{}, logger)
	composite.SetCredentialHandler(controllerTransport.NewCredentialHandler(credSvc, cfgSvc, ctrl, logger))

	srvCert, err := mgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, IPAddresses: []string{"127.0.0.1"},
		Organization: "Test", ValidityDays: 30,
	})
	require.NoError(t, err)
	tlsCert, err := tls.X509KeyPair(srvCert.CertificatePEM, srvCert.PrivateKeyPEM)
	require.NoError(t, err)
	caPEM, err := mgr.GetCACertificate()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))

	s := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{tlsCert}, ClientCAs: pool,
			ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
		})),
		grpc.ChainUnaryInterceptor(controllerTransport.NewUnaryAccessLogInterceptor(logger)),
		grpc.ChainUnaryInterceptor(newUnaryRevocationInterceptor(checker, logger)),
	)
	transportpb.RegisterStewardTransportServer(s, composite)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)

	return &credentialRevocationEnv{mgr: mgr, addr: lis.Addr().String(), pool: pool, ctrl: ctrl, cfgSvc: cfgSvc}
}

// steward registers stewardID under the test tenant with one declared
// activedirectory.user resource and returns a client for a freshly issued
// certificate whose CN is stewardID, plus that certificate's serial.
func (e *credentialRevocationEnv) steward(t *testing.T, stewardID, resource string) (transportpb.StewardTransportClient, string) {
	t.Helper()
	require.NoError(t, e.ctrl.RegisterSteward(stewardID, unaryRevocationTenant, "localhost:4433", "connected"))
	cfg := &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{
			ID:      stewardID,
			Logging: stewardtypes.LoggingConfig{Level: "info"},
			ErrorHandling: stewardtypes.ErrorHandlingConfig{
				ModuleLoadFailure:  stewardtypes.ActionContinue,
				ResourceFailure:    stewardtypes.ActionWarn,
				ConfigurationError: stewardtypes.ActionFail,
			},
		},
		Resources: []stewardtypes.ResourceConfig{{
			Name: resource, Module: controllercreds.KindActiveDirectoryUser,
			Config: map[string]interface{}{"sam_account_name": resource},
		}},
	}
	require.NoError(t, e.cfgSvc.SetConfiguration(ctxkeys.WithSystem(context.Background()), unaryRevocationTenant, stewardID, cfg))

	c, err := e.mgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: stewardID, Organization: "Test", ValidityDays: 30,
	})
	require.NoError(t, err)
	pair, err := tls.X509KeyPair(c.CertificatePEM, c.PrivateKeyPEM)
	require.NoError(t, err)
	conn, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs: e.pool, ServerName: "localhost", MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair},
	})))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return transportpb.NewStewardTransportClient(conn), c.SerialNumber
}

func issueRequest(resource string) *transportpb.IssueInitialCredentialRequest {
	return &transportpb.IssueInitialCredentialRequest{ResourceId: resource, Kind: controllercreds.KindActiveDirectoryUser}
}

// A steward whose certificate is revoked after it was issued a pending
// credential must not be able to collect that password again, even though the
// credential service would return the same pending password to its identity.
func TestUnaryRevocation_RevokedSerialCannotObtainCredential(t *testing.T) {
	env := startCredentialRevocationServer(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, serial := env.steward(t, "steward-unary-revoke", "svc-account")
	resp, err := client.IssueInitialCredential(ctx, issueRequest("svc-account"))
	require.NoError(t, err, "a valid certificate must reach the credential handler")
	require.Len(t, resp.GetPassword(), controllercreds.PasswordLength)

	require.NoError(t, env.mgr.Revoke(serial))
	resp, err = client.IssueInitialCredential(ctx, issueRequest("svc-account"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, resp.GetPassword())
}

func TestUnaryRevocation_LookupErrorFailsClosed(t *testing.T) {
	env := startCredentialRevocationServer(t, errChecker{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, _ := env.steward(t, "steward-unary-lookup", "svc-account")
	resp, err := client.IssueInitialCredential(ctx, issueRequest("svc-account"))
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Empty(t, resp.GetPassword())
}

func TestUnaryRevocation_NoPeerCertificateUnauthenticated(t *testing.T) {
	interceptor := newUnaryRevocationInterceptor(errChecker{}, logging.NewNoopLogger())
	_, err := interceptor(context.Background(), issueRequest("svc-account"),
		&grpc.UnaryServerInfo{FullMethod: transportpb.StewardTransport_IssueInitialCredential_FullMethodName},
		func(context.Context, interface{}) (interface{}, error) {
			t.Fatal("handler must not run")
			return nil, nil
		})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
