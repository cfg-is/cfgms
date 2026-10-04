// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// storedIdentityFixture is a steward with a stored identity enrolled against a
// real controller CA: identity record + client certificate in a cert store under
// a temporary directory that registerAndConnect resolves as its cert store.
type storedIdentityFixture struct {
	certStoreDir string
	controller   *cert.Manager
	caPEM        string
	stewardID    string
}

func newStoredIdentityFixture(t *testing.T, transportAddress string) *storedIdentityFixture {
	t.Helper()
	controller, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &cert.CAConfig{Organization: "CFGMS Reconnect Test CA", Country: "US", ValidityDays: 30},
	})
	require.NoError(t, err)
	caPEM, err := controller.GetCACertificate()
	require.NoError(t, err)

	f := &storedIdentityFixture{
		certStoreDir: t.TempDir(),
		controller:   controller,
		caPEM:        string(caPEM),
		stewardID:    "steward-reconnect-test",
	}
	clientCert, err := controller.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: f.stewardID, ClientID: f.stewardID, ValidityDays: 30,
	})
	require.NoError(t, err)
	require.NotNil(t, buildClientCertManagerAtPath(f.certStoreDir, string(clientCert.CertificatePEM),
		string(clientCert.PrivateKeyPEM), "", logging.NewLogger("error")))

	serverCert := f.serverCert(t)
	require.NoError(t, saveIdentity(f.certStoreDir, StewardIdentity{
		StewardID:        f.stewardID,
		TenantID:         "tenant-reconnect",
		TransportAddress: transportAddress,
		CACertPEM:        f.caPEM,
		ServerCertPEM:    string(serverCert.CertificatePEM),
	}))

	prev := certStoreDirResolver
	certStoreDirResolver = func() string { return f.certStoreDir }
	t.Cleanup(func() { certStoreDirResolver = prev })
	return f
}

func (f *storedIdentityFixture) serverCert(t *testing.T) *cert.Certificate {
	t.Helper()
	c, err := f.controller.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, IPAddresses: []string{"127.0.0.1"}, ValidityDays: 30,
	})
	require.NoError(t, err)
	return c
}

func (f *storedIdentityFixture) identityBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.certStoreDir, identityFileName))
	require.NoError(t, err)
	return b
}

// registrationCounter is an HTTPS controller API that counts every request and
// refuses them all; a non-zero count means the steward attempted registration.
func registrationCounter(t *testing.T) (*httptest.Server, string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "registration refused by test", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.TLS.Certificates[0].Certificate[0]}))
	return srv, caPEM, &hits
}

// unusedUDPAddr returns a loopback UDP address with nothing listening on it.
func unusedUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := conn.LocalAddr().String()
	require.NoError(t, conn.Close())
	return addr
}

// denyAllApproval refuses every steward's control channel, as the controller does
// for an unknown, deregistered or revoked steward.
type denyAllApproval struct{}

func (denyAllApproval) IsApproved(context.Context, string) (bool, error) { return false, nil }

// TestRegisterAndConnect_UnreachableControlPlane_KeepsStoredIdentity guards Issue
// #4532: a controller whose HTTPS API is up while its control plane is unreachable
// must not make a healthy steward register — no registration request, identity
// untouched, and an error the connect loop retries.
func TestRegisterAndConnect_UnreachableControlPlane_KeepsStoredIdentity(t *testing.T) {
	f := newStoredIdentityFixture(t, unusedUDPAddr(t))
	before := f.identityBytes(t)
	srv, httpsCAPEM, hits := registrationCounter(t)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	tc, err := registerAndConnect(ctx, "one-time-token", srv.URL, trustSourceInstallPinned, httpsCAPEM, nil, false, logging.NewLogger("error"))

	assert.Nil(t, tc)
	require.ErrorIs(t, err, errStoredIdentityUnreachable)
	assert.NotErrorIs(t, err, controlplaneInterfaces.ErrIdentityRejected)
	assert.Zero(t, hits.Load(), "an unreachable control plane must never trigger a registration attempt")
	assert.Equal(t, before, f.identityBytes(t), "the stored identity must be retained")
}

// TestRegisterAndConnect_ControllerRejectsIdentity_FallsBackToRegistration guards
// the stranded-steward case Issue #4532 exists for: a controller that refuses the
// stored identity (here, the control channel's approval check) sends the steward
// to registration with its token.
func TestRegisterAndConnect_ControllerRejectsIdentity_FallsBackToRegistration(t *testing.T) {
	f := newStoredIdentityFixture(t, "placeholder")
	serverCert := f.serverCert(t)
	serverTLS, err := cert.CreateServerTLSConfig(serverCert.CertificatePEM, serverCert.PrivateKeyPEM, []byte(f.caPEM), tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}

	server := grpcCP.New(grpcCP.ModeServer, grpcCP.WithApprovalChecker(denyAllApproval{}))
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
		"registry":   registry.NewRegistry(),
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	id, err := loadIdentity(f.certStoreDir)
	require.NoError(t, err)
	id.TransportAddress = server.ListenAddr()
	require.NoError(t, saveIdentity(f.certStoreDir, *id))

	srv, httpsCAPEM, hits := registrationCounter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tc, err := registerAndConnect(ctx, "one-time-token", srv.URL, trustSourceInstallPinned, httpsCAPEM, nil, false, logging.NewLogger("error"))

	assert.Nil(t, tc)
	require.Error(t, err, "the test controller refuses registration too")
	assert.NotErrorIs(t, err, errStoredIdentityUnreachable)
	assert.Positive(t, hits.Load(), "a rejected stored identity must fall back to registration")
}
