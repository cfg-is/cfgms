//go:build commercial
// +build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/commercial/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testing/storage"
)

// newClusterModeHAManager creates a commercial ha.Manager in ClusterMode with the given CA cert path.
func newClusterModeHAManager(t *testing.T, caCertPath string) *ha.Manager {
	t.Helper()
	sm, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := ha.DefaultConfig()
	cfg.Mode = ha.ClusterMode
	cfg.CACertPath = caCertPath
	cfg.Node.ID = fmt.Sprintf("test-node-%d", time.Now().UnixNano())

	manager, err := ha.NewManager(cfg, logging.GetLogger(), sm)
	require.NoError(t, err)
	return manager
}

// TestSetupManagedTLS_ClusterMode_RequestsClientCert verifies that in ClusterMode with a valid
// HA CA cert, setupManagedTLS sets ClientAuth = tls.RequestClientCert so HA peers can present
// a certificate while non-HA clients without certs continue to connect normally.
func TestSetupManagedTLS_ClusterMode_RequestsClientCert(t *testing.T) {
	certMgr := newTLSTestCertManager(t)

	// Obtain the cert manager's CA cert so the HA manager and server share the same trust root.
	caCertPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, caCertPEM, 0600))

	haManager := newClusterModeHAManager(t, caPath)
	server := newMinimalTLSServer(t, certMgr, haManager)

	tlsConfig, err := server.setupManagedTLS()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, tls.RequestClientCert, tlsConfig.ClientAuth,
		"ClusterMode must set ClientAuth = RequestClientCert to allow HA peer inspection without requiring certs from non-HA clients")
}

// TestSetupManagedTLS_ClusterMode_NoCert_HandshakeSucceeds verifies the product decision:
// in ClusterMode, a client without a client certificate can complete the TLS handshake.
// The connection is accepted and r.TLS.PeerCertificates is nil for that client.
func TestSetupManagedTLS_ClusterMode_NoCert_HandshakeSucceeds(t *testing.T) {
	certMgr := newTLSTestCertManager(t)

	caCertPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, caCertPEM, 0600))

	haManager := newClusterModeHAManager(t, caPath)
	server := newMinimalTLSServer(t, certMgr, haManager)

	tlsConfig, err := server.setupManagedTLS()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// Start a real TLS listener using the returned config.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer ln.Close()

	var (
		mu         sync.Mutex
		peerCerts  []*x509.Certificate
		gotRequest bool
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.TLS != nil {
			peerCerts = r.TLS.PeerCertificates
		}
		gotRequest = true
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	// Build a client that trusts the cert manager's CA but presents no client cert.
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/", ln.Addr().String()))
	require.NoError(t, err, "HTTPS request without a client cert must succeed in ClusterMode")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	assert.True(t, gotRequest, "handler must have been called")
	assert.Empty(t, peerCerts, "client without cert must result in empty r.TLS.PeerCertificates")
}

// TestSetupManagedTLS_ClusterMode_EmptyCACertPath verifies that in ClusterMode, even when
// GetCACertPEM() returns nil (no CA cert configured), setupManagedTLS still sets
// ClientAuth = tls.RequestClientCert because the ClusterMode gate is the determining factor.
func TestSetupManagedTLS_ClusterMode_EmptyCACertPath(t *testing.T) {
	certMgr := newTLSTestCertManager(t)

	// ClusterMode manager with empty CACertPath → GetCACertPEM() returns nil.
	haManager := newClusterModeHAManager(t, "")
	server := newMinimalTLSServer(t, certMgr, haManager)

	tlsConfig, err := server.setupManagedTLS()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, tls.RequestClientCert, tlsConfig.ClientAuth,
		"ClusterMode must set RequestClientCert even when GetCACertPEM returns nil")
}
