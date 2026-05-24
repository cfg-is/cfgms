// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ha"
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

// TestSetupManagedTLS_ClusterMode_VerifyClientCertIfGiven verifies that in ClusterMode with a
// valid HA CA cert, setupManagedTLS sets ClientAuth = tls.VerifyClientCertIfGiven. Presented
// certs are chain-verified against both the controller CA and the HA CA; clients without
// certs continue to connect normally (falling through to API-key auth).
func TestSetupManagedTLS_ClusterMode_VerifyClientCertIfGiven(t *testing.T) {
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
	assert.Equal(t, tls.VerifyClientCertIfGiven, tlsConfig.ClientAuth,
		"ClusterMode must set ClientAuth = VerifyClientCertIfGiven: presented certs are chain-verified "+
			"against both controller CA and HA CA; missing cert falls through to API-key auth")
}

// TestSetupManagedTLS_ClusterMode_NoCert_HandshakeSucceeds verifies the product decision:
// in ClusterMode, a client without a client certificate can complete the TLS handshake.
// The connection is accepted and r.TLS.PeerCertificates is nil for that client.
// This remains true under VerifyClientCertIfGiven (no cert = no verification attempt).
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
	defer func() { _ = ln.Close() }()

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
	require.NoError(t, err, "HTTPS request without a client cert must succeed under VerifyClientCertIfGiven")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	assert.True(t, gotRequest, "handler must have been called")
	assert.Empty(t, peerCerts, "client without cert must result in empty r.TLS.PeerCertificates")
}

// TestSetupManagedTLS_ClusterMode_EmptyCACertPath verifies that in ClusterMode, even when
// GetCACertPEM() returns nil (no HA CA cert configured), setupManagedTLS still sets
// ClientAuth = tls.VerifyClientCertIfGiven because certManager is the determining factor.
// ClientCAs will contain only the controller CA cert.
func TestSetupManagedTLS_ClusterMode_EmptyCACertPath(t *testing.T) {
	certMgr := newTLSTestCertManager(t)

	// ClusterMode manager with empty CACertPath → GetCACertPEM() returns nil.
	haManager := newClusterModeHAManager(t, "")
	server := newMinimalTLSServer(t, certMgr, haManager)

	tlsConfig, err := server.setupManagedTLS()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, tls.VerifyClientCertIfGiven, tlsConfig.ClientAuth,
		"ClusterMode must set VerifyClientCertIfGiven even when GetCACertPEM returns nil (controller CA still in ClientCAs)")
}

// TestSetupManagedTLS_ClusterMode_AdminCertAndHAPeerCertBothVerify verifies that in cluster
// mode, setupManagedTLS merges both the controller CA and the HA peer CA into ClientCAs,
// so a cert signed by either CA succeeds TLS handshake. The admin marker (application-layer
// concern) is validated separately in middleware tests.
func TestSetupManagedTLS_ClusterMode_AdminCertAndHAPeerCertBothVerify(t *testing.T) {
	// Controller CA: from the cert manager.
	certMgr := newTLSTestCertManager(t)
	controllerCACertPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)

	// HA CA: a separate CA created for this test so the two CAs are distinct.
	haCACert, haCAKey, haCACertPEM := makeCommercialTestCA(t)

	haCAPath := filepath.Join(t.TempDir(), "ha-ca.pem")
	require.NoError(t, os.WriteFile(haCAPath, haCACertPEM, 0600))

	haManager := newClusterModeHAManager(t, haCAPath)
	server := newMinimalTLSServer(t, certMgr, haManager)

	tlsConfig, err := server.setupManagedTLS()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, tls.VerifyClientCertIfGiven, tlsConfig.ClientAuth)

	// Start a real TLS listener.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	// Combined trust root pool for clients verifying the server cert.
	serverTrustPool := x509.NewCertPool()
	serverTrustPool.AppendCertsFromPEM(controllerCACertPEM)

	addr := fmt.Sprintf("https://%s/", ln.Addr().String())

	// Case 1: client cert signed by controller CA (represents an admin cert).
	adminClientCert := makeCommercialTestClientCert(t, certMgr)
	doTLSHandshake(t, addr, adminClientCert, serverTrustPool,
		"admin cert (controller-CA-signed) must complete TLS handshake")

	// Case 2: client cert signed by HA CA (represents an HA peer cert).
	haPeerClientCert := makeCommercialTestClientCertFromCA(t, haCACert, haCAKey)
	doTLSHandshake(t, addr, haPeerClientCert, serverTrustPool,
		"HA peer cert (HA-CA-signed) must complete TLS handshake when HA CA is in ClientCAs")
}

// --- helpers for the cluster-mode HA+admin cert test ---

// makeCommercialTestCA creates an in-memory CA (cert, key, PEM) for test use.
func makeCommercialTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test HA CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return caCert, caKey, caPEM
}

// makeCommercialTestClientCert creates a client cert signed by certMgr's CA.
// Uses certMgr.GenerateClientCertificate so the cert is signed by the controller CA.
func makeCommercialTestClientCert(t *testing.T, certMgr *cert.Manager) tls.Certificate {
	t.Helper()
	clientCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "test-admin-client",
		ValidityDays: 1,
	})
	require.NoError(t, err)

	tlsCert, err := tls.X509KeyPair(clientCert.CertificatePEM, clientCert.PrivateKeyPEM)
	require.NoError(t, err)
	return tlsCert
}

// makeCommercialTestClientCertFromCA creates a client cert signed by an arbitrary CA.
func makeCommercialTestClientCertFromCA(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) tls.Certificate {
	t.Helper()
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ha-peer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(leafKey),
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return tlsCert
}

// doTLSHandshake connects to addr with the given client cert, trusting serverTrustPool.
func doTLSHandshake(t *testing.T, addr string, clientCert tls.Certificate, serverTrustPool *x509.CertPool, msg string) {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      serverTrustPool,
			},
		},
	}
	resp, err := client.Get(addr)
	require.NoError(t, err, msg)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode, msg)
}
