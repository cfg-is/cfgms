// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"go.etcd.io/raft/v3/raftpb"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/proto"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testing/storage"
)

// newClusterModeHAManager creates an ha.Manager in ClusterMode with the given CA cert path
// and cert manager. It uses FastElectionConfig so raft elections converge in milliseconds
// (not seconds), preventing election storms under CI CPU contention.
//
// Cleanup ordering (LIFO): manager.Stop → sm.Close → goleak.VerifyNone.
// goleak.IgnoreCurrent snapshots goroutines before the manager is constructed so only
// goroutines introduced by this helper are checked for leaks.
func newClusterModeHAManager(t *testing.T, caCertPath string, certMgr *cert.Manager) *ha.Manager {
	t.Helper()

	// Snapshot pre-existing goroutines; goleak.VerifyNone (registered below, runs last)
	// will only flag goroutines that are NEW relative to this snapshot.
	existingGoroutines := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, existingGoroutines) })

	sm, err := storage.CreateTestStorageManager()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, sm.Close()) })

	cfg := ha.DefaultConfig()
	cfg.Mode = ha.ClusterMode
	cfg.CACertPath = caCertPath
	cfg.Node.ID = fmt.Sprintf("test-node-%d", time.Now().UnixNano())
	cfg.Cluster = ha.FastElectionConfig()

	manager, err := ha.NewManager(cfg, logging.GetLogger(), sm, certMgr, "")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, manager.Stop(context.Background())) })
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

	haManager := newClusterModeHAManager(t, caPath, certMgr)
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

	haManager := newClusterModeHAManager(t, caPath, certMgr)
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
	haManager := newClusterModeHAManager(t, "", certMgr)
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

	haManager := newClusterModeHAManager(t, haCAPath, certMgr)
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
//
// Uses an ECDSA P-256 key rather than RSA: key generation is the dominant cost of
// these TLS handshake tests, and under the FIPS-140 module RSA prime search
// (Miller-Rabin over Montgomery multiplication) is ~1000× slower than ECDSA curve
// point generation. P-256 is FIPS-140 approved, so the trust properties under test
// are unchanged while removing the slow key-generation frame that pushed the
// package over the 5m test-fast budget (cf. Issue #2591 for the argon2id analog).
func makeCommercialTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
// ECDSA P-256 for the same key-generation-cost reason as makeCommercialTestCA.
func makeCommercialTestClientCertFromCA(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ha-peer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
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

// TestTwoNodeRaftPeerMTLS_MessageExchangeSucceeds verifies that a cert.Manager-generated
// "peer-a" client certificate passes verifyPeerCN on a real ha.Manager in ClusterMode,
// and that a genuine POST /raft/message over mTLS returns 200 (not 403). This exercises
// the full mTLS chain: TLS handshake, cert chain verification, and CN allowlist check.
//
// Both managers are real ha.Manager instances in ClusterMode backed by the same cert.Manager.
// MangerB's production RaftTransport.HandleMessage serves the request; the client cert is
// generated with the same parameters that managerA's initializeRaftConsensus would use
// (CommonName = node ID, signed by the shared CA).
func TestTwoNodeRaftPeerMTLS_MessageExchangeSucceeds(t *testing.T) {
	// Shared cert manager — both nodes' peer certs signed by the same CA.
	sharedCertMgr := newTLSTestCertManager(t)

	caCertPEM, err := sharedCertMgr.GetCACertificate()
	require.NoError(t, err)

	caFile := filepath.Join(t.TempDir(), "shared-ca.pem")
	require.NoError(t, os.WriteFile(caFile, caCertPEM, 0600))

	// Server cert for the mTLS listener: signed by sharedCA so the peer-A
	// client (RootCAs=sharedCA from caFile) trusts it. CreateServerTLSConfig
	// sets ClientAuth=RequireAndVerifyClientCert, so only sharedCA-signed
	// client certs complete the handshake.
	serverCert, err := sharedCertMgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName:   "127.0.0.1",
		IPAddresses:  []string{"127.0.0.1"},
		ValidityDays: 1,
	})
	require.NoError(t, err)

	serverTLSConfig, err := cert.CreateServerTLSConfig(
		serverCert.CertificatePEM, serverCert.PrivateKeyPEM,
		caCertPEM, tls.VersionTLS12,
	)
	require.NoError(t, err)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	listenAddr := ln.Addr().String()

	// Build a two-node cluster config: self + one peer at peerAddr.
	makeCfg := func(selfID, peerID, peerAddr string) *ha.Config {
		cfg := ha.DefaultConfig()
		cfg.Mode = ha.ClusterMode
		cfg.CACertPath = caFile
		cfg.Node.ID = selfID
		cfg.Cluster = ha.FastElectionConfig()
		cfg.Cluster.Discovery.Config = map[string]interface{}{
			"nodes": []interface{}{
				map[string]interface{}{"id": selfID, "address": "127.0.0.1:0"},
				map[string]interface{}{"id": peerID, "address": peerAddr},
			},
		}
		return cfg
	}

	smA, err := storage.CreateTestStorageManager()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, smA.Close()) })

	smB, err := storage.CreateTestStorageManager()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, smB.Close()) })

	// Node IDs must be ≥8 chars: manager.go truncates to [:8] when forming the
	// default node name. "mtls-node-a" / "mtls-node-b" are 11 chars.
	const (
		nodeIDA = "mtls-node-a"
		nodeIDB = "mtls-node-b"
	)

	// managerA: nodeIDA. Its initializeRaftConsensus generates a client cert with
	// CommonName=nodeIDA from sharedCertMgr. That CN must be in managerB's
	// allowedCNs (built from discovery config) for verifyPeerCN to pass.
	managerA, err := ha.NewManager(
		makeCfg(nodeIDA, nodeIDB, listenAddr),
		logging.GetLogger(), smA, sharedCertMgr, "",
	)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, managerA.Stop(context.Background())) })

	// managerB: nodeIDB. Its production RaftTransport.HandleMessage serves the
	// listener. allowedCNs = {nodeIDB, nodeIDA} from the discovery config.
	managerB, err := ha.NewManager(
		makeCfg(nodeIDB, nodeIDA, "127.0.0.1:0"),
		logging.GetLogger(), smB, sharedCertMgr, "",
	)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, managerB.Stop(context.Background())) })

	mux := http.NewServeMux()
	mux.HandleFunc("/raft/message", managerB.GetRaftTransport().HandleMessage)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// Generate a nodeIDA client cert from sharedCertMgr — the same call that
	// managerA's initializeRaftConsensus makes (CommonName=nodeID, ValidityDays=365).
	// Both are signed by sharedCertMgr's CA, which is in the listener's ClientCAs.
	peerACert, err := sharedCertMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   nodeIDA,
		ValidityDays: 365,
	})
	require.NoError(t, err)

	clientTLSConfig, err := cert.CreateClientTLSConfig(
		peerACert.CertificatePEM, peerACert.PrivateKeyPEM,
		caCertPEM, "127.0.0.1", tls.VersionTLS12,
	)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLSConfig},
		Timeout:   5 * time.Second,
	}

	// A zero-value raftpb.Message (type=MsgHup) is a local message: node.Step
	// ignores it and returns nil, so HandleMessage writes 200 after the CN check.
	// v3.7.0: use proto.Marshal on a pointer; raftpb.Message no longer has Marshal().
	msg := &raftpb.Message{}
	data, err := proto.Marshal(msg)
	require.NoError(t, err)

	resp, err := client.Post(
		fmt.Sprintf("https://%s/raft/message", listenAddr),
		"application/octet-stream",
		bytes.NewReader(data),
	)
	require.NoError(t, err, "POST /raft/message must succeed: mTLS handshake and CN check must both pass")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"verifyPeerCN must accept CN=%q (in managerB's allowedCNs from discovery config); "+
			"403 means the CN check failed; 500 means consensus.Process rejected the message", nodeIDA)
}
