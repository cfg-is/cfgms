// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/cert"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration/identity"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// allowAllApproval admits every steward's control channel.
type allowAllApproval struct{}

func (allowAllApproval) IsApproved(context.Context, string) (bool, error) { return true, nil }

// lifecycleHarness is a connected steward whose client certificate is short
// lived, against a real gRPC control plane and the refresh endpoints of a real CA.
type lifecycleHarness struct {
	controller *readmitTestController
	tc         *client.TransportClient
	ks         identity.KeyStore
	dir        string
	idBefore   []byte

	mu         sync.Mutex
	handshakes []string // serial of the client certificate presented on each handshake
}

func (h *lifecycleHarness) presentedSerials() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.handshakes...)
}

func newLifecycleHarness(t *testing.T, initialLifetime, renewedLifetime time.Duration) *lifecycleHarness {
	t.Helper()
	controller := newReadmitTestController(t, "issue")
	controller.lifetime = renewedLifetime
	h := &lifecycleHarness{controller: controller, dir: t.TempDir(), ks: newReadmitKeyStore(t)}

	serverCert, err := controller.certMgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, IPAddresses: []string{"127.0.0.1"}, ValidityDays: 30,
	})
	require.NoError(t, err)
	serverTLS, err := cert.CreateServerTLSConfig(serverCert.CertificatePEM, serverCert.PrivateKeyPEM, []byte(controller.caPEM), tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}
	serverTLS.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) > 0 {
			if leaf, parseErr := x509.ParseCertificate(raw[0]); parseErr == nil {
				h.mu.Lock()
				h.handshakes = append(h.handshakes, leaf.SerialNumber.String())
				h.mu.Unlock()
			}
		}
		return nil
	}
	server := grpcCP.New(grpcCP.ModeServer, grpcCP.WithApprovalChecker(allowAllApproval{}))
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": serverTLS, "registry": registry.NewRegistry(),
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	deviceID := h.ks.DeviceID()
	initial, err := controller.certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: deviceID, ClientID: deviceID, ValidityDays: 30,
		TemplateModifier: func(tpl *x509.Certificate) {
			tpl.NotBefore = time.Now().Add(-time.Second)
			tpl.NotAfter = time.Now().Add(initialLifetime)
		},
	})
	require.NoError(t, err)

	bundle := approvedRegistration{
		StewardID:        "steward-lifecycle",
		TenantID:         "tenant-lifecycle",
		TransportAddress: server.ListenAddr(),
		ClientCert:       string(initial.CertificatePEM),
		ClientKey:        string(initial.PrivateKeyPEM),
		CACert:           controller.caPEM,
		ServerCert:       string(serverCert.CertificatePEM),
	}
	enrichApprovedWithDeviceIdentity(&bundle, h.ks)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tc, err := connectWithApprovedRegistration(ctx, bundle, h.dir, "tok", trustSourceCompileBaked, "", "",
		stewardconfig.StewardConfig{}, false, logging.NewLogger("error"))
	require.NoError(t, err)
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dcancel()
		_ = tc.Disconnect(dctx)
		// The data plane provider is process-global; release it for the next test.
		_ = dataplaneInterfaces.GetProvider("grpc").Stop(dctx)
	})
	h.tc = tc
	h.idBefore = readIdentityBytes(t, h.dir)
	require.Eventually(t, tc.ControlStreamConnected, 10*time.Second, 50*time.Millisecond)
	return h
}

func readIdentityBytes(t *testing.T, dir string) []byte {
	t.Helper()
	f := &storedIdentityFixture{certStoreDir: dir}
	return f.identityBytes(t)
}

func (h *lifecycleHarness) lifecycle(t *testing.T) *identityLifecycle {
	t.Helper()
	return &identityLifecycle{
		tc:            h.tc,
		ks:            h.ks,
		certStoreDir:  h.dir,
		controllerURL: h.controller.server.URL,
		trustSrc:      trustSourceCompileBaked,
		logger:        logging.NewLogger("error"),
		mu:            &sync.Mutex{},
		tick:          50 * time.Millisecond,
		interval:      100 * time.Millisecond,
		jitter:        50 * time.Millisecond,
		renewWindow:   func(lifetime time.Duration) time.Duration { return lifetime / 2 },
	}
}

// newestClientSerial is the serial of the client certificate the next handshake presents.
func (h *lifecycleHarness) newestClientSerial(t *testing.T) string {
	t.Helper()
	tlsCert, err := h.tc.CertManager().GetClientCertificate(context.Background())
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)
	return leaf.SerialNumber.String()
}

func reasonCodes(tc *client.TransportClient) []string {
	var codes []string
	for _, r := range tc.HealthReasons() {
		codes = append(codes, r.Code)
	}
	return codes
}

// TestIdentityLifecycle_RenewsInWindowWithoutRestart: the watcher renews a
// certificate inside its renewal window and the SAME client re-dials with the
// new one — no new client, no restart.
func TestIdentityLifecycle_RenewsInWindowWithoutRestart(t *testing.T) {
	h := newLifecycleHarness(t, 8*time.Second, time.Hour)
	original := h.newestClientSerial(t)
	tcBefore := h.tc

	lc := h.lifecycle(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { lc.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	require.Eventually(t, func() bool { return h.newestClientSerial(t) != original }, 20*time.Second, 100*time.Millisecond,
		"the client certificate is replaced inside the renewal window")
	renewed := h.newestClientSerial(t)
	require.Eventually(t, func() bool {
		s := h.presentedSerials()
		return len(s) > 1 && s[len(s)-1] == renewed && h.tc.ControlStreamConnected()
	}, 20*time.Second, 100*time.Millisecond, "the control stream is re-established presenting the new certificate")
	assert.Same(t, tcBefore, lc.tc, "renewal reuses the same TransportClient")
	assert.Empty(t, reasonCodes(h.tc))
}

// TestIdentityLifecycle_ExpiredCertificateRenewsThroughProof: a certificate that
// already lapsed is replaced through the device-key proof flow in-process.
func TestIdentityLifecycle_ExpiredCertificateRenewsThroughProof(t *testing.T) {
	h := newLifecycleHarness(t, 2*time.Second, time.Hour)
	original := h.newestClientSerial(t)
	time.Sleep(3 * time.Second)
	certs, err := h.tc.CertManager().ListCertificates()
	require.NoError(t, err)
	for _, c := range certs {
		if c.Type == cert.CertificateTypeClient {
			require.False(t, c.ExpiresAt.After(time.Now()), "the client certificate has expired")
		}
	}

	lc := h.lifecycle(t)
	require.True(t, lc.checkOnce(context.Background()))

	assert.NotEqual(t, original, h.newestClientSerial(t))
	assert.Equal(t, 1, h.controller.completes)
	renewed := h.newestClientSerial(t)
	require.Eventually(t, func() bool {
		s := h.presentedSerials()
		return s[len(s)-1] == renewed && h.tc.ControlStreamConnected()
	}, 20*time.Second, 100*time.Millisecond)
}

// TestIdentityLifecycle_FailureReportsAndClears: an unreachable refresh endpoint
// surfaces client_cert.renewal_failed and a later success clears it.
func TestIdentityLifecycle_FailureReportsAndClears(t *testing.T) {
	h := newLifecycleHarness(t, 4*time.Second, time.Hour)
	original := h.newestClientSerial(t)
	h.controller.failComplete.Store(true)
	time.Sleep(2500 * time.Millisecond) // inside the window

	lc := h.lifecycle(t)
	require.False(t, lc.checkOnce(context.Background()))
	assert.Equal(t, []string{clientCertReasonRenewalFailed}, reasonCodes(h.tc))
	assert.Equal(t, original, h.newestClientSerial(t), "a failed renewal keeps the current credential")

	h.controller.failComplete.Store(false)
	require.True(t, lc.checkOnce(context.Background()))
	assert.Empty(t, reasonCodes(h.tc))
	assert.NotEqual(t, original, h.newestClientSerial(t))
}

// TestIdentityLifecycle_DeviceKeyUnusable: without a usable device key no
// renewal is attempted, the reason is set and the hook runs exactly once.
func TestIdentityLifecycle_DeviceKeyUnusable(t *testing.T) {
	h := newLifecycleHarness(t, 4*time.Second, time.Hour)
	time.Sleep(2500 * time.Millisecond)

	missing, err := identity.NewFileKeyStoreForTesting(t.TempDir()) // GenerateOrLoad never ran: no key
	require.NoError(t, err)
	for name, ks := range map[string]identity.KeyStore{"nil": nil, "missing": missing} {
		t.Run(name, func(t *testing.T) {
			var calls int
			lc := h.lifecycle(t)
			lc.ks = ks
			lc.onDeviceKeyUnusable = func() { calls++ }
			before := h.controller.completes

			require.False(t, lc.checkOnce(context.Background()))
			require.False(t, lc.checkOnce(context.Background()))

			assert.Equal(t, []string{clientCertReasonDeviceKeyUnusable}, reasonCodes(h.tc))
			assert.Equal(t, 1, calls, "the hook runs exactly once")
			assert.Equal(t, before, h.controller.completes, "no renewal is attempted with a weaker credential")
			h.tc.ClearHealthReason(clientCertReasonComponent)
		})
	}
}

// TestIdentityLifecycle_FreshMTLSKeyEveryRenewal: each renewal's CSR carries a new
// mTLS public key while the device identity key is unchanged.
func TestIdentityLifecycle_FreshMTLSKeyEveryRenewal(t *testing.T) {
	h := newLifecycleHarness(t, time.Hour, time.Hour)
	pubBefore := h.ks.PublicKey()
	id, err := loadIdentity(h.dir)
	require.NoError(t, err)

	for range 2 {
		_, err = renewIntoCertStore(context.Background(), id, h.ks, h.tc.CertManager(), h.dir, h.controller.server.URL,
			trustSourceCompileBaked, "", logging.NewLogger("error"))
		require.NoError(t, err)
	}

	require.Len(t, h.controller.csrKeys, 2)
	assert.NotEqual(t, h.controller.csrKeys[0], h.controller.csrKeys[1], "a fresh mTLS key per renewal")
	assert.Equal(t, pubBefore, h.ks.PublicKey(), "the identity key is not rotated")
	assert.Equal(t, h.idBefore, readIdentityBytes(t, h.dir), "renewal leaves the stored identity untouched")
}

// TestIdentityLifecycle_CertificateOnlyResponseKeepsStoredIdentity: a tampered
// steward's renewal returns the certificate alone; the stored CA, server
// certificate and transport address stay, and the next dial presents the new
// certificate.
func TestIdentityLifecycle_CertificateOnlyResponseKeepsStoredIdentity(t *testing.T) {
	h := newLifecycleHarness(t, 4*time.Second, time.Hour)
	h.controller.certOnly = true
	original := h.newestClientSerial(t)
	time.Sleep(2500 * time.Millisecond)

	id, err := loadIdentity(h.dir)
	require.NoError(t, err)
	cred, err := requestRefreshedCredential(context.Background(), id, h.ks, h.dir, h.controller.server.URL,
		trustSourceCompileBaked, "", logging.NewLogger("error"))
	require.NoError(t, err)
	assert.Equal(t, id.CACertPEM, cred.bundle.CACert, "an absent CA keeps the stored CA")
	assert.Equal(t, id.ServerCertPEM, cred.bundle.ServerCert)
	assert.Equal(t, id.TransportAddress, cred.bundle.TransportAddress)

	lc := h.lifecycle(t)
	require.True(t, lc.checkOnce(context.Background()))
	assert.Equal(t, h.idBefore, readIdentityBytes(t, h.dir), "CA, server certificate and transport address are kept")
	renewed := h.newestClientSerial(t)
	assert.NotEqual(t, original, renewed)
	require.Eventually(t, func() bool {
		s := h.presentedSerials()
		return s[len(s)-1] == renewed && h.tc.ControlStreamConnected()
	}, 20*time.Second, 100*time.Millisecond, "the new certificate is used on the next dial")
}

func TestDefaultRenewWindow(t *testing.T) {
	assert.Equal(t, 7*24*time.Hour, defaultRenewWindow(10*24*time.Hour), "short lifetimes use the 7 day floor")
	assert.Equal(t, 25*24*time.Hour, defaultRenewWindow(100*24*time.Hour), "long lifetimes use 25%")
}
