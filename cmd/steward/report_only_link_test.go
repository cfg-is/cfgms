// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/modules/install"
	"github.com/cfgis/cfgms/pkg/cert"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// roServer is a real controller-side test server: the gRPC control plane
// provider behind a QUIC listener with mTLS, composed with recording handlers
// for every RPC a report-only steward must not call.
type roServer struct {
	mgr   *cert.Manager
	caPEM string
	cp    *grpcCP.Provider
	reg   registry.Registry
	addr  string

	heartbeats chan *cpTypes.Heartbeat
	events     chan *cpTypes.Event
	logs       chan *transportpb.LogEntry
	pulls      atomic.Int64

	// revoked holds the serials (decimal) the server refuses at admission;
	// handshakes records the serial each client presented, in order.
	revoked     sync.Map
	handshakeMu sync.Mutex
	handshakes  []string
}

// handshakeSerials returns the client certificate serial of every handshake so far.
func (s *roServer) handshakeSerials() []string {
	s.handshakeMu.Lock()
	defer s.handshakeMu.Unlock()
	return append([]string(nil), s.handshakes...)
}

// admit records the client certificate a handshake presented and refuses a
// revoked one.
func (s *roServer) admit(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return nil
	}
	c, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	serial := c.SerialNumber.String()
	s.handshakeMu.Lock()
	s.handshakes = append(s.handshakes, serial)
	s.handshakeMu.Unlock()
	if _, revoked := s.revoked.Load(serial); revoked {
		return fmt.Errorf("client certificate %s is revoked", serial)
	}
	return nil
}

type roTransport struct {
	transportpb.StewardTransportServer
	srv *roServer
}

func (s *roTransport) SyncConfig(*transportpb.ConfigSyncRequest, grpc.ServerStreamingServer[transportpb.ConfigChunk]) error {
	s.srv.pulls.Add(1)
	return status.Error(codes.Unavailable, "no config")
}

func (s *roTransport) FetchModuleBundle(*transportpb.FetchModuleBundleRequest, grpc.ServerStreamingServer[transportpb.ModuleBundleChunk]) error {
	s.srv.pulls.Add(1)
	return status.Error(codes.NotFound, "no bundle")
}

func (s *roTransport) BulkTransfer(grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
	s.srv.pulls.Add(1)
	return status.Error(codes.Unavailable, "no bulk")
}

func (s *roTransport) LogStream(stream grpc.ClientStreamingServer[transportpb.LogEntry, transportpb.LogStreamResponse]) error {
	for {
		entry, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return stream.SendAndClose(&transportpb.LogStreamResponse{})
			}
			return err
		}
		s.srv.logs <- entry
	}
}

func newROServer(t *testing.T) *roServer {
	t.Helper()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &cert.CAConfig{Organization: "CFGMS Report-Only Test CA", Country: "US", ValidityDays: 30},
	})
	require.NoError(t, err)
	caPEM, err := mgr.GetCACertificate()
	require.NoError(t, err)
	serverCert, err := mgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, IPAddresses: []string{"127.0.0.1"}, ValidityDays: 30,
	})
	require.NoError(t, err)
	serverTLS, err := cert.CreateServerTLSConfig(serverCert.CertificatePEM, serverCert.PrivateKeyPEM, caPEM, tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}

	ln, err := quictransport.Listen("127.0.0.1:0", serverTLS, nil)
	require.NoError(t, err)
	grpcSrv := grpc.NewServer(grpc.Creds(quictransport.TransportCredentials()))
	s := &roServer{
		mgr: mgr, caPEM: string(caPEM), reg: registry.NewRegistry(), addr: ln.Addr().String(),
		heartbeats: make(chan *cpTypes.Heartbeat, 64), events: make(chan *cpTypes.Event, 64), logs: make(chan *transportpb.LogEntry, 64),
	}
	serverTLS.VerifyPeerCertificate = s.admit
	s.cp = grpcCP.New(grpcCP.ModeServer)
	require.NoError(t, s.cp.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "grpc_server": grpcSrv, "registry": s.reg,
	}))
	require.NoError(t, s.cp.Start(context.Background()))
	transportpb.RegisterStewardTransportServer(grpcSrv, &roTransport{StewardTransportServer: s.cp.ServerHandler(), srv: s})
	go func() { _ = grpcSrv.Serve(ln) }()
	t.Cleanup(grpcSrv.Stop)
	require.NoError(t, s.cp.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *cpTypes.Heartbeat) error {
		s.heartbeats <- hb
		return nil
	}))
	require.NoError(t, s.cp.SubscribeEvents(context.Background(), nil, func(_ context.Context, e *cpTypes.Event) error {
		s.events <- e
		return nil
	}))
	return s
}

const roStewardID = "steward-ro-link"

// roFixture is a steward with a stored identity and a cert store holding a
// client certificate issued by srv's CA.
type roFixture struct {
	dir string
	srv *roServer
	id  StewardIdentity
}

func fingerprintOf(t *testing.T, caPEM string) string {
	t.Helper()
	fp, err := computeCAPEMFingerprint(caPEM)
	require.NoError(t, err)
	return fp
}

func newROFixture(t *testing.T, trustMode TrustSource) *roFixture {
	t.Helper()
	srv := newROServer(t)
	clientCert, err := srv.mgr.GenerateClientCertificate(&cert.ClientCertConfig{CommonName: roStewardID, ClientID: roStewardID, ValidityDays: 30})
	require.NoError(t, err)
	dir := t.TempDir()
	require.NotNil(t, buildClientCertManagerAtPath(dir, string(clientCert.CertificatePEM), string(clientCert.PrivateKeyPEM), "", logging.NewNoopLogger()))
	id := StewardIdentity{
		StewardID:        roStewardID,
		TenantID:         "tenant-ro",
		TransportAddress: srv.addr,
		CACertPEM:        srv.caPEM,
		TrustMode:        trustModeString(trustMode),
		CAPinFingerprint: fingerprintOf(t, srv.caPEM),
	}
	require.NoError(t, saveIdentity(dir, id))
	return &roFixture{dir: dir, srv: srv, id: id}
}

func connectRO(t *testing.T, f *roFixture, src TrustSource) *client.TransportClient {
	t.Helper()
	tc, err := connectReportOnly(context.Background(), f.dir, src, logging.NewLogger("error"))
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tc.Disconnect(ctx)
	})
	require.Eventually(t, func() bool { _, ok := f.srv.reg.Get(roStewardID); return ok }, 10*time.Second, 20*time.Millisecond)
	return tc
}

// treeSnapshot records every file under root (relative path, mode, content hash).
func treeSnapshot(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range roots {
		require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			info, err := d.Info()
			if err != nil {
				return err
			}
			if d.IsDir() {
				out[root+"|"+rel] = "dir"
				return nil
			}
			data, err := os.ReadFile(p) // #nosec G304 -- test-owned temp tree
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			out[root+"|"+rel] = info.Mode().String() + hex.EncodeToString(sum[:])
			return nil
		}))
	}
	return out
}

func waitHeartbeat(t *testing.T, srv *roServer) *cpTypes.Heartbeat {
	t.Helper()
	select {
	case hb := <-srv.heartbeats:
		return hb
	case <-time.After(15 * time.Second):
		t.Fatal("no heartbeat reached the controller")
		return nil
	}
}

func TestConnectReportOnly_ConnectsHeartbeatsAndReportsReasons(t *testing.T) {
	f := newROFixture(t, trustSourceCompileBaked)
	// The S1 startup reasons are applied to the link before it connects.
	startupReasons.Set("tamper", "tamper.test", "test tamper reason")
	t.Cleanup(func() { startupReasons.Clear("tamper") })
	tc := connectRO(t, f, trustSourceCompileBaked)

	hb := waitHeartbeat(t, f.srv)
	// A binary with no baked root also says operator actions are unavailable.
	codes := make([]string, 0, len(hb.Reasons))
	for _, r := range hb.Reasons {
		codes = append(codes, r.Code)
	}
	assert.ElementsMatch(t, []string{"tamper.test", cpTypes.ReasonCodeLockedNoBakedRoot}, codes)
	assert.Equal(t, cpTypes.StatusError, hb.Status)
	assert.Equal(t, roStewardID, hb.StewardID)
	assert.True(t, tc.IsReportOnly())
	assert.Nil(t, tc.GetConfigExecutor())
}

// With a baked publisher list that matches no controller root, the link still
// connects, heartbeats, and delivers TamperState and RepairRequest.
func TestConnectReportOnly_BakedFingerprintNeverAffectsTheLink(t *testing.T) {
	t.Setenv("CFGMS_TEST_STEWARD_PUBLISHER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") // matches no controller root
	f := newROFixture(t, trustSourceCompileBaked)
	tc := connectRO(t, f, trustSourceCompileBaked)

	var mu sync.Mutex
	var tamper []bool
	var repairs []cpTypes.RepairRequest
	tc.SetTamperStateHandler(func(l bool) { mu.Lock(); tamper = append(tamper, l); mu.Unlock() })
	tc.SetRepairHandler(func(r cpTypes.RepairRequest) { mu.Lock(); repairs = append(repairs, r); mu.Unlock() })

	require.NoError(t, f.srv.cp.SendTamperState(context.Background(), roStewardID, true))
	require.NoError(t, f.srv.cp.SendTamperState(context.Background(), roStewardID, false))
	require.NoError(t, f.srv.cp.SendRepair(context.Background(), roStewardID, cpTypes.RepairRequest{RepairID: "rp-1", ApprovedLossCodes: []string{"logs.local"}}))
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(tamper) == 2 && len(repairs) == 1 },
		10*time.Second, 20*time.Millisecond)
	assert.NotNil(t, waitHeartbeat(t, f.srv))
}

// No trust material is written during a report-only session.
func TestConnectReportOnly_WritesNoTrustMaterial(t *testing.T) {
	f := newROFixture(t, trustSourceCompileBaked)
	dataDir := t.TempDir()
	t.Setenv("CFGMS_STEWARD_DATA_DIR", dataDir)
	before := treeSnapshot(t, f.dir, dataDir)

	tc := connectRO(t, f, trustSourceCompileBaked)
	require.True(t, tc.EnqueueLog(&transportpb.LogEntry{Message: "alarm"}))
	select {
	case <-f.srv.logs:
	case <-time.After(10 * time.Second):
		t.Fatal("log entry did not leave the host")
	}
	waitHeartbeat(t, f.srv)
	// DNA inventory has left too.
	require.Eventually(t, func() bool {
		select {
		case e := <-f.srv.events:
			return e.Type == cpTypes.EventDNAChanged
		default:
			return false
		}
	}, 20*time.Second, 20*time.Millisecond)

	after := treeSnapshot(t, f.dir, dataDir)
	assert.Equal(t, before, after, "a report-only session must not write, change or delete anything under the cert store or data directory")
	for path := range after {
		for _, forbidden := range []string{"module", "config", "signing", "queue", "pin"} {
			assert.NotContains(t, strings.ToLower(filepath.Base(path)), forbidden+"_cache", path)
		}
	}
}

// A module binary planted in the module cache is never started while
// report-only, and the DNA sent holds host facts only.
func TestConnectReportOnly_HostFactsOnly_PlantedModuleNeverStarts(t *testing.T) {
	moduleRoot := t.TempDir()
	marker := filepath.Join(t.TempDir(), "module-ran")
	binDir := filepath.Join(moduleRoot, "vendor-a", "planted", "1.0.0")
	require.NoError(t, os.MkdirAll(binDir, 0o750))
	script := "#!/bin/sh\ntouch " + marker + "\n"
	// #nosec G306 -- an executable test fixture in a temp dir.
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "planted"), []byte(script), 0o700))
	t.Setenv(install.BundleDirEnvVar, moduleRoot)

	f := newROFixture(t, trustSourceCompileBaked)
	tc := connectRO(t, f, trustSourceCompileBaked)

	var dnaEvent *cpTypes.Event
	require.Eventually(t, func() bool {
		select {
		case e := <-f.srv.events:
			if e.Type == cpTypes.EventDNAChanged {
				dnaEvent = e
				return true
			}
		default:
		}
		return false
	}, 30*time.Second, 20*time.Millisecond)

	frags, ok := dnaEvent.Details["dna"].([]interface{})
	require.True(t, ok, "the DNA event carries fragments: %#v", dnaEvent.Details["dna"])
	require.NotEmpty(t, frags)
	for _, raw := range frags {
		fr, _ := raw.(map[string]interface{})
		id, _ := fr["fragmentId"].(string)
		assert.True(t, strings.HasPrefix(id, "host:"), "fragment %q is not a host fact", id)
		assert.Equal(t, "gatherer", fr["authority"], "fragment %q came from a source other than the in-process host-fact gatherer", id)
	}
	assert.NoFileExists(t, marker, "the planted module must never be started")
	assert.Nil(t, tc.GetConfigExecutor())
}

func TestConnectReportOnly_NoIdentityIsATypedError(t *testing.T) {
	_, err := connectReportOnly(context.Background(), t.TempDir(), trustSourceCompileBaked, logging.NewNoopLogger())
	require.ErrorIs(t, err, errReportOnlyNoIdentity)
}

// A CA that does not verify against its anchor returns a typed error and
// dials nothing.
func TestConnectReportOnly_CADoesNotVerifyAgainstPin_TypedErrorNoDial(t *testing.T) {
	f := newROFixture(t, trustSourceTOFU)
	attacker := newROServer(t)
	bad := f.id
	bad.CACertPEM = attacker.caPEM // CA swapped, pin left at the real CA's
	require.NoError(t, saveIdentity(f.dir, bad))

	_, err := connectReportOnly(context.Background(), f.dir, trustSourceTOFU, logging.NewNoopLogger())
	require.ErrorIs(t, err, errReportOnlyAnchor)
	assert.Equal(t, 0, f.srv.reg.Count(), "nothing is dialed")
	assert.Equal(t, 0, attacker.reg.Count(), "the attacker's controller is not dialed either")
}

// A swapped CA-plus-pin pair in the stored identity receives no inbound data:
// the install-pinned CA is the anchor, the pair does not match it, nothing is
// dialed and nothing inbound is handled. The controller URL is never read from
// the identity file.
func TestConnectReportOnly_SwappedCAAndPinPair_InstallPinnedAnchor_NothingDialed(t *testing.T) {
	f := newROFixture(t, trustSourceInstallPinned)
	installCA := filepath.Join(t.TempDir(), "controller-ca.crt")
	require.NoError(t, os.WriteFile(installCA, []byte(f.srv.caPEM), 0o600))
	t.Setenv("CFGMS_HTTP_CA_CERT_PATH", installCA)

	attacker := newROServer(t)
	swapped := f.id
	swapped.CACertPEM = attacker.caPEM
	swapped.CAPinFingerprint = fingerprintOf(t, attacker.caPEM)
	swapped.TransportAddress = attacker.addr
	require.NoError(t, saveIdentity(f.dir, swapped))
	raw, err := os.ReadFile(filepath.Join(f.dir, identityFileName)) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	var generic map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &generic))
	generic["controller_url"] = "https://" + attacker.addr
	patched, err := json.Marshal(generic)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, identityFileName), patched, 0o600))

	_, err = connectReportOnly(context.Background(), f.dir, trustSourceInstallPinned, logging.NewNoopLogger())
	require.ErrorIs(t, err, errReportOnlyAnchor)
	assert.Equal(t, 0, attacker.reg.Count(), "the attacker's server is never dialed")
	assert.Equal(t, 0, f.srv.reg.Count())
	assert.Zero(t, attacker.pulls.Load())
}

func TestConnectReportOnly_InstallPinnedWithoutInstallerCA_IsAnchorError(t *testing.T) {
	f := newROFixture(t, trustSourceInstallPinned)
	t.Setenv("CFGMS_HTTP_CA_CERT_PATH", filepath.Join(t.TempDir(), "absent.crt"))
	if _, err := os.Stat(defaultPlatformCACertPath()); err == nil {
		t.Skip("a platform installer CA exists on this machine")
	}
	_, err := connectReportOnly(context.Background(), f.dir, trustSourceInstallPinned, logging.NewNoopLogger())
	require.ErrorIs(t, err, errReportOnlyAnchor)
}

// A swapped transport address with an attacker-controlled CA is refused by the
// handshake; nothing inbound is handled.
func TestConnectReportOnly_SwappedTransportAddress_RefusedByHandshake(t *testing.T) {
	prev := reportOnlyConnectBudget
	reportOnlyConnectBudget = 2 * time.Second
	t.Cleanup(func() { reportOnlyConnectBudget = prev })

	f := newROFixture(t, trustSourceCompileBaked)
	attacker := newROServer(t)
	swapped := f.id
	swapped.TransportAddress = attacker.addr // the CA and pin stay the real ones
	require.NoError(t, saveIdentity(f.dir, swapped))

	_, err := connectReportOnly(context.Background(), f.dir, trustSourceCompileBaked, logging.NewNoopLogger())
	require.Error(t, err)
	assert.NotErrorIs(t, err, errReportOnlyAnchor, "the anchor is fine; the server is what fails")
	assert.Equal(t, 0, attacker.reg.Count(), "the attacker's server admitted no stream")
	assert.Zero(t, attacker.pulls.Load())
}

// The S9 certificate renewer keeps working on the report-only link: a
// short-lived certificate is renewed in-process while report-only and the link
// stays connected.
func TestConnectReportOnly_CertificateRenewerKeepsWorking(t *testing.T) {
	h := newLifecycleHarness(t, 8*time.Second, time.Hour)
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = h.tc.Disconnect(dctx)
	_ = dataplaneInterfaces.GetProvider("grpc").Stop(dctx)
	dcancel()

	// Identity stored by the harness is a compile-baked one with the controller CA.
	ro, err := connectReportOnly(context.Background(), h.dir, trustSourceCompileBaked, logging.NewLogger("error"))
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ro.Disconnect(ctx)
	})
	h.tc = ro
	require.Eventually(t, ro.ControlStreamConnected, 10*time.Second, 50*time.Millisecond)
	original := h.newestClientSerial(t)

	lc := h.lifecycle(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { lc.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	require.Eventually(t, func() bool { return h.newestClientSerial(t) != original }, 30*time.Second, 100*time.Millisecond,
		"the client certificate is renewed in-process")
	renewed := h.newestClientSerial(t)
	require.Eventually(t, func() bool {
		s := h.presentedSerials()
		return len(s) > 1 && s[len(s)-1] == renewed && ro.ControlStreamConnected()
	}, 30*time.Second, 100*time.Millisecond, "the link re-dials with the renewed certificate and stays connected")
	assert.True(t, ro.IsReportOnly())
	assert.Same(t, ro, lc.tc)
}

// A normal client that receives TamperState{locked:true} over the real
// transport switches to report-only; commands after that are dropped.
func TestNormalClient_TamperStateLocked_SwitchesToReportOnly(t *testing.T) {
	srv := newROServer(t)
	clientCert, err := srv.mgr.GenerateClientCertificate(&cert.ClientCertConfig{CommonName: roStewardID, ClientID: roStewardID, ValidityDays: 30})
	require.NoError(t, err)
	serverCert, err := srv.mgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, IPAddresses: []string{"127.0.0.1"}, ValidityDays: 30,
	})
	require.NoError(t, err)
	dir := t.TempDir()
	bundle := approvedRegistration{
		StewardID: roStewardID, TenantID: "tenant-ro", TransportAddress: srv.addr,
		ClientCert: string(clientCert.CertificatePEM), ClientKey: string(clientCert.PrivateKeyPEM),
		CACert: srv.caPEM, ServerCert: string(serverCert.CertificatePEM),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tc, err := connectWithApprovedRegistration(ctx, bundle, dir, "tok", trustSourceCompileBaked, "", "",
		stewardconfig.StewardConfig{}, false, logging.NewLogger("error"))
	require.NoError(t, err)
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dcancel()
		_ = tc.Disconnect(dctx)
		_ = dataplaneInterfaces.GetProvider("grpc").Stop(dctx)
	})
	require.Eventually(t, tc.ControlStreamConnected, 10*time.Second, 50*time.Millisecond)
	require.False(t, tc.IsReportOnly())

	// The on-connect sync runs in a background goroutine; let it land before
	// the lock so the snapshot below cannot race with it.
	require.Eventually(t, func() bool { return srv.pulls.Load() >= 1 }, 30*time.Second, 20*time.Millisecond,
		"the on-connect sync pulls once before the lock")

	require.NoError(t, srv.cp.SendTamperState(context.Background(), roStewardID, true))
	require.Eventually(t, tc.IsReportOnly, 10*time.Second, 20*time.Millisecond)
	pullsAtSwitch := srv.pulls.Load()

	require.NoError(t, srv.cp.SendCommand(context.Background(), &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID: "after-lock", Type: cpTypes.CommandSyncConfig, StewardID: roStewardID, Timestamp: time.Now()}}))
	require.Eventually(t, func() bool { return tc.InboundDroppedKind("command") == 1 }, 10*time.Second, 20*time.Millisecond)
	assert.Equal(t, pullsAtSwitch, srv.pulls.Load(), "the switched client pulls nothing")
	var codes []string
	for _, r := range tc.HealthReasons() {
		codes = append(codes, r.Code)
	}
	assert.Contains(t, codes, client.ReasonTamperLocked)
}

// clusterModuleSource returns the real module DNA producer — a
// *execution.Executor driven by a Monitor-capable module — publishing a
// cluster:node resource snapshot. If the adapter consults it, cluster:*
// attributes and fragments appear in the collected DNA.
func clusterModuleSource(t *testing.T) moduleDNASource {
	t.Helper()
	return newModuleDNAExecutor(t, logging.NewNoopLogger(), "cluster:node", map[string]interface{}{"name": "n1"})
}

func TestDNACollectorAdapter_HostFactsOnlyDropsModuleSource(t *testing.T) {
	src := clusterModuleSource(t)
	require.NotEmpty(t, src.CollectModuleFragments(context.Background()),
		"the real module source must publish a cluster fragment for this test to mean anything")
	adapter := newDNACollectorAdapter(logging.NewNoopLogger(), src)
	narrowed := adapter.HostFactsOnly()
	attrs, err := narrowed.CollectAttributes(context.Background())
	require.NoError(t, err)
	for k := range attrs {
		assert.False(t, strings.HasPrefix(k, "cluster:"), "module attribute %q leaked into host-facts-only DNA", k)
	}
	for _, fr := range narrowed.CollectFragments(context.Background()) {
		assert.True(t, strings.HasPrefix(fr.GetFragmentId(), "host:"), fr.GetFragmentId())
	}
}

// A client-package collector without the narrowing hook is rejected nowhere
// else, so the adapter must be the one place that drops the module source.
func TestDNACollectorAdapter_FullAdapterStillCarriesModuleSource(t *testing.T) {
	src := clusterModuleSource(t)
	adapter := newDNACollectorAdapter(logging.NewNoopLogger(), src)
	attrs, err := adapter.CollectAttributes(context.Background())
	require.NoError(t, err)
	want := src.CollectModuleDNAAttributes(context.Background())
	require.NotEmpty(t, want)
	for k, v := range want {
		assert.True(t, strings.HasPrefix(k, "cluster:node"), k)
		assert.Equal(t, v, attrs[k], "full adapter must carry module attribute %s", k)
	}
}
