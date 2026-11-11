// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/steward/operatorroster"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// Real-component tests for operator actions on a locked (report-only) steward.
// The controller side is a real gRPC control plane behind a QUIC listener with
// mTLS and the lockdown gate; its root certificate is the one "baked" into the
// steward under test (the matcher closes over its fingerprint).

type lockedCtl struct {
	mgr      *cert.Manager
	caPEM    []byte
	root     *x509.Certificate
	cp       *grpcCP.Provider
	reg      registry.Registry
	addr     string
	stop     func()
	signing  *cert.Certificate
	operator *cert.Certificate
	chainPEM []byte

	events     chan *cpTypes.Event
	heartbeats chan *cpTypes.Heartbeat
	terminals  chan grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData]
}

type lockedCtlTransport struct {
	transportpb.StewardTransportServer
	ctl *lockedCtl
}

func (s *lockedCtlTransport) LogStream(stream grpc.ClientStreamingServer[transportpb.LogEntry, transportpb.LogStreamResponse]) error {
	for {
		if _, err := stream.Recv(); err != nil {
			if err == io.EOF {
				return stream.SendAndClose(&transportpb.LogStreamResponse{})
			}
			return err
		}
	}
}

func (s *lockedCtlTransport) Terminal(stream grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData]) error {
	s.ctl.terminals <- stream
	<-stream.Context().Done()
	return nil
}

// startLockedCtl starts a controller. mgr is its PKI (a new one when nil); addr
// is where it listens ("127.0.0.1:0" for any port); acceptClientCAs are extra CA
// certificates it accepts client certificates from, so a stolen steward
// certificate is accepted by an attacker's server.
func startLockedCtl(t *testing.T, mgr *cert.Manager, addr string, acceptClientCAs ...[]byte) *lockedCtl {
	t.Helper()
	var err error
	if mgr == nil {
		mgr, err = cert.NewManager(&cert.ManagerConfig{
			StoragePath: t.TempDir(),
			CAConfig:    &cert.CAConfig{Organization: "Locked Test CA", Country: "US", ValidityDays: 30},
		})
		require.NoError(t, err)
	}
	caPEM, err := mgr.GetCACertificate()
	require.NoError(t, err)
	root, err := cert.ParseCertificateFromPEM(caPEM)
	require.NoError(t, err)
	serverCert, err := mgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, IPAddresses: []string{"127.0.0.1"}, ValidityDays: 30,
	})
	require.NoError(t, err)
	clientCAs := append([]byte{}, caPEM...)
	for _, extra := range acceptClientCAs {
		clientCAs = append(clientCAs, extra...)
	}
	serverTLS, err := cert.CreateServerTLSConfig(serverCert.CertificatePEM, serverCert.PrivateKeyPEM, clientCAs, tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}

	ln, err := quictransport.Listen(addr, serverTLS, nil)
	require.NoError(t, err)
	grpcSrv := grpc.NewServer(grpc.Creds(quictransport.TransportCredentials()))

	signing, err := mgr.GenerateSigningCertificate(&cert.SigningCertConfig{
		CommonName: "locked-test-signer", Organization: "Locked Test", ValidityDays: 30, KeySize: 2048,
	})
	require.NoError(t, err)
	operator, err := mgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: "operator.test", ValidityDays: 30, KeySize: 2048, ClientID: "operator.test",
		TemplateModifier: func(template *x509.Certificate) {
			cert.SetPayloadSigningMarker(template)
			require.NoError(t, cert.SetAccountBinding(template, lockedOperatorAccountID))
		},
	})
	require.NoError(t, err)

	c := &lockedCtl{
		mgr: mgr, caPEM: caPEM, root: root, reg: registry.NewRegistry(), addr: ln.Addr().String(),
		signing: signing, operator: operator,
		chainPEM:   append(append([]byte{}, signing.CertificatePEM...), caPEM...),
		events:     make(chan *cpTypes.Event, 256),
		heartbeats: make(chan *cpTypes.Heartbeat, 256),
		terminals:  make(chan grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData], 4),
	}
	c.cp = grpcCP.New(grpcCP.ModeServer, grpcCP.WithLockdown(lockedStewards{reportOnlyStewardID: true}, nil))
	require.NoError(t, c.cp.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "grpc_server": grpcSrv, "registry": c.reg,
	}))
	require.NoError(t, c.cp.Start(context.Background()))
	transportpb.RegisterStewardTransportServer(grpcSrv, &lockedCtlTransport{StewardTransportServer: c.cp.ServerHandler(), ctl: c})
	go func() { _ = grpcSrv.Serve(ln) }()
	c.stop = grpcSrv.Stop
	t.Cleanup(grpcSrv.Stop)
	require.NoError(t, c.cp.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *cpTypes.Heartbeat) error {
		select {
		case c.heartbeats <- hb:
		default:
		}
		return nil
	}))
	require.NoError(t, c.cp.SubscribeEvents(context.Background(), nil, func(_ context.Context, e *cpTypes.Event) error {
		select {
		case c.events <- e:
		default:
		}
		return nil
	}))
	return c
}

func (c *lockedCtl) waitConnected(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool { _, ok := c.reg.Get(reportOnlyStewardID); return ok }, 15*time.Second, 20*time.Millisecond)
}

// lockedOperatorAccountID is the account the locked-steward tests' operator certificates are
// bound to, and that the manifest server's signer roster names as their owner.
const lockedOperatorAccountID = "acct-locked-operator"

// manifestServer serves the signed revocation manifest the way the controller does, including
// the X.509 signer roster for the operators it was built to authorize.
type manifestServer struct {
	srv       *httptest.Server
	mu        sync.Mutex
	issuedAt  func() time.Time
	revoked   []string
	signer    *cert.Certificate
	authorize []*cert.Certificate
	hits      atomic.Int64
}

type manifestSigner struct {
	Kind      string   `json:"kind"`
	Serial    string   `json:"serial"`
	AccountID string   `json:"account_id"`
	TenantID  string   `json:"tenant_id"`
	RootScope bool     `json:"root_scope"`
	Grants    []string `json:"grants"`
}

// newManifestServer serves manifests signed by signer whose roster authorizes operators as
// root-scope holders of operator-payload:sign.
func newManifestServer(t *testing.T, signer *cert.Certificate, operators ...*cert.Certificate) *manifestServer {
	t.Helper()
	m := &manifestServer{signer: signer, authorize: operators, issuedAt: func() time.Time { return time.Now() }}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != operatorroster.ManifestPath {
			http.NotFound(w, r)
			return
		}
		m.hits.Add(1)
		m.mu.Lock()
		defer m.mu.Unlock()
		manifest := struct {
			Kind                  string           `json:"kind"`
			Version               int64            `json:"version"`
			IssuedAt              time.Time        `json:"issued_at"`
			RevokedSerials        []string         `json:"revoked_serials"`
			AuthorizedX509Signers []manifestSigner `json:"authorized_x509_signers,omitempty"`
		}{Kind: "operator-cert-revocation", Version: int64(len(m.revoked)), IssuedAt: m.issuedAt().UTC().Truncate(time.Second), RevokedSerials: append([]string{}, m.revoked...)}
		for _, op := range m.authorize {
			manifest.AuthorizedX509Signers = append(manifest.AuthorizedX509Signers, manifestSigner{
				Kind: "x509-signing-certificate", Serial: op.SerialNumber, AccountID: lockedOperatorAccountID,
				RootScope: true, Grants: []string{"operator-payload:sign"},
			})
		}
		data, _ := json.Marshal(manifest)
		s, _ := signature.NewSigner(&signature.SignerConfig{CertificatePEM: m.signer.CertificatePEM, PrivateKeyPEM: m.signer.PrivateKeyPEM})
		sig, _ := s.Sign(data)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"manifest": manifest, "signature": sig, "signer_certificate_pem": string(m.signer.CertificatePEM),
		})
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *manifestServer) revoke(serial string) {
	m.mu.Lock()
	m.revoked = append(m.revoked, serial)
	m.mu.Unlock()
}

// bakedMatcher is the baked-root check of a binary baked with these roots.
func bakedMatcher(roots ...*x509.Certificate) func(*x509.Certificate) bool {
	return func(c *x509.Certificate) bool {
		if c == nil || !c.IsCA || c.CheckSignatureFrom(c) != nil {
			return false
		}
		sum := sha256.Sum256(c.Raw)
		for _, r := range roots {
			if sum == sha256.Sum256(r.Raw) {
				return true
			}
		}
		return false
	}
}

type lockedClientOpts struct {
	anchorPEM  []byte
	certMgr    *cert.Manager
	manifest   *manifestServer
	tools      LockedToolsConfig
	certStore  string
	interval   time.Duration
	skipEnable bool
}

func newLockedClient(t *testing.T, ctl *lockedCtl, o lockedClientOpts) *TransportClient {
	t.Helper()
	if o.anchorPEM == nil {
		o.anchorPEM = ctl.caPEM
	}
	if o.certMgr == nil {
		o.certMgr = ctl.mgr
	}
	if o.certStore == "" {
		o.certStore = t.TempDir()
	}
	_, err := o.certMgr.GenerateClientCertificate(&cert.ClientCertConfig{CommonName: reportOnlyStewardID, ClientID: reportOnlyStewardID, ValidityDays: 30})
	require.NoError(t, err)
	cfg := &TransportConfig{
		ReportOnly: true, ControllerURL: ctl.addr, CACertPEM: string(o.anchorPEM), CertManager: o.certMgr,
		CertStoreDir: o.certStore, HeartbeatInterval: 50 * time.Millisecond,
		DNACollector: &staticDNACollector{attrs: map[string]string{"host.os": "test-os"}},
		Logger:       newTestLogger(t),
	}
	if o.manifest != nil {
		cfg.ControllerHTTPSBaseURL = o.manifest.srv.URL
	}
	c, err := NewTransportClient(cfg)
	require.NoError(t, err)
	c.heartbeatJitter = time.Millisecond
	c.SetStewardID(reportOnlyStewardID)
	c.SetTenantID("tenant-report-only")
	if o.manifest != nil {
		c.upgradeHTTPClient = o.manifest.srv.Client()
	}
	if o.tools.MatchesBakedRoot == nil {
		o.tools.MatchesBakedRoot = bakedMatcher(ctl.root)
	}
	if o.interval > 0 {
		o.tools.RevocationRefreshInterval = o.interval
	}
	if !o.skipEnable {
		require.NoError(t, c.EnableLockedTools(o.tools))
	}
	require.NoError(t, c.Connect(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Disconnect(ctx)
	})
	return c
}

// ---- command builders ----

func rsaKeyFromPEM(t *testing.T, keyPEM []byte) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key
}

func envelopeParams(t *testing.T, op *cert.Certificate, content []byte, shell string, targets []string, nonce string, exp time.Time) map[string]interface{} {
	t.Helper()
	canonical, err := operatorpayload.CanonicalBytes(operatorpayload.Envelope{Content: content, Shell: shell, Targets: targets, Nonce: nonce, ExpiresAt: exp})
	require.NoError(t, err)
	h := sha256.Sum256(canonical)
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKeyFromPEM(t, op.PrivateKeyPEM), crypto.SHA256, h[:])
	require.NoError(t, err)
	return map[string]interface{}{
		"signature_algorithm": "rsa-sha256", "signature_value": base64.StdEncoding.EncodeToString(sig),
		"signature_public_key": string(op.CertificatePEM), "targets": targets, "nonce": nonce,
		"expires_at": exp.UTC().Format(time.RFC3339),
	}
}

func lockedNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type lockedKind string

const (
	kindScript   lockedKind = "script"
	kindAction   lockedKind = "action"
	kindTerminal lockedKind = "terminal"
)

func lockedShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "bash"
}

// buildCommand builds a command of the kind, with the operator envelope signed
// by op, and signs it with signer and attaches chain.
func buildCommand(t *testing.T, kind lockedKind, id string, op, signer *cert.Certificate, chain []byte, term uint64) *cpTypes.SignedCommand {
	t.Helper()
	exp := time.Now().Add(time.Minute)
	var typ cpTypes.CommandType
	var params map[string]interface{}
	switch kind {
	case kindScript:
		typ = cpTypes.CommandExecuteScript
		content := []byte("echo locked-ok")
		params = envelopeParams(t, op, content, lockedShell(), []string{reportOnlyStewardID}, lockedNonce(), exp)
		params["script_content"] = base64.StdEncoding.EncodeToString(content)
		params["shell"] = lockedShell()
	case kindAction:
		typ = cpTypes.CommandStewardAction
		content, err := operatorpayload.ActionContent(operatorpayload.Action{Verb: "service.start", TargetKind: "service", TargetName: "cfgms-test-nonexistent"})
		require.NoError(t, err)
		params = envelopeParams(t, op, content, operatorpayload.ActionShell, []string{reportOnlyStewardID}, lockedNonce(), exp)
		params["verb"] = "service.start"
		params["target"] = map[string]interface{}{"kind": "service", "name": "cfgms-test-nonexistent"}
		params["parameters"] = map[string]string{}
	case kindTerminal:
		typ = cpTypes.CommandOpenTerminal
		content, err := operatorpayload.TerminalContent(reportOnlyStewardID, lockedShell())
		require.NoError(t, err)
		params = envelopeParams(t, op, content, operatorpayload.TerminalShell, []string{reportOnlyStewardID}, lockedNonce(), exp)
		params["shell"] = lockedShell()
		params["session_id"] = "sess-" + id
		params["cols"] = float64(80)
		params["rows"] = float64(24)
	}
	if kind != kindTerminal {
		params["execution_id"] = "exec-" + id
	}
	sc := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID: id, Type: typ, StewardID: reportOnlyStewardID, Timestamp: time.Now(), Params: params,
		Term: term, SigningPayloadVersion: cpTypes.SigningPayloadV2,
	}}
	s, err := signature.NewSigner(&signature.SignerConfig{CertificatePEM: signer.CertificatePEM, PrivateKeyPEM: signer.PrivateKeyPEM})
	require.NoError(t, err)
	data, err := cpTypes.CommandSigningBytesVersion(&sc.Command, cpTypes.InterfaceParamsToStringMap(params), cpTypes.SigningPayloadV2)
	require.NoError(t, err)
	sc.Signature, err = s.Sign(data)
	require.NoError(t, err)
	sc.SignerChainPEM = chain
	return sc
}

func (c *lockedCtl) genuine(t *testing.T, kind lockedKind, id string) *cpTypes.SignedCommand {
	return buildCommand(t, kind, id, c.operator, c.signing, c.chainPEM, 0)
}

func (c *lockedCtl) send(t *testing.T, sc *cpTypes.SignedCommand) {
	t.Helper()
	require.NoError(t, c.cp.SendCommand(controlplaneInterfaces.WithOperatorOrigin(context.Background(), "operator-1"), sc))
}

func (c *lockedCtl) waitEvent(t *testing.T, typ cpTypes.EventType, commandID string) *cpTypes.Event {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case e := <-c.events:
			if e.Type == typ && e.CommandID == commandID {
				return e
			}
		case <-deadline:
			t.Fatalf("no %s event for command %s", typ, commandID)
			return nil
		}
	}
}

// noEvent asserts no completion-style event arrives for any of the commands.
func (c *lockedCtl) noEvent(t *testing.T, window time.Duration, ids ...string) {
	t.Helper()
	deadline := time.After(window)
	for {
		select {
		case e := <-c.events:
			for _, id := range ids {
				if e.CommandID == id && (e.Type == cpTypes.EventScriptCompleted || e.Type == cpTypes.EventCommandCompleted) {
					t.Fatalf("command %s ran: %s", id, e.Type)
				}
			}
		case <-deadline:
			return
		}
	}
}

func (c *lockedCtl) noTerminal(t *testing.T, window time.Duration) {
	t.Helper()
	select {
	case <-c.terminals:
		t.Fatal("a terminal session opened")
	case <-time.After(window):
	}
}

func (c *lockedCtl) waitReason(t *testing.T, code string) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case hb := <-c.heartbeats:
			for _, r := range hb.Reasons {
				if r.Code == code {
					assert.Equal(t, cpTypes.HealthComponentLockedTools, r.Component)
					return
				}
			}
		case <-deadline:
			t.Fatalf("no heartbeat carried reason %s", code)
			return
		}
	}
}

func (c *TransportClient) refusals(key string) int64 {
	c.reportOnlyMu.Lock()
	lt := c.lockedTrust
	c.reportOnlyMu.Unlock()
	return lt.RefusalCount(key)
}

func driveTerminal(t *testing.T, ctl *lockedCtl, sessionID string) {
	t.Helper()
	var stream grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData]
	select {
	case stream = <-ctl.terminals:
	case <-time.After(20 * time.Second):
		t.Fatal("terminal session did not open")
	}
	out := make(chan []byte, 256)
	go func() {
		for {
			f, err := stream.Recv()
			if err != nil {
				return
			}
			out <- f.GetData()
		}
	}()
	// The shell is started by the steward; send a command and wait for its echo.
	require.NoError(t, stream.Send(&transportpb.TerminalData{SessionId: sessionID, Data: []byte("echo terminal-e2e-ok\n")}))
	var got bytes.Buffer
	deadline := time.After(20 * time.Second)
	for !strings.Contains(got.String(), "terminal-e2e-ok") {
		select {
		case b := <-out:
			got.Write(b)
		case <-deadline:
			t.Fatalf("terminal output never arrived: %q", got.String())
		}
	}
}

func listTree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel+"|"+info.Mode().String())
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// ---- tests ----

func TestLockedTools_RunsEachKindWithChainFromController(t *testing.T) {
	ctl := startLockedCtl(t, nil, "127.0.0.1:0")
	ms := newManifestServer(t, ctl.signing, ctl.operator)
	certStore, dataDir := t.TempDir(), t.TempDir()
	c := newLockedClient(t, ctl, lockedClientOpts{manifest: ms, certStore: certStore})
	ctl.waitConnected(t)
	before := [][]string{listTree(t, certStore), listTree(t, dataDir)}

	ctl.send(t, ctl.genuine(t, kindScript, "ok-script"))
	ev := ctl.waitEvent(t, cpTypes.EventScriptCompleted, "ok-script")
	assert.EqualValues(t, 0, ev.Details["exit_code"])

	ctl.send(t, ctl.genuine(t, kindAction, "ok-action"))
	ctl.waitEvent(t, cpTypes.EventScriptCompleted, "ok-action")

	ctl.send(t, ctl.genuine(t, kindTerminal, "ok-term"))
	driveTerminal(t, ctl, "sess-ok-term")

	assert.True(t, c.IsReportOnly())
	assert.Positive(t, ms.hits.Load(), "the revocation manifest was fetched on the locked link")
	// A locked session writes no trust material, and script staging is elsewhere.
	assert.Equal(t, before, [][]string{listTree(t, certStore), listTree(t, dataDir)})
}

func TestLockedTools_PlantedTrustInDataFolderRefusedForAllKinds(t *testing.T) {
	ctl := startLockedCtl(t, nil, "127.0.0.1:0")
	ms := newManifestServer(t, ctl.signing, ctl.operator)
	planted := startLockedCtl(t, nil, "127.0.0.1:0")
	certStore := t.TempDir()
	// The data folder holds a planted CA and signing certificate.
	require.NoError(t, os.WriteFile(filepath.Join(certStore, "ca.crt"), planted.caPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(certStore, "signing.crt"), planted.signing.CertificatePEM, 0o600))
	c := newLockedClient(t, ctl, lockedClientOpts{manifest: ms, certStore: certStore})
	ctl.waitConnected(t)

	ids := []string{"pl-script", "pl-action", "pl-term"}
	for i, k := range []lockedKind{kindScript, kindAction, kindTerminal} {
		// Planted operator certificate, planted signer, planted root chain; the
		// outer signature is valid under the planted signing certificate.
		ctl.send(t, buildCommand(t, k, ids[i], planted.operator, planted.signing, planted.chainPEM, 0))
	}
	require.Eventually(t, func() bool { return c.refusals(cpTypes.ReasonCodeLockedRootMismatch) == 3 }, 20*time.Second, 20*time.Millisecond)
	ctl.noEvent(t, 500*time.Millisecond, ids...)
	ctl.noTerminal(t, 100*time.Millisecond)
	ctl.waitReason(t, cpTypes.ReasonCodeLockedRootMismatch)
}

func TestLockedTools_RelayAndSwappedPinAttackersRefused(t *testing.T) {
	real := startLockedCtl(t, nil, "127.0.0.1:0")
	ms := newManifestServer(t, real.signing, real.operator)
	// The attacker's server certificate chains to its own CA, which the steward's
	// stored pin was swapped to trust; it holds the stolen client certificate.
	proxy := startLockedCtl(t, nil, "127.0.0.1:0", real.caPEM)
	c := newLockedClient(t, proxy, lockedClientOpts{
		manifest: ms, certMgr: real.mgr, anchorPEM: proxy.caPEM,
		tools: LockedToolsConfig{MatchesBakedRoot: bakedMatcher(real.root)},
	})
	proxy.waitConnected(t)

	// Relay: a genuine, fully valid operator command from the real controller.
	var ids []string
	for i, k := range []lockedKind{kindScript, kindAction, kindTerminal} {
		id := "relay-" + string(rune('a'+i))
		ids = append(ids, id)
		proxy.send(t, real.genuine(t, k, id))
	}
	require.Eventually(t, func() bool { return c.refusals(cpTypes.ReasonCodeLockedLinkNotAnchored) == 3 }, 20*time.Second, 20*time.Millisecond)
	proxy.noEvent(t, 500*time.Millisecond, ids...)
	proxy.noTerminal(t, 100*time.Millisecond)
	proxy.waitReason(t, cpTypes.ReasonCodeLockedLinkNotAnchored)

	// Swapped pin: a validly shaped command with a planted root and signer.
	for i, k := range []lockedKind{kindScript, kindAction, kindTerminal} {
		id := "swap-" + string(rune('a'+i))
		ids = append(ids, id)
		proxy.send(t, proxy.genuine(t, k, id))
	}
	require.Eventually(t, func() bool { return c.refusals(cpTypes.ReasonCodeLockedRootMismatch) == 3 }, 20*time.Second, 20*time.Millisecond)
	proxy.noEvent(t, 500*time.Millisecond, ids...)
	proxy.noTerminal(t, 100*time.Millisecond)
}

func TestLockedTools_ReconnectChecksTheNewSessionsCertificate(t *testing.T) {
	a := startLockedCtl(t, nil, "127.0.0.1:0")
	ms := newManifestServer(t, a.signing, a.operator)
	b := startLockedCtl(t, nil, "127.0.0.1:0", a.caPEM)
	// The steward's TLS pin trusts both servers; only A's root is baked.
	anchor := append(append([]byte{}, a.caPEM...), b.caPEM...)

	// B listens where A did once A is stopped.
	addr := a.addr
	c := newLockedClient(t, a, lockedClientOpts{
		manifest: ms, anchorPEM: anchor, tools: LockedToolsConfig{MatchesBakedRoot: bakedMatcher(a.root)},
	})
	a.waitConnected(t)
	a.send(t, a.genuine(t, kindAction, "before-reconnect"))
	a.waitEvent(t, cpTypes.EventScriptCompleted, "before-reconnect")

	a.stop()
	b2 := startLockedCtl(t, b.mgr, addr, a.caPEM)
	c.mu.RLock()
	cp := c.controlPlane
	c.mu.RUnlock()
	require.NoError(t, cp.Reconnect(context.Background()))
	b2.waitConnected(t)
	// The same genuine command from A's root, relayed through B's session.
	b2.send(t, a.genuine(t, kindAction, "after-reconnect"))
	require.Eventually(t, func() bool { return c.refusals(cpTypes.ReasonCodeLockedLinkNotAnchored) >= 1 }, 20*time.Second, 20*time.Millisecond)
	b2.noEvent(t, 500*time.Millisecond, "after-reconnect")
}

func TestLockedTools_RevokedCertificateAndStaleManifest(t *testing.T) {
	ctl := startLockedCtl(t, nil, "127.0.0.1:0")
	opCert, err := cert.ParseCertificateFromPEM(ctl.operator.CertificatePEM)
	require.NoError(t, err)

	t.Run("revoked", func(t *testing.T) {
		ms := newManifestServer(t, ctl.signing, ctl.operator)
		ms.revoke(opCert.SerialNumber.String())
		_ = newLockedClient(t, ctl, lockedClientOpts{manifest: ms})
		ctl.waitConnected(t)
		ctl.send(t, ctl.genuine(t, kindAction, "revoked-1"))
		ev := ctl.waitEvent(t, cpTypes.EventCommandFailed, "revoked-1")
		assert.Contains(t, ev.Details["error"], "revoked")
		ctl.noEvent(t, 300*time.Millisecond, "revoked-1")
	})
	t.Run("stale manifest", func(t *testing.T) {
		ms := newManifestServer(t, ctl.signing, ctl.operator)
		ms.issuedAt = func() time.Time { return time.Now().Add(-time.Hour) }
		c := newLockedClient(t, ctl, lockedClientOpts{manifest: ms, interval: time.Minute})
		ctl.waitConnected(t)
		ctl.send(t, ctl.genuine(t, kindScript, "stale-1"))
		require.Eventually(t, func() bool { return c.refusals(cpTypes.ReasonCodeLockedRevocationStale) >= 1 }, 20*time.Second, 20*time.Millisecond)
		ctl.waitReason(t, cpTypes.ReasonCodeLockedRevocationStale)
		ctl.noEvent(t, 300*time.Millisecond, "stale-1")
	})
	t.Run("no manifest endpoint", func(t *testing.T) {
		c := newLockedClient(t, ctl, lockedClientOpts{})
		ctl.waitConnected(t)
		ctl.send(t, ctl.genuine(t, kindScript, "nomanifest-1"))
		require.Eventually(t, func() bool { return c.refusals(cpTypes.ReasonCodeLockedRevocationStale) >= 1 }, 20*time.Second, 20*time.Millisecond)
		ctl.noEvent(t, 300*time.Millisecond, "nomanifest-1")
	})
}

func TestLockedTools_BakedRootStatesRefuseCommandsButSignalsStillArrive(t *testing.T) {
	cases := map[string]LockedToolsConfig{
		cpTypes.ReasonCodeLockedNoBakedRoot: {
			MatchesBakedRoot: func(*x509.Certificate) bool { return false },
			BakedRootReason:  func() string { return cpTypes.ReasonCodeLockedNoBakedRoot },
		},
		cpTypes.ReasonCodeLockedBakedRootMalformed: {
			MatchesBakedRoot: func(*x509.Certificate) bool { return false },
			BakedRootReason:  func() string { return cpTypes.ReasonCodeLockedBakedRootMalformed },
		},
		// A baked list that matches no controller root.
		cpTypes.ReasonCodeLockedRootMismatch: {
			MatchesBakedRoot: bakedMatcher(startLockedCtl(t, nil, "127.0.0.1:0").root),
		},
	}
	for code, tools := range cases {
		t.Run(code, func(t *testing.T) {
			ctl := startLockedCtl(t, nil, "127.0.0.1:0")
			ms := newManifestServer(t, ctl.signing, ctl.operator)
			c := newLockedClient(t, ctl, lockedClientOpts{manifest: ms, tools: tools})
			ctl.waitConnected(t)

			var mu sync.Mutex
			var tamper []bool
			var repairs []string
			c.SetTamperStateHandler(func(locked bool) { mu.Lock(); tamper = append(tamper, locked); mu.Unlock() })
			c.SetRepairHandler(func(r cpTypes.RepairRequest) { mu.Lock(); repairs = append(repairs, r.RepairID); mu.Unlock() })

			var ids []string
			for i, k := range []lockedKind{kindScript, kindAction, kindTerminal} {
				id := "baked-" + string(rune('a'+i))
				ids = append(ids, id)
				ctl.send(t, ctl.genuine(t, k, id))
			}
			ctl.waitReason(t, code)
			require.NoError(t, ctl.cp.SendTamperState(context.Background(), reportOnlyStewardID, true))
			require.NoError(t, ctl.cp.SendTamperState(context.Background(), reportOnlyStewardID, false))
			require.NoError(t, ctl.cp.SendRepair(context.Background(), reportOnlyStewardID, cpTypes.RepairRequest{RepairID: "rep-1"}))
			require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(tamper) == 2 && len(repairs) == 1 }, 10*time.Second, 20*time.Millisecond)
			ctl.noEvent(t, 300*time.Millisecond, ids...)
			ctl.noTerminal(t, 100*time.Millisecond)
		})
	}
}

func TestLockedTools_LargeTermDoesNotMoveTheFence(t *testing.T) {
	ctl := startLockedCtl(t, nil, "127.0.0.1:0")
	ms := newManifestServer(t, ctl.signing, ctl.operator)
	c := newLockedClient(t, ctl, lockedClientOpts{manifest: ms})
	ctl.waitConnected(t)
	ctl.send(t, buildCommand(t, kindAction, "term-1", ctl.operator, ctl.signing, ctl.chainPEM, 1<<62))
	ctl.waitEvent(t, cpTypes.EventScriptCompleted, "term-1")

	c.mu.RLock()
	set, highest := c.termRatchetSet, c.highestTermSeen
	c.mu.RUnlock()
	assert.False(t, set, "an unsigned Term never moves the stored fence")
	assert.Zero(t, highest)
	assert.False(t, c.commandsSignatureVerified())
}

func TestLockedTools_ConfigCanOnlyRestrict(t *testing.T) {
	ctl := startLockedCtl(t, nil, "127.0.0.1:0")
	ms := newManifestServer(t, ctl.signing, ctl.operator)
	c := newLockedClient(t, ctl, lockedClientOpts{manifest: ms, tools: LockedToolsConfig{DisableRemoteTerminal: true}})
	ctl.waitConnected(t)
	ctl.send(t, ctl.genuine(t, kindTerminal, "noterm"))
	ctl.waitEvent(t, cpTypes.EventCommandFailed, "noterm")
	ctl.noTerminal(t, 200*time.Millisecond)
	assert.True(t, c.IsReportOnly())
}

func TestLockedTools_WithoutLockedToolsCommandsAreDropped(t *testing.T) {
	ctl := startLockedCtl(t, nil, "127.0.0.1:0")
	c := newLockedClient(t, ctl, lockedClientOpts{skipEnable: true})
	ctl.waitConnected(t)
	ctl.send(t, ctl.genuine(t, kindAction, "dropped"))
	require.Eventually(t, func() bool { return c.InboundDroppedKind("command") == 1 }, 10*time.Second, 20*time.Millisecond)
	ctl.noEvent(t, 200*time.Millisecond, "dropped")
}

func TestEnableLockedTools_RequiresReportOnlyAndMatcher(t *testing.T) {
	c, err := NewTransportClient(&TransportConfig{ControllerURL: "127.0.0.1:1", Logger: newTestLogger(t)})
	require.NoError(t, err)
	assert.Error(t, c.EnableLockedTools(LockedToolsConfig{MatchesBakedRoot: func(*x509.Certificate) bool { return false }}))

	ro, err := NewTransportClient(&TransportConfig{ReportOnly: true, ControllerURL: "127.0.0.1:1", Logger: newTestLogger(t)})
	require.NoError(t, err)
	assert.Error(t, ro.EnableLockedTools(LockedToolsConfig{}), "a matcher is required")
}
