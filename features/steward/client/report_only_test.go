// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/steward/modules/install"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// reportOnlyController is a real controller-side test server: the gRPC control
// plane provider in server mode behind a QUIC listener with mTLS, composed with
// recording handlers for the RPCs a report-only steward must never call (pulls)
// and the ones it uses to report (LogStream).
type reportOnlyController struct {
	mgr   *cert.Manager
	caPEM []byte
	cp    *grpcCP.Provider
	reg   registry.Registry
	addr  string

	heartbeats chan *cpTypes.Heartbeat
	events     chan *cpTypes.Event
	logs       chan *transportpb.LogEntry

	syncConfigCalls atomic.Int64
	syncDNACalls    atomic.Int64
	bulkCalls       atomic.Int64
	fetchCalls      atomic.Int64
	lockdownPulls   atomic.Bool
}

type reportOnlyTransport struct {
	transportpb.StewardTransportServer
	ctl *reportOnlyController
}

func (s *reportOnlyTransport) SyncConfig(_ *transportpb.ConfigSyncRequest, _ grpc.ServerStreamingServer[transportpb.ConfigChunk]) error {
	s.ctl.syncConfigCalls.Add(1)
	return status.Error(codes.Unavailable, "test controller serves no config")
}

func (s *reportOnlyTransport) SyncDNA(grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse]) error {
	s.ctl.syncDNACalls.Add(1)
	return status.Error(codes.Unavailable, "test controller takes no DNA stream")
}

func (s *reportOnlyTransport) BulkTransfer(grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
	s.ctl.bulkCalls.Add(1)
	return status.Error(codes.Unavailable, "test controller serves no bulk")
}

func (s *reportOnlyTransport) FetchModuleBundle(_ *transportpb.FetchModuleBundleRequest, _ grpc.ServerStreamingServer[transportpb.ModuleBundleChunk]) error {
	s.ctl.fetchCalls.Add(1)
	if s.ctl.lockdownPulls.Load() {
		return controlplaneInterfaces.NewLockedDownError()
	}
	return status.Error(codes.NotFound, "no bundle")
}

func (s *reportOnlyTransport) LogStream(stream grpc.ClientStreamingServer[transportpb.LogEntry, transportpb.LogStreamResponse]) error {
	for {
		entry, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return stream.SendAndClose(&transportpb.LogStreamResponse{})
			}
			return err
		}
		s.ctl.logs <- entry
	}
}

const reportOnlyStewardID = "steward-report-only"

func newReportOnlyController(t *testing.T) *reportOnlyController {
	t.Helper()
	return newReportOnlyControllerWithLockdown(t, nil)
}

// lockedStewards is the lockdown predicate of a controller that has these
// stewards locked down and no others.
type lockedStewards map[string]bool

func (l lockedStewards) IsLockedDown(_ context.Context, stewardID string) (bool, error) {
	return l[stewardID], nil
}

// newReportOnlyControllerWithLockdown is newReportOnlyController with the
// controller's lockdown gate installed over checker. A nil checker installs no gate.
func newReportOnlyControllerWithLockdown(t *testing.T, checker controlplaneInterfaces.LockdownChecker) *reportOnlyController {
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

	c := &reportOnlyController{
		mgr: mgr, caPEM: caPEM, reg: registry.NewRegistry(), addr: ln.Addr().String(),
		heartbeats: make(chan *cpTypes.Heartbeat, 64),
		events:     make(chan *cpTypes.Event, 64),
		logs:       make(chan *transportpb.LogEntry, 64),
	}
	c.cp = grpcCP.New(grpcCP.ModeServer, grpcCP.WithLockdown(checker, nil))
	require.NoError(t, c.cp.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "grpc_server": grpcSrv, "registry": c.reg,
	}))
	require.NoError(t, c.cp.Start(context.Background()))
	transportpb.RegisterStewardTransportServer(grpcSrv, &reportOnlyTransport{StewardTransportServer: c.cp.ServerHandler(), ctl: c})
	go func() { _ = grpcSrv.Serve(ln) }()
	t.Cleanup(grpcSrv.Stop)

	require.NoError(t, c.cp.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *cpTypes.Heartbeat) error {
		c.heartbeats <- hb
		return nil
	}))
	require.NoError(t, c.cp.SubscribeEvents(context.Background(), nil, func(_ context.Context, e *cpTypes.Event) error {
		c.events <- e
		return nil
	}))
	return c
}

// clientCertManager issues the steward's client certificate into a fresh store
// signed by the controller's CA, as an enrolled steward holds one.
func (c *reportOnlyController) clientCertManager(t *testing.T, stewardID string) *cert.Manager {
	t.Helper()
	_, err := c.mgr.GenerateClientCertificate(&cert.ClientCertConfig{CommonName: stewardID, ClientID: stewardID, ValidityDays: 30})
	require.NoError(t, err)
	return c.mgr
}

func (c *reportOnlyController) waitConnected(t *testing.T, stewardID string) {
	t.Helper()
	require.Eventually(t, func() bool { _, ok := c.reg.Get(stewardID); return ok }, 10*time.Second, 20*time.Millisecond)
}

type staticDNACollector struct {
	attrs map[string]string
}

func (s *staticDNACollector) CollectAttributes(context.Context) (map[string]string, error) {
	return s.attrs, nil
}
func (s *staticDNACollector) CollectFragments(context.Context) []*commonpb.Fragment {
	f, err := dna.NewFragment("host:os", "test", dna.MapState(map[string]interface{}{"name": s.attrs["host.os"]}))
	if err != nil {
		return nil
	}
	return []*commonpb.Fragment{f}
}

func newReportOnlyClient(t *testing.T, ctl *reportOnlyController, mutate func(*TransportConfig)) *TransportClient {
	t.Helper()
	cfg := &TransportConfig{
		ReportOnly:        true,
		ControllerURL:     ctl.addr,
		CACertPEM:         string(ctl.caPEM),
		CertManager:       ctl.clientCertManager(t, reportOnlyStewardID),
		CertStoreDir:      t.TempDir(),
		HeartbeatInterval: 50 * time.Millisecond,
		DNACollector:      &staticDNACollector{attrs: map[string]string{"host.os": "test-os", "host.name": "test-host"}},
		Logger:            newTestLogger(t),
	}
	if mutate != nil {
		mutate(cfg)
	}
	c, err := NewTransportClient(cfg)
	require.NoError(t, err)
	c.heartbeatJitter = time.Millisecond
	c.SetStewardID(reportOnlyStewardID)
	c.SetTenantID("tenant-report-only")
	require.NoError(t, c.Connect(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Disconnect(ctx)
	})
	ctl.waitConnected(t, reportOnlyStewardID)
	return c
}

func unknownKindControlMessage() *transportpb.ControlMessage {
	msg := &transportpb.ControlMessage{}
	unknown := protowire.AppendTag(nil, 99, protowire.BytesType)
	msg.ProtoReflect().SetUnknown(protowire.AppendBytes(unknown, []byte("future-kind")))
	return msg
}

func (c *reportOnlyController) rawSend(t *testing.T, msg *transportpb.ControlMessage) {
	t.Helper()
	conn, ok := c.reg.Get(reportOnlyStewardID)
	require.True(t, ok)
	require.NoError(t, conn.Send(msg))
}

func TestReportOnly_EnforcesNothingInbound_HeartbeatCarriesReasons(t *testing.T) {
	ctl := newReportOnlyController(t)
	c := newReportOnlyClient(t, ctl, nil)
	c.SetHealthReason("tamper", "tamper.logs_cleared", "local log files were cleared")

	// One message of every ControlMessage payload kind: commands (including
	// sync_config and sync_dna), event, heartbeat, response, and an unknown kind.
	for i, typ := range []cpTypes.CommandType{
		cpTypes.CommandSyncConfig, cpTypes.CommandSyncDNA, cpTypes.CommandExecuteScript,
		cpTypes.CommandPushSigningCert, cpTypes.CommandReconnect,
	} {
		require.NoError(t, ctl.cp.SendCommand(context.Background(), &cpTypes.SignedCommand{Command: cpTypes.Command{
			ID: "cmd-" + string(rune('a'+i)), Type: typ, StewardID: reportOnlyStewardID, Timestamp: time.Now()}}))
	}
	ctl.rawSend(t, &transportpb.ControlMessage{Payload: &transportpb.ControlMessage_Event{Event: &transportpb.Event{Id: "e1"}}})
	ctl.rawSend(t, &transportpb.ControlMessage{Payload: &transportpb.ControlMessage_Heartbeat{Heartbeat: &transportpb.Heartbeat{StewardId: reportOnlyStewardID}}})
	ctl.rawSend(t, &transportpb.ControlMessage{Payload: &transportpb.ControlMessage_Response{Response: &transportpb.Response{CommandId: "x"}}})
	ctl.rawSend(t, unknownKindControlMessage())

	require.Eventually(t, func() bool { return c.InboundDropped() == 9 }, 10*time.Second, 20*time.Millisecond,
		"every inbound payload must be dropped and counted")
	assert.EqualValues(t, 5, c.InboundDroppedKind("command"))
	assert.EqualValues(t, 1, c.InboundDroppedKind("event"))
	assert.EqualValues(t, 1, c.InboundDroppedKind("heartbeat"))
	assert.EqualValues(t, 1, c.InboundDroppedKind("response"))
	assert.EqualValues(t, 1, c.InboundDroppedKind("unknown"))

	assert.Nil(t, c.GetConfigExecutor(), "no config executor may exist on a report-only link")
	assert.Zero(t, ctl.syncConfigCalls.Load(), "the server must see no SyncConfig RPC from this steward")
	assert.Zero(t, ctl.fetchCalls.Load())
	assert.Zero(t, ctl.bulkCalls.Load())

	// The heartbeat still arrives, with status error and the reasons.
	var hb *cpTypes.Heartbeat
	require.Eventually(t, func() bool {
		select {
		case h := <-ctl.heartbeats:
			if len(h.Reasons) > 0 {
				hb = h
				return true
			}
		default:
		}
		return false
	}, 10*time.Second, 20*time.Millisecond)
	assert.Equal(t, cpTypes.StatusError, hb.Status)
	var codes []string
	for _, r := range hb.Reasons {
		codes = append(codes, r.Code)
	}
	assert.Contains(t, codes, "tamper.logs_cleared")
}

func TestReportOnly_StartsOnlyWhitelistedComponents(t *testing.T) {
	ctl := newReportOnlyController(t)
	c := newReportOnlyClient(t, ctl, nil)

	assert.Equal(t, []string{ReportOnlyComponentDNAInventory, ReportOnlyComponentEventEmitter, ReportOnlyComponentHeartbeat},
		c.ReportOnlyComponents(), "exactly the heartbeat, the out-only DNA inventory loop and the event emitter")
	assert.Nil(t, c.GetConfigExecutor())
	c.mu.RLock()
	assert.Nil(t, c.dataPlaneSession, "no data plane: nothing can be pulled")
	assert.Nil(t, c.commandHandler, "no command handler")
	c.mu.RUnlock()

	// Config, convergence and sync entry points refuse.
	_, _, err := c.GetConfiguration(context.Background(), nil)
	assert.ErrorIs(t, err, ErrReportOnly)
	assert.ErrorIs(t, c.syncConfigNow(context.Background(), "x", nil), ErrReportOnly)
	assert.NoError(t, c.TriggerConvergence(context.Background()))
	assert.Zero(t, ctl.syncConfigCalls.Load())
}

func TestReportOnly_OutOnlySharing_DNAAndLogsLeave_InboundIsNotApplied(t *testing.T) {
	ctl := newReportOnlyController(t)
	c := newReportOnlyClient(t, ctl, nil)

	var dnaEvent *cpTypes.Event
	require.Eventually(t, func() bool {
		select {
		case e := <-ctl.events:
			if e.Type == cpTypes.EventDNAChanged {
				dnaEvent = e
				return true
			}
		default:
		}
		return false
	}, 10*time.Second, 20*time.Millisecond, "the controller must receive DNA inventory")
	assert.NotEmpty(t, dnaEvent.Details["dna_hash"])

	require.True(t, c.EnqueueLog(&transportpb.LogEntry{Message: "tamper alarm raised", Level: transportpb.Severity_SEVERITY_WARNING}))
	select {
	case entry := <-ctl.logs:
		assert.Equal(t, "tamper alarm raised", entry.Message)
		assert.Equal(t, reportOnlyStewardID, entry.StewardId)
	case <-time.After(10 * time.Second):
		t.Fatal("the controller must receive the log entry")
	}

	// currentDNAHash is written by the DNA inventory loop under dnaMu; read it
	// under the same lock.
	c.dnaMu.RLock()
	hashBefore := c.currentDNAHash
	c.dnaMu.RUnlock()
	require.NoError(t, ctl.cp.SendCommand(context.Background(), &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID: "dna-back", Type: cpTypes.CommandSyncDNA, StewardID: reportOnlyStewardID, Timestamp: time.Now()}}))
	require.NoError(t, ctl.cp.SendCommand(context.Background(), &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID: "cfg-back", Type: cpTypes.CommandSyncConfig, StewardID: reportOnlyStewardID, Timestamp: time.Now()}}))
	require.Eventually(t, func() bool { return c.InboundDroppedKind("command") == 2 }, 10*time.Second, 20*time.Millisecond)
	c.dnaMu.RLock()
	hashAfter := c.currentDNAHash
	c.dnaMu.RUnlock()
	assert.Equal(t, hashBefore, hashAfter)
	assert.Nil(t, c.GetConfigExecutor())
	assert.Zero(t, ctl.syncConfigCalls.Load())
	assert.Zero(t, ctl.syncDNACalls.Load(), "no SyncDNA stream is opened in answer to a sync_dna command")
}

func TestReportOnly_QueueIsMemoryOnly_EvenWhenQueueDirIsSet(t *testing.T) {
	ctl := newReportOnlyController(t)
	queueDir := t.TempDir()
	c := newReportOnlyClient(t, ctl, func(cfg *TransportConfig) { cfg.QueueDir = queueDir })

	require.True(t, c.offlineQueue.Enqueue(&cpTypes.Event{ID: "e", Type: cpTypes.EventError, StewardID: reportOnlyStewardID, Timestamp: time.Now()}))
	assert.Equal(t, "", c.offlineQueue.config.Dir, "the queue has no directory: it is memory only")
	assert.NoDirExists(t, queueDir+"/queue")
	entries, err := readDirNames(queueDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "nothing may be written under the configured queue directory")
}

func TestReportOnly_TamperStateAndRepairReachTheirCallbacks(t *testing.T) {
	ctl := newReportOnlyController(t)
	c := newReportOnlyClient(t, ctl, nil)

	var mu sync.Mutex
	var tamper []bool
	var repairs []cpTypes.RepairRequest
	c.SetTamperStateHandler(func(locked bool) { mu.Lock(); tamper = append(tamper, locked); mu.Unlock() })
	c.SetRepairHandler(func(r cpTypes.RepairRequest) { mu.Lock(); repairs = append(repairs, r); mu.Unlock() })

	require.NoError(t, ctl.cp.SendTamperState(context.Background(), reportOnlyStewardID, true))
	require.NoError(t, ctl.cp.SendTamperState(context.Background(), reportOnlyStewardID, false))
	full := cpTypes.RepairRequest{RepairID: "rep-1", ApprovedLossCodes: []string{"logs.local"}, LossDigest: "d",
		ExpiresAtUnix: 1893456000, Signature: []byte("sig"), SignerChainPEM: []byte("chain")}
	require.NoError(t, ctl.cp.SendRepair(context.Background(), reportOnlyStewardID, full))
	require.NoError(t, ctl.cp.SendRepair(context.Background(), reportOnlyStewardID, cpTypes.RepairRequest{RepairID: "rep-2"}))

	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(tamper) == 2 && len(repairs) == 2 },
		10*time.Second, 20*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []bool{true, false}, tamper)
	assert.Equal(t, full, repairs[0])
	assert.Equal(t, "rep-2", repairs[1].RepairID)
	assert.True(t, c.IsReportOnly())
}

func TestReportOnly_RepairWithoutHandlerIsDroppedAndCounted(t *testing.T) {
	ctl := newReportOnlyController(t)
	c := newReportOnlyClient(t, ctl, nil)
	require.NoError(t, ctl.cp.SendRepair(context.Background(), reportOnlyStewardID, cpTypes.RepairRequest{RepairID: "r"}))
	require.Eventually(t, func() bool { return c.InboundDroppedKind("repair_request") == 1 }, 10*time.Second, 20*time.Millisecond)
}

func TestReportOnly_LockedCommandHandlerReceivesCommandAndPeerChain(t *testing.T) {
	// The controller attaches the signer chain only to a steward it has locked
	// down, and only operator-origin commands reach such a steward.
	ctl := newReportOnlyControllerWithLockdown(t, lockedStewards{reportOnlyStewardID: true})
	c := newReportOnlyClient(t, ctl, nil)

	type got struct {
		cmd   *cpTypes.SignedCommand
		chain []*x509.Certificate
	}
	received := make(chan got, 1)
	c.SetLockedCommandHandler(func(_ context.Context, cmd *cpTypes.SignedCommand, chain controlplaneInterfaces.PeerChain) error {
		received <- got{cmd: cmd, chain: chain()}
		return nil
	})
	signer := []byte("signer-chain")
	operatorCtx := controlplaneInterfaces.WithOperatorOrigin(context.Background(), "operator-1")
	require.NoError(t, ctl.cp.SendCommand(operatorCtx, &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID: "locked-1", Type: cpTypes.CommandExecuteScript, StewardID: reportOnlyStewardID, Timestamp: time.Now()},
		SignerChainPEM: signer}))
	select {
	case g := <-received:
		assert.Equal(t, "locked-1", g.cmd.Command.ID)
		assert.Equal(t, signer, g.cmd.SignerChainPEM)
		assert.Equal(t, signer, g.cmd.Command.SignerChainPEM)
		require.NotEmpty(t, g.chain)
		assert.Equal(t, "localhost", g.chain[0].Subject.CommonName)
	case <-time.After(10 * time.Second):
		t.Fatal("locked-trust handler did not receive the command")
	}
	assert.Zero(t, c.InboundDroppedKind("command"))
}

func TestReportOnly_CertificateRotationKeepsLinkConnected(t *testing.T) {
	ctl := newReportOnlyController(t)
	c := newReportOnlyClient(t, ctl, nil)
	require.True(t, c.ControlStreamConnected())

	// The renewer imports a new client certificate and re-dials on the same client.
	_, err := ctl.mgr.GenerateClientCertificate(&cert.ClientCertConfig{CommonName: reportOnlyStewardID, ClientID: reportOnlyStewardID, ValidityDays: 30})
	require.NoError(t, err)
	require.NoError(t, c.ReconnectWithNewCredentials(context.Background()))

	require.Eventually(t, c.ControlStreamConnected, 15*time.Second, 50*time.Millisecond)
	ctl.waitConnected(t, reportOnlyStewardID)
	assert.True(t, c.IsReportOnly())
	// A heartbeat still arrives after the re-dial.
	for len(ctl.heartbeats) > 0 {
		<-ctl.heartbeats
	}
	select {
	case hb := <-ctl.heartbeats:
		assert.Equal(t, cpTypes.StatusError, hb.Status)
	case <-time.After(10 * time.Second):
		t.Fatal("no heartbeat after the certificate rotation")
	}
}

// A normal client that receives TamperState{locked:true} switches to report-only
// at runtime; commands arriving afterwards are dropped (no handler installed).
func TestEnterReportOnly_OnTamperStateLocked_DropsLaterCommands(t *testing.T) {
	ctx := context.Background()
	bus := memory.NewBus()
	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() { _ = server.Stop(ctx) })
	mem := memory.New(memory.ModeClient)
	require.NoError(t, mem.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": "steward-normal"}))
	require.NoError(t, mem.Start(ctx))
	t.Cleanup(func() { _ = mem.Stop(ctx) })

	c, err := NewTransportClient(&TransportConfig{ControllerURL: "127.0.0.1:1", Logger: newTestLogger(t),
		DNACollector: &staticDNACollector{attrs: map[string]string{"host.os": "x"}}})
	require.NoError(t, err)
	c.SetStewardID("steward-normal")
	c.mu.Lock()
	c.controlPlane = mem
	c.mu.Unlock()
	c.installInboundHooks(mem)

	handled := make(chan string, 4)
	require.NoError(t, mem.SubscribeCommands(ctx, "steward-normal", func(_ context.Context, sc *cpTypes.SignedCommand) error {
		handled <- sc.Command.ID
		return nil
	}))

	send := func(id string) {
		require.NoError(t, server.SendCommand(ctx, &cpTypes.SignedCommand{Command: cpTypes.Command{
			ID: id, Type: cpTypes.CommandSyncConfig, StewardID: "steward-normal", Timestamp: time.Now()}}))
	}
	send("before")
	select {
	case id := <-handled:
		assert.Equal(t, "before", id)
	case <-time.After(5 * time.Second):
		t.Fatal("a normal client must run commands")
	}
	assert.False(t, c.IsReportOnly())

	require.NoError(t, server.SendTamperState(ctx, "steward-normal", true))
	assert.True(t, c.IsReportOnly(), "TamperState{locked:true} switches the client to report-only")
	assert.Equal(t, string(cpTypes.StatusError), c.heartbeatStatus())
	var codes []string
	for _, r := range c.HealthReasons() {
		codes = append(codes, r.Code)
	}
	assert.Contains(t, codes, ReasonTamperLocked)

	send("after")
	select {
	case id := <-handled:
		t.Fatalf("command %s ran after the switch to report-only", id)
	case <-time.After(300 * time.Millisecond):
	}
	assert.EqualValues(t, 1, c.InboundDroppedKind("command"))
}

// recordingSession counts ReceiveConfig calls and answers each with err.
type lockdownSession struct {
	testDataPlaneSession
	calls atomic.Int64
	err   error
}

func (s *lockdownSession) ReceiveConfig(context.Context) (*dpTypes.ConfigTransfer, error) {
	s.calls.Add(1)
	return nil, s.err
}

func TestHandleLockedDown_SyncConfigRefusal_EntersReportOnlyAndDoesNotRetry(t *testing.T) {
	sess := &lockdownSession{testDataPlaneSession: *newTestSession(), err: controlplaneInterfaces.NewLockedDownError()}
	c := newMinimalClientWithCP(t, sess, nil, newEventCapture(), "steward-locked-pull", "t")

	_, _, err := c.GetConfiguration(context.Background(), nil)
	require.Error(t, err)
	require.True(t, c.IsReportOnly())
	var codes []string
	for _, r := range c.HealthReasons() {
		codes = append(codes, r.Code)
	}
	assert.Contains(t, codes, ReasonControllerLockedDown)

	for i := 0; i < 5; i++ {
		_, _, err := c.GetConfiguration(context.Background(), nil)
		assert.ErrorIs(t, err, ErrReportOnly)
	}
	assert.EqualValues(t, 1, sess.calls.Load(), "a locked-down controller must not be pulled from again")
}

func TestHandleLockedDown_FetchModuleBundleRefusal_FromRealServer(t *testing.T) {
	ctl := newReportOnlyController(t)
	ctl.lockdownPulls.Store(true)

	prov := grpcCP.New(grpcCP.ModeClient)
	mgr := ctl.clientCertManager(t, reportOnlyStewardID)
	tlsCfg, err := mgr.CreateOnDemandClientTLSConfig(ctl.caPEM, tls.VersionTLS13)
	require.NoError(t, err)
	tlsCfg.NextProtos = []string{quictransport.ALPNProtocol}
	require.NoError(t, prov.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": ctl.addr, "tls_config": tlsCfg, "steward_id": reportOnlyStewardID,
	}))
	require.NoError(t, prov.Start(context.Background()))
	t.Cleanup(func() { _ = prov.Stop(context.Background()) })

	c, err := NewTransportClient(&TransportConfig{ControllerURL: ctl.addr, Logger: newTestLogger(t)})
	require.NoError(t, err)
	c.mu.Lock()
	c.controlPlane = prov
	c.mu.Unlock()

	inst, ok := c.newModuleInstaller().(*install.Installer)
	require.True(t, ok)
	stream, err := inst.Client.FetchModuleBundle(context.Background(), &transportpb.FetchModuleBundleRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	require.Error(t, err)
	assert.True(t, controlplaneInterfaces.IsLockedDown(err))
	assert.True(t, c.IsReportOnly(), "the typed lockdown code on a module pull enters report-only")
	assert.EqualValues(t, 1, ctl.fetchCalls.Load())
}

func TestHandleLockedDown_BulkTransferRefusal_AndOrdinaryErrorsAreIgnored(t *testing.T) {
	c, err := NewTransportClient(&TransportConfig{ControllerURL: "127.0.0.1:1", Logger: newTestLogger(t)})
	require.NoError(t, err)

	assert.False(t, c.HandleLockedDown(status.Error(codes.Unavailable, "down")))
	assert.False(t, c.HandleLockedDown(status.Error(codes.FailedPrecondition, "other precondition")))
	assert.False(t, c.HandleLockedDown(nil))
	assert.False(t, c.IsReportOnly())

	wrapped := status.Convert(controlplaneInterfaces.NewLockedDownError()).Err()
	assert.True(t, c.HandleLockedDown(wrapped))
	assert.True(t, c.IsReportOnly())
}

func TestReportOnly_NormalClientBehaviourUnchanged(t *testing.T) {
	c, err := NewTransportClient(&TransportConfig{ControllerURL: "127.0.0.1:1", Logger: newTestLogger(t)})
	require.NoError(t, err)
	assert.False(t, c.IsReportOnly())
	assert.Equal(t, string(cpTypes.StatusHealthy), c.heartbeatStatus())
	assert.Empty(t, c.ReportOnlyComponents())
	// A normal client still builds its offline queue from QueueDir.
	dir := t.TempDir()
	n, err := NewTransportClient(&TransportConfig{ControllerURL: "127.0.0.1:1", Logger: newTestLogger(t), QueueDir: dir})
	require.NoError(t, err)
	assert.NotEqual(t, "", n.offlineQueue.queueFilePath())
}

func TestReportOnly_PEMHelperSanity(t *testing.T) {
	// The harness issues a parseable CA; a report-only link needs it as its anchor.
	ctl := newReportOnlyController(t)
	block, _ := pem.Decode(ctl.caPEM)
	require.NotNil(t, block)
	_, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
}

func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
