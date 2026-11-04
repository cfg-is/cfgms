// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// inboundRecorder collects what the receive switch hands to each callback.
type inboundRecorder struct {
	mu       sync.Mutex
	tamper   []bool
	repairs  []types.RepairRequest
	commands []*types.SignedCommand
	chains   [][]*x509.Certificate
	dropped  []string
	signal   chan struct{}
}

func newInboundRecorder() *inboundRecorder {
	return &inboundRecorder{signal: make(chan struct{}, 64)}
}

func (r *inboundRecorder) hooks() interfaces.InboundHooks {
	return interfaces.InboundHooks{
		OnTamperState: func(locked bool) {
			r.mu.Lock()
			r.tamper = append(r.tamper, locked)
			r.mu.Unlock()
			r.signal <- struct{}{}
		},
		OnRepair: func(req types.RepairRequest) {
			r.mu.Lock()
			r.repairs = append(r.repairs, req)
			r.mu.Unlock()
			r.signal <- struct{}{}
		},
		OnCommand: func(_ context.Context, cmd *types.SignedCommand, chain interfaces.PeerChain) error {
			r.mu.Lock()
			r.commands = append(r.commands, cmd)
			r.chains = append(r.chains, chain())
			r.mu.Unlock()
			r.signal <- struct{}{}
			return nil
		},
		OnDropped: func(kind string) {
			r.mu.Lock()
			r.dropped = append(r.dropped, kind)
			r.mu.Unlock()
			r.signal <- struct{}{}
		},
	}
}

// wait blocks until n callbacks have fired.
func (r *inboundRecorder) wait(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-r.signal:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for callback %d of %d", i+1, n)
		}
	}
}

func (r *inboundRecorder) snapshot() (tamper []bool, repairs []types.RepairRequest, dropped []string, commands int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.tamper...), append([]types.RepairRequest(nil), r.repairs...),
		append([]string(nil), r.dropped...), len(r.commands)
}

// connectInboundClient connects a client provider (with opts) to the server.
func connectInboundClient(t *testing.T, tc *testCA, reg registry.Registry, server *Provider, id string, opts ...option) *Provider {
	t.Helper()
	client := New(ModeClient, opts...)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": server.ListenAddr(), "tls_config": tc.clientTLSConfig(t, id), "steward_id": id,
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })
	require.Eventually(t, func() bool { _, ok := reg.Get(id); return ok }, 5*time.Second, 10*time.Millisecond)
	return client
}

func newInboundServer(t *testing.T, tc *testCA) (*Provider, registry.Registry) {
	t.Helper()
	reg := registry.NewRegistry()
	server := New(ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": tc.serverTLSConfig(t), "registry": reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)
	return server, reg
}

func rawSend(t *testing.T, reg registry.Registry, id string, msg *transportpb.ControlMessage) {
	t.Helper()
	conn, ok := reg.Get(id)
	require.True(t, ok)
	require.NoError(t, conn.Send(msg))
}

// unknownKindMessage is a ControlMessage whose only content is a payload field
// number this build does not define.
func unknownKindMessage() *transportpb.ControlMessage {
	msg := &transportpb.ControlMessage{}
	unknown := protowire.AppendTag(nil, 99, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, []byte("not-a-known-kind"))
	msg.ProtoReflect().SetUnknown(unknown)
	return msg
}

// The unknown-payload drop is asserted at the receive switch in
// clientReceiveLoop: one message of every ControlMessage payload kind reaches a
// report-only client, and none is handled.
func TestInbound_ReceiveSwitch_ReportOnlyDropsEveryOtherKind(t *testing.T) {
	const id = "steward-inbound-switch"
	tc := newTestCA(t)
	server, reg := newInboundServer(t, tc)
	client := connectInboundClient(t, tc, reg, server, id)

	rec := newInboundRecorder()
	hooks := rec.hooks()
	hooks.OnCommand = nil // no locked-trust handler installed
	client.SetInboundHooks(hooks)
	client.SetReportOnly(true)

	handled := make(chan *types.SignedCommand, 4)
	require.NoError(t, client.SubscribeCommands(context.Background(), id, func(_ context.Context, sc *types.SignedCommand) error {
		handled <- sc
		return nil
	}))

	require.NoError(t, server.SendCommand(context.Background(), &types.SignedCommand{Command: types.Command{
		ID: "c-sync", Type: types.CommandSyncConfig, StewardID: id, Timestamp: time.Now()}}))
	require.NoError(t, server.SendCommand(context.Background(), &types.SignedCommand{Command: types.Command{
		ID: "c-dna", Type: types.CommandSyncDNA, StewardID: id, Timestamp: time.Now()}}))
	rawSend(t, reg, id, &transportpb.ControlMessage{Payload: &transportpb.ControlMessage_Event{Event: &transportpb.Event{Id: "e"}}})
	rawSend(t, reg, id, &transportpb.ControlMessage{Payload: &transportpb.ControlMessage_Heartbeat{Heartbeat: &transportpb.Heartbeat{StewardId: id}}})
	rawSend(t, reg, id, &transportpb.ControlMessage{Payload: &transportpb.ControlMessage_Response{Response: &transportpb.Response{CommandId: "c"}}})
	rawSend(t, reg, id, unknownKindMessage())

	rec.wait(t, 6)
	_, _, dropped, commands := rec.snapshot()
	assert.ElementsMatch(t, []string{"command", "command", "event", "heartbeat", "response", "unknown"}, dropped)
	assert.Zero(t, commands, "no command may reach a handler while report-only")
	assert.EqualValues(t, 6, client.InboundDropped())
	select {
	case sc := <-handled:
		t.Fatalf("subscribed command handler ran for %s while report-only", sc.Command.ID)
	default:
	}
}

// A normal client still delivers commands to the subscribed handler.
func TestInbound_ReceiveSwitch_NormalClientDeliversCommands(t *testing.T) {
	const id = "steward-inbound-normal"
	tc := newTestCA(t)
	server, reg := newInboundServer(t, tc)
	client := connectInboundClient(t, tc, reg, server, id)

	handled := make(chan *types.SignedCommand, 1)
	require.NoError(t, client.SubscribeCommands(context.Background(), id, func(_ context.Context, sc *types.SignedCommand) error {
		handled <- sc
		return nil
	}))
	require.NoError(t, server.SendCommand(context.Background(), &types.SignedCommand{Command: types.Command{
		ID: "c1", Type: types.CommandSyncConfig, StewardID: id, Timestamp: time.Now()}}))
	select {
	case sc := <-handled:
		assert.Equal(t, "c1", sc.Command.ID)
	case <-time.After(5 * time.Second):
		t.Fatal("normal client did not deliver the command")
	}
}

// With a locked-trust handler installed, a report-only client hands it the
// command together with the peer chain of the stream it arrived on, and after
// a reconnect to a different server the chain is the new server's.
func TestInbound_CommandCallback_ReceivesPeerChainOfCurrentStream(t *testing.T) {
	const id = "steward-inbound-chain"
	tc := newTestCA(t)
	reg := registry.NewRegistry()
	server1 := New(ModeServer)
	require.NoError(t, server1.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": tc.serverTLSConfig(t), "registry": reg,
	}))
	require.NoError(t, server1.Start(context.Background()))

	client := newTestClient(t, server1.ListenAddr(), tc.clientTLSConfig(t, id), id)
	rec := newInboundRecorder()
	client.SetInboundHooks(rec.hooks())
	client.SetReportOnly(true)
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })
	require.Eventually(t, func() bool { _, ok := reg.Get(id); return ok }, 5*time.Second, 10*time.Millisecond)

	send := func(srv *Provider, cmdID string) {
		require.NoError(t, srv.SendCommand(context.Background(), &types.SignedCommand{Command: types.Command{
			ID: cmdID, Type: types.CommandExecuteScript, StewardID: id, Timestamp: time.Now()}}))
		rec.wait(t, 1)
	}
	send(server1, "first")

	server1.ForceStop()
	server2 := restartServerAndRepoint(t, client, tc, reg)
	require.Eventually(t, func() bool { return GetState(client) == StateConnected }, 30*time.Second, 100*time.Millisecond)
	require.Eventually(t, func() bool { _, ok := reg.Get(id); return ok }, 5*time.Second, 10*time.Millisecond)
	send(server2, "second")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Len(t, rec.chains, 2)
	require.NotEmpty(t, rec.chains[0])
	require.NotEmpty(t, rec.chains[1])
	assert.NotEqual(t, rec.chains[0][0].SerialNumber, rec.chains[1][0].SerialNumber,
		"after a reconnect to a different server the callback must see that server's chain")
	assert.Equal(t, "localhost", rec.chains[1][0].Subject.CommonName)
}

func TestInbound_TamperState_LockedAlwaysHonored_UnlockedNeedsAnchor(t *testing.T) {
	const id = "steward-inbound-tamper"
	tc := newTestCA(t)
	server, reg := newInboundServer(t, tc)

	t.Run("anchor verified honors both", func(t *testing.T) {
		client := connectInboundClient(t, tc, reg, server, id)
		rec := newInboundRecorder()
		client.SetInboundHooks(rec.hooks())
		require.NoError(t, server.SendTamperState(context.Background(), id, true))
		require.NoError(t, server.SendTamperState(context.Background(), id, false))
		rec.wait(t, 2)
		tamper, _, dropped, _ := rec.snapshot()
		assert.Equal(t, []bool{true, false}, tamper)
		assert.Empty(t, dropped)
	})

	t.Run("failed anchor check ignores unlocked, honors locked", func(t *testing.T) {
		const id2 = "steward-inbound-tamper-2"
		// The handshake trusts the CA, but the anchor check is given a different
		// pool: the session connects and then fails the anchor check.
		otherCA := newTestCA(t)
		pool := x509.NewCertPool()
		require.True(t, pool.AppendCertsFromPEM(otherCA.caPEM))
		client := connectInboundClient(t, tc, reg, server, id2, WithTrustAnchor(pool))
		rec := newInboundRecorder()
		client.SetInboundHooks(rec.hooks())
		require.NoError(t, server.SendTamperState(context.Background(), id2, false))
		rec.wait(t, 1) // dropped
		require.NoError(t, server.SendTamperState(context.Background(), id2, true))
		rec.wait(t, 1)
		tamper, _, dropped, _ := rec.snapshot()
		assert.Equal(t, []bool{true}, tamper, "locked:true is honored from a session that failed the anchor check")
		assert.Equal(t, []string{"tamper_state"}, dropped, "locked:false from that session is ignored")
	})
}

func TestInbound_TamperState_MalformedIsIgnored(t *testing.T) {
	const id = "steward-inbound-tamper-bad"
	tc := newTestCA(t)
	server, reg := newInboundServer(t, tc)
	client := connectInboundClient(t, tc, reg, server, id)
	rec := newInboundRecorder()
	client.SetInboundHooks(rec.hooks())

	// An extra field makes the fixed-shape signal malformed.
	bad := &transportpb.TamperState{Locked: true}
	bad.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 7, protowire.VarintType), 1))
	rawSend(t, reg, id, &transportpb.ControlMessage{Payload: &transportpb.ControlMessage_TamperState{TamperState: bad}})
	rawSend(t, reg, id, &transportpb.ControlMessage{Payload: &transportpb.ControlMessage_TamperState{TamperState: nil}})
	rec.wait(t, 1)

	tamper, _, dropped, _ := rec.snapshot()
	assert.NotContains(t, tamper, true, "a malformed TamperState must never lock")
	assert.Contains(t, dropped, "tamper_state")
}

func TestInbound_RepairRequest_DeliveredOnlyOnAnchoredSession(t *testing.T) {
	const id = "steward-inbound-repair"
	tc := newTestCA(t)
	server, reg := newInboundServer(t, tc)

	full := types.RepairRequest{
		RepairID: "repair-1", ApprovedLossCodes: []string{"logs.local", "cache.config"}, LossDigest: "digest-1",
		ExpiresAtUnix: 1893456000, Signature: []byte("sig"), SignerChainPEM: []byte("chain"),
	}

	t.Run("with loss approval and without", func(t *testing.T) {
		client := connectInboundClient(t, tc, reg, server, id)
		rec := newInboundRecorder()
		client.SetInboundHooks(rec.hooks())
		require.NoError(t, server.SendRepair(context.Background(), id, full))
		noLoss := types.RepairRequest{RepairID: "repair-2", Signature: []byte("s2")}
		require.NoError(t, server.SendRepair(context.Background(), id, noLoss))
		rec.wait(t, 2)
		_, repairs, dropped, _ := rec.snapshot()
		require.Len(t, repairs, 2)
		assert.Equal(t, full, repairs[0])
		assert.Equal(t, "repair-2", repairs[1].RepairID)
		assert.Empty(t, repairs[1].ApprovedLossCodes)
		assert.Empty(t, dropped)
	})

	t.Run("ignored on a session that failed the anchor check", func(t *testing.T) {
		const id2 = "steward-inbound-repair-2"
		otherCA := newTestCA(t)
		pool := x509.NewCertPool()
		require.True(t, pool.AppendCertsFromPEM(otherCA.caPEM))
		client := connectInboundClient(t, tc, reg, server, id2, WithTrustAnchor(pool))
		rec := newInboundRecorder()
		client.SetInboundHooks(rec.hooks())
		require.NoError(t, server.SendRepair(context.Background(), id2, full))
		rec.wait(t, 1)
		_, repairs, dropped, _ := rec.snapshot()
		assert.Empty(t, repairs)
		assert.Equal(t, []string{"repair_request"}, dropped)
	})

	t.Run("malformed or missing-field requests are ignored", func(t *testing.T) {
		const id3 = "steward-inbound-repair-3"
		client := connectInboundClient(t, tc, reg, server, id3)
		rec := newInboundRecorder()
		client.SetInboundHooks(rec.hooks())

		unknownField := &transportpb.RepairRequest{RepairId: "r"}
		unknownField.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 40, protowire.VarintType), 1))
		manyCodes := &transportpb.RepairRequest{RepairId: "r"}
		for i := 0; i < maxApprovedLossCodes+1; i++ {
			manyCodes.ApprovedLossCodes = append(manyCodes.ApprovedLossCodes, "code")
		}
		bad := []*transportpb.RepairRequest{
			{}, // missing repair id
			{RepairId: "r", ApprovedLossCodes: []string{""}},
			unknownField,
			manyCodes,
			{RepairId: string(make([]byte, maxRepairIDLen+1))},
		}
		for _, rr := range bad {
			rawSend(t, reg, id3, &transportpb.ControlMessage{Payload: &transportpb.ControlMessage_RepairRequest{RepairRequest: rr}})
		}
		rec.wait(t, len(bad))
		_, repairs, dropped, _ := rec.snapshot()
		assert.Empty(t, repairs, "a malformed request must never reach the repair callback")
		assert.Len(t, dropped, len(bad))
	})
}

func TestInbound_SignalsOnlyInServerMode_AndNeedConnectedSteward(t *testing.T) {
	tc := newTestCA(t)
	server, _ := newInboundServer(t, tc)
	err := server.SendTamperState(context.Background(), "nobody", true)
	require.ErrorIs(t, err, interfaces.ErrStewardNotConnected)
	err = server.SendRepair(context.Background(), "nobody", types.RepairRequest{RepairID: "r"})
	require.ErrorIs(t, err, interfaces.ErrStewardNotConnected)

	client := New(ModeClient)
	require.Error(t, client.SendTamperState(context.Background(), "x", true))
	require.Error(t, client.SendRepair(context.Background(), "x", types.RepairRequest{}))
}

func TestConvert_CommandSignerChain_RoundTrips(t *testing.T) {
	sc := &types.SignedCommand{Command: types.Command{
		ID: "c", Type: types.CommandExecuteScript, StewardID: "s", Timestamp: time.Now(),
		SignerChainPEM: []byte("-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n"),
	}}
	pb := signedCommandToProto(sc)
	assert.Equal(t, sc.Command.SignerChainPEM, pb.GetSignerChainPem())
	back := signedCommandFromProto(pb)
	require.NotNil(t, back)
	assert.Equal(t, sc.Command.SignerChainPEM, back.Command.SignerChainPEM)
}

func TestConvert_RepairRequest_RoundTrips(t *testing.T) {
	req := types.RepairRequest{
		RepairID: "r1", ApprovedLossCodes: []string{"a", "b"}, LossDigest: "d", ExpiresAtUnix: 42,
		Signature: []byte{1, 2, 3}, SignerChainPEM: []byte("pem"),
	}
	assert.Equal(t, req, RepairRequestFromProto(RepairRequestToProto(req)))
}
