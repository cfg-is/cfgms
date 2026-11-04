// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

func TestSendTamperStateAndRepair_RoundTripToClientHooks(t *testing.T) {
	bus := memory.NewBus()
	server := startServer(t, bus)
	client := startClient(t, bus, "steward-signals")

	var tamper []bool
	var repairs []types.RepairRequest
	var dropped []string
	client.SetInboundHooks(interfaces.InboundHooks{
		OnTamperState: func(locked bool) { tamper = append(tamper, locked) },
		OnRepair:      func(r types.RepairRequest) { repairs = append(repairs, r) },
		OnDropped:     func(kind string) { dropped = append(dropped, kind) },
	})

	ctx := context.Background()
	require.NoError(t, server.SendTamperState(ctx, "steward-signals", true))
	require.NoError(t, server.SendTamperState(ctx, "steward-signals", false))
	req := types.RepairRequest{RepairID: "r1", ApprovedLossCodes: []string{"a"}, LossDigest: "d",
		ExpiresAtUnix: 7, Signature: []byte("s"), SignerChainPEM: []byte("c")}
	require.NoError(t, server.SendRepair(ctx, "steward-signals", req))
	require.NoError(t, server.SendRepair(ctx, "steward-signals", types.RepairRequest{}))

	assert.Equal(t, []bool{true, false}, tamper)
	require.Len(t, repairs, 1)
	assert.Equal(t, req, repairs[0])
	assert.Equal(t, []string{"repair_request"}, dropped, "a request without a repair id is ignored")
}

func TestSendSignals_UnknownStewardAndWrongMode(t *testing.T) {
	bus := memory.NewBus()
	server := startServer(t, bus)
	client := startClient(t, bus, "steward-signals-2")

	err := server.SendTamperState(context.Background(), "ghost", true)
	require.ErrorIs(t, err, interfaces.ErrStewardNotConnected)
	err = server.SendRepair(context.Background(), "ghost", types.RepairRequest{RepairID: "r"})
	require.ErrorIs(t, err, interfaces.ErrStewardNotConnected)

	require.Error(t, client.SendTamperState(context.Background(), "steward-signals-2", true))
	require.Error(t, client.SendRepair(context.Background(), "steward-signals-2", types.RepairRequest{RepairID: "r"}))
}

func TestReportOnly_CommandsGoOnlyToLockedHandler(t *testing.T) {
	bus := memory.NewBus()
	server := startServer(t, bus)
	client := startClient(t, bus, "steward-signals-3")

	subscribed := make(chan *types.SignedCommand, 2)
	require.NoError(t, client.SubscribeCommands(context.Background(), "steward-signals-3",
		func(_ context.Context, sc *types.SignedCommand) error { subscribed <- sc; return nil }))

	dropped := make(chan string, 4)
	locked := make(chan *types.SignedCommand, 2)
	hooks := interfaces.InboundHooks{OnDropped: func(kind string) { dropped <- kind }}
	client.SetInboundHooks(hooks)
	client.SetReportOnly(true)

	cmd := &types.SignedCommand{Command: types.Command{ID: "c1", Type: types.CommandSyncConfig,
		StewardID: "steward-signals-3", Timestamp: time.Now()}}
	require.NoError(t, server.SendCommand(context.Background(), cmd))
	assert.Equal(t, "command", <-dropped, "no locked-trust handler: the command is dropped and counted")

	hooks.OnCommand = func(_ context.Context, sc *types.SignedCommand, _ interfaces.PeerChain) error {
		locked <- sc
		return nil
	}
	client.SetInboundHooks(hooks)
	cmd2 := &types.SignedCommand{Command: types.Command{ID: "c2", Type: types.CommandExecuteScript,
		StewardID: "steward-signals-3", Timestamp: time.Now()}}
	require.NoError(t, server.SendCommand(context.Background(), cmd2))
	select {
	case got := <-locked:
		assert.Equal(t, "c2", got.Command.ID)
	case <-time.After(5 * time.Second):
		t.Fatal("locked-trust handler did not receive the command")
	}
	assert.Empty(t, subscribed, "the normal subscription must not see commands while report-only")
}
