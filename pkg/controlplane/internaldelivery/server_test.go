// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package internaldelivery

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	deliverypb "github.com/cfgis/cfgms/api/proto/clusterdelivery"
	grpcconvert "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// fakeSender implements registry.MessageSender. It is a role fake for a
// steward's transport stream (the registry only needs somewhere to write
// to), not a stand-in for any CFGMS business component under test.
type fakeSender struct{}

func (fakeSender) SendMsg(_ interface{}) error { return nil }

// newConnectedMemoryPair starts a real memory.Provider server/client pair on
// a fresh bus, with the client subscribed to receive commands for stewardID.
// Returns the server-side provider (used as the local control plane) and a
// channel the test can read delivered commands from.
func newConnectedMemoryPair(t *testing.T, stewardID string) (*memory.Provider, chan *controlplaneTypes.SignedCommand) {
	t.Helper()
	ctx := context.Background()
	bus := memory.NewBus()

	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(stopCtx)
	})

	client := memory.New(memory.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": stewardID}))
	require.NoError(t, client.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Stop(stopCtx)
	})

	received := make(chan *controlplaneTypes.SignedCommand, 4)
	require.NoError(t, client.SubscribeCommands(ctx, stewardID, func(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
		received <- cmd
		return nil
	}))

	return server, received
}

func newTestRequest(stewardID, commandID string) *deliverypb.DeliverCommandRequest {
	cmd := &controlplaneTypes.SignedCommand{
		Command: controlplaneTypes.Command{
			ID:        commandID,
			Type:      controlplaneTypes.CommandSyncConfig,
			StewardID: stewardID,
			Timestamp: time.Now(),
		},
	}
	return &deliverypb.DeliverCommandRequest{
		StewardId: stewardID,
		Command:   grpcconvert.SignedCommandToProto(cmd),
	}
}

func TestServer_DeliverCommand_DeliversToLocallyConnectedSteward(t *testing.T) {
	localCP, received := newConnectedMemoryPair(t, "steward-1")

	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(&registry.StewardConnection{
		StewardID:   "steward-1",
		Sender:      fakeSender{},
		ConnectedAt: time.Now(),
	}))

	srv := NewServer(reg, localCP, logging.NewNoopLogger())
	resp, err := srv.DeliverCommand(context.Background(), newTestRequest("steward-1", "cmd-1"))
	require.NoError(t, err)
	assert.True(t, resp.GetDelivered())
	assert.False(t, resp.GetNotConnected())

	select {
	case got := <-received:
		assert.Equal(t, "cmd-1", got.Command.ID)
	case <-time.After(2 * time.Second):
		t.Fatal("locally connected steward never received the forwarded command")
	}
}

func TestServer_DeliverCommand_NotConnectedWhenAbsentFromLocalRegistry(t *testing.T) {
	localCP, _ := newConnectedMemoryPair(t, "steward-1")

	reg := registry.NewRegistry() // steward-1 never registered here

	srv := NewServer(reg, localCP, logging.NewNoopLogger())
	resp, err := srv.DeliverCommand(context.Background(), newTestRequest("steward-1", "cmd-1"))
	require.NoError(t, err)
	assert.False(t, resp.GetDelivered())
	assert.True(t, resp.GetNotConnected())
}

func TestServer_DeliverCommand_RejectsMismatchedStewardID(t *testing.T) {
	localCP, _ := newConnectedMemoryPair(t, "steward-1")

	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(&registry.StewardConnection{
		StewardID:   "steward-1",
		Sender:      fakeSender{},
		ConnectedAt: time.Now(),
	}))

	srv := NewServer(reg, localCP, logging.NewNoopLogger())

	// The request targets steward-1 but the embedded command envelope is
	// addressed to a different steward — a peer must never be able to smuggle
	// delivery to a steward other than the one it named in the request.
	req := newTestRequest("steward-1", "cmd-1")
	req.Command.StewardId = "steward-2"

	_, err := srv.DeliverCommand(context.Background(), req)
	require.Error(t, err)
}

func TestServer_DeliverCommand_RejectsEmptyStewardID(t *testing.T) {
	localCP, _ := newConnectedMemoryPair(t, "steward-1")
	srv := NewServer(registry.NewRegistry(), localCP, logging.NewNoopLogger())

	req := newTestRequest("steward-1", "cmd-1")
	req.StewardId = ""

	_, err := srv.DeliverCommand(context.Background(), req)
	require.Error(t, err)
}

func TestServer_DeliverCommand_RejectsNilCommand(t *testing.T) {
	localCP, _ := newConnectedMemoryPair(t, "steward-1")
	srv := NewServer(registry.NewRegistry(), localCP, logging.NewNoopLogger())

	_, err := srv.DeliverCommand(context.Background(), &deliverypb.DeliverCommandRequest{StewardId: "steward-1"})
	require.Error(t, err)
}
