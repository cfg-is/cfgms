// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// peerSupportSender is a connection sender for a registry entry no test writes to.
type peerSupportSender struct{}

func (peerSupportSender) SendMsg(interface{}) error { return nil }

func allCommandTypeNumbers() []int32 {
	out := make([]int32, 0, 15)
	for n := int32(1); n <= 15; n++ {
		out = append(out, n)
	}
	return out
}

// newPeerSupportPublisher is a publisher over a real in-process control plane
// whose signing source is a real capability resolver. The steward's connection is
// registered and settled to state with cmdTypes. A nil cmdTypes registers no
// connection, so the steward has no state.
func newPeerSupportPublisher(t *testing.T, stewardID, state string, cmdTypes []int32) (*commands.Publisher, chan *controlplaneTypes.SignedCommand) {
	t.Helper()
	reg := registry.NewRegistry()
	if cmdTypes != nil {
		conn := &registry.StewardConnection{StewardID: stewardID, Sender: peerSupportSender{}, ConnectionID: "conn-1", ConnectedAt: time.Now()}
		require.NoError(t, reg.Register(conn))
		conn.SettleCapabilities(state, cmdTypes, []uint32{controlplaneTypes.SigningPayloadV1, controlplaneTypes.SigningPayloadV2})
	}
	resolver := commands.NewCapabilityResolver(reg, nil, logging.NewNoopLogger(), commands.WithCapabilityResolveWait(50*time.Millisecond))

	received := make(chan *controlplaneTypes.SignedCommand, 4)
	publisher := newDrainHookTestPublisherWithConfig(t, stewardID,
		func(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
			received <- cmd
			return nil
		},
		func(cfg *commands.Config) { cfg.SigningVersions = resolver })
	return publisher, received
}

func requireNothingReceived(t *testing.T, received chan *controlplaneTypes.SignedCommand) {
	t.Helper()
	select {
	case sc := <-received:
		t.Fatalf("no command expected, got %s", sc.Command.Type)
	case <-time.After(150 * time.Millisecond):
	}
}

// On a floor steward the hook sends nothing, returns nil, logs the Info event and
// no error, and does not retry.
func TestTransportAddressHook_OnConnect_FloorStewardIsSkippedQuietly(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")
	publisher, received := newPeerSupportPublisher(t, "steward-floor", registry.CapabilityFloor, controlplaneTypes.FloorProfile().CommandTypes)
	transport := &controllerconfig.TransportConfig{ListenAddr: "192.168.1.10:4433"}
	logger := &recordingLogger{}

	hook := service.NewTransportAddressHook(transport, publisher, logger)
	require.NoError(t, hook.OnConnect(context.Background(), "steward-floor"))

	requireNothingReceived(t, received)

	logger.mu.Lock()
	entries := append([]recordedLogEntry(nil), logger.entries...)
	logger.mu.Unlock()
	var infoEvents, errorsOrWarnings int
	for _, e := range entries {
		switch e.level {
		case "INFO":
			for i := 0; i+1 < len(e.fields); i += 2 {
				if e.fields[i] == "event" && e.fields[i+1] == "command_not_sent_peer_unsupported" {
					infoEvents++
				}
			}
		case "WARN", "ERROR", "FATAL":
			errorsOrWarnings++
		}
	}
	assert.Equal(t, 1, infoEvents, "one Info event per skipped connect; got log:\n%s", logger.allText())
	assert.Zero(t, errorsOrWarnings, "a skip is not an error or a warning; got log:\n%s", logger.allText())
	assert.NotContains(t, strings.ToLower(logger.allText()), "retry")

	// Nothing is pending: a second look after the connect finds no delayed send.
	time.Sleep(100 * time.Millisecond)
	requireNothingReceived(t, received)
}

func TestTransportAddressHook_OnConnect_CurrentStewardStillReceivesTheAdvertisement(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")
	publisher, received := newPeerSupportPublisher(t, "steward-cur", registry.CapabilityDeclared, allCommandTypeNumbers())
	transport := &controllerconfig.TransportConfig{ListenAddr: "192.168.1.10:4433"}

	hook := service.NewTransportAddressHook(transport, publisher, logging.NewNoopLogger())
	require.NoError(t, hook.OnConnect(context.Background(), "steward-cur"))

	select {
	case sc := <-received:
		assert.Equal(t, controlplaneTypes.CommandAdvertiseTransportAddress, sc.Command.Type)
	case <-time.After(2 * time.Second):
		t.Fatal("a current steward never received the advertise command")
	}
}

func newPeerSupportDrainFixture(t *testing.T, stewardID string, rows map[string]controlplaneTypes.CommandType) (business.CommandStore, business.StewardStore) {
	t.Helper()
	ctx := context.Background()
	commandStore, stewardStore := newDrainHookTestStores(t)
	require.NoError(t, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
		ID: stewardID, TenantID: "tenant-a", Status: business.StewardStatusActive,
	}))
	for id, cmdType := range rows {
		require.NoError(t, commandStore.CreateCommandRecord(ctx, &business.CommandRecord{
			ID: id, Type: string(cmdType), StewardID: stewardID, TenantID: "tenant-a",
			DeliveryStatus: business.DeliveryStatusPending,
		}))
	}
	return commandStore, stewardStore
}

// A pending row whose type a floor steward does not support ends terminal with
// the controller's detail, is never sent, and is not tried again on the next
// reconnect; a shared-type row for the same steward is still delivered.
func TestPendingDeliveryDrainHook_UnsupportedTypeEndsTerminal(t *testing.T) {
	ctx := context.Background()
	commandStore, stewardStore := newPeerSupportDrainFixture(t, "steward-floor", map[string]controlplaneTypes.CommandType{
		"cmd-unsupported": controlplaneTypes.CommandAdvertiseTransportAddress,
		"cmd-action":      controlplaneTypes.CommandStewardAction,
		"cmd-shared":      controlplaneTypes.CommandSyncConfig,
	})
	publisher, received := newPeerSupportPublisher(t, "steward-floor", registry.CapabilityFloor, controlplaneTypes.FloorProfile().CommandTypes)
	logger := &recordingLogger{}
	hook := service.NewPendingDeliveryDrainHook(commandStore, stewardStore, publisher, logger)

	require.NoError(t, hook.OnConnect(ctx, "steward-floor"))

	select {
	case sc := <-received:
		assert.Equal(t, "cmd-shared", sc.Command.ID)
		assert.Equal(t, controlplaneTypes.CommandSyncConfig, sc.Command.Type)
	case <-time.After(2 * time.Second):
		t.Fatal("the shared-type row was never delivered")
	}
	requireNothingReceived(t, received)

	for _, id := range []string{"cmd-unsupported", "cmd-action"} {
		rec, err := commandStore.GetCommandRecord(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, business.DeliveryStatusRejected, rec.DeliveryStatus, id)
		assert.Equal(t, business.DeliveryDetailCommandTypeUnsupportedByPeer, rec.DeliveryDetail, id)
	}
	shared, err := commandStore.GetCommandRecord(ctx, "cmd-shared")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusDelivered, shared.DeliveryStatus)

	// Terminal: the next reconnect lists nothing for these rows and sends nothing.
	pending, err := commandStore.ListPendingDeliveries(ctx, "steward-floor", "tenant-a")
	require.NoError(t, err)
	assert.Empty(t, pending, "no row stays pending to be retried on every reconnect")
	require.NoError(t, hook.OnConnect(ctx, "steward-floor"))
	requireNothingReceived(t, received)

	assert.NotContains(t, logger.allText(), "leaving pending")
}

// The same rows go out to a steward that supports their types.
func TestPendingDeliveryDrainHook_SupportedTypeIsDeliveredToACurrentSteward(t *testing.T) {
	ctx := context.Background()
	commandStore, stewardStore := newPeerSupportDrainFixture(t, "steward-cur", map[string]controlplaneTypes.CommandType{
		"cmd-action": controlplaneTypes.CommandStewardAction,
	})
	publisher, received := newPeerSupportPublisher(t, "steward-cur", registry.CapabilityDeclared, allCommandTypeNumbers())
	hook := service.NewPendingDeliveryDrainHook(commandStore, stewardStore, publisher, logging.NewNoopLogger())

	require.NoError(t, hook.OnConnect(ctx, "steward-cur"))

	select {
	case sc := <-received:
		assert.Equal(t, "cmd-action", sc.Command.ID)
	case <-time.After(2 * time.Second):
		t.Fatal("the row was never delivered to a steward that supports its type")
	}
	rec, err := commandStore.GetCommandRecord(ctx, "cmd-action")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusDelivered, rec.DeliveryStatus)
}

// A type the controller does not know, and a steward it holds no state for, are
// not gated: the row is sent as before.
func TestPendingDeliveryDrainHook_UnknownTypeAndNoRecordAreNotGated(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown type", func(t *testing.T) {
		commandStore, stewardStore := newPeerSupportDrainFixture(t, "steward-floor", map[string]controlplaneTypes.CommandType{
			"cmd-future": controlplaneTypes.CommandType("from_the_future"),
		})
		publisher, received := newPeerSupportPublisher(t, "steward-floor", registry.CapabilityFloor, controlplaneTypes.FloorProfile().CommandTypes)
		hook := service.NewPendingDeliveryDrainHook(commandStore, stewardStore, publisher, logging.NewNoopLogger())

		require.NoError(t, hook.OnConnect(ctx, "steward-floor"))

		select {
		case sc := <-received:
			assert.Equal(t, "cmd-future", sc.Command.ID)
		case <-time.After(2 * time.Second):
			t.Fatal("an unknown type must not be gated")
		}
	})

	t.Run("steward with no record", func(t *testing.T) {
		commandStore, stewardStore := newPeerSupportDrainFixture(t, "steward-new", map[string]controlplaneTypes.CommandType{
			"cmd-action": controlplaneTypes.CommandStewardAction,
		})
		publisher, received := newPeerSupportPublisher(t, "steward-new", "", nil)
		hook := service.NewPendingDeliveryDrainHook(commandStore, stewardStore, publisher, logging.NewNoopLogger())

		require.NoError(t, hook.OnConnect(ctx, "steward-new"))

		select {
		case sc := <-received:
			assert.Equal(t, "cmd-action", sc.Command.ID)
		case <-time.After(2 * time.Second):
			t.Fatal("a steward with no record must not be gated")
		}
	})
}
