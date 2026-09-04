// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newDrainHookTestStores returns real, in-memory SQLite-backed CommandStore
// and StewardStore instances (no mocks) for exercising the drain hook.
func newDrainHookTestStores(t *testing.T) (business.CommandStore, business.StewardStore) {
	t.Helper()
	provider := &sqlite.SQLiteProvider{}
	commandStore, err := provider.CreateCommandStore(map[string]interface{}{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = commandStore.Close() })

	stewardStore, err := provider.CreateStewardStore(map[string]interface{}{})
	require.NoError(t, err)
	return commandStore, stewardStore
}

// newDrainHookTestPublisher starts a real memory.Provider server/client pair
// for stewardID and returns a commands.Publisher backed by the server side,
// plus a channel the test can read delivered commands from.
func newDrainHookTestPublisher(t *testing.T, stewardID string) (*commands.Publisher, chan *controlplaneTypes.SignedCommand) {
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

	publisher, err := commands.New(&commands.Config{ControlPlane: server, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	return publisher, received
}

func TestPendingDeliveryDrainHook_OnConnect_RedeliversPendingRecord(t *testing.T) {
	ctx := context.Background()
	commandStore, stewardStore := newDrainHookTestStores(t)
	publisher, received := newDrainHookTestPublisher(t, "steward-1")

	require.NoError(t, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
		ID:       "steward-1",
		TenantID: "tenant-a",
		Status:   business.StewardStatusActive,
	}))
	require.NoError(t, commandStore.CreateCommandRecord(ctx, &business.CommandRecord{
		ID:             "cmd-pending-1",
		Type:           string(controlplaneTypes.CommandSyncConfig),
		StewardID:      "steward-1",
		TenantID:       "tenant-a",
		DeliveryStatus: business.DeliveryStatusPending,
	}))

	hook := service.NewPendingDeliveryDrainHook(commandStore, stewardStore, nil, logging.NewNoopLogger())
	hook.SetPublisher(publisher)

	require.NoError(t, hook.OnConnect(ctx, "steward-1"))

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("steward never received the redelivered pending command")
	}

	rec, err := commandStore.GetCommandRecord(ctx, "cmd-pending-1")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusDelivered, rec.DeliveryStatus)
}

func TestPendingDeliveryDrainHook_OnConnect_NoopWithoutPublisher(t *testing.T) {
	ctx := context.Background()
	commandStore, stewardStore := newDrainHookTestStores(t)

	require.NoError(t, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
		ID: "steward-1", TenantID: "tenant-a", Status: business.StewardStatusActive,
	}))
	require.NoError(t, commandStore.CreateCommandRecord(ctx, &business.CommandRecord{
		ID: "cmd-1", Type: string(controlplaneTypes.CommandSyncConfig), StewardID: "steward-1", TenantID: "tenant-a",
		DeliveryStatus: business.DeliveryStatusPending,
	}))

	// publisher deliberately nil: construction may happen before commands.Publisher exists.
	hook := service.NewPendingDeliveryDrainHook(commandStore, stewardStore, nil, logging.NewNoopLogger())
	require.NoError(t, hook.OnConnect(ctx, "steward-1"))

	rec, err := commandStore.GetCommandRecord(ctx, "cmd-1")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusPending, rec.DeliveryStatus, "without a publisher nothing should be redelivered or marked delivered")
}

func TestPendingDeliveryDrainHook_OnConnect_UnknownStewardIsNoop(t *testing.T) {
	ctx := context.Background()
	commandStore, stewardStore := newDrainHookTestStores(t)
	publisher, _ := newDrainHookTestPublisher(t, "steward-ghost")

	hook := service.NewPendingDeliveryDrainHook(commandStore, stewardStore, publisher, logging.NewNoopLogger())
	// steward-ghost was never registered in stewardStore, so its tenant cannot
	// be resolved: OnConnect must not error, and must not attempt an unscoped read.
	require.NoError(t, hook.OnConnect(ctx, "steward-ghost"))
}

// TestPendingDeliveryDrainHook_OnConnect_NeverDrainsAnotherStewardsRecords
// documents the identity-scoping guarantee (Security review round 2): the
// hook is only ever called by the transport layer with the mTLS-authenticated
// CN of the connecting steward, and it resolves that steward's tenant itself
// rather than accepting one from the caller — so connecting as steward-a can
// never surface or redeliver steward-b's pending rows, even when both share
// the same tenant.
func TestPendingDeliveryDrainHook_OnConnect_NeverDrainsAnotherStewardsRecords(t *testing.T) {
	ctx := context.Background()
	commandStore, stewardStore := newDrainHookTestStores(t)
	publisherA, receivedA := newDrainHookTestPublisher(t, "steward-a")

	require.NoError(t, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
		ID: "steward-a", TenantID: "tenant-shared", Status: business.StewardStatusActive,
	}))
	require.NoError(t, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
		ID: "steward-b", TenantID: "tenant-shared", Status: business.StewardStatusActive,
	}))
	require.NoError(t, commandStore.CreateCommandRecord(ctx, &business.CommandRecord{
		ID: "cmd-for-b", Type: string(controlplaneTypes.CommandSyncConfig), StewardID: "steward-b", TenantID: "tenant-shared",
		DeliveryStatus: business.DeliveryStatusPending,
	}))

	hook := service.NewPendingDeliveryDrainHook(commandStore, stewardStore, publisherA, logging.NewNoopLogger())

	// steward-a connects; only steward-a's own (empty) backlog may be drained.
	require.NoError(t, hook.OnConnect(ctx, "steward-a"))

	select {
	case <-receivedA:
		t.Fatal("steward-a must never receive a command queued for steward-b")
	case <-time.After(200 * time.Millisecond):
	}

	rec, err := commandStore.GetCommandRecord(ctx, "cmd-for-b")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusPending, rec.DeliveryStatus, "steward-b's record must be untouched by steward-a's connect")
}
