// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	stewardcommands "github.com/cfgis/cfgms/features/steward/commands"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newDrainHookTestStores returns real, in-memory SQLite-backed CommandStore
// and StewardStore instances (no mocks) for exercising the drain hook. The
// concrete provider construction lives in providers_test.go, the allowlisted
// path for direct pkg/storage/providers/* imports (see
// scripts/check-providers.sh).
func newDrainHookTestStores(t *testing.T) (business.CommandStore, business.StewardStore) {
	t.Helper()
	return newSQLiteDrainHookStores(t)
}

// newDrainHookTestPublisher starts a real memory.Provider server/client pair
// for stewardID and returns a commands.Publisher backed by the server side,
// plus a channel the test can read delivered commands from.
func newDrainHookTestPublisher(t *testing.T, stewardID string) (*commands.Publisher, chan *controlplaneTypes.SignedCommand) {
	t.Helper()
	received := make(chan *controlplaneTypes.SignedCommand, 4)
	publisher := newDrainHookTestPublisherWithHandler(t, stewardID, func(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
		received <- cmd
		return nil
	})
	return publisher, received
}

// newDrainHookTestPublisherWithHandler is newDrainHookTestPublisher with a
// caller-supplied steward-side subscriber in place of the channel subscriber.
func newDrainHookTestPublisherWithHandler(t *testing.T, stewardID string, handler cpinterfaces.CommandHandler) *commands.Publisher {
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

	require.NoError(t, client.SubscribeCommands(ctx, stewardID, handler))

	publisher, err := commands.New(&commands.Config{ControlPlane: server, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	return publisher
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

func TestPendingDeliveryDrainHook_OnConnect_RedeliversUnderRecordID(t *testing.T) {
	ctx := context.Background()
	commandStore, stewardStore := newDrainHookTestStores(t)
	publisher, received := newDrainHookTestPublisher(t, "steward-1")

	require.NoError(t, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
		ID: "steward-1", TenantID: "tenant-a", Status: business.StewardStatusActive,
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
	case cmd := <-received:
		assert.Equal(t, "cmd-pending-1", cmd.Command.ID)
	case <-time.After(2 * time.Second):
		t.Fatal("steward never received the redelivered pending command")
	}
}

// TestPendingDeliveryDrainHook_RedeliveryRejectedAsDuplicate uses a real steward
// command handler as the subscriber: a drained re-send of an ID the steward has
// already accepted is dropped with ErrCommandReplay and does not run again.
func TestPendingDeliveryDrainHook_RedeliveryRejectedAsDuplicate(t *testing.T) {
	ctx := context.Background()
	commandStore, stewardStore := newDrainHookTestStores(t)

	handler, err := stewardcommands.New(&stewardcommands.Config{
		StewardID: "steward-1",
		OnStatus:  func(context.Context, *controlplaneTypes.Event) {},
		Logger:    logging.NewNoopLogger(),
	})
	require.NoError(t, err)

	var mu sync.Mutex
	runs := 0
	handler.RegisterHandler(controlplaneTypes.CommandSyncConfig, func(context.Context, *controlplaneTypes.Command) error {
		mu.Lock()
		defer mu.Unlock()
		runs++
		return nil
	})

	handleErrs := make(chan error, 4)
	publisher := newDrainHookTestPublisherWithHandler(t, "steward-1", func(c context.Context, cmd *controlplaneTypes.SignedCommand) error {
		err := handler.HandleCommand(c, cmd)
		handleErrs <- err
		return err
	})
	waitErr := func() error {
		select {
		case e := <-handleErrs:
			return e
		case <-time.After(2 * time.Second):
			t.Fatal("steward handler never saw the command")
			return nil
		}
	}

	require.NoError(t, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
		ID: "steward-1", TenantID: "tenant-a", Status: business.StewardStatusActive,
	}))
	require.NoError(t, commandStore.CreateCommandRecord(ctx, &business.CommandRecord{
		ID:             "cmd-dup-1",
		Type:           string(controlplaneTypes.CommandSyncConfig),
		StewardID:      "steward-1",
		TenantID:       "tenant-a",
		DeliveryStatus: business.DeliveryStatusPending,
	}))

	require.NoError(t, publisher.PublishCommandWithID(ctx, "cmd-dup-1", "steward-1", controlplaneTypes.CommandSyncConfig, nil))
	require.NoError(t, waitErr())
	handler.Wait()

	require.NoError(t, commandStore.UpdateDeliveryStatus(ctx, "cmd-dup-1", business.DeliveryStatusPending, ""))
	hook := service.NewPendingDeliveryDrainHook(commandStore, stewardStore, nil, logging.NewNoopLogger())
	hook.SetPublisher(publisher)
	require.NoError(t, hook.OnConnect(ctx, "steward-1"))

	reErr := waitErr()
	assert.True(t, errors.Is(reErr, stewardcommands.ErrCommandReplay), "re-send must be rejected as a replay, got %v", reErr)
	handler.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, runs, "handler must run exactly once")
}
