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
	stewardclient "github.com/cfgis/cfgms/features/steward/client"
	stewardcommands "github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

type fixedTermSource struct{ term uint64 }

func (f fixedTermSource) GetTerm() uint64 { return f.term }

func newRecorderCommandStore(t *testing.T) business.CommandStore {
	t.Helper()
	store, _ := newSQLiteDrainHookStores(t)
	return store
}

func createRecord(t *testing.T, store business.CommandStore, id, stewardID string, status business.DeliveryStatus) {
	t.Helper()
	require.NoError(t, store.CreateCommandRecord(context.Background(), &business.CommandRecord{
		ID:             id,
		Type:           string(controlplaneTypes.CommandSyncConfig),
		StewardID:      stewardID,
		TenantID:       "tenant-a",
		DeliveryStatus: status,
	}))
}

func rejectionResponse(commandID, stewardID, reason string) *controlplaneTypes.Response {
	return &controlplaneTypes.Response{
		CommandID: commandID,
		StewardID: stewardID,
		Message:   reason,
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"reason": reason, "retryable": reason == "term_fenced"},
	}
}

func TestCommandRejectionRecorder_FenceRejectionRecorded(t *testing.T) {
	ctx := context.Background()
	const stewardID = "steward-fence"

	store := newRecorderCommandStore(t)
	recorder := service.NewCommandRejectionRecorder(store, logging.NewNoopLogger())

	bus := memory.NewBus()
	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	cp := memory.New(memory.ModeClient)
	require.NoError(t, cp.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": stewardID}))
	require.NoError(t, cp.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = cp.Stop(stopCtx)
		_ = server.Stop(stopCtx)
	})

	require.NoError(t, recorder.Subscribe(ctx, server))

	received := make(chan string, 8)
	handler, err := stewardcommands.New(&stewardcommands.Config{
		StewardID: stewardID,
		Logger:    logging.NewNoopLogger(),
		OnStatus: func(_ context.Context, ev *controlplaneTypes.Event) {
			if ev.Type == controlplaneTypes.EventCommandReceived {
				received <- ev.CommandID
			}
		},
	})
	require.NoError(t, err)
	t.Cleanup(handler.Wait)

	_, err = stewardclient.NewReceivePathClient(ctx, stewardID, cp, handler, logging.NewNoopLogger())
	require.NoError(t, err)

	// Term 5 command: accepted, and sets the steward's ratchet.
	termPublisher, err := commands.New(&commands.Config{ControlPlane: server, TermSource: fixedTermSource{term: 5}, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	require.NoError(t, termPublisher.PublishCommandWithID(ctx, "seed-cmd", stewardID, controlplaneTypes.CommandSyncConfig, nil))
	select {
	case id := <-received:
		require.Equal(t, "seed-cmd", id)
	case <-time.After(5 * time.Second):
		t.Fatal("steward never received the seed command")
	}

	// The record's command goes out stamped term 0, below the ratchet.
	createRecord(t, store, "rec-fenced", stewardID, business.DeliveryStatusPending)
	unstamped, err := commands.New(&commands.Config{ControlPlane: server, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	require.NoError(t, unstamped.PublishCommandWithID(ctx, "rec-fenced", stewardID, controlplaneTypes.CommandSyncConfig, nil))

	require.Eventually(t, func() bool {
		rec, getErr := store.GetCommandRecord(ctx, "rec-fenced")
		return getErr == nil && rec.DeliveryStatus == business.DeliveryStatusRejected
	}, 5*time.Second, 20*time.Millisecond, "the fence rejection must reach the delivery record")

	rec, err := store.GetCommandRecord(ctx, "rec-fenced")
	require.NoError(t, err)
	assert.Equal(t, "term_fenced", rec.DeliveryDetail)
	assert.Equal(t, int64(1), recorder.RejectionCounts()["term_fenced"])
}

func TestCommandRejectionRecorder_RuleTable(t *testing.T) {
	ctx := context.Background()
	const stewardID = "steward-rules"

	rejectedCodes := []string{
		"term_fenced", "unauthenticated", "wrong_steward",
		"stale_timestamp", "params_too_large", "invalid_command",
	}
	for _, code := range rejectedCodes {
		for _, from := range []business.DeliveryStatus{business.DeliveryStatusPending, business.DeliveryStatusDelivered} {
			t.Run(code+"_from_"+string(from), func(t *testing.T) {
				store := newRecorderCommandStore(t)
				recorder := service.NewCommandRejectionRecorder(store, logging.NewNoopLogger())
				createRecord(t, store, "rec", stewardID, from)

				require.NoError(t, recorder.HandleResponse(ctx, rejectionResponse("rec", stewardID, code)))

				rec, err := store.GetCommandRecord(ctx, "rec")
				require.NoError(t, err)
				assert.Equal(t, business.DeliveryStatusRejected, rec.DeliveryStatus)
				assert.Equal(t, code, rec.DeliveryDetail)
				assert.Equal(t, int64(1), recorder.RejectionCounts()[code])
			})
		}
	}

	t.Run("duplicate_id_moves_pending_to_delivered", func(t *testing.T) {
		store := newRecorderCommandStore(t)
		recorder := service.NewCommandRejectionRecorder(store, logging.NewNoopLogger())
		createRecord(t, store, "rec", stewardID, business.DeliveryStatusPending)

		require.NoError(t, recorder.HandleResponse(ctx, rejectionResponse("rec", stewardID, "duplicate_id")))

		rec, err := store.GetCommandRecord(ctx, "rec")
		require.NoError(t, err)
		assert.Equal(t, business.DeliveryStatusDelivered, rec.DeliveryStatus)
		assert.Equal(t, "duplicate_id", rec.DeliveryDetail)
	})

	t.Run("acknowledged_record_unchanged", func(t *testing.T) {
		store := newRecorderCommandStore(t)
		recorder := service.NewCommandRejectionRecorder(store, logging.NewNoopLogger())
		createRecord(t, store, "rec", stewardID, business.DeliveryStatusAcknowledged)

		require.NoError(t, recorder.HandleResponse(ctx, rejectionResponse("rec", stewardID, "term_fenced")))
		require.NoError(t, recorder.HandleResponse(ctx, rejectionResponse("rec", stewardID, "duplicate_id")))

		rec, err := store.GetCommandRecord(ctx, "rec")
		require.NoError(t, err)
		assert.Equal(t, business.DeliveryStatusAcknowledged, rec.DeliveryStatus)
		assert.Empty(t, rec.DeliveryDetail)
	})

	t.Run("unknown_reason_ignored", func(t *testing.T) {
		store := newRecorderCommandStore(t)
		recorder := service.NewCommandRejectionRecorder(store, logging.NewNoopLogger())
		createRecord(t, store, "rec", stewardID, business.DeliveryStatusDelivered)

		require.NoError(t, recorder.HandleResponse(ctx, rejectionResponse("rec", stewardID, "totally_made_up")))

		rec, err := store.GetCommandRecord(ctx, "rec")
		require.NoError(t, err)
		assert.Equal(t, business.DeliveryStatusDelivered, rec.DeliveryStatus)
		assert.Empty(t, rec.DeliveryDetail)
		assert.Empty(t, recorder.RejectionCounts())
	})

	t.Run("successful_response_ignored", func(t *testing.T) {
		store := newRecorderCommandStore(t)
		recorder := service.NewCommandRejectionRecorder(store, logging.NewNoopLogger())
		createRecord(t, store, "rec", stewardID, business.DeliveryStatusDelivered)

		resp := rejectionResponse("rec", stewardID, "term_fenced")
		resp.Success = true
		require.NoError(t, recorder.HandleResponse(ctx, resp))

		rec, err := store.GetCommandRecord(ctx, "rec")
		require.NoError(t, err)
		assert.Equal(t, business.DeliveryStatusDelivered, rec.DeliveryStatus)
	})

	t.Run("missing_record_counted_not_failed", func(t *testing.T) {
		store := newRecorderCommandStore(t)
		recorder := service.NewCommandRejectionRecorder(store, logging.NewNoopLogger())

		require.NoError(t, recorder.HandleResponse(ctx, rejectionResponse("no-such-record", stewardID, "term_fenced")))
		assert.Equal(t, int64(1), recorder.RejectionCounts()["term_fenced"])
	})

	t.Run("detail_comes_from_constant_not_wire", func(t *testing.T) {
		store := newRecorderCommandStore(t)
		recorder := service.NewCommandRejectionRecorder(store, logging.NewNoopLogger())
		createRecord(t, store, "rec", stewardID, business.DeliveryStatusPending)

		resp := rejectionResponse("rec", stewardID, "term_fenced")
		resp.Message = "highest seen term 99"
		require.NoError(t, recorder.HandleResponse(ctx, resp))

		rec, err := store.GetCommandRecord(ctx, "rec")
		require.NoError(t, err)
		assert.Equal(t, "term_fenced", rec.DeliveryDetail)
	})
}

func TestCommandRejectionRecorder_CrossStewardResponseDropped(t *testing.T) {
	ctx := context.Background()
	store := newRecorderCommandStore(t)
	recorder := service.NewCommandRejectionRecorder(store, logging.NewNoopLogger())
	createRecord(t, store, "rec-of-a", "steward-a", business.DeliveryStatusDelivered)

	require.NoError(t, recorder.HandleResponse(ctx, rejectionResponse("rec-of-a", "steward-b", "term_fenced")))

	rec, err := store.GetCommandRecord(ctx, "rec-of-a")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusDelivered, rec.DeliveryStatus)
	assert.Empty(t, rec.DeliveryDetail)
	assert.Empty(t, recorder.RejectionCounts())
}
