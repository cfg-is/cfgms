// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service_test

import (
	"context"
	"sync/atomic"
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

// callCountTermSource returns first on the first GetTerm call and later on every
// call after it. GetTerm runs once per publish, so calls is the number of sends.
type callCountTermSource struct {
	first, later uint64
	calls        atomic.Int64
}

func (c *callCountTermSource) GetTerm() uint64 {
	if c.calls.Add(1) == 1 {
		return c.first
	}
	return c.later
}

// fenceRetryFixture wires a real steward receive path (ratchet seeded to term 5),
// a real publisher with a 10ms fence retry delay, and a recorder with the
// publisher set as its retrier.
type fenceRetryFixture struct {
	store     business.CommandStore
	recorder  *service.CommandRejectionRecorder
	publisher *commands.Publisher
	accepted  chan string
	terms     *callCountTermSource
}

func newFenceRetryFixture(t *testing.T, stewardID string, first, later uint64) *fenceRetryFixture {
	t.Helper()
	ctx := context.Background()

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

	accepted := make(chan string, 16)
	handler, err := stewardcommands.New(&stewardcommands.Config{
		StewardID: stewardID,
		Logger:    logging.NewNoopLogger(),
		OnStatus: func(_ context.Context, ev *controlplaneTypes.Event) {
			if ev.Type == controlplaneTypes.EventCommandReceived {
				accepted <- ev.CommandID
			}
		},
	})
	require.NoError(t, err)
	t.Cleanup(handler.Wait)
	_, err = stewardclient.NewReceivePathClient(ctx, stewardID, cp, handler, logging.NewNoopLogger())
	require.NoError(t, err)

	// Seed the steward's term ratchet at 5.
	seeder, err := commands.New(&commands.Config{ControlPlane: server, TermSource: fixedTermSource{term: 5}, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	require.NoError(t, seeder.PublishCommandWithID(ctx, "seed-cmd", stewardID, controlplaneTypes.CommandSyncConfig, nil))
	select {
	case id := <-accepted:
		require.Equal(t, "seed-cmd", id)
	case <-time.After(5 * time.Second):
		t.Fatal("steward never received the seed command")
	}

	terms := &callCountTermSource{first: first, later: later}
	pub, err := commands.New(&commands.Config{
		ControlPlane:    server,
		TermSource:      terms,
		FenceRetryDelay: 10 * time.Millisecond,
		Logger:          logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pub.Stop(context.Background()) })
	recorder.SetRetrier(pub)

	return &fenceRetryFixture{store: store, recorder: recorder, publisher: pub, accepted: accepted, terms: terms}
}

func TestCommandRejectionRecorder_FenceRetryDelivers(t *testing.T) {
	ctx := context.Background()
	const stewardID = "steward-retry-ok"
	f := newFenceRetryFixture(t, stewardID, 3, 6)

	createRecord(t, f.store, "rec-retry", stewardID, business.DeliveryStatusPending)
	require.NoError(t, f.publisher.PublishCommandWithID(ctx, "rec-retry", stewardID, controlplaneTypes.CommandSyncConfig, nil))

	require.Eventually(t, func() bool {
		rec, err := f.store.GetCommandRecord(ctx, "rec-retry")
		return err == nil && rec.DeliveryStatus == business.DeliveryStatusDelivered &&
			rec.DeliveryDetail == "term_fenced: delivered on retry 1"
	}, 5*time.Second, 10*time.Millisecond, "the retried command must leave the record delivered")

	select {
	case id := <-f.accepted:
		assert.Equal(t, "rec-retry", id, "the steward must accept the re-send under the same ID")
	case <-time.After(5 * time.Second):
		t.Fatal("steward never accepted the retried command")
	}
	assert.Equal(t, int64(2), f.terms.calls.Load(), "original at term 3, then one retry at term 6")
	assert.Equal(t, int64(1), f.recorder.RejectionCounts()["term_fenced"], "only the original send is fenced")
}

func TestCommandRejectionRecorder_FenceRetryExhausted(t *testing.T) {
	ctx := context.Background()
	const stewardID = "steward-retry-exhausted"
	f := newFenceRetryFixture(t, stewardID, 3, 3)

	createRecord(t, f.store, "rec-exhaust", stewardID, business.DeliveryStatusPending)
	require.NoError(t, f.publisher.PublishCommandWithID(ctx, "rec-exhaust", stewardID, controlplaneTypes.CommandSyncConfig, nil))

	require.Eventually(t, func() bool {
		rec, err := f.store.GetCommandRecord(ctx, "rec-exhaust")
		return err == nil && rec.DeliveryStatus == business.DeliveryStatusRejected
	}, 5*time.Second, 10*time.Millisecond, "an exhausted retry budget must end rejected")

	rec, err := f.store.GetCommandRecord(ctx, "rec-exhaust")
	require.NoError(t, err)
	assert.Equal(t, "term_fenced", rec.DeliveryDetail)
	assert.Equal(t, int64(4), f.terms.calls.Load(), "original plus 3 retries")
	assert.Equal(t, int64(4), f.recorder.RejectionCounts()["term_fenced"], "steward rejected every send")

	// No further send follows exhaustion.
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int64(4), f.terms.calls.Load())
	assert.Empty(t, f.accepted)
}

func TestCommandRejectionRecorder_NonRetryableNotRetried(t *testing.T) {
	ctx := context.Background()
	const stewardID = "steward-no-retry"
	f := newFenceRetryFixture(t, stewardID, 3, 6)

	wrongSteward := rejectionResponse("rec-wrong", stewardID, "wrong_steward")
	unretryableFence := rejectionResponse("rec-flag", stewardID, "term_fenced")
	unretryableFence.Details["retryable"] = false

	for _, resp := range []*controlplaneTypes.Response{wrongSteward, unretryableFence} {
		createRecord(t, f.store, resp.CommandID, stewardID, business.DeliveryStatusDelivered)
		require.NoError(t, f.recorder.HandleResponse(ctx, resp))

		rec, err := f.store.GetCommandRecord(ctx, resp.CommandID)
		require.NoError(t, err)
		assert.Equal(t, business.DeliveryStatusRejected, rec.DeliveryStatus)
	}

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int64(0), f.terms.calls.Load(), "a non-retryable rejection must not produce a send")
	assert.Empty(t, f.accepted)
}
