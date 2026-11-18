// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	stewardcommands "github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/pkg/cert"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/transport/registry"
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
	return newDrainHookTestPublisherWithConfig(t, stewardID, handler, nil)
}

// newDrainHookTestPublisherWithConfig is newDrainHookTestPublisherWithHandler
// with a hook to adjust the publisher's configuration before it is built.
func newDrainHookTestPublisherWithConfig(t *testing.T, stewardID string, handler cpinterfaces.CommandHandler, adjust func(*commands.Config)) *commands.Publisher {
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

	cfg := &commands.Config{ControlPlane: server, Logger: logging.NewNoopLogger()}
	if adjust != nil {
		adjust(cfg)
	}
	publisher, err := commands.New(cfg)
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

// lateTestSigner returns a signer and the verifier a steward holds for it.
func lateTestSigner(t *testing.T) (signature.Signer, signature.Verifier) {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{Organization: "Late Declaration Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	sc, err := ca.GenerateSigningCertificate(&cert.SigningCertConfig{CommonName: "late-test", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{CertificatePEM: sc.CertificatePEM, PrivateKeyPEM: sc.PrivateKeyPEM})
	require.NoError(t, err)
	verifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: sc.CertificatePEM})
	require.NoError(t, err)
	return signer, verifier
}

// newLateStewardHandler is a real steward command handler that verifies against
// verifier and counts the sync_config commands it runs.
func newLateStewardHandler(t *testing.T, stewardID string, verifier signature.Verifier, ran *atomic.Int32) *stewardcommands.Handler {
	t.Helper()
	h, err := stewardcommands.New(&stewardcommands.Config{
		StewardID: stewardID,
		OnStatus:  func(context.Context, *controlplaneTypes.Event) {},
		Logger:    logging.NewNoopLogger(),
		Verifier:  verifier,
	})
	require.NoError(t, err)
	h.RegisterHandler(controlplaneTypes.CommandSyncConfig, func(context.Context, *controlplaneTypes.Command) error {
		ran.Add(1)
		return nil
	})
	return h
}

// hookRuns counts how often an on-connect hook ran.
type hookRuns struct {
	mu    sync.Mutex
	times []time.Time
}

func (h *hookRuns) record() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.times = append(h.times, time.Now())
}

func (h *hookRuns) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.times)
}

func (h *hookRuns) first() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.times) == 0 {
		return time.Time{}
	}
	return h.times[0]
}

// countingHook is an on-connect hook that only counts its runs: it stands in for
// the hooks that never sign.
type countingHook struct{ runs hookRuns }

func (c *countingHook) OnConnect(context.Context, string) error {
	c.runs.record()
	return nil
}

// signingProbeHook stands in for a hook that signs and sends a command: it
// publishes a sync_config through the real publisher, which resolves the
// signing version for the connection (waiting, bounded, for its declaration).
type signingProbeHook struct {
	runs      hookRuns
	publisher atomic.Pointer[commands.Publisher]
}

func (s *signingProbeHook) OnConnect(ctx context.Context, stewardID string) error {
	s.runs.record()
	pub := s.publisher.Load()
	if pub == nil {
		return nil
	}
	_, err := pub.PublishCommand(ctx, stewardID, controlplaneTypes.CommandSyncConfig, nil)
	return err
}

// lateChain is the on-connect chain a late-declaration test runs: a counting
// hook in every non-signing slot, a signing probe in every signing slot but the
// drain, and the real drain hook.
type lateChain struct {
	nonSigning map[service.ConnectHookSlot]*countingHook
	signing    map[service.ConnectHookSlot]*signingProbeHook
	drain      *service.PendingDeliveryDrainHook
	hooks      []service.SlottedConnectHook
}

func newLateChain(commandStore business.CommandStore, stewardStore business.StewardStore) *lateChain {
	c := &lateChain{
		nonSigning: map[service.ConnectHookSlot]*countingHook{},
		signing:    map[service.ConnectHookSlot]*signingProbeHook{},
		drain:      service.NewPendingDeliveryDrainHook(commandStore, stewardStore, nil, logging.NewNoopLogger()),
	}
	for _, slot := range []service.ConnectHookSlot{
		service.SlotRegistry, service.SlotCompletionReconcile, service.SlotRouting, service.SlotLockdown, service.SlotRepair,
	} {
		h := &countingHook{}
		c.nonSigning[slot] = h
		c.hooks = append(c.hooks, service.SlottedConnectHook{Slot: slot, Hook: h})
	}
	for _, slot := range []service.ConnectHookSlot{
		service.SlotSigningRotation, service.SlotMigration, service.SlotTransportAddress,
	} {
		h := &signingProbeHook{}
		c.signing[slot] = h
		c.hooks = append(c.hooks, service.SlottedConnectHook{Slot: slot, Hook: h})
	}
	c.hooks = append(c.hooks, service.SlottedConnectHook{Slot: service.SlotDrain, Hook: c.drain})
	return c
}

func (c *lateChain) setPublisher(p *commands.Publisher) {
	c.drain.SetPublisher(p)
	for _, h := range c.signing {
		h.publisher.Store(p)
	}
}

// lateHook lets the provider be constructed before the chain exists.
type lateHook struct {
	chain atomic.Pointer[service.CompositeOnConnectHook]
}

func (l *lateHook) OnConnect(ctx context.Context, stewardID string) error {
	if c := l.chain.Load(); c != nil {
		return c.OnConnect(ctx, stewardID)
	}
	return nil
}

type fixedTerm uint64

func (f fixedTerm) GetTerm() uint64 { return uint64(f) }

// TestLateDeclarationReplacesFloor: a steward that declares v2 after the grace
// has its profile replaced, the replay set (and only it) re-runs once, and what
// the replay sends then verifies on a real steward command handler. A second
// declaration on the same connection does not re-run it.
func TestLateDeclarationReplacesFloor(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-late-replace"

	sm := pkgtesting.SetupTestStorage(t)
	stewardStore, commandStore := sm.GetStewardStore(), sm.GetCommandStore()
	require.NoError(t, stewardStore.RegisterSteward(context.Background(), &business.StewardRecord{
		ID: stewardID, TenantID: "tenant-a", Status: business.StewardStatusActive,
		RegisteredAt: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}))
	// A row waiting in the outbox when the steward connects.
	require.NoError(t, commandStore.CreateCommandRecord(context.Background(), &business.CommandRecord{
		ID: "cmd-floor-row", Type: string(controlplaneTypes.CommandSyncConfig), StewardID: stewardID,
		TenantID: "tenant-a", DeliveryStatus: business.DeliveryStatusPending,
	}))

	chain := newLateChain(commandStore, stewardStore)
	entry := &lateHook{}
	var replay atomic.Pointer[service.LateDeclarationReplay]
	f := newCapFixture(t, stewardID, stewardStore, capConfig{
		grace: 400 * time.Millisecond,
		hook:  func(*service.ControllerService) grpcCP.StewardOnConnectHook { return entry },
		onLate: func(ctx context.Context, id string) {
			if r := replay.Load(); r != nil {
				r.OnLateCapabilities(ctx, id)
			}
		},
	})

	resolver := commands.NewCapabilityResolver(f.reg, stewardStore, logging.NewNoopLogger(),
		commands.WithCapabilityResolveWait(150*time.Millisecond))
	signer, verifier := lateTestSigner(t)
	publisher, err := commands.New(&commands.Config{
		ControlPlane: f.server, Signer: signer, TermSource: fixedTerm(7),
		SigningVersions: resolver, Logger: logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	chain.setPublisher(publisher)
	chain.drain.SetSigningResolver(resolver)
	entry.chain.Store(service.NewOrderedCompositeOnConnectHook(logging.NewNoopLogger(), chain.hooks...))
	replay.Store(service.NewLateDeclarationReplay(logging.NewNoopLogger(), commandStore, chain.drain.FloorSent(), resolver, chain.hooks...))

	// The steward side: a real handler that verifies what it is sent.
	var ran atomic.Int32
	handler := newLateStewardHandler(t, stewardID, verifier, &ran)
	var refused, accepted atomic.Int32
	client, conn := f.connect(t, false)
	require.NoError(t, client.SubscribeCommands(context.Background(), stewardID,
		func(ctx context.Context, sc *controlplaneTypes.SignedCommand) error {
			if err := handler.HandleCommand(ctx, sc); err != nil {
				refused.Add(1)
				return err
			}
			accepted.Add(1)
			return nil
		}))

	// The grace ends with no declaration: floor. Everything the connect chain
	// sent was signed v1, and a current steward refuses all of it.
	require.Eventually(t, func() bool { return conn.CapabilitySnapshot().State == registry.CapabilityFloor },
		5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return refused.Load() >= 4 }, 5*time.Second, 10*time.Millisecond,
		"three probes and the drain row were signed for the floor")
	assert.Zero(t, accepted.Load())
	row, err := commandStore.GetCommandRecord(context.Background(), "cmd-floor-row")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusDelivered, row.DeliveryStatus, "marked delivered on publish")

	connectRuns := func() map[service.ConnectHookSlot]int {
		out := map[service.ConnectHookSlot]int{}
		for slot, h := range chain.nonSigning {
			out[slot] = h.runs.count()
		}
		for slot, h := range chain.signing {
			out[slot] = h.runs.count()
		}
		return out
	}
	before := connectRuns()
	for slot, n := range before {
		assert.Equal(t, 1, n, "%s ran once on connect", slot)
	}

	// The steward declares late.
	local := grpcCP.LocalCapabilities(stewardID)
	require.NoError(t, client.SendCapabilities(context.Background(), &local))

	// The replay set runs again, once, and what it signs is v2, which verifies.
	require.Eventually(t, func() bool { return ran.Load() == 3 }, 10*time.Second, 10*time.Millisecond,
		"the three signing hooks' commands run on the real handler")
	after := connectRuns()
	for _, slot := range service.LateReplaySlots() {
		if slot == service.SlotDrain {
			continue // no probe: the drain's own rows are checked below
		}
		assert.Equal(t, 2, after[slot], "%s is in the replay set and runs again", slot)
	}
	for _, slot := range []service.ConnectHookSlot{
		service.SlotRegistry, service.SlotCompletionReconcile, service.SlotRouting, service.SlotLockdown, service.SlotRepair,
	} {
		assert.Equal(t, 1, after[slot], "%s is not in the replay set and does not run again", slot)
	}

	// The row sent at the floor is marked: it did not run and must be re-issued.
	require.Eventually(t, func() bool {
		r, err := commandStore.GetCommandRecord(context.Background(), "cmd-floor-row")
		return err == nil && r.DeliveryStatus == business.DeliveryStatusRejected
	}, 5*time.Second, 10*time.Millisecond)
	row, err = commandStore.GetCommandRecord(context.Background(), "cmd-floor-row")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryDetailSigningFormRefusedReissue, row.DeliveryDetail)

	// A second declaration on the connection, and a second call of the callback
	// for it, do not run the set again.
	require.NoError(t, client.SendCapabilities(context.Background(), &local))
	replay.Load().OnLateCapabilities(context.Background(), stewardID)
	time.Sleep(300 * time.Millisecond)
	assert.Equal(t, after, connectRuns(), "a second late declaration does not re-run the replay set")
	assert.Equal(t, int32(3), ran.Load())
}

// TestSilentStewardFirstSignedCommandWaitsOnlyTheGrace: a steward that never
// declares gets its first signed on-connect command no later than the grace plus
// a small bound, and the hooks that do not sign are not held up by that wait.
func TestSilentStewardFirstSignedCommandWaitsOnlyTheGrace(t *testing.T) {
	t.Parallel()
	const (
		stewardID = "steward-late-silent"
		grace     = 800 * time.Millisecond
		wait      = 500 * time.Millisecond
		bound     = 700 * time.Millisecond
	)
	sm := pkgtesting.SetupTestStorage(t)
	stewardStore, commandStore := sm.GetStewardStore(), sm.GetCommandStore()
	require.NoError(t, stewardStore.RegisterSteward(context.Background(), &business.StewardRecord{
		ID: stewardID, TenantID: "tenant-a", Status: business.StewardStatusActive,
		RegisteredAt: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}))

	chain := newLateChain(commandStore, stewardStore)
	entry := &lateHook{}
	f := newCapFixture(t, stewardID, stewardStore, capConfig{
		grace: grace,
		hook:  func(*service.ControllerService) grpcCP.StewardOnConnectHook { return entry },
	})
	resolver := commands.NewCapabilityResolver(f.reg, stewardStore, logging.NewNoopLogger(), commands.WithCapabilityResolveWait(wait))
	signer, _ := lateTestSigner(t)
	publisher, err := commands.New(&commands.Config{
		ControlPlane: f.server, Signer: signer, TermSource: fixedTerm(7),
		SigningVersions: resolver, Logger: logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	chain.setPublisher(publisher)
	entry.chain.Store(service.NewOrderedCompositeOnConnectHook(logging.NewNoopLogger(), chain.hooks...))

	received := make(chan time.Time, 8)
	start := time.Now()
	client, _ := f.connect(t, false)
	var first atomic.Pointer[controlplaneTypes.SignedCommand]
	require.NoError(t, client.SubscribeCommands(context.Background(), stewardID,
		func(_ context.Context, sc *controlplaneTypes.SignedCommand) error {
			first.CompareAndSwap(nil, sc)
			received <- time.Now()
			return nil
		}))

	select {
	case at := <-received:
		elapsed := at.Sub(start)
		assert.LessOrEqual(t, elapsed, grace+bound, "the first signed command is produced by the grace plus a small bound")
		assert.GreaterOrEqual(t, elapsed, wait-100*time.Millisecond, "it did wait for the declaration first")
	case <-time.After(grace + 5*time.Second):
		t.Fatal("no signed command reached the silent steward")
	}
	sc := first.Load()
	require.NotNil(t, sc)
	assert.Zero(t, sc.Command.SigningPayloadVersion, "a silent steward is signed for at the floor (v1)")
	assert.NotNil(t, sc.Signature)

	// The hooks that do not sign ran at once, not behind the wait.
	require.Eventually(t, func() bool {
		for _, h := range chain.nonSigning {
			if h.runs.count() == 0 {
				return false
			}
		}
		return true
	}, 5*time.Second, 5*time.Millisecond)
	for slot, h := range chain.nonSigning {
		assert.Less(t, h.runs.first().Sub(start), wait, "%s was not delayed by the signing hooks' wait", slot)
	}
}

// lateEnv is one steward connection held by a real registry, settled at the floor
// with a drain row waiting, and every component of the recovery real: resolver,
// publisher, drain hook, rejection recorder, replay.
type lateEnv struct {
	t         *testing.T
	id        string
	conn      *registry.StewardConnection
	commands  *deliveryWrites
	drain     *service.PendingDeliveryDrainHook
	recorder  *service.CommandRejectionRecorder
	replay    *service.LateDeclarationReplay
	chain     *lateChain
	sendGate  chan struct{} // when set, the first send blocks until it is closed
	inSend    chan struct{}
	resolver  *commands.CapabilityResolver
	sentCount atomic.Int32
	failSend  atomic.Bool
	gated     atomic.Bool // the one send the gate holds has been taken
}

// deliveryWrites is the real command store, recording the delivery statuses
// written through it.
type deliveryWrites struct {
	business.CommandStore
	mu     sync.Mutex
	writes []business.DeliveryStatus
}

func (d *deliveryWrites) UpdateDeliveryStatus(ctx context.Context, id string, status business.DeliveryStatus, detail string) error {
	d.mu.Lock()
	d.writes = append(d.writes, status)
	d.mu.Unlock()
	return d.CommandStore.UpdateDeliveryStatus(ctx, id, status, detail)
}

func (d *deliveryWrites) wrote(status business.DeliveryStatus) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, s := range d.writes {
		if s == status {
			n++
		}
	}
	return n
}

type nopSender struct{}

func (nopSender) SendMsg(interface{}) error { return nil }

// gatedCP is a control plane whose first SendCommand can be held.
type gatedCP struct {
	cpinterfaces.ControlPlaneProvider
	env *lateEnv
}

func (g *gatedCP) SendCommand(context.Context, *controlplaneTypes.SignedCommand) error {
	g.env.sentCount.Add(1)
	if g.env.failSend.Load() {
		return errors.New("send failed")
	}
	if g.env.sendGate != nil && g.env.gated.CompareAndSwap(false, true) {
		select {
		case g.env.inSend <- struct{}{}:
		default:
		}
		<-g.env.sendGate
	}
	return nil
}

const lateRowID = "cmd-floor-row"

// newLateEnv builds the env. The connection is settled at the floor (its grace
// ended with no declaration) and one pending drain row waits for it. When gated,
// the first send is held until the test closes env.sendGate.
func newLateEnv(t *testing.T, gated bool) *lateEnv {
	t.Helper()
	const stewardID = "steward-late-orders"
	sm := pkgtesting.SetupTestStorage(t)
	stewardStore := sm.GetStewardStore()
	cmds := &deliveryWrites{CommandStore: sm.GetCommandStore()}
	ctx := context.Background()
	require.NoError(t, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
		ID: stewardID, TenantID: "tenant-a", Status: business.StewardStatusActive,
		RegisteredAt: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}))
	require.NoError(t, cmds.CreateCommandRecord(ctx, &business.CommandRecord{
		ID: lateRowID, Type: string(controlplaneTypes.CommandSyncConfig), StewardID: stewardID,
		TenantID: "tenant-a", DeliveryStatus: business.DeliveryStatusPending,
	}))

	reg := registry.NewRegistry()
	conn := &registry.StewardConnection{
		StewardID: stewardID, Sender: nopSender{}, ConnectionID: "conn-orders",
		ConnectedAt: time.Now().Add(-time.Minute),
	}
	require.NoError(t, stewardStore.ResetCapabilities(ctx, stewardID, conn.ConnectionID))
	require.NoError(t, reg.Register(conn))
	floor := controlplaneTypes.FloorProfile()
	conn.SettleCapabilities(registry.CapabilityFloor, floor.CommandTypes, floor.SigningPayloadVersions)

	env := &lateEnv{t: t, id: stewardID, conn: conn, commands: cmds, inSend: make(chan struct{}, 1)}
	if gated {
		env.sendGate = make(chan struct{})
	}
	env.resolver = commands.NewCapabilityResolver(reg, stewardStore, logging.NewNoopLogger(),
		commands.WithCapabilityResolveWait(50*time.Millisecond))
	signer, _ := lateTestSigner(t)
	publisher, err := commands.New(&commands.Config{
		ControlPlane: &gatedCP{env: env}, Signer: signer, TermSource: fixedTerm(7),
		SigningVersions: env.resolver, Logger: logging.NewNoopLogger(),
	})
	require.NoError(t, err)

	env.chain = newLateChain(cmds, stewardStore)
	env.drain = env.chain.drain
	env.chain.setPublisher(publisher)
	env.drain.SetSigningResolver(env.resolver)
	env.recorder = service.NewCommandRejectionRecorder(cmds, logging.NewNoopLogger())
	env.recorder.SetFloorSentTracker(env.drain.FloorSent(), env.resolver)
	env.replay = service.NewLateDeclarationReplay(logging.NewNoopLogger(), cmds, env.drain.FloorSent(), env.resolver, env.chain.hooks...)
	return env
}

// declareCurrent is the late declaration: floor to declared.
func (e *lateEnv) declareCurrent() {
	e.t.Helper()
	changed, late := e.conn.SettleCapabilities(registry.CapabilityDeclared,
		[]int32{1}, []uint32{controlplaneTypes.SigningPayloadV1, controlplaneTypes.SigningPayloadV2})
	require.True(e.t, changed)
	require.True(e.t, late)
}

// steward refuses the stamped v1 command: the response a current steward sends.
func (e *lateEnv) refusal() *controlplaneTypes.Response {
	return &controlplaneTypes.Response{
		CommandID: lateRowID, StewardID: e.id, Success: false,
		Message: service.RejectionUnauthenticated,
		Details: map[string]interface{}{"reason": service.RejectionUnauthenticated},
	}
}

func (e *lateEnv) requireRow(status business.DeliveryStatus, detail string) {
	e.t.Helper()
	rec, err := e.commands.GetCommandRecord(context.Background(), lateRowID)
	require.NoError(e.t, err)
	assert.Equal(e.t, status, rec.DeliveryStatus)
	assert.Equal(e.t, detail, rec.DeliveryDetail)
}

// TestLateDeclarationFloorSentRowOrderings: whichever of the steward's refusal,
// the late-declaration callback and the drain hook's own delivered write comes
// first, the row ends rejected with the re-issue detail.
func TestLateDeclarationFloorSentRowOrderings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	want := business.DeliveryDetailSigningFormRefusedReissue

	t.Run("a: the steward's unauthenticated response is recorded first, then the callback", func(t *testing.T) {
		t.Parallel()
		env := newLateEnv(t, false)
		require.NoError(t, env.drain.OnConnect(ctx, env.id))
		env.requireRow(business.DeliveryStatusDelivered, "")

		env.declareCurrent()
		require.NoError(t, env.recorder.HandleResponse(ctx, env.refusal()))
		env.requireRow(business.DeliveryStatusRejected, want)

		env.replay.OnLateCapabilities(ctx, env.id)
		env.requireRow(business.DeliveryStatusRejected, want)
	})

	t.Run("b: the callback first, then the steward's response", func(t *testing.T) {
		t.Parallel()
		env := newLateEnv(t, false)
		require.NoError(t, env.drain.OnConnect(ctx, env.id))

		env.declareCurrent()
		env.replay.OnLateCapabilities(ctx, env.id)
		env.requireRow(business.DeliveryStatusRejected, want)

		require.NoError(t, env.recorder.HandleResponse(ctx, env.refusal()))
		env.requireRow(business.DeliveryStatusRejected, want)
		assert.Equal(t, int64(1), env.recorder.RejectionCounts()[service.RejectionUnauthenticated])
	})

	t.Run("c: the callback before the drain hook's delivered write", func(t *testing.T) {
		t.Parallel()
		env := newLateEnv(t, true)
		drained := make(chan error, 1)
		go func() { drained <- env.drain.OnConnect(ctx, env.id) }()

		select {
		case <-env.inSend:
		case <-time.After(5 * time.Second):
			t.Fatal("the drain hook never published the row")
		}
		// The row is in flight: published, delivered not yet written.
		env.requireRow(business.DeliveryStatusPending, "")
		env.declareCurrent()
		env.replay.OnLateCapabilities(ctx, env.id)
		env.requireRow(business.DeliveryStatusRejected, want)

		close(env.sendGate)
		select {
		case err := <-drained:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("the drain hook did not finish")
		}
		env.requireRow(business.DeliveryStatusRejected, want)
		assert.Zero(t, env.commands.wrote(business.DeliveryStatusDelivered),
			"the drain hook did not write delivered over a row the callback marked")
	})
}

// TestFloorSentRowOfARealFloorStewardIsNotRewritten: a row sent in v1 to a steward
// that never declares keeps what it was given.
func TestFloorSentRowOfARealFloorStewardIsNotRewritten(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("no response and no declaration: the row stays delivered", func(t *testing.T) {
		t.Parallel()
		env := newLateEnv(t, false)
		require.NoError(t, env.drain.OnConnect(ctx, env.id))

		// Nothing declares, so the callback never runs; running the replay without
		// a late declaration must not mark anything either.
		env.requireRow(business.DeliveryStatusDelivered, "")
		assert.Zero(t, env.commands.wrote(business.DeliveryStatusRejected))
	})

	t.Run("a genuine unauthenticated refusal keeps the generic reason", func(t *testing.T) {
		t.Parallel()
		env := newLateEnv(t, false)
		require.NoError(t, env.drain.OnConnect(ctx, env.id))

		require.NoError(t, env.recorder.HandleResponse(ctx, env.refusal()))
		env.requireRow(business.DeliveryStatusRejected, service.RejectionUnauthenticated)
	})

	t.Run("a refusal of a row that was never tracked keeps the generic reason after a declaration", func(t *testing.T) {
		t.Parallel()
		env := newLateEnv(t, false)
		// Sent by some other path in v1: there is no floor-sent entry for it.
		require.NoError(t, env.commands.UpdateDeliveryStatus(ctx, lateRowID, business.DeliveryStatusDelivered, ""))
		env.declareCurrent()

		require.NoError(t, env.recorder.HandleResponse(ctx, env.refusal()))
		env.requireRow(business.DeliveryStatusRejected, service.RejectionUnauthenticated)
	})
}

// TestFloorSentRowNeverSentIsNotMarked: a drain row whose publish failed was never
// sent, so a late declaration does not mark it; it stays pending for a later drain.
func TestFloorSentRowNeverSentIsNotMarked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newLateEnv(t, false)
	env.failSend.Store(true)

	require.NoError(t, env.drain.OnConnect(ctx, env.id))
	env.requireRow(business.DeliveryStatusPending, "")
	_, tracked := env.drain.FloorSent().ConnectionOf(env.id, lateRowID)
	assert.False(t, tracked, "a row that was never sent is not tracked")

	env.declareCurrent()
	env.replay.OnLateCapabilities(ctx, env.id)
	env.requireRow(business.DeliveryStatusPending, "")
	assert.Zero(t, env.commands.wrote(business.DeliveryStatusRejected))
}

func TestLateDeclarationReplayRunsOncePerConnectionAndOnlyTheReplaySet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newLateEnv(t, false)
	env.declareCurrent()

	env.replay.OnLateCapabilities(ctx, env.id)
	env.replay.OnLateCapabilities(ctx, env.id)

	for slot, h := range env.chain.signing {
		assert.Equal(t, 1, h.runs.count(), "%s ran once for one connection", slot)
	}
	for slot, h := range env.chain.nonSigning {
		assert.Zero(t, h.runs.count(), "%s is not in the replay set", slot)
	}
	// The drain, in the set, replayed the pending row once under the real
	// resolution, now v2.
	env.requireRow(business.DeliveryStatusDelivered, "")
	assert.Equal(t, int32(4), env.sentCount.Load(), "three signing probes and the drain row")
}

func TestLateReplaySlotsIsTheExplicitSigningSet(t *testing.T) {
	t.Parallel()
	assert.Equal(t,
		[]service.ConnectHookSlot{service.SlotSigningRotation, service.SlotMigration, service.SlotDrain, service.SlotTransportAddress},
		service.LateReplaySlots())
	for _, slot := range []service.ConnectHookSlot{
		service.SlotRegistry, service.SlotCompletionReconcile, service.SlotRouting, service.SlotLockdown, service.SlotRepair,
	} {
		assert.NotContains(t, service.LateReplaySlots(), slot)
	}
	// The returned list is a copy.
	service.LateReplaySlots()[0] = service.SlotRegistry
	assert.Equal(t, service.SlotSigningRotation, service.LateReplaySlots()[0])
}

func TestFloorSentTrackerIsBoundedAndPerConnection(t *testing.T) {
	t.Parallel()
	tr := service.NewFloorSentTracker()

	tr.Track("s1", "conn-a", "row-1")
	conn, ok := tr.ConnectionOf("s1", "row-1")
	require.True(t, ok)
	assert.Equal(t, "conn-a", conn)

	// A new connection replaces the set.
	tr.Track("s1", "conn-b", "row-2")
	_, ok = tr.ConnectionOf("s1", "row-1")
	assert.False(t, ok, "the earlier connection's rows are dropped")

	// A stale connection's callback marks nothing.
	var marked []string
	tr.RefuseAll("s1", "conn-a", func(id string) { marked = append(marked, id) })
	assert.Empty(t, marked)
	tr.RefuseAll("s1", "conn-b", func(id string) { marked = append(marked, id) })
	assert.Equal(t, []string{"row-2"}, marked)
	tr.RefuseAll("s1", "conn-b", func(id string) { marked = append(marked, id) })
	assert.Equal(t, []string{"row-2"}, marked, "a row is marked once")

	// WriteUnlessRefused skips a refused row and writes any other.
	wrote := 0
	tr.WriteUnlessRefused("s1", "row-2", func() { wrote++ })
	assert.Zero(t, wrote)
	tr.WriteUnlessRefused("s1", "other", func() { wrote++ })
	assert.Equal(t, 1, wrote)

	// Untrack drops a row that was never sent.
	tr.Track("s2", "conn-c", "row-3")
	tr.Untrack("s2", "row-3")
	_, ok = tr.ConnectionOf("s2", "row-3")
	assert.False(t, ok)

	// Rows per connection are bounded, oldest first.
	for i := 0; i < 1100; i++ {
		tr.Track("s3", "conn-d", "row-"+time.Duration(i).String())
	}
	_, oldest := tr.ConnectionOf("s3", "row-"+time.Duration(0).String())
	_, newest := tr.ConnectionOf("s3", "row-"+time.Duration(1099).String())
	assert.False(t, oldest, "the oldest row was dropped at the bound")
	assert.True(t, newest)

	// The nil tracker is a no-op.
	var nilTracker *service.FloorSentTracker
	nilTracker.Track("s", "c", "r")
	nilTracker.Untrack("s", "r")
	_, ok = nilTracker.ConnectionOf("s", "r")
	assert.False(t, ok)
	nilTracker.RefuseAll("s", "c", func(string) { t.Fatal("nil tracker marked a row") })
	nilTracker.WriteUnlessRefused("s", "r", func() { wrote++ })
	assert.Equal(t, 2, wrote)
}
