// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service_test

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/service"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// capStore wraps a real StewardStore so a test can fail the reset, and hold the
// durable declaration write until released.
type capStore struct {
	business.StewardStore
	resetErr    error
	declareGate chan struct{}
}

func (c *capStore) ResetCapabilities(ctx context.Context, stewardID, connectionID string) error {
	if c.resetErr != nil {
		return c.resetErr
	}
	return c.StewardStore.ResetCapabilities(ctx, stewardID, connectionID)
}

func (c *capStore) DeclareCapabilities(ctx context.Context, stewardID, connectionID string, rec business.StewardCapabilityRecord) (bool, error) {
	if c.declareGate != nil {
		select {
		case <-c.declareGate:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return c.StewardStore.DeclareCapabilities(ctx, stewardID, connectionID, rec)
}

// capFixture is a real controller-side gRPC provider whose capability recorder is
// a ControllerService over a real steward store, plus the client TLS material.
type capFixture struct {
	stewardID string
	store     business.StewardStore
	svc       *service.ControllerService
	server    *grpcCP.Provider
	reg       registry.Registry
	clientTLS *tls.Config
}

func newCapStore(t *testing.T, stewardID string) business.StewardStore {
	t.Helper()
	store := pkgtesting.SetupTestStorage(t).GetStewardStore()
	require.NotNil(t, store)
	require.NoError(t, store.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:           stewardID,
		TenantID:     "tenant-a",
		Status:       business.StewardStatusActive,
		RegisteredAt: time.Now().UTC(),
		LastSeen:     time.Now().UTC(),
	}))
	return store
}

// seedRecord stores a capability record that belongs to an earlier connection.
func seedRecord(t *testing.T, store business.StewardStore, stewardID, state string, cmds []int32, vers []uint32) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.ResetCapabilities(ctx, stewardID, "old-connection"))
	applied, err := store.DeclareCapabilities(ctx, stewardID, "old-connection", business.StewardCapabilityRecord{
		State: state, CommandTypes: cmds, SigningPayloadVersions: vers,
	})
	require.NoError(t, err)
	require.True(t, applied)
}

// capConfig is what a test varies on the controller side. Zero values are the
// provider defaults: the default grace, no on-connect hook, no late callback.
type capConfig struct {
	grace  time.Duration
	hook   func(svc *service.ControllerService) grpcCP.StewardOnConnectHook
	onLate func(ctx context.Context, stewardID string)
}

// newCapFixture starts the controller side. store is what the service writes to
// (a wrapper around the real store for fault injection).
func newCapFixture(t *testing.T, stewardID string, store business.StewardStore, cfg capConfig) *capFixture {
	t.Helper()
	f := &capFixture{stewardID: stewardID, store: store, reg: registry.NewRegistry()}
	f.svc = service.NewControllerService(logging.NewNoopLogger())
	f.svc.SetStewardStore(store)
	f.svc.SetCapabilityPollInterval(20 * time.Millisecond)

	var serverTLS *tls.Config
	serverTLS, f.clientTLS = tlsForTest(t, stewardID)
	var hook grpcCP.StewardOnConnectHook
	if cfg.hook != nil {
		hook = cfg.hook(f.svc)
	}
	f.server = grpcCP.New(grpcCP.ModeServer,
		grpcCP.WithCapabilityRecorder(f.svc),
		grpcCP.WithCapabilityGrace(cfg.grace),
		grpcCP.WithOnConnectHook(hook),
		grpcCP.WithOnLateCapabilities(cfg.onLate))
	require.NoError(t, f.server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": serverTLS, "registry": f.reg,
	}))
	require.NoError(t, f.server.Start(context.Background()))
	t.Cleanup(f.server.ForceStop)
	return f
}

// connect starts a steward-side provider; declare chooses whether it declares
// its build's capabilities as the first message of its stream.
func (f *capFixture) connect(t *testing.T, declare bool) (*grpcCP.Provider, *registry.StewardConnection) {
	t.Helper()
	client := grpcCP.New(grpcCP.ModeClient)
	if declare {
		client = grpcCP.New(grpcCP.ModeClient, grpcCP.WithStewardCapabilities(grpcCP.LocalCapabilities(f.stewardID)))
	}
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": f.server.ListenAddr(), "tls_config": f.clientTLS, "steward_id": f.stewardID,
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	var conn *registry.StewardConnection
	require.Eventually(t, func() bool {
		c, ok := f.reg.Get(f.stewardID)
		conn = c
		return ok
	}, 5*time.Second, 10*time.Millisecond, "steward should register")
	return client, conn
}

func (f *capFixture) record(t *testing.T) *business.StewardCapabilityRecord {
	t.Helper()
	rec, err := f.store.GetSteward(context.Background(), f.stewardID)
	require.NoError(t, err)
	return rec.Capabilities
}

func (f *capFixture) requireRecordState(t *testing.T, state string) *business.StewardCapabilityRecord {
	t.Helper()
	var rec *business.StewardCapabilityRecord
	require.Eventually(t, func() bool {
		rec = f.record(t)
		return rec != nil && rec.State == state
	}, 10*time.Second, 20*time.Millisecond, "durable record should reach %s", state)
	return rec
}

// onConnectProbe is an on-connect hook that, like the replay hooks, waits for the
// connection's capabilities before it would build its first command, and reports
// what it saw.
type onConnectProbe struct {
	svc  *service.ControllerService
	seen chan types.CapabilityProfile
}

func (p *onConnectProbe) OnConnect(ctx context.Context, stewardID string) error {
	profile, err := p.svc.WaitCapabilities(ctx, stewardID)
	if err != nil {
		return err
	}
	p.seen <- profile
	return nil
}

func TestCapabilitiesDeclaredBeforeOnConnectCommands(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-cap-before-hook"
	store := newCapStore(t, stewardID)
	// The stored record says floor, from an earlier connection.
	floor := types.FloorProfile()
	seedRecord(t, store, stewardID, business.StewardCapabilityFloor, floor.CommandTypes, floor.SigningPayloadVersions)

	probe := &onConnectProbe{seen: make(chan types.CapabilityProfile, 4)}
	// A long grace: the hook can only see declared by the declaration, not the timer.
	f := newCapFixture(t, stewardID, store, capConfig{
		grace: time.Minute,
		hook:  func(svc *service.ControllerService) grpcCP.StewardOnConnectHook { probe.svc = svc; return probe },
	})
	_, conn := f.connect(t, true)

	select {
	case profile := <-probe.seen:
		assert.Equal(t, types.CapabilityDeclared, profile.State, "the hook builds its commands against the declared profile")
		assert.True(t, profile.SupportsSigningPayloadVersion(types.SigningPayloadV2))
		assert.Equal(t, grpcCP.LocalCapabilities(stewardID).CommandTypes, profile.CommandTypes)
	case <-time.After(10 * time.Second):
		t.Fatal("on-connect hook never saw the connection's capabilities")
	}

	rec := f.requireRecordState(t, business.StewardCapabilityDeclared)
	assert.Equal(t, conn.ConnectionID, rec.ConnectionID, "the record is this connection's, not the stored floor one")
	assert.Contains(t, rec.SigningPayloadVersions, types.SigningPayloadV2)
}

func TestCapabilitiesSettledSignalRaceOutcomes(t *testing.T) {
	t.Parallel()

	t.Run("a declaring steward releases the signal on its first message", func(t *testing.T) {
		t.Parallel()
		const stewardID = "steward-cap-race-declare"
		f := newCapFixture(t, stewardID, newCapStore(t, stewardID), capConfig{grace: time.Minute})
		_, conn := f.connect(t, true)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		profile, err := f.svc.WaitCapabilities(ctx, stewardID)
		require.NoError(t, err)
		assert.Equal(t, types.CapabilityDeclared, profile.State)
		assert.Equal(t, registry.CapabilityDeclared, conn.CapabilitySnapshot().State)

		// The signal is released from memory before the durable write lands; wait
		// for the write so the test does not end with it still running.
		rec := f.requireRecordState(t, business.StewardCapabilityDeclared)
		assert.Equal(t, conn.ConnectionID, rec.ConnectionID)
	})

	t.Run("a silent steward releases it at the grace and the record becomes floor", func(t *testing.T) {
		t.Parallel()
		const stewardID = "steward-cap-race-silent"
		f := newCapFixture(t, stewardID, newCapStore(t, stewardID), capConfig{grace: 300 * time.Millisecond})
		start := time.Now()
		_, conn := f.connect(t, false)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		profile, err := f.svc.WaitCapabilities(ctx, stewardID)
		require.NoError(t, err)
		assert.Equal(t, types.CapabilityFloor, profile.State)
		assert.Equal(t, types.FloorProfile(), profile)
		assert.GreaterOrEqual(t, time.Since(start), 250*time.Millisecond, "the signal waited for the grace")

		rec := f.requireRecordState(t, business.StewardCapabilityFloor)
		assert.Equal(t, conn.ConnectionID, rec.ConnectionID)
	})
}

func TestCapabilitiesLateDeclarationIsDurableAndCallsBackOnce(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-cap-late-durable"
	var calls atomic.Int32
	f := newCapFixture(t, stewardID, newCapStore(t, stewardID), capConfig{
		grace: 100 * time.Millisecond,
		onLate: func(_ context.Context, id string) {
			if id == stewardID {
				calls.Add(1)
			}
		},
	})
	client, conn := f.connect(t, false)

	floorRec := f.requireRecordState(t, business.StewardCapabilityFloor)
	assert.Equal(t, conn.ConnectionID, floorRec.ConnectionID)
	assert.Zero(t, calls.Load(), "no late callback for a floor settle")

	local := grpcCP.LocalCapabilities(stewardID)
	require.NoError(t, client.SendCapabilities(context.Background(), &local))

	declared := f.requireRecordState(t, business.StewardCapabilityDeclared)
	assert.Equal(t, conn.ConnectionID, declared.ConnectionID, "the late write is a compare-and-set on this connection")
	assert.Equal(t, local.CommandTypes, declared.CommandTypes)
	assert.Equal(t, registry.CapabilityDeclared, conn.CapabilitySnapshot().State, "memory moved with it")
	require.Eventually(t, func() bool { return calls.Load() == 1 }, 5*time.Second, 10*time.Millisecond)

	// A second declaration on the same connection does not call back again.
	require.NoError(t, client.SendCapabilities(context.Background(), &local))
	require.NoError(t, client.SendHeartbeat(context.Background(), &types.Heartbeat{StewardID: stewardID}))
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, int32(1), calls.Load())
}

func TestCapabilitiesNonOwningNodeWaitsOnPendingThenSeesDeclared(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-cap-non-owner"
	store := newCapStore(t, stewardID)
	f := newCapFixture(t, stewardID, store, capConfig{grace: time.Minute})
	// A second node: it shares the store and owns no connection.
	other := service.NewControllerService(logging.NewNoopLogger())
	other.SetStewardStore(store)
	other.SetCapabilityPollInterval(20 * time.Millisecond)

	client, _ := f.connect(t, false)
	profile, err := other.CapabilityProfile(context.Background(), stewardID)
	require.NoError(t, err)
	assert.Equal(t, types.CapabilityPending, profile.State)

	type result struct {
		profile types.CapabilityProfile
		err     error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		p, err := other.WaitCapabilities(ctx, stewardID)
		done <- result{p, err}
	}()

	select {
	case r := <-done:
		t.Fatalf("a pending record must make the non-owning node wait, got %+v", r)
	case <-time.After(300 * time.Millisecond):
	}

	local := grpcCP.LocalCapabilities(stewardID)
	require.NoError(t, client.SendCapabilities(context.Background(), &local))
	select {
	case r := <-done:
		require.NoError(t, r.err)
		assert.Equal(t, types.CapabilityDeclared, r.profile.State)
		assert.Equal(t, local.CommandTypes, r.profile.CommandTypes)
	case <-time.After(10 * time.Second):
		t.Fatal("non-owning node never saw the declaration")
	}
}

func TestCapabilitiesNonOwningNodeNeverSeesPreviousConnectionProfile(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-cap-reconnect-stale"
	store := newCapStore(t, stewardID)
	f := newCapFixture(t, stewardID, store, capConfig{grace: time.Minute})
	other := service.NewControllerService(logging.NewNoopLogger())
	other.SetStewardStore(store)

	first, firstConn := f.connect(t, true)
	profile, err := other.WaitCapabilities(context.Background(), stewardID)
	require.NoError(t, err)
	require.Equal(t, types.CapabilityDeclared, profile.State, "the first connection declared v2")
	require.NoError(t, first.Stop(context.Background()))
	require.Eventually(t, func() bool {
		c, ok := f.reg.Get(stewardID)
		return !ok || c != firstConn
	}, 10*time.Second, 20*time.Millisecond, "the first connection ends")

	// The next connection is from a steward that does not declare.
	_, secondConn := f.connect(t, false)
	require.NotEqual(t, firstConn.ConnectionID, secondConn.ConnectionID)

	profile, err = other.CapabilityProfile(context.Background(), stewardID)
	require.NoError(t, err)
	assert.Equal(t, types.CapabilityPending, profile.State, "the previous connection's declared profile is gone")
	assert.Empty(t, profile.CommandTypes)

	rec := f.record(t)
	require.NotNil(t, rec)
	assert.Equal(t, secondConn.ConnectionID, rec.ConnectionID)
	assert.Equal(t, business.StewardCapabilityPending, rec.State)
	assert.Empty(t, rec.CommandTypes, "no stale carry-over of the earlier sets")
}

func TestCapabilitiesEveryNewStreamResetsRecordToPending(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-cap-reset-each"
	store := newCapStore(t, stewardID)
	seedRecord(t, store, stewardID, business.StewardCapabilityDeclared, []int32{1, 2, 3}, []uint32{1, 2})
	f := newCapFixture(t, stewardID, store, capConfig{grace: time.Minute})

	_, conn := f.connect(t, false)
	// The reset is synchronous in the registration path, so it is done by the
	// time the connection is visible.
	rec := f.record(t)
	require.NotNil(t, rec)
	assert.Equal(t, business.StewardCapabilityPending, rec.State)
	assert.Equal(t, conn.ConnectionID, rec.ConnectionID)
	assert.NotEqual(t, "old-connection", rec.ConnectionID)
	assert.Empty(t, rec.CommandTypes)
	assert.Empty(t, rec.SigningPayloadVersions)

	// A connection that never declares stays pending (grace is a minute).
	time.Sleep(300 * time.Millisecond)
	rec = f.record(t)
	assert.Equal(t, business.StewardCapabilityPending, rec.State)
	profile, err := f.svc.CapabilityProfile(context.Background(), stewardID)
	require.NoError(t, err)
	assert.Equal(t, types.CapabilityPending, profile.State)
}

func TestCapabilitiesFailedResetFailsClosed(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T, stewardID string, g time.Duration) (*capFixture, *registry.StewardConnection) {
		t.Helper()
		real := newCapStore(t, stewardID)
		// The stored record is a previous connection's declared v2 profile.
		seedRecord(t, real, stewardID, business.StewardCapabilityDeclared, []int32{1, 2, 7}, []uint32{1, 2})
		store := &capStore{StewardStore: real, resetErr: errors.New("store unavailable")}
		f := newCapFixture(t, stewardID, store, capConfig{grace: g})
		_, conn := f.connect(t, false)
		return f, conn
	}

	t.Run("the resolver reports pending and never the old stored record", func(t *testing.T) {
		t.Parallel()
		const stewardID = "steward-cap-resetfail-pending"
		f, _ := setup(t, stewardID, time.Minute)

		profile, err := f.svc.CapabilityProfile(context.Background(), stewardID)
		require.NoError(t, err)
		assert.Equal(t, types.CapabilityPending, profile.State)
		assert.Empty(t, profile.CommandTypes)

		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		profile, err = f.svc.WaitCapabilities(ctx, stewardID)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, types.CapabilityPending, profile.State, "waiting does not fall back to the stored record")
	})

	t.Run("a connection that settles takes the floor, not the old record, and writes nothing", func(t *testing.T) {
		t.Parallel()
		const stewardID = "steward-cap-resetfail-floor"
		f, _ := setup(t, stewardID, 150*time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		profile, err := f.svc.WaitCapabilities(ctx, stewardID)
		require.NoError(t, err)
		assert.Equal(t, types.CapabilityFloor, profile.State)
		assert.False(t, profile.SupportsCommandType(14))

		time.Sleep(200 * time.Millisecond)
		rec := f.record(t)
		require.NotNil(t, rec)
		assert.Equal(t, "old-connection", rec.ConnectionID, "no durable write for a connection whose reset failed")
		assert.Equal(t, business.StewardCapabilityDeclared, rec.State)
	})
}

func TestCapabilitiesReceiveLoopDoesNotBlockOnSlowStore(t *testing.T) {
	t.Parallel()
	const stewardID = "steward-cap-slow-store"
	gate := make(chan struct{})
	store := &capStore{StewardStore: newCapStore(t, stewardID), declareGate: gate}
	f := newCapFixture(t, stewardID, store, capConfig{grace: time.Minute})

	var mu sync.Mutex
	var versions []string
	require.NoError(t, f.server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		mu.Lock()
		versions = append(versions, hb.Version)
		mu.Unlock()
		return nil
	}))

	client, conn := f.connect(t, true)
	select {
	case <-conn.CapabilitiesSettled():
	case <-time.After(10 * time.Second):
		t.Fatal("never settled")
	}
	// The store write is parked; the next message on the stream is still read.
	require.NoError(t, client.SendHeartbeat(context.Background(), &types.Heartbeat{StewardID: stewardID, Version: "next-message"}))
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(versions) == 1 && versions[0] == "next-message"
	}, 5*time.Second, 10*time.Millisecond, "a slow store must not delay the next message")
	profile, err := f.svc.CapabilityProfile(context.Background(), stewardID)
	require.NoError(t, err)
	assert.Equal(t, types.CapabilityDeclared, profile.State, "the owning node's copy is current before the write lands")
	assert.Equal(t, business.StewardCapabilityPending, f.record(t).State, "the durable write has not landed")

	close(gate)
	f.requireRecordState(t, business.StewardCapabilityDeclared)
}

func TestCapabilityProfileWithoutRecord(t *testing.T) {
	t.Parallel()
	t.Run("no store reads as pending", func(t *testing.T) {
		svc := service.NewControllerService(logging.NewNoopLogger())
		profile, err := svc.CapabilityProfile(context.Background(), "nobody")
		require.NoError(t, err)
		assert.Equal(t, types.CapabilityPending, profile.State)
	})

	t.Run("unknown steward reads as pending", func(t *testing.T) {
		svc := service.NewControllerService(logging.NewNoopLogger())
		svc.SetStewardStore(newCapStore(t, "known"))
		profile, err := svc.CapabilityProfile(context.Background(), "unknown")
		require.NoError(t, err)
		assert.Equal(t, types.CapabilityPending, profile.State)
	})

	t.Run("a steward that never connected reads as pending and waiting honours the context", func(t *testing.T) {
		svc := service.NewControllerService(logging.NewNoopLogger())
		svc.SetStewardStore(newCapStore(t, "never-connected"))
		svc.SetCapabilityPollInterval(10 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		profile, err := svc.WaitCapabilities(ctx, "never-connected")
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, types.CapabilityPending, profile.State)
	})

	t.Run("an unreadable store is an error and pending", func(t *testing.T) {
		svc := service.NewControllerService(logging.NewNoopLogger())
		real := newCapStore(t, "broken")
		svc.SetStewardStore(&brokenReadStore{StewardStore: real})
		profile, err := svc.CapabilityProfile(context.Background(), "broken")
		require.Error(t, err)
		assert.Equal(t, types.CapabilityPending, profile.State)
	})
}

// brokenReadStore fails every steward read.
type brokenReadStore struct{ business.StewardStore }

func (brokenReadStore) GetSteward(context.Context, string) (*business.StewardRecord, error) {
	return nil, errors.New("read failed")
}
