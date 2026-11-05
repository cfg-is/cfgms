// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package fleet_test

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

func newStewardStore(t *testing.T) business.StewardStore {
	t.Helper()
	store := pkgtesting.SetupTestStorage(t).GetStewardStore()
	require.NotNil(t, store)
	return store
}

// failingReadStore is a real StewardStore whose reads fail, to drive the
// fail-closed paths.
type failingReadStore struct{ business.StewardStore }

func (failingReadStore) GetSteward(context.Context, string) (*business.StewardRecord, error) {
	return nil, errors.New("store unavailable")
}

func registerSteward(t *testing.T, store business.StewardStore, id string, status business.StewardStatus) {
	t.Helper()
	require.NoError(t, store.RegisterSteward(context.Background(), &business.StewardRecord{
		ID: id, TenantID: "tenant-a", Hostname: id, Platform: "linux", Status: status,
		RegisteredAt: time.Now(), LastSeen: time.Now(),
	}))
}

func setStatus(t *testing.T, store business.StewardStore, id string, to business.StewardStatus, from ...business.StewardStatus) {
	t.Helper()
	ok, err := store.TransitionStewardStatus(context.Background(), id, to, from...)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestIsLockedDown_TrueOnlyForTampered(t *testing.T) {
	store := newStewardStore(t)
	ld := fleet.NewLockdown(store, logging.NewNoopLogger())
	ctx := context.Background()

	statuses := []business.StewardStatus{
		business.StewardStatusRegistered, business.StewardStatusActive, business.StewardStatusLost,
		business.StewardStatusTampered,
	}
	for _, st := range statuses {
		id := "s-" + string(st)
		registerSteward(t, store, id, st)
		locked, err := ld.IsLockedDown(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, st == business.StewardStatusTampered, locked, "status %s", st)
	}
}

func TestIsLockedDown_FailsClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown steward", func(t *testing.T) {
		ld := fleet.NewLockdown(newStewardStore(t), logging.NewNoopLogger())
		locked, err := ld.IsLockedDown(ctx, "nobody")
		require.Error(t, err)
		assert.True(t, locked)
	})

	t.Run("store error", func(t *testing.T) {
		store := newStewardStore(t)
		registerSteward(t, store, "s1", business.StewardStatusActive)
		ld := fleet.NewLockdown(failingReadStore{store}, logging.NewNoopLogger())
		locked, err := ld.IsLockedDown(ctx, "s1")
		require.Error(t, err)
		assert.True(t, locked)
	})

	t.Run("no store", func(t *testing.T) {
		locked, err := fleet.NewLockdown(nil, logging.NewNoopLogger()).IsLockedDown(ctx, "s1")
		require.Error(t, err)
		assert.True(t, locked)
	})
}

// A transition made through the shared store is seen by every Lockdown (every
// controller node) on its very next call: nothing is cached.
func TestIsLockedDown_TransitionVisibleToOtherNodeImmediately(t *testing.T) {
	store := newStewardStore(t)
	registerSteward(t, store, "s1", business.StewardStatusActive)
	nodeA := fleet.NewLockdown(store, logging.NewNoopLogger())
	nodeB := fleet.NewLockdown(store, logging.NewNoopLogger())
	ctx := context.Background()

	locked, err := nodeB.IsLockedDown(ctx, "s1")
	require.NoError(t, err)
	require.False(t, locked)

	setStatus(t, store, "s1", business.StewardStatusTampered, business.StewardStatusActive)
	for _, n := range []*fleet.Lockdown{nodeA, nodeB} {
		locked, err = n.IsLockedDown(ctx, "s1")
		require.NoError(t, err)
		assert.True(t, locked)
	}

	setStatus(t, store, "s1", business.StewardStatusActive, business.StewardStatusTampered)
	locked, err = nodeB.IsLockedDown(ctx, "s1")
	require.NoError(t, err)
	assert.False(t, locked)
}

// --- send on connect, over a real control channel ---

type tamperRecorder struct {
	mu  sync.Mutex
	got []bool
}

func (r *tamperRecorder) hooks() interfaces.InboundHooks {
	return interfaces.InboundHooks{OnTamperState: func(locked bool) {
		r.mu.Lock()
		r.got = append(r.got, locked)
		r.mu.Unlock()
	}}
}

func (r *tamperRecorder) snapshot() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.got...)
}

type testPKI struct {
	ca        *cert.CA
	caPEM     []byte
	serverTLS *tls.Config
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{Organization: "CFGMS Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	sc, err := ca.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, ValidityDays: 1, KeySize: 2048,
	})
	require.NoError(t, err)
	serverTLS, err := cert.CreateServerTLSConfig(sc.CertificatePEM, sc.PrivateKeyPEM, caPEM, tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}
	return &testPKI{ca: ca, caPEM: caPEM, serverTLS: serverTLS}
}

func (p *testPKI) clientTLS(t *testing.T, id string) *tls.Config {
	t.Helper()
	cc, err := p.ca.GenerateClientCertificate(&cert.ClientCertConfig{CommonName: id, ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	cfg, err := cert.CreateClientTLSConfig(cc.CertificatePEM, cc.PrivateKeyPEM, p.caPEM, "localhost", tls.VersionTLS13)
	require.NoError(t, err)
	cfg.NextProtos = []string{quictransport.ALPNProtocol}
	return cfg
}

// newServer starts a real server-mode provider with the lockdown hook wired the
// way the controller server wires it.
func newServer(t *testing.T, pki *testPKI, ld *fleet.Lockdown) (*grpcCP.Provider, registry.Registry) {
	t.Helper()
	reg := registry.NewRegistry()
	server := grpcCP.New(grpcCP.ModeServer, grpcCP.WithOnConnectHook(ld))
	ld.SetSender(server)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": pki.serverTLS, "registry": reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)
	return server, reg
}

func connect(t *testing.T, pki *testPKI, server *grpcCP.Provider, reg registry.Registry, id string, rec *tamperRecorder) *grpcCP.Provider {
	t.Helper()
	client := grpcCP.New(grpcCP.ModeClient)
	client.SetInboundHooks(rec.hooks())
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": server.ListenAddr(), "tls_config": pki.clientTLS(t, id), "steward_id": id,
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })
	require.Eventually(t, func() bool { _, ok := reg.Get(id); return ok }, 5*time.Second, 10*time.Millisecond)
	return client
}

func TestTamperStateSentOnConnect(t *testing.T) {
	pki := newTestPKI(t)
	store := newStewardStore(t)
	registerSteward(t, store, "s-tampered", business.StewardStatusTampered)
	registerSteward(t, store, "s-active", business.StewardStatusActive)
	server, reg := newServer(t, pki, fleet.NewLockdown(store, logging.NewNoopLogger()))

	tampered, active := &tamperRecorder{}, &tamperRecorder{}
	connect(t, pki, server, reg, "s-tampered", tampered)
	connect(t, pki, server, reg, "s-active", active)

	require.Eventually(t, func() bool { return len(tampered.snapshot()) == 1 && len(active.snapshot()) == 1 },
		5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []bool{true}, tampered.snapshot())
	assert.Equal(t, []bool{false}, active.snapshot())
}

func TestTamperStateSentOnConnect_RestoredWhileOffline(t *testing.T) {
	pki := newTestPKI(t)
	store := newStewardStore(t)
	registerSteward(t, store, "s1", business.StewardStatusActive)
	server, reg := newServer(t, pki, fleet.NewLockdown(store, logging.NewNoopLogger()))

	first := &tamperRecorder{}
	c1 := connect(t, pki, server, reg, "s1", first)
	require.Eventually(t, func() bool { return len(first.snapshot()) == 1 }, 5*time.Second, 10*time.Millisecond)

	// The steward goes offline and is marked tampered, then restored, while away.
	require.NoError(t, c1.Stop(context.Background()))
	require.Eventually(t, func() bool { _, ok := reg.Get("s1"); return !ok }, 5*time.Second, 10*time.Millisecond)
	setStatus(t, store, "s1", business.StewardStatusTampered, business.StewardStatusActive)
	setStatus(t, store, "s1", business.StewardStatusActive, business.StewardStatusTampered)

	second := &tamperRecorder{}
	connect(t, pki, server, reg, "s1", second)
	require.Eventually(t, func() bool { return len(second.snapshot()) == 1 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []bool{false}, second.snapshot())
}

func TestTamperStateSentToConnectedStewardOnTransition(t *testing.T) {
	pki := newTestPKI(t)
	store := newStewardStore(t)
	registerSteward(t, store, "s1", business.StewardStatusActive)
	ld := fleet.NewLockdown(store, logging.NewNoopLogger())
	server, reg := newServer(t, pki, ld)

	rec := &tamperRecorder{}
	connect(t, pki, server, reg, "s1", rec)
	require.Eventually(t, func() bool { return len(rec.snapshot()) == 1 }, 5*time.Second, 10*time.Millisecond)

	setStatus(t, store, "s1", business.StewardStatusTampered, business.StewardStatusActive)
	require.NoError(t, ld.NotifyTransition(context.Background(), "s1"))

	require.Eventually(t, func() bool { return len(rec.snapshot()) == 2 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []bool{false, true}, rec.snapshot())
}

func TestNotifyTransition_NoSender(t *testing.T) {
	store := newStewardStore(t)
	registerSteward(t, store, "s1", business.StewardStatusTampered)
	require.Error(t, fleet.NewLockdown(store, logging.NewNoopLogger()).NotifyTransition(context.Background(), "s1"))
}

// A store failure must tell the steward it is locked, never unlocked.
func TestTamperStateSentOnConnect_StoreErrorCountsAsLocked(t *testing.T) {
	pki := newTestPKI(t)
	store := newStewardStore(t)
	registerSteward(t, store, "s1", business.StewardStatusActive)
	ld := fleet.NewLockdown(failingReadStore{store}, logging.NewNoopLogger())
	server, reg := newServer(t, pki, ld)

	rec := &tamperRecorder{}
	connect(t, pki, server, reg, "s1", rec)
	require.Eventually(t, func() bool { return len(rec.snapshot()) == 1 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, []bool{true}, rec.snapshot())
}
