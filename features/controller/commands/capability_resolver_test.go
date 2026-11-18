// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

const resolverTestWait = 150 * time.Millisecond

// nullSender is a connection sender for a registry entry no test writes to.
type nullSender struct{}

func (nullSender) SendMsg(interface{}) error { return nil }

// resolverFixture is a real registry and a real steward store behind a resolver.
type resolverFixture struct {
	t        *testing.T
	id       string
	reg      *registry.InMemoryRegistry
	store    business.StewardStore
	resolver *commands.CapabilityResolver
}

func newResolverFixture(t *testing.T, opts ...commands.CapabilityResolverOption) *resolverFixture {
	t.Helper()
	f := &resolverFixture{t: t, id: "steward-r1", reg: registry.NewRegistry()}
	f.store = pkgtesting.SetupTestStorage(t).GetStewardStore()
	require.NotNil(t, f.store)
	require.NoError(t, f.store.RegisterSteward(context.Background(), &business.StewardRecord{
		ID: f.id, TenantID: "tenant-a", Status: business.StewardStatusActive,
		RegisteredAt: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}))
	all := append([]commands.CapabilityResolverOption{
		commands.WithCapabilityResolveWait(resolverTestWait),
		commands.WithCapabilityPollInterval(10 * time.Millisecond),
	}, opts...)
	f.resolver = commands.NewCapabilityResolver(f.reg, f.store, logging.NewNoopLogger(), all...)
	return f
}

// connect registers a connection started connectedAgo ago whose durable record is
// reset to pending, as the stream handler does on admission.
func (f *resolverFixture) connect(connID string, connectedAgo time.Duration) *registry.StewardConnection {
	f.t.Helper()
	conn := &registry.StewardConnection{
		StewardID: f.id, Sender: nullSender{}, ConnectionID: connID,
		ConnectedAt: time.Now().Add(-connectedAgo),
	}
	require.NoError(f.t, f.store.ResetCapabilities(context.Background(), f.id, connID))
	require.NoError(f.t, f.reg.Register(conn))
	return conn
}

// seedOld stores a record that belongs to an earlier connection.
func (f *resolverFixture) seedOld(state string, vers []uint32) {
	f.t.Helper()
	ctx := context.Background()
	require.NoError(f.t, f.store.ResetCapabilities(ctx, f.id, "old-connection"))
	applied, err := f.store.DeclareCapabilities(ctx, f.id, "old-connection", business.StewardCapabilityRecord{
		State: state, CommandTypes: []int32{1, 2, 3}, SigningPayloadVersions: vers,
	})
	require.NoError(f.t, err)
	require.True(f.t, applied)
}

func (f *resolverFixture) version(ctx context.Context) uint32 {
	return f.resolver.SigningVersionFor(ctx, f.id)
}

func current() []uint32 { return []uint32{types.SigningPayloadV1, types.SigningPayloadV2} }

func TestCapabilityResolver_OwningNodeUsesConnectionState(t *testing.T) {
	cases := []struct {
		name   string
		settle func(c *registry.StewardConnection)
		want   uint32
	}{
		{"declared current", func(c *registry.StewardConnection) {
			c.SettleCapabilities(registry.CapabilityDeclared, []int32{1}, current())
		}, types.SigningPayloadV2},
		{"declared v1 only", func(c *registry.StewardConnection) {
			c.SettleCapabilities(registry.CapabilityDeclared, []int32{1}, []uint32{1})
		}, types.SigningPayloadV1},
		{"declared nothing signable falls to current", func(c *registry.StewardConnection) {
			c.SettleCapabilities(registry.CapabilityDeclared, []int32{1}, []uint32{3})
		}, types.SigningPayloadV2},
		{"floor", func(c *registry.StewardConnection) {
			c.SettleCapabilities(registry.CapabilityFloor, []int32{1}, []uint32{1})
		}, types.SigningPayloadV1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newResolverFixture(t)
			tc.settle(f.connect("conn-1", 0))
			start := time.Now()
			assert.Equal(t, tc.want, f.version(context.Background()))
			assert.Less(t, time.Since(start), resolverTestWait/2, "a settled connection never waits")
		})
	}
}

func TestCapabilityResolver_PendingConnectionDeclaresDuringTheWait(t *testing.T) {
	f := newResolverFixture(t, commands.WithCapabilityResolveWait(5*time.Second))
	conn := f.connect("conn-1", 0)
	go func() {
		time.Sleep(40 * time.Millisecond)
		conn.SettleCapabilities(registry.CapabilityDeclared, []int32{1}, current())
	}()
	start := time.Now()
	assert.Equal(t, types.SigningPayloadV2, f.version(context.Background()))
	assert.Less(t, time.Since(start), 2*time.Second, "the wait ends when the connection settles")
}

// Rollback reconnect: the stored record says current, the new connection declares
// nothing. After the bounded wait the command is signed v1.
func TestCapabilityResolver_RollbackReconnectSignsV1AfterTheWait(t *testing.T) {
	f := newResolverFixture(t)
	f.seedOld(business.StewardCapabilityDeclared, current())
	f.connect("conn-new", 0) // pending; never declares

	start := time.Now()
	assert.Equal(t, types.SigningPayloadV1, f.version(context.Background()))
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, resolverTestWait/2, "waits for the declaration first")
	assert.Less(t, elapsed, 3*time.Second)
}

// The wait is measured from the connection start, not from the call.
func TestCapabilityResolver_PublishLongAfterConnectToSilentStewardReturnsFloorAtOnce(t *testing.T) {
	f := newResolverFixture(t, commands.WithCapabilityResolveWait(5*time.Second))
	f.connect("conn-1", 10*time.Second)

	start := time.Now()
	assert.Equal(t, types.SigningPayloadV1, f.version(context.Background()))
	assert.Less(t, time.Since(start), 500*time.Millisecond)
}

func TestCapabilityResolver_NonOwningNodeReadsTheDurableRecord(t *testing.T) {
	t.Run("no record is current", func(t *testing.T) {
		f := newResolverFixture(t)
		assert.Equal(t, types.SigningPayloadV2, f.version(context.Background()))
	})
	t.Run("unknown steward is current", func(t *testing.T) {
		f := newResolverFixture(t)
		assert.Equal(t, types.SigningPayloadV2, f.resolver.SigningVersionFor(context.Background(), "nobody"))
	})
	t.Run("declared current", func(t *testing.T) {
		f := newResolverFixture(t)
		f.seedOld(business.StewardCapabilityDeclared, current())
		assert.Equal(t, types.SigningPayloadV2, f.version(context.Background()))
	})
	t.Run("declared v1 only", func(t *testing.T) {
		f := newResolverFixture(t)
		f.seedOld(business.StewardCapabilityDeclared, []uint32{1})
		assert.Equal(t, types.SigningPayloadV1, f.version(context.Background()))
	})
	t.Run("floor", func(t *testing.T) {
		f := newResolverFixture(t)
		f.seedOld(business.StewardCapabilityFloor, []uint32{1})
		assert.Equal(t, types.SigningPayloadV1, f.version(context.Background()))
	})
}

// Upgrade reconnect, seen from another node: the stored floor record is replaced
// by the new connection's pending record, and the declaration that follows wins.
func TestCapabilityResolver_NonOwningNodeWaitsOnPendingForTheDeclaration(t *testing.T) {
	f := newResolverFixture(t, commands.WithCapabilityResolveWait(5*time.Second))
	f.seedOld(business.StewardCapabilityFloor, []uint32{1})
	require.NoError(t, f.store.ResetCapabilities(context.Background(), f.id, "conn-new"))
	go func() {
		time.Sleep(40 * time.Millisecond)
		_, _ = f.store.DeclareCapabilities(context.Background(), f.id, "conn-new", business.StewardCapabilityRecord{
			State: business.StewardCapabilityDeclared, CommandTypes: []int32{1}, SigningPayloadVersions: current(),
		})
	}()
	assert.Equal(t, types.SigningPayloadV2, f.version(context.Background()))
}

// A pending connection never takes the previous connection's record: a stored
// current record does not make a silent new connection current.
func TestCapabilityResolver_PendingNeverUsesThePreviousConnectionsRecord(t *testing.T) {
	t.Run("non-owning", func(t *testing.T) {
		f := newResolverFixture(t)
		f.seedOld(business.StewardCapabilityDeclared, current())
		require.NoError(t, f.store.ResetCapabilities(context.Background(), f.id, "conn-new"))
		assert.Equal(t, types.SigningPayloadV1, f.version(context.Background()))
	})
	t.Run("owning", func(t *testing.T) {
		f := newResolverFixture(t)
		f.seedOld(business.StewardCapabilityDeclared, current())
		f.connect("conn-new", 0)
		assert.Equal(t, types.SigningPayloadV1, f.version(context.Background()))
	})
	t.Run("owning, durable reset lost", func(t *testing.T) {
		f := newResolverFixture(t)
		f.seedOld(business.StewardCapabilityDeclared, current())
		conn := &registry.StewardConnection{StewardID: f.id, Sender: nullSender{}, ConnectionID: "conn-new", ConnectedAt: time.Now()}
		conn.MarkCapabilityDurableLost()
		require.NoError(t, f.reg.Register(conn))
		assert.Equal(t, types.SigningPayloadV1, f.version(context.Background()), "the stale stored record is not read")
	})
}

func TestCapabilityResolver_NonOwningPendingBoundIsMeasuredFromTheRecordStart(t *testing.T) {
	var offset atomic.Int64
	clock := func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	f := newResolverFixture(t, commands.WithCapabilityResolveWait(5*time.Second), commands.WithCapabilityResolverClock(clock))
	require.NoError(t, f.store.ResetCapabilities(context.Background(), f.id, "conn-new"))

	offset.Store(int64(10 * time.Second)) // the publish happens 10 s after connect
	start := time.Now()
	assert.Equal(t, types.SigningPayloadV1, f.version(context.Background()))
	assert.Less(t, time.Since(start), 500*time.Millisecond)
}

func TestCapabilityResolver_ContextEndsTheWait(t *testing.T) {
	f := newResolverFixture(t, commands.WithCapabilityResolveWait(30*time.Second))
	f.connect("conn-1", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	assert.Equal(t, types.SigningPayloadV1, f.version(ctx), "an unsettled connection is floor")
	assert.Less(t, time.Since(start), 2*time.Second)

	// The same for a connection this node does not hold.
	g := newResolverFixture(t, commands.WithCapabilityResolveWait(30*time.Second))
	require.NoError(t, g.store.ResetCapabilities(context.Background(), g.id, "conn-new"))
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	start = time.Now()
	assert.Equal(t, types.SigningPayloadV1, g.version(ctx2))
	assert.Less(t, time.Since(start), 2*time.Second)
}

// failingReader is a steward store whose read fails.
type failingReader struct{ business.StewardStore }

func (failingReader) GetSteward(context.Context, string) (*business.StewardRecord, error) {
	return nil, errors.New("store down")
}

func TestCapabilityResolver_UnreadableRecordIsCurrent(t *testing.T) {
	r := commands.NewCapabilityResolver(registry.NewRegistry(), failingReader{}, logging.NewNoopLogger())
	assert.Equal(t, types.SigningPayloadV2, r.SigningVersionFor(context.Background(), "s"))
}

func TestCapabilityResolver_NilResolverAndNilSourcesAreCurrent(t *testing.T) {
	var nilResolver *commands.CapabilityResolver
	assert.Equal(t, types.SigningPayloadV2, nilResolver.SigningVersionFor(context.Background(), "s"))
	r := commands.NewCapabilityResolver(nil, nil, logging.NewNoopLogger())
	assert.Equal(t, types.SigningPayloadV2, r.SigningVersionFor(context.Background(), "s"))
}

func TestCapabilityResolver_DefaultWaitIsThreeSeconds(t *testing.T) {
	assert.Equal(t, 3*time.Second, commands.DefaultCapabilityResolveWait)
}
