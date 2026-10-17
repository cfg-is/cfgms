// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tenantTestStewardStore is a real in-memory business.StewardStore holding only
// the records the tenant resolver reads. Every other store method is inherited
// from the embedded interface and panics if called, which keeps the test honest
// about which method the resolver depends on.
type tenantTestStewardStore struct {
	business.StewardStore
	mu      sync.RWMutex
	records map[string]*business.StewardRecord
	err     error
}

func newTenantTestStewardStore(tenantByStewardID map[string]string) *tenantTestStewardStore {
	records := make(map[string]*business.StewardRecord, len(tenantByStewardID))
	for stewardID, tenantID := range tenantByStewardID {
		records[stewardID] = &business.StewardRecord{
			ID:       stewardID,
			TenantID: tenantID,
			Status:   business.StewardStatusActive,
		}
	}
	return &tenantTestStewardStore{records: records}
}

func (s *tenantTestStewardStore) GetSteward(_ context.Context, stewardID string) (*business.StewardRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.err != nil {
		return nil, s.err
	}
	record, ok := s.records[stewardID]
	if !ok {
		return nil, business.ErrStewardNotFound
	}
	return record, nil
}

// tenantResolverFor builds the production resolver over an in-memory fleet record set.
func tenantResolverFor(tenantByStewardID map[string]string) StewardTenantResolver {
	return NewStewardStoreTenantResolver(newTenantTestStewardStore(tenantByStewardID))
}

// tokenStoreFor builds a real in-memory RegistrationTokenStore where each token
// string is bound to a tenant, matching how a registration token carries the
// authoritative tenant at connect time.
func tokenStoreFor(t *testing.T, tenantByToken map[string]string) *inMemoryTokenStore {
	t.Helper()
	store := newInMemoryTokenStore()
	for token, tenantID := range tenantByToken {
		require.NoError(t, store.SaveToken(context.Background(), &business.RegistrationTokenData{
			Token: token, TenantID: tenantID,
		}))
	}
	return store
}

// TestWithTenantAdmission_OptionSetsField verifies that WithTenantAdmission wires
// the admission gate into the Provider struct field.
func TestWithTenantAdmission_OptionSetsField(t *testing.T) {
	t.Parallel()
	queue := controllerTransport.NewTenantQueue()
	p := New(ModeServer, WithTenantAdmission(queue))
	assert.Equal(t, TenantAdmission(queue), p.tenantAdmission)
}

// TestWithStewardTenantResolver_OptionSetsField verifies that the server-side
// steward→tenant resolver — the source of every admission bucket key — is wired
// into the Provider struct field.
func TestWithStewardTenantResolver_OptionSetsField(t *testing.T) {
	t.Parallel()
	resolver := tenantResolverFor(map[string]string{"steward-x": "tenant-x"})
	p := New(ModeServer, WithStewardTenantResolver(resolver))
	assert.Equal(t, resolver, p.stewardTenantResolver)
}

// TestStewardStoreTenantResolver_Semantics pins the resolver's three answers:
// a known steward's tenant, "unknown" (not an error) for a steward with no
// record, and a genuine lookup failure surfaced as an error.
func TestStewardStoreTenantResolver_Semantics(t *testing.T) {
	t.Parallel()

	store := newTenantTestStewardStore(map[string]string{"steward-known": "tenant-known"})
	resolver := NewStewardStoreTenantResolver(store)

	tenantID, err := resolver.TenantForSteward(context.Background(), "steward-known")
	require.NoError(t, err)
	assert.Equal(t, "tenant-known", tenantID)

	tenantID, err = resolver.TenantForSteward(context.Background(), "steward-absent")
	require.NoError(t, err, "a steward with no fleet record is unknown, not a lookup failure")
	assert.Empty(t, tenantID)

	store.err = errors.New("database unavailable")
	_, err = resolver.TenantForSteward(context.Background(), "steward-known")
	require.Error(t, err)
}

// TestValidAdmissionTenantID bounds the admission key space. TenantQueue entries
// are never evicted, so an unbounded or attacker-shaped key is a memory
// exhaustion vector: only bounded-length IDs over the hierarchical tenant-path
// character set may become keys.
func TestValidAdmissionTenantID(t *testing.T) {
	t.Parallel()

	accepted := []string{"tenant-a", "root/msp-a/client-1", "t_1.2", strings.Repeat("a", maxAdmissionTenantIDLen)}
	for _, id := range accepted {
		assert.True(t, validAdmissionTenantID(id), "expected %q to be a valid admission key", id)
	}

	rejected := []string{
		"",
		strings.Repeat("a", maxAdmissionTenantIDLen+1),
		"tenant with spaces",
		"tenant\nid",
		"tenant\x00id",
		"tenant:id", // ':' is reserved for the per-steward bucket namespace
	}
	for _, id := range rejected {
		assert.False(t, validAdmissionTenantID(id), "expected %q to be rejected as an admission key", id)
	}
}

// TestAdmissionBucket_ServerVerifiedSourcesOnly verifies the precedence and the
// fallbacks of the bucket key: a tenant already proven server-side wins; else the
// fleet record's tenant; else — unknown steward, resolver outage, or a record
// value that is not a usable key — the mTLS-verified CN, which is bounded by
// what this controller's CA has issued.
func TestAdmissionBucket_ServerVerifiedSourcesOnly(t *testing.T) {
	t.Parallel()

	resolverStore := newTenantTestStewardStore(map[string]string{
		"steward-known":   "tenant-known",
		"steward-badname": "tenant id with spaces",
	})
	p := New(ModeServer, WithStewardTenantResolver(NewStewardStoreTenantResolver(resolverStore)))
	ctx := context.Background()

	assert.Equal(t, "tenant-proven", p.admissionBucket(ctx, "steward-known", "tenant-proven"),
		"an already-proven tenant must win over the record lookup")
	assert.Equal(t, "tenant-known", p.admissionBucket(ctx, "steward-known", ""))
	assert.Equal(t, stewardBucketPrefix+"steward-absent", p.admissionBucket(ctx, "steward-absent", ""),
		"a steward with no fleet record falls back to its own CN bucket")
	assert.Equal(t, stewardBucketPrefix+"steward-badname", p.admissionBucket(ctx, "steward-badname", ""),
		"an unusable record tenant must not become a queue key")

	resolverStore.err = errors.New("database unavailable")
	assert.Equal(t, stewardBucketPrefix+"steward-known", p.admissionBucket(ctx, "steward-known", ""),
		"a resolver outage degrades to a per-steward bucket, never to an unbounded or shared one")

	noResolver := New(ModeServer)
	assert.Equal(t, stewardBucketPrefix+"steward-known", noResolver.admissionBucket(ctx, "steward-known", ""))
}

// TestRegister_NoTenantAdmissionConfigured_Unaffected verifies that a nil
// admission gate (the default, pre-#3759 behavior) never rejects Register.
func TestRegister_NoTenantAdmissionConfigured_Unaffected(t *testing.T) {
	t.Parallel()
	server := &transportServer{provider: New(ModeServer)}

	resp, err := server.Register(verifiedPeerContext("steward-no-admission"), &controllerpb.RegisterRequest{
		Version:     "1.0.0",
		Credentials: &commonpb.Credentials{TenantId: "any-tenant"},
	})
	require.NoError(t, err)
	assert.Equal(t, "steward-no-admission", resp.GetStewardId())
}

// TestRegister_TenantAdmissionQueueFull_ResourceExhausted verifies that the
// steward connect (Register) path is gated by the same TenantQueue mechanism
// the DNA ingest path already uses (Issue #3759, ADR-031 Decision 6): a
// saturated tenant is rejected with ResourceExhausted, while a different
// tenant registering against the same server is unaffected — the isolation
// property the acceptance criteria requires ("without starving other tenants").
//
// The bucket comes from the registration token's tenant binding, the tenant the
// caller has proven server-side.
func TestRegister_TenantAdmissionQueueFull_ResourceExhausted(t *testing.T) {
	t.Parallel()
	queue := controllerTransport.NewTenantQueue()
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, queue.Acquire("tenant-full"))
	}

	provider := New(ModeServer, WithTenantAdmission(queue))
	provider.registrationTokenStore = tokenStoreFor(t, map[string]string{
		"token-full": "tenant-full",
		"token-ok":   "tenant-ok",
	})
	server := &transportServer{provider: provider}

	_, err := server.Register(verifiedPeerContext("steward-full"), &controllerpb.RegisterRequest{
		Version:     "1.0.0",
		Credentials: &commonpb.Credentials{ClientId: "token-full", TenantId: "tenant-full"},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, st.Code())

	// A different tenant must not be starved by tenant-full's saturation.
	resp, err := server.Register(verifiedPeerContext("steward-ok"), &controllerpb.RegisterRequest{
		Version:     "1.0.0",
		Credentials: &commonpb.Credentials{ClientId: "token-ok", TenantId: "tenant-ok"},
	})
	require.NoError(t, err, "an unrelated tenant must register normally while tenant-full is saturated")
	assert.Equal(t, "steward-ok", resp.GetStewardId())
}

// TestRegister_TenantAdmissionKeyedOnResolvedTenantNotClaimedTenant is the
// cross-tenant denial-of-service regression test for the connect path. A steward
// holding a valid certificate claims a victim tenant in creds.tenant_id; because
// the bucket is keyed on the tenant the controller's own fleet record reports for
// the mTLS-verified CN, the claim selects nothing:
//
//   - the victim tenant being saturated must not block the attacker's own
//     registration (proof the forged field no longer picks the bucket), and
//   - the attacker's own bucket saturation must still reject it, even while it
//     claims a wide-open victim tenant.
func TestRegister_TenantAdmissionKeyedOnResolvedTenantNotClaimedTenant(t *testing.T) {
	t.Parallel()

	queue := controllerTransport.NewTenantQueue()
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, queue.Acquire("tenant-victim"))
	}

	resolver := tenantResolverFor(map[string]string{"steward-attacker": "tenant-attacker"})
	server := &transportServer{provider: New(ModeServer,
		WithTenantAdmission(queue),
		WithStewardTenantResolver(resolver),
	)}

	resp, err := server.Register(verifiedPeerContext("steward-attacker"), &controllerpb.RegisterRequest{
		Version:     "1.0.0",
		Credentials: &commonpb.Credentials{TenantId: "tenant-victim"},
	})
	require.NoError(t, err, "a forged creds.tenant_id must not put the caller in the victim's bucket")
	assert.Equal(t, "steward-attacker", resp.GetStewardId())

	// Conversely, the attacker's own bucket is the one that gates it.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, queue.Acquire("tenant-attacker"))
	}
	_, err = server.Register(verifiedPeerContext("steward-attacker"), &controllerpb.RegisterRequest{
		Version:     "1.0.0",
		Credentials: &commonpb.Credentials{TenantId: "tenant-wide-open"},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, st.Code(),
		"claiming an unsaturated tenant must not buy capacity in the caller's own bucket")
}

// TestRegister_ForgedTenantNeverAllocatesABucket proves the memory-exhaustion
// half of the same finding: TenantQueue entries are never evicted, so a rejected
// or misattributed Register must not leave a bucket behind for whatever string
// the caller sent. After a run of forged tenant IDs, the victim tenant's bucket
// must still have its full budget and the forged keys must have no slots taken.
func TestRegister_ForgedTenantNeverAllocatesABucket(t *testing.T) {
	t.Parallel()

	queue := controllerTransport.NewTenantQueue()
	resolver := tenantResolverFor(map[string]string{"steward-flood": "tenant-flood"})
	server := &transportServer{provider: New(ModeServer,
		WithTenantAdmission(queue),
		WithStewardTenantResolver(resolver),
	)}

	for i := 0; i < 64; i++ {
		_, err := server.Register(verifiedPeerContext("steward-flood"), &controllerpb.RegisterRequest{
			Version: "1.0.0",
			Credentials: &commonpb.Credentials{
				TenantId: fmt.Sprintf("%s-%d", strings.Repeat("z", 512), i),
			},
		})
		require.NoError(t, err)
	}

	// Every slot of the caller's real bucket is free again (nothing leaked), and
	// the flood never touched any other tenant's budget.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, queue.Acquire("tenant-flood"))
		require.NoError(t, queue.Acquire("tenant-victim"))
	}
}

// TestRegister_TenantAdmissionSlotReleasedAfterCall verifies that Register
// releases its admission slot when the call returns, so a tenant's connect
// traffic never accumulates unreleased slots across repeated connects.
func TestRegister_TenantAdmissionSlotReleasedAfterCall(t *testing.T) {
	t.Parallel()
	queue := controllerTransport.NewTenantQueue()
	resolver := tenantResolverFor(map[string]string{"steward-cycle": "tenant-cycle"})
	server := &transportServer{provider: New(ModeServer,
		WithTenantAdmission(queue),
		WithStewardTenantResolver(resolver),
	)}

	// Register well beyond MaxConcurrentPerTenant sequential times for the same
	// tenant. If a slot leaked on any call, this would eventually fail with
	// ResourceExhausted.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant*3; i++ {
		_, err := server.Register(verifiedPeerContext("steward-cycle"), &controllerpb.RegisterRequest{
			Version:     "1.0.0",
			Credentials: &commonpb.Credentials{TenantId: "tenant-cycle"},
		})
		require.NoError(t, err, "call %d should not be rejected — prior slots must have been released", i)
	}

	// The queue must still have full headroom for tenant-cycle.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, queue.Acquire("tenant-cycle"))
	}
}

// TestRegister_TenantAdmissionQueueFull_OverRealTransport verifies the gate at
// the wire level: a real steward dialing over QUIC+mTLS whose fleet record puts
// it in a saturated tenant receives codes.ResourceExhausted from the live
// Register RPC, while a steward in another tenant connects normally. Both send a
// forged creds.tenant_id to confirm the wire field never selects the bucket.
func TestRegister_TenantAdmissionQueueFull_OverRealTransport(t *testing.T) {
	t.Parallel()

	tc := newTestCA(t)
	reg := registry.NewRegistry()
	queue := controllerTransport.NewTenantQueue()
	resolver := tenantResolverFor(map[string]string{
		"steward-wire-full": "tenant-wire-full",
		"steward-wire-ok":   "tenant-wire-ok",
	})

	server := New(ModeServer, WithTenantAdmission(queue), WithStewardTenantResolver(resolver))
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, queue.Acquire("tenant-wire-full"))
	}

	_, err := dialAndRegister(t, server.ListenAddr(), tc.clientTLSConfig(t, "steward-wire-full"), &controllerpb.RegisterRequest{
		Version:     "1.0.0",
		Credentials: &commonpb.Credentials{TenantId: "tenant-wire-ok"},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, st.Code())

	// A steward under a different tenant must still be able to connect.
	resp, err := dialAndRegister(t, server.ListenAddr(), tc.clientTLSConfig(t, "steward-wire-ok"), &controllerpb.RegisterRequest{
		Version:     "1.0.0",
		Credentials: &commonpb.Credentials{TenantId: "tenant-wire-full"},
	})
	require.NoError(t, err, "an unrelated tenant must not be starved by tenant-wire-full's saturation")
	assert.Equal(t, "steward-wire-ok", resp.GetStewardId())
}

// newAdmissionEnv sets up a server with a TenantAdmission gate and the
// server-side tenant resolver wired in, plus two clients (steward-adm-a in
// tenant-adm-a, steward-adm-b in tenant-adm-b) connected over real QUIC+mTLS —
// mirroring newMultiStewardEnv, with the queue exposed so tests can saturate a
// tenant directly (matching TestDNAHandler_QueueFull_ReturnsResourceExhausted's
// pattern of pre-filling the real TenantQueue rather than a stub).
type admissionEnv struct {
	server  *Provider
	clientA *Provider
	clientB *Provider
	queue   *controllerTransport.TenantQueue
	// eventQueue is the events-only gate, a different instance from queue.
	eventQueue *controllerTransport.TenantQueue
	logger     *verbatimLogger
	reg        *registry.InMemoryRegistry
	tc         *testCA
}

const (
	admissionTenantA = "tenant-adm-a"
	admissionTenantB = "tenant-adm-b"
)

func newAdmissionEnv(t *testing.T) *admissionEnv {
	t.Helper()

	tc := newTestCA(t)
	reg := registry.NewRegistry()
	queue := controllerTransport.NewTenantQueue()
	resolver := tenantResolverFor(map[string]string{
		"steward-adm-a": admissionTenantA,
		"steward-adm-b": admissionTenantB,
		"steward-adm-c": admissionTenantA,
	})
	eventQueue := controllerTransport.NewTenantQueue()
	vl := &verbatimLogger{Logger: logging.NewNoopLogger()}

	server := New(ModeServer, WithTenantAdmission(queue), WithEventAdmission(eventQueue), WithStewardTenantResolver(resolver))
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"logger":     vl,
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	listenAddr := server.ListenAddr()

	clientA := New(ModeClient)
	require.NoError(t, clientA.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": tc.clientTLSConfig(t, "steward-adm-a"),
		"steward_id": "steward-adm-a",
	}))
	require.NoError(t, clientA.Start(context.Background()))
	t.Cleanup(func() { _ = clientA.Stop(context.Background()) })

	clientB := New(ModeClient)
	require.NoError(t, clientB.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       listenAddr,
		"tls_config": tc.clientTLSConfig(t, "steward-adm-b"),
		"steward_id": "steward-adm-b",
	}))
	require.NoError(t, clientB.Start(context.Background()))
	t.Cleanup(func() { _ = clientB.Stop(context.Background()) })

	require.Eventually(t, func() bool {
		return reg.Count() == 2
	}, 5*time.Second, 10*time.Millisecond, "both stewards should register")

	return &admissionEnv{server: server, clientA: clientA, clientB: clientB, queue: queue, eventQueue: eventQueue, logger: vl, reg: reg, tc: tc}
}

// TestControlChannel_Heartbeat_TenantAdmissionQueueFull_DroppedWithoutStarvingOtherTenants
// is the required test for the heartbeat half of Issue #3759 / ADR-031 Decision 6:
// a tenant whose admission queue is saturated has its heartbeat dropped, while a
// different tenant's heartbeat on a concurrently-connected steward is delivered
// normally — the same tenant cannot exhaust the shared cell's heartbeat capacity,
// and other tenants are not starved by it.
func TestControlChannel_Heartbeat_TenantAdmissionQueueFull_DroppedWithoutStarvingOtherTenants(t *testing.T) {
	t.Parallel()
	env := newAdmissionEnv(t)

	dispatched := make(chan *types.Heartbeat, 10)
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		dispatched <- hb
		return nil
	}))

	// steward-adm-a's tenant, as the controller's own fleet record reports it.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, env.queue.Acquire(admissionTenantA))
	}

	// steward-adm-a belongs to the saturated tenant — must be dropped, not dispatched.
	require.NoError(t, env.clientA.SendHeartbeat(context.Background(), &types.Heartbeat{
		StewardID: "steward-adm-a",
		TenantID:  admissionTenantA,
		Status:    types.StatusHealthy,
		Timestamp: time.Now().Truncate(time.Microsecond),
	}))

	// steward-adm-b belongs to an unrelated, non-saturated tenant — must still be delivered.
	require.NoError(t, env.clientB.SendHeartbeat(context.Background(), &types.Heartbeat{
		StewardID: "steward-adm-b",
		TenantID:  admissionTenantB,
		Status:    types.StatusHealthy,
		Timestamp: time.Now().Truncate(time.Microsecond),
	}))

	select {
	case got := <-dispatched:
		assert.Equal(t, "steward-adm-b", got.StewardID, "the non-saturated tenant's heartbeat should be dispatched")
		assert.Equal(t, admissionTenantB, got.TenantID)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for tenant-adm-b's heartbeat — other tenants must not be starved")
	}

	// The saturated tenant's heartbeat must never show up, even after giving the
	// async dispatch path time to run.
	require.Never(t, func() bool {
		select {
		case got := <-dispatched:
			return got.StewardID == "steward-adm-a"
		default:
			return false
		}
	}, 300*time.Millisecond, 20*time.Millisecond, "the saturated tenant's heartbeat must be dropped, not dispatched")
}

// TestControlChannel_Heartbeat_AdmissionKeyedOnResolvedTenantNotPayload is the
// cross-tenant denial-of-service regression test for the heartbeat path. A
// dropped heartbeat makes the controller's liveness path see a steward as stale,
// so if the payload's tenant_id chose the bucket, one steward could saturate a
// victim tenant and blind the controller to that whole fleet.
//
// With the victim tenant saturated, a steward from another tenant that forges
// heartbeat.tenant_id to the victim's value must still be dispatched — its own
// server-resolved bucket is what gates it — while the steward that genuinely
// belongs to the saturated tenant is dropped even when it forges an unsaturated
// tenant_id.
func TestControlChannel_Heartbeat_AdmissionKeyedOnResolvedTenantNotPayload(t *testing.T) {
	t.Parallel()
	env := newAdmissionEnv(t)

	dispatched := make(chan *types.Heartbeat, 10)
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		dispatched <- hb
		return nil
	}))

	// Saturate steward-adm-b's tenant. steward-adm-a is in tenant-adm-a.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, env.queue.Acquire(admissionTenantB))
	}

	// steward-adm-a forges the victim tenant on the wire: it must not be bucketed there.
	require.NoError(t, env.clientA.SendHeartbeat(context.Background(), &types.Heartbeat{
		StewardID: "steward-adm-a",
		TenantID:  admissionTenantB,
		Status:    types.StatusHealthy,
		Timestamp: time.Now().Truncate(time.Microsecond),
	}))

	// steward-adm-b forges an unsaturated tenant: it must not escape its own bucket.
	require.NoError(t, env.clientB.SendHeartbeat(context.Background(), &types.Heartbeat{
		StewardID: "steward-adm-b",
		TenantID:  "tenant-wide-open",
		Status:    types.StatusHealthy,
		Timestamp: time.Now().Truncate(time.Microsecond),
	}))

	select {
	case got := <-dispatched:
		assert.Equal(t, "steward-adm-a", got.StewardID,
			"a forged tenant_id must not place a steward in another tenant's saturated bucket")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out: steward-adm-a's heartbeat must be dispatched from its own, unsaturated bucket")
	}

	require.Never(t, func() bool {
		select {
		case got := <-dispatched:
			return got.StewardID == "steward-adm-b"
		default:
			return false
		}
	}, 300*time.Millisecond, 20*time.Millisecond,
		"a forged tenant_id must not buy capacity outside the caller's own saturated bucket")
}

// startExtraSteward connects another steward (steward-adm-c, tenant A in the
// resolver) over real QUIC+mTLS and waits for it to register.
func (e *admissionEnv) startExtraSteward(t *testing.T) *Provider {
	t.Helper()
	before := e.reg.Count()
	c := New(ModeClient)
	require.NoError(t, c.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       e.server.ListenAddr(),
		"tls_config": e.tc.clientTLSConfig(t, "steward-adm-c"),
		"steward_id": "steward-adm-c",
	}))
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	require.Eventually(t, func() bool { return e.reg.Count() == before+1 },
		5*time.Second, 10*time.Millisecond, "extra steward should register")
	return c
}

func testHeartbeat(id, tenant string) *types.Heartbeat {
	return &types.Heartbeat{StewardID: id, TenantID: tenant, Status: types.StatusHealthy, Timestamp: time.Now().Truncate(time.Microsecond)}
}

// concurrencyProbe is a handler body that records how many invocations run at
// once and blocks each until released.
type concurrencyProbe struct {
	cur, max atomic.Int32
	started  atomic.Int32
	release  chan struct{}
}

func newConcurrencyProbe() *concurrencyProbe {
	return &concurrencyProbe{release: make(chan struct{})}
}

func (c *concurrencyProbe) enter() {
	n := c.cur.Add(1)
	for {
		m := c.max.Load()
		if n <= m || c.max.CompareAndSwap(m, n) {
			break
		}
	}
	c.started.Add(1)
	<-c.release
	c.cur.Add(-1)
}

// tenantSlotsFree reports whether every admission slot for tenant is free,
// leaving the queue as it found it.
func tenantSlotsFree(q *controllerTransport.TenantQueue, tenant string) bool {
	var got int
	for q.Acquire(tenant) == nil {
		got++
	}
	for i := 0; i < got; i++ {
		q.Release(tenant)
	}
	return got == controllerTransport.MaxConcurrentPerTenant
}

// requireTenantSlotsFree waits until no handler holds a slot of tenant in q.
// Handlers free their stream slot before their tenant slot, so this also
// proves the stream's in-flight slots have been returned.
func requireTenantSlotsFree(t *testing.T, q *controllerTransport.TenantQueue, tenant string, msgAndArgs ...interface{}) {
	t.Helper()
	require.Eventually(t, func() bool { return tenantSlotsFree(q, tenant) }, 5*time.Second, 10*time.Millisecond, msgAndArgs...)
}

func (e *admissionEnv) stats(t *testing.T) *types.ControlPlaneStats {
	t.Helper()
	st, err := e.server.GetStats(context.Background())
	require.NoError(t, err)
	return st
}

func publishEvents(t *testing.T, c *Provider, stewardID string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		require.NoError(t, c.PublishEvent(context.Background(), &types.Event{
			ID: fmt.Sprintf("evt-%d", i), StewardID: stewardID, TenantID: admissionTenantA,
			Type: "test.event", Timestamp: time.Now().Truncate(time.Microsecond),
		}))
	}
}

// TestControlChannel_Event_PerStreamInFlightCap: one stream sending more events
// than the stream limit while the handler blocks never has more than
// maxInFlightEventsPerStream handlers running; the rest are dropped.
func TestControlChannel_Event_PerStreamInFlightCap(t *testing.T) {
	t.Parallel()
	env := newAdmissionEnv(t)
	probe := newConcurrencyProbe()
	require.NoError(t, env.server.SubscribeEvents(context.Background(), nil, func(context.Context, *types.Event) error {
		probe.enter()
		return nil
	}))

	const extra = 12
	publishEvents(t, env.clientA, "steward-adm-a", maxInFlightEventsPerStream+extra)

	require.Eventually(t, func() bool { return env.stats(t).EventsDropped >= extra },
		5*time.Second, 10*time.Millisecond, "events past the stream cap must be dropped")
	assert.EqualValues(t, maxInFlightEventsPerStream, probe.started.Load())
	assert.EqualValues(t, maxInFlightEventsPerStream, probe.max.Load())

	close(probe.release)
	require.Eventually(t, func() bool { return probe.cur.Load() == 0 }, 5*time.Second, 10*time.Millisecond)
	assert.EqualValues(t, maxInFlightEventsPerStream, probe.max.Load(), "concurrency must never exceed the stream cap")
	assert.EqualValues(t, extra, env.stats(t).EventsDropped)

	// Slots come back once handlers return.
	require.Eventually(t, func() bool { return env.stats(t).EventsReceived >= maxInFlightEventsPerStream }, 5*time.Second, 10*time.Millisecond)
	publishEvents(t, env.clientA, "steward-adm-a", 1)
	require.Eventually(t, func() bool { return env.stats(t).EventsReceived == maxInFlightEventsPerStream+1 },
		5*time.Second, 10*time.Millisecond, "an event after the handlers returned must be accepted")
}

// TestControlChannel_Event_FloodDoesNotStarveConnectOrHeartbeat: a tenant's
// blocked event handlers use only the events queue, so another steward of the
// same tenant can still Register and have its heartbeat dispatched.
func TestControlChannel_Event_FloodDoesNotStarveConnectOrHeartbeat(t *testing.T) {
	t.Parallel()
	env := newAdmissionEnv(t)
	probe := newConcurrencyProbe()
	t.Cleanup(func() { close(probe.release) })
	require.NoError(t, env.server.SubscribeEvents(context.Background(), nil, func(context.Context, *types.Event) error {
		probe.enter()
		return nil
	}))
	beats := make(chan *types.Heartbeat, 4)
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		beats <- hb
		return nil
	}))

	publishEvents(t, env.clientA, "steward-adm-a", maxInFlightEventsPerStream)
	require.Eventually(t, func() bool { return probe.cur.Load() == maxInFlightEventsPerStream },
		5*time.Second, 10*time.Millisecond)

	// Fill the rest of the tenant's event slots from other streams' point of
	// view: the events queue is exhausted for tenant A.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant-maxInFlightEventsPerStream; i++ {
		require.NoError(t, env.eventQueue.Acquire(admissionTenantA))
	}
	require.Error(t, env.eventQueue.Acquire(admissionTenantA), "tenant A's event slots are exhausted")

	c := env.startExtraSteward(t)
	require.NoError(t, c.SendHeartbeat(context.Background(), testHeartbeat("steward-adm-c", admissionTenantA)))
	select {
	case got := <-beats:
		assert.Equal(t, "steward-adm-c", got.StewardID)
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat of a same-tenant steward must still be dispatched while events are saturated")
	}
}

// TestControlChannel_Heartbeat_PerStreamAndPerTenantConcurrency: with a blocking
// heartbeat handler a stream has at most one heartbeat in flight, and a tenant
// never exceeds the admission limit.
func TestControlChannel_Heartbeat_PerStreamAndPerTenantConcurrency(t *testing.T) {
	t.Parallel()
	env := newAdmissionEnv(t)
	probe := newConcurrencyProbe()
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(context.Context, *types.Heartbeat) error {
		probe.enter()
		return nil
	}))

	const extra = 10
	for i := 0; i < 1+extra; i++ {
		require.NoError(t, env.clientA.SendHeartbeat(context.Background(), testHeartbeat("steward-adm-a", admissionTenantA)))
	}
	require.Eventually(t, func() bool { return env.stats(t).HeartbeatsDropped >= extra },
		5*time.Second, 10*time.Millisecond, "heartbeats past one in flight must be dropped")
	assert.EqualValues(t, 1, probe.started.Load())

	// Per tenant: leave exactly the slot the in-flight heartbeat holds plus none
	// free, then a second steward of the tenant is gated by the tenant limit.
	for {
		if err := env.queue.Acquire(admissionTenantA); err != nil {
			break
		}
	}
	c := env.startExtraSteward(t)
	dropsBefore := env.stats(t).HeartbeatsDropped
	require.NoError(t, c.SendHeartbeat(context.Background(), testHeartbeat("steward-adm-c", admissionTenantA)))
	require.Eventually(t, func() bool { return env.stats(t).HeartbeatsDropped > dropsBefore },
		5*time.Second, 10*time.Millisecond, "tenant gate must drop the second steward's heartbeat")

	close(probe.release)
	require.Eventually(t, func() bool { return probe.cur.Load() == 0 }, 5*time.Second, 10*time.Millisecond)
	assert.EqualValues(t, 1, probe.max.Load(), "per-stream heartbeat concurrency must never exceed one")
	assert.EqualValues(t, 1, probe.started.Load(), "the tenant-gated heartbeat must not reach the handler")
}

// TestControlChannel_Heartbeat_TenantAdmissionSlotHeldUntilHandlerReturns: the
// tenant slot is taken for the whole handler run and free only after it returns.
func TestControlChannel_Heartbeat_TenantAdmissionSlotHeldUntilHandlerReturns(t *testing.T) {
	t.Parallel()
	env := newAdmissionEnv(t)
	probe := newConcurrencyProbe()
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(context.Context, *types.Heartbeat) error {
		probe.enter()
		return nil
	}))

	require.NoError(t, env.clientA.SendHeartbeat(context.Background(), testHeartbeat("steward-adm-a", admissionTenantA)))
	require.Eventually(t, func() bool { return probe.cur.Load() == 1 }, 5*time.Second, 10*time.Millisecond)

	// While the handler runs the tenant has one fewer free slot.
	var held int
	for env.queue.Acquire(admissionTenantA) == nil {
		held++
	}
	assert.Equal(t, controllerTransport.MaxConcurrentPerTenant-1, held, "slot must be held while the handler runs")
	for i := 0; i < held; i++ {
		env.queue.Release(admissionTenantA)
	}

	close(probe.release)
	require.Eventually(t, func() bool {
		var got int
		for env.queue.Acquire(admissionTenantA) == nil {
			got++
		}
		for i := 0; i < got; i++ {
			env.queue.Release(admissionTenantA)
		}
		return got == controllerTransport.MaxConcurrentPerTenant
	}, 5*time.Second, 20*time.Millisecond, "slot must be free after the handler returns")
}

// TestControlChannel_HandlerPanic_FreesSlotsAndKeepsProcessAlive: a panicking
// handler is recovered and still releases both the stream and tenant slots.
func TestControlChannel_HandlerPanic_FreesSlotsAndKeepsProcessAlive(t *testing.T) {
	t.Parallel()
	env := newAdmissionEnv(t)
	var calls atomic.Int32
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(context.Context, *types.Heartbeat) error {
		calls.Add(1)
		panic("handler boom\nforged=1")
	}))
	require.NoError(t, env.server.SubscribeEvents(context.Background(), nil, func(context.Context, *types.Event) error {
		panic("event boom")
	}))

	// Well beyond both the one-heartbeat stream cap and the event cap: every
	// message is accepted only if each previous panic released its slots. The
	// release callback frees the stream slot before the tenant slot, so waiting
	// for every tenant slot to be free proves the stream slot is free too.
	for i := 0; i < 5; i++ {
		before := calls.Load()
		require.NoError(t, env.clientA.SendHeartbeat(context.Background(), testHeartbeat("steward-adm-a", admissionTenantA)))
		require.Eventually(t, func() bool { return calls.Load() == before+1 }, 5*time.Second, 10*time.Millisecond)
		requireTenantSlotsFree(t, env.queue, admissionTenantA, "heartbeat %d: panicking handler must release its slots", i)
	}
	for round := int64(1); round <= 3; round++ {
		publishEvents(t, env.clientA, "steward-adm-a", maxInFlightEventsPerStream)
		require.Eventually(t, func() bool { return env.stats(t).EventsReceived == round*maxInFlightEventsPerStream },
			5*time.Second, 10*time.Millisecond, "round %d: events must be accepted once earlier panics released their slots", round)
		requireTenantSlotsFree(t, env.eventQueue, admissionTenantA, "round %d: panicking event handlers must release their slots", round)
	}
	assert.Zero(t, env.stats(t).EventsDropped, "no event may be dropped for a leaked slot")
	requireTenantSlotsFree(t, env.queue, admissionTenantA, "heartbeat tenant slots must be free after panicking handlers")

	panics := 0
	for _, rec := range env.logger.snapshot() {
		if strings.Contains(rec, "handler panicked") {
			panics++
			assert.NotContains(t, rec, "\n")
		}
	}
	assert.Positive(t, panics, "recovered panics must be logged")
}

// TestControlChannel_DropsAreCountedAndLogRateLimited: tenant-gate and
// stream-limit drops increment the counters, and a burst writes one log line.
func TestControlChannel_DropsAreCountedAndLogRateLimited(t *testing.T) {
	t.Parallel()
	env := newAdmissionEnv(t)
	probe := newConcurrencyProbe()
	t.Cleanup(func() { close(probe.release) })
	require.NoError(t, env.server.SubscribeEvents(context.Background(), nil, func(context.Context, *types.Event) error {
		probe.enter()
		return nil
	}))

	// Tenant gate: saturate tenant B's event queue; clientB's events drop.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, env.eventQueue.Acquire(admissionTenantB))
	}
	publishEvents(t, env.clientB, "steward-adm-b", 3)
	require.Eventually(t, func() bool { return env.stats(t).EventsDropped == 3 }, 5*time.Second, 10*time.Millisecond)
	assert.Zero(t, probe.started.Load())

	// Tenant gate on heartbeats.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, env.queue.Acquire(admissionTenantB))
	}
	require.NoError(t, env.clientB.SendHeartbeat(context.Background(), testHeartbeat("steward-adm-b", admissionTenantB)))
	require.Eventually(t, func() bool { return env.stats(t).HeartbeatsDropped == 1 }, 5*time.Second, 10*time.Millisecond)

	// Stream limit: a burst from stream A past the cap.
	const extra = 20
	publishEvents(t, env.clientA, "steward-adm-a", maxInFlightEventsPerStream+extra)
	require.Eventually(t, func() bool { return env.stats(t).EventsDropped == 3+extra }, 5*time.Second, 10*time.Millisecond)

	// One line for stream B's 3 tenant-gate drops and one for stream A's burst of
	// 20 — never one per drop.
	lines := 0
	for _, rec := range env.logger.snapshot() {
		if strings.Contains(rec, "controlchannel event dropped") {
			lines++
		}
	}
	assert.Equal(t, 2, lines, "each stream logs its first drop once; the rest of the burst is suppressed")
}

func TestDropLogLimiter_FirstThenOncePerInterval(t *testing.T) {
	t.Parallel()
	var d dropLogLimiter
	now := time.Now()
	ok, n := d.record(now)
	assert.True(t, ok)
	assert.EqualValues(t, 1, n)
	for i := 0; i < 5; i++ {
		ok, _ = d.record(now.Add(time.Second))
		assert.False(t, ok)
	}
	ok, n = d.record(now.Add(dropLogInterval))
	assert.True(t, ok)
	assert.EqualValues(t, 6, n, "the line carries the drops since the last one")
}

func TestWithEventAdmission_OptionSetsField(t *testing.T) {
	t.Parallel()
	q := controllerTransport.NewTenantQueue()
	p := New(ModeServer, WithEventAdmission(q))
	assert.Same(t, q, p.eventAdmission)
}
