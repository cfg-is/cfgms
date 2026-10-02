// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for Issue #4413: wiring the tenantsync and correlator entity-graph
// writers into controller startup. Both writers (pkg/entitygraph/writers/
// tenantsync, pkg/entitygraph/writers/correlator) were complete and tested in
// their own packages but never constructed by features/controller/server —
// Issue #3253 wired their sibling configstore writer and explicitly left these
// two out of scope, and no follow-up wired them until now.
//
// These tests exercise the wired path: the Writer instances server.go's New()
// actually constructs (srv.egTenantSyncWriter, srv.egCorrelatorWriter) against
// the same srv.egProvider and srv.storageManager.GetTenantStore() a running
// controller uses — not a fresh writer built directly against a bare provider
// in the writer's own package, which pkg/entitygraph/writers/{correlator,
// tenantsync}'s own test suites already cover.
package server

import (
	"context"
	"math/rand/v2"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/pkg/cert"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newUngatedSweepLease returns the SingletonJob a non-cluster deployment gets:
// ha.Manager.NewBackgroundLoopLease is nil-receiver-safe and yields a job with
// no lease substrate, so RunIfLeader always runs (ADR-029 Decision 4). Built
// through the real production constructor rather than a zero value so these
// tests exercise the same object server.go hands the sweeper.
func newUngatedSweepLease(t *testing.T, name string) lease.SingletonJob {
	t.Helper()
	job, err := (*ha.Manager)(nil).NewBackgroundLoopLease(name, logging.NewNoopLogger())
	require.NoError(t, err)
	return job
}

// reservePrivateMetricsAddressForWiring returns a free loopback address
// outside the ephemeral port range, suitable for config.MetricsListenAddr —
// ValidatePrivateListenerAddress requires a fixed numeric port (never 0), and
// Server.Start()'s API server fails closed without one. Mirrors
// features/controller/api's own reservePrivateMetricsAddress test helper
// (unexported there, so reimplemented here rather than imported).
func reservePrivateMetricsAddressForWiring(t *testing.T) string {
	t.Helper()
	high := 32767
	low := 20000
	for attempt := 0; attempt < 100; attempt++ {
		port := low + rand.IntN(high-low+1)
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		listener, err := net.Listen("tcp", address)
		if err != nil {
			continue // in use by another process — try another port
		}
		require.NoError(t, listener.Close())
		return address
	}
	t.Fatalf("no free loopback port in %d-%d after 100 attempts", low, high)
	return ""
}

// newWiredEntityGraphTestServer builds a full Server via New(), the same
// construction path a running controller takes, backed by logger so callers
// that need to inspect warnings can pass a *logging.CapturingLogger.
func newWiredEntityGraphTestServer(t *testing.T, logger logging.Logger) *Server {
	t.Helper()

	tempDir := t.TempDir()
	caDir := tempDir + "/ca"
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "EG Writers Wiring Test",
			Country:      "US",
			ValidityDays: 3650,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "failed to create test CA")

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "eg-writers-wiring-controller",
				Organization: "EG Writers Wiring Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		Storage: createTestStorageConfig(tempDir, "eg-writers-wiring"),
	}

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })
	return srv
}

// newStartableWiredEntityGraphTestServer builds a full Server via New() with
// everything Server.Start() itself additionally requires (a fixed, reachable
// ListenAddr, a matching ExternalURL, and a private MetricsListenAddr) — unlike
// newWiredEntityGraphTestServer above, whose callers never call Start(). Mirrors
// test/integration/controller's newHealthTestControllerConfig.
func newStartableWiredEntityGraphTestServer(t *testing.T, logger logging.Logger) *Server {
	t.Helper()

	root := t.TempDir()
	certPath := root + "/certs"
	httpAddr := reservePrivateMetricsAddressForWiring(t)
	cfg := &config.Config{
		ListenAddr:        httpAddr,
		ExternalURL:       "https://" + httpAddr,
		MetricsListenAddr: reservePrivateMetricsAddressForWiring(t),
		CertPath:          certPath,
		DataDir:           root + "/data",
		AdminBundlePath:   root + "/admin.bundle.yaml",
		Storage:           createTestStorageConfig(root, "eg-writers-startable-wiring"),
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               certPath + "/ca",
			Server: &config.ServerCertificateConfig{
				CommonName:   "localhost",
				DNSNames:     []string{"localhost", "127.0.0.1"},
				IPAddresses:  []string{"127.0.0.1", "::1"},
				Organization: "EG Writers Startable Wiring Test",
			},
		},
	}

	// First-run initialization (`controller --init`): New() refuses to start an
	// uninitialized controller (ErrNotInitialized) when cert management is
	// enabled, matching test/integration/controller/health_routes_test.go.
	_, err := initialization.Run(cfg, logger)
	require.NoError(t, err, "initialization.Run")

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })
	return srv
}

// mustCreateTenantForWiring inserts a tenant row directly, failing the test on
// error.
func mustCreateTenantForWiring(t *testing.T, store business.TenantStore, id, name, parentID string) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, store.CreateTenant(context.Background(), &business.TenantData{
		ID:        id,
		Name:      name,
		ParentID:  parentID,
		Status:    business.TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}))
}

// reportWiringEntity writes a single entity observation directly to p.
func reportWiringEntity(t *testing.T, p eginterfaces.EntityGraphProvider, subject string, payload map[string]interface{}) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, p.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: "test",
		Observations: []egtypes.Observation{
			{
				Source:     "test",
				ObservedAt: now,
				RecordedAt: now,
				Subject:    subject,
				Kind:       egtypes.ObservationKindState,
				Confidence: egtypes.ConfidenceHigh,
				Payload:    payload,
			},
		},
	}))
}

// ─── TestServer_New_ConstructsTenantSyncAndCorrelatorWriters ───────────────

// TestServer_New_ConstructsTenantSyncAndCorrelatorWriters is the regression
// guard for Issue #4413: New() must construct both writers against the same
// egProvider it wires into the API server, so they are no longer
// standalone-invokable-only.
func TestServer_New_ConstructsTenantSyncAndCorrelatorWriters(t *testing.T) {
	srv := newWiredEntityGraphTestServer(t, logging.NewNoopLogger())

	require.NotNil(t, srv.egTenantSyncWriter, "tenantsync writer must be constructed at startup (Issue #4413)")
	require.NotNil(t, srv.egCorrelatorWriter, "correlator writer must be constructed at startup (Issue #4413)")
}

// ─── REQUIRED TEST: reserved-delimiter / injection defences on the wired path ─

// TestWiredTenantSync_RejectsReservedDelimiterTenantID proves that the
// tenantsync writer server.go actually constructs still enforces its
// reserved-delimiter quarantine (not a weaker copy) once wired: a tenant ID
// containing the reserved "|" edge-subject delimiter must never mint an EID —
// it is quarantined (skipped and logged) rather than mirrored, while
// unaffected tenants are still mirrored. This is the same injection class
// Issue #4335's containment work has been closing elsewhere, now proven
// reachable through the controller's own construction path.
func TestWiredTenantSync_RejectsReservedDelimiterTenantID(t *testing.T) {
	capture := logging.NewCapturingLogger()
	srv := newWiredEntityGraphTestServer(t, capture)

	tenantStore := srv.storageManager.GetTenantStore()
	mustCreateTenantForWiring(t, tenantStore, "root", "Root", "")
	mustCreateTenantForWiring(t, tenantStore, "bad|tenant", "Bad", "root")
	mustCreateTenantForWiring(t, tenantStore, "good", "Good", "root")

	ctx := context.Background()
	require.NoError(t, srv.egTenantSyncWriter.Ingest(ctx, tenantStore),
		"one unrepresentable tenant must not abort the snapshot on the wired path")

	rootEID, err := egtypes.ParseEID("cfgms:tenant/root")
	require.NoError(t, err)
	goodEID, err := egtypes.ParseEID("cfgms:tenant/good")
	require.NoError(t, err)

	rootView, err := srv.egProvider.GetEntity(ctx, rootEID, eginterfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.NotNil(t, rootView, "root must still be mirrored")

	goodView, err := srv.egProvider.GetEntity(ctx, goodEID, eginterfaces.GetEntityOpts{})
	require.NoError(t, err)
	require.NotNil(t, goodView, "good must still be mirrored")

	// The delimiter-bearing tenant must never produce a mirrored entity under
	// any EID — in particular not one that embeds the raw "|" in local_id.
	page, err := srv.egProvider.QueryEntities(ctx, eginterfaces.EntityFilter{Kind: "tenant"}, eginterfaces.PageToken{})
	require.NoError(t, err)
	for _, ev := range page.Entities {
		assert.NotContains(t, ev.Entity.EID.String(), "bad|tenant",
			"a tenant id containing the reserved delimiter must never be minted into an EID")
	}

	entry, ok := capture.FindWarn("tenantsync: skipping tenant with unrepresentable id")
	require.True(t, ok, "the quarantined row must be logged on the wired path")
	assert.Equal(t, "bad|tenant", entry["tenant_id"])
	assert.Contains(t, entry["error"], "tenant id contains reserved delimiter",
		"the writer must surface its specific reserved-delimiter error, not a generic failure")
}

// TestWiredCorrelator_SkipsReservedDelimiterEID proves that the correlator
// writer server.go constructs still enforces its edge-subject delimiter
// rejection once wired: an entity whose EID (authority name) contains the
// reserved "|" delimiter must be skipped from pairing rather than producing a
// same-as edge whose from/to round-trip would be non-injective, while an
// unaffected pair sharing the same MAC in the same sweep still correlates.
func TestWiredCorrelator_SkipsReservedDelimiterEID(t *testing.T) {
	srv := newWiredEntityGraphTestServer(t, logging.NewNoopLogger())
	ctx := context.Background()

	const sharedMAC = "0A:0B:0C:0D:0E:0F"

	// Attacker-authored entity whose authority name embeds the delimiter.
	reportWiringEntity(t, srv.egProvider, "cluster:victim|host:pad", map[string]interface{}{
		"entity_kind": "host",
		"network_adapters": []interface{}{
			map[string]interface{}{"mac_address": sharedMAC},
		},
	})
	// Legitimate host sharing the MAC, from a different authority segment.
	reportWiringEntity(t, srv.egProvider, "host:legit-guest", map[string]interface{}{
		"entity_kind":   "host",
		"primary_mac":   sharedMAC,
		"mac_addresses": sharedMAC,
	})

	require.NoError(t, srv.egCorrelatorWriter.Correlate(ctx))

	edges, err := srv.egProvider.GetEdges(ctx, eginterfaces.EdgeFilter{Types: []string{"same-as"}})
	require.NoError(t, err)
	assert.Empty(t, edges,
		"an EID containing the edge-subject delimiter must not produce a same-as edge on the wired path")
}

// ─── REQUIRED TEST: cross-tenant edges carry no access-control attribute ───

// TestWiredTenantSync_TenantEntitiesCarryNoOwningTenant pins ADR-022 §7's
// rule — authorization never uses graph traversal — against a future change:
// the tenantsync writer mirrors a multi-root tenant tree (itself a
// cross-tenant structural relationship) but must never set owning_tenant on
// the tenant entities it creates, on the wired path.
func TestWiredTenantSync_TenantEntitiesCarryNoOwningTenant(t *testing.T) {
	srv := newWiredEntityGraphTestServer(t, logging.NewNoopLogger())
	ctx := context.Background()

	tenantStore := srv.storageManager.GetTenantStore()
	mustCreateTenantForWiring(t, tenantStore, "root-a", "Root A", "")
	mustCreateTenantForWiring(t, tenantStore, "root-b", "Root B", "")
	mustCreateTenantForWiring(t, tenantStore, "child-of-a", "Child", "root-a")

	require.NoError(t, srv.egTenantSyncWriter.Ingest(ctx, tenantStore))

	for _, id := range []string{"root-a", "root-b", "child-of-a"} {
		eid, err := egtypes.ParseEID("cfgms:tenant/" + id)
		require.NoError(t, err)
		view, err := srv.egProvider.GetEntity(ctx, eid, eginterfaces.GetEntityOpts{})
		require.NoError(t, err)
		require.NotNil(t, view)
		assert.Equal(t, "", view.Entity.OwningTenant,
			"tenantsync must never set owning_tenant on a mirrored tenant entity (ADR-022 §7): tenant %q", id)
	}
}

// TestWiredCorrelator_SameAsEdgeCarriesNoOwningTenantAttribute pins the
// correlator half of the same ADR-022 §7 rule: a same-as edge the correlator
// asserts between two entities in different tenants carries no attribute that
// could be read as an access-control signal.
func TestWiredCorrelator_SameAsEdgeCarriesNoOwningTenantAttribute(t *testing.T) {
	srv := newWiredEntityGraphTestServer(t, logging.NewNoopLogger())
	ctx := context.Background()

	const sharedMAC = "1A:2B:3C:4D:5E:6F"
	reportWiringEntity(t, srv.egProvider, "host:tenant-a-host", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/tenant-a",
		"primary_mac":   sharedMAC,
		"mac_addresses": sharedMAC,
	})
	reportWiringEntity(t, srv.egProvider, "host:tenant-b-host", map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": "root/tenant-b",
		"primary_mac":   sharedMAC,
		"mac_addresses": sharedMAC,
	})

	require.NoError(t, srv.egCorrelatorWriter.Correlate(ctx))

	edges, err := srv.egProvider.GetEdges(ctx, eginterfaces.EdgeFilter{Types: []string{"same-as"}})
	require.NoError(t, err)
	require.Len(t, edges, 1, "the cross-tenant pair sharing a MAC must still correlate")
	_, hasOwningTenant := edges[0].Edge.Attributes["owning_tenant"]
	assert.False(t, hasOwningTenant,
		"a cross-tenant same-as edge must carry no owning_tenant (or other access-control) attribute (ADR-022 §7)")
}

// ─── REQUIRED TEST: lifecycle tied to controller shutdown ──────────────────

// TestEntityGraphPeriodicSweeper_StopExitsGoroutine proves the scheduler
// mechanism both writers' Start()/Stop() wiring uses: cancelling the sweep
// (what Server.Stop() triggers via Stop()) actually stops the running
// goroutine, not merely requests it to stop. The sweep func increments a
// counter so the test can also confirm the loop was actually ticking before
// it is asked to stop.
func TestEntityGraphPeriodicSweeper_StopExitsGoroutine(t *testing.T) {
	var ticks atomic.Int64
	sweeper := newEntityGraphPeriodicSweeper("test-sweep", 5*time.Millisecond, func(context.Context) error {
		ticks.Add(1)
		return nil
	}, newUngatedSweepLease(t, "test-sweep"), logging.NewNoopLogger())

	sweeper.Start(context.Background())

	require.Eventually(t, func() bool { return ticks.Load() > 0 }, time.Second, time.Millisecond,
		"the sweep function must fire at least once while running")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	require.NoError(t, sweeper.Stop(stopCtx), "Stop must observe cancellation and drain promptly")

	// The goroutine must have actually exited: done is closed synchronously
	// before Stop returns (see entityGraphPeriodicSweeper.Stop), so it must
	// already be closed here.
	select {
	case <-sweeper.done:
	default:
		t.Fatal("sweeper.done must be closed once Stop has returned, proving the goroutine exited")
	}

	countAfterStop := ticks.Load()
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, countAfterStop, ticks.Load(),
		"no further sweep must fire after Stop returns — the goroutine must have exited, not just missed a tick")
}

// ─── REQUIRED TEST: cluster-singleton gating of both sweeps ────────────────

// TestServer_New_BuildsClusterSingletonLeasesForBothSweeps pins ADR-031
// Decision 4 for Issue #4413: New() must hand each sweep its own background-loop
// lease, under its own name, rather than leaving the sweeps ungated. In cluster
// mode the entity graph is a single shared Postgres instance, so an ungated
// sweep would run one fleet-sized scan per node per tick against the same
// database.
func TestServer_New_BuildsClusterSingletonLeasesForBothSweeps(t *testing.T) {
	srv := newWiredEntityGraphTestServer(t, logging.NewNoopLogger())

	assert.Equal(t, "entitygraph-tenantsync", srv.egTenantSyncLeaseJob.Name,
		"the tenant-sync sweep must contend under its own lease name")
	assert.Equal(t, "entitygraph-correlator", srv.egCorrelatorLeaseJob.Name,
		"the correlator sweep must contend under its own lease name")
	assert.NotEqual(t, srv.egTenantSyncLeaseJob.Name, srv.egCorrelatorLeaseJob.Name,
		"the two sweeps must not share one lease — holding either must not block the other")
}

// TestServer_Start_SweepersCarryTheirLeaseJob proves the lease New() built is
// actually the one the running sweeper gates on — not dropped on the floor
// between New() and Start().
func TestServer_Start_SweepersCarryTheirLeaseJob(t *testing.T) {
	srv := newStartableWiredEntityGraphTestServer(t, logging.NewNoopLogger())
	require.NoError(t, srv.Start())

	require.NotNil(t, srv.egTenantSyncSweeper)
	require.NotNil(t, srv.egCorrelatorSweeper)
	assert.Equal(t, srv.egTenantSyncLeaseJob.Name, srv.egTenantSyncSweeper.leaseJob.Name)
	assert.Equal(t, srv.egCorrelatorLeaseJob.Name, srv.egCorrelatorSweeper.leaseJob.Name)
}

// TestEntityGraphPeriodicSweeper_DoesNotSweepWithoutTheLease proves the gate
// actually suppresses work on a node that does not hold the lease: a real
// lease.Manager over a real flatfile lease store, with the lease already held
// by a different holder, must leave the sweep function uncalled across many
// ticks. Without the gate this sweep would run on every node in the cluster.
func TestEntityGraphPeriodicSweeper_DoesNotSweepWithoutTheLease(t *testing.T) {
	store := newFlatFileLeaseStore(t)

	const (
		leaseName = "entitygraph-correlator"
		ttl       = 30 * time.Second
	)
	manager, err := lease.NewManager(store, ttl, 5*time.Second, 5*time.Second)
	require.NoError(t, err)

	// Another node in the cluster already holds this sweep's lease.
	_, acquired, err := manager.TryAcquire(context.Background(), leaseName, "other-node", ttl)
	require.NoError(t, err)
	require.True(t, acquired, "the peer node must hold the lease for this test to mean anything")

	leaseJob, err := lease.NewSingletonJob(manager, leaseName, "this-node", ttl, 5*time.Second, logging.NewNoopLogger())
	require.NoError(t, err)

	var sweeps atomic.Int64
	sweeper := newEntityGraphPeriodicSweeper(leaseName, time.Millisecond, func(context.Context) error {
		sweeps.Add(1)
		return nil
	}, leaseJob, logging.NewNoopLogger())

	sweeper.Start(context.Background())
	time.Sleep(100 * time.Millisecond) // ~100 ticks at a 1ms interval

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	require.NoError(t, sweeper.Stop(stopCtx))

	assert.Zero(t, sweeps.Load(),
		"a node that does not hold the sweep's lease must never sweep the shared entity graph")
}

// TestEntityGraphPeriodicSweeper_SweepsWhileHoldingTheLease is the positive half
// of the gate: the node that does hold the lease still sweeps, so gating does
// not silently disable the writers.
func TestEntityGraphPeriodicSweeper_SweepsWhileHoldingTheLease(t *testing.T) {
	store := newFlatFileLeaseStore(t)

	const (
		leaseName = "entitygraph-tenantsync"
		ttl       = 30 * time.Second
	)
	manager, err := lease.NewManager(store, ttl, 5*time.Second, 5*time.Second)
	require.NoError(t, err)

	leaseJob, err := lease.NewSingletonJob(manager, leaseName, "this-node", ttl, 5*time.Second, logging.NewNoopLogger())
	require.NoError(t, err)

	var sweeps atomic.Int64
	sweeper := newEntityGraphPeriodicSweeper(leaseName, 5*time.Millisecond, func(context.Context) error {
		sweeps.Add(1)
		return nil
	}, leaseJob, logging.NewNoopLogger())

	sweeper.Start(context.Background())
	require.Eventually(t, func() bool { return sweeps.Load() > 0 }, 5*time.Second, time.Millisecond,
		"the lease holder must perform the sweep")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	require.NoError(t, sweeper.Stop(stopCtx))
}

// TestServer_StartStop_StopsEntityGraphWriterSweepGoroutines proves the full
// controller-shutdown lifecycle requirement end to end: Server.Start() starts
// both writers' periodic sweeps, and Server.Stop() — cancelling the sweep
// context it owns — stops both goroutines, which this test asserts directly
// via each sweeper's done channel.
func TestServer_StartStop_StopsEntityGraphWriterSweepGoroutines(t *testing.T) {
	srv := newStartableWiredEntityGraphTestServer(t, logging.NewNoopLogger())

	require.NoError(t, srv.Start())

	require.NotNil(t, srv.egTenantSyncSweeper, "tenant-sync sweep must be started by Start()")
	require.NotNil(t, srv.egCorrelatorSweeper, "correlator sweep must be started by Start()")

	tenantSyncDone := srv.egTenantSyncSweeper.done
	correlatorDone := srv.egCorrelatorSweeper.done

	select {
	case <-tenantSyncDone:
		t.Fatal("tenant-sync sweep goroutine must still be running before Stop()")
	default:
	}
	select {
	case <-correlatorDone:
		t.Fatal("correlator sweep goroutine must still be running before Stop()")
	default:
	}

	require.NoError(t, srv.Stop())

	select {
	case <-tenantSyncDone:
	default:
		t.Fatal("tenant-sync sweep goroutine must have exited once Server.Stop() returns")
	}
	select {
	case <-correlatorDone:
	default:
		t.Fatal("correlator sweep goroutine must have exited once Server.Stop() returns")
	}
}
