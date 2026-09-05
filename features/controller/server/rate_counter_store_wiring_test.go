// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Composition-root wiring tests for the cluster-visible rate-counter store
// (Issue #3896, ADR-031 Decision 1). Server.New must hand the StorageManager's
// business.RateCounterStore to the API server, which is what makes the per-source
// rate limiters and the operator-payload sign-ceremony throttle count against the
// fleet-wide budget instead of a per-process one.
//
// Every test in features/controller/api calls SetRateCounterStore directly, so none
// of them can observe a composition root that never calls the setter — the gap that
// shipped twice before with the ip-trust store (Issue #3096) and the tag/role store
// (Issue #2548). This file closes it in three layers:
//
//  1. Server.New calls wireClusterRateCounterStore — asserted against the parsed
//     source of New itself, because the branch it guards cannot be reached in a test
//     process (see below).
//  2. wireClusterRateCounterStore reads GetRateCounterStore and hands the store to a
//     real *api.Server — asserted functionally, with a real StorageManager and a real
//     store.
//  3. api.Server.SetRateCounterStore wires the limiters when the deployment is
//     clustered — asserted in features/controller/api
//     (TestSourceRateLimiter_ClusterModeUsesSharedCounter and
//     TestClusterRateCounter_ConcurrentRequestsNeverExceedLimit).
//
// Layer 1 is a source assertion rather than an end-to-end run because a clustered
// controller cannot be started in-process: initializeHAManager refuses ha.mode
// cluster unless the storage tier supplies a node-shared (Postgres) lease store, and
// loadExistingCertificateManager loads a cluster deployment's CA from Vault rather
// than local disk. A test that started one would need both a live Postgres and a
// live OpenBao.
package server

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newRateCounterWiringTestConfig builds a controller config New can start: the OSS
// (node-local) storage tier, which supplies no RateCounterStore, matching a
// single-node deployment.
func newRateCounterWiringTestConfig(t *testing.T) *config.Config {
	t.Helper()

	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "Rate Counter Wiring Test",
			Country:      "US",
			ValidityDays: 3650,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "failed to create test CA")

	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "rate-counter-wiring-controller",
				Organization: "Rate Counter Wiring Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		Storage: createTestStorageConfig(tempDir, "rate-counter-wiring"),
	}
}

// TestServer_New_CallsRateCounterStoreWiring is layer 1: the composition root must
// actually invoke wireClusterRateCounterStore. Without this, every functional test
// below could pass while a clustered controller silently kept per-node abuse budgets
// — the store would be created by CreateClusterStorageManager and then never handed
// to anything.
func TestServer_New_CallsRateCounterStoreWiring(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	require.NoError(t, err, "parsing features/controller/server/server.go")

	var newFunc *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "New" && fn.Recv == nil {
			newFunc = fn
			break
		}
	}
	require.NotNil(t, newFunc, "server.go must declare func New — the controller composition root")

	called := false
	ast.Inspect(newFunc, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, isIdent := call.Fun.(*ast.Ident); isIdent && ident.Name == "wireClusterRateCounterStore" {
			called = true
			return false
		}
		return true
	})
	assert.True(t, called,
		"Server.New must call wireClusterRateCounterStore, or a clustered controller's abuse budgets stay per-node no matter what the storage tier created")
}

// TestWireClusterRateCounterStore_HandsStoreToAPIServer is layer 2: given a real
// StorageManager carrying a real cluster-visible counter store, the wiring hands
// that exact store to the real *api.Server built by New. The API server applies its
// own deployment-shape gate afterwards, which is asserted separately below.
func TestWireClusterRateCounterStore_HandsStoreToAPIServer(t *testing.T) {
	srv, err := New(newRateCounterWiringTestConfig(t), logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })
	require.NotNil(t, srv.httpServer, "API server must be initialized")

	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "rate-counter-wiring.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	store := pkgtesting.SetupTestRateCounterStore()
	sm.SetRateCounterStore(store)

	wired := wireClusterRateCounterStore(srv.httpServer, sm)
	require.NotNil(t, wired,
		"the wiring must read StorageManager.GetRateCounterStore and pass it on")
	assert.Same(t, store, wired,
		"the store handed to the API server must be the one the storage tier created, not a substitute")

	// The store must be usable, not merely non-nil: a store that errored on every
	// call would degrade every clustered node back to its in-memory budget.
	count, retryAfter, err := wired.Increment(context.Background(), "wiring-test:203.0.113.5", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Greater(t, retryAfter, time.Duration(0))
}

// TestWireClusterRateCounterStore_NoStoreAvailableIsNoop covers the fallback
// branches: no StorageManager at all, and a StorageManager whose provider implements
// no RateCounterStoreCreator (the OSS tier). Both must wire nothing, leaving the API
// server's limiters and sign throttle on their in-memory counters.
func TestWireClusterRateCounterStore_NoStoreAvailableIsNoop(t *testing.T) {
	srv, err := New(newRateCounterWiringTestConfig(t), logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })
	require.NotNil(t, srv.httpServer)

	unwired, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "rate-counter-unwired.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unwired.Close() })
	require.Nil(t, unwired.GetRateCounterStore(), "sanity: the OSS tier wires no rate counter store")

	assert.Nil(t, wireClusterRateCounterStore(srv.httpServer, nil),
		"a nil storage manager must wire nothing rather than panic")
	assert.Nil(t, wireClusterRateCounterStore(srv.httpServer, unwired),
		"a provider that implements no RateCounterStoreCreator must leave every consumer on its in-memory counter")
	assert.Nil(t, wireClusterRateCounterStore(nil, unwired),
		"a nil API server must wire nothing rather than panic")
}

// TestServer_New_SingleNodeKeepsInMemoryCounters is the AC guard at the composition
// root: a single-node deployment must see no behavioural change from this story. The
// OSS tier supplies no counter store, and the API server the real startup path built
// must therefore report none — even after being offered one, because
// SetRateCounterStore declines outside ha.ClusterMode.
func TestServer_New_SingleNodeKeepsInMemoryCounters(t *testing.T) {
	srv, err := New(newRateCounterWiringTestConfig(t), logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })
	require.NotNil(t, srv.httpServer)
	require.NotNil(t, srv.storageManager)

	assert.Nil(t, srv.storageManager.GetRateCounterStore(),
		"the node-local storage tier must supply no cluster-visible counter store")
	assert.Nil(t, srv.httpServer.RateCounterStore(),
		"a single-node controller must come out of New with its abuse budgets on the in-memory default")

	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "rate-counter-single.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	sm.SetRateCounterStore(pkgtesting.SetupTestRateCounterStore())

	wireClusterRateCounterStore(srv.httpServer, sm)
	assert.Nil(t, srv.httpServer.RateCounterStore(),
		"even offered a store, a non-clustered API server must stay on its in-memory counters (deployment-shape gate, AC: single-node unchanged)")
}
