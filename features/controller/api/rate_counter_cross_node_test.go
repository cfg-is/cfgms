// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3896 (ADR-031 follow-up to Issue #3761): [REQUIRED TEST]
// cross-node budget-exhaustion coverage for sourceRateLimiter's shared-counter
// path. TestSourceRateLimiter_ClusterModeUsesSharedCounter
// (rate_limiter_test.go) already proves the wiring picks the shared backend in
// ClusterMode; this file proves the resulting behavior is actually safe under
// concurrency: two nodes serving the same source against a real, shared,
// database-backed business.RateCounterStore (mirroring the
// setupTwoNodeSharedStoreServers pattern in cas_cross_node_test.go — two
// independent servers sharing one durable store) must never together grant
// more than the configured limit, regardless of which node each attempt lands
// on. Run with -race.
package api

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestClusterRateCounter_ConcurrentRequestsNeverExceedLimit is the
// [REQUIRED TEST] for Issue #3896: a budget-exhaustion race from two nodes
// serving the same source concurrently must never grant more than the
// configured limit total. Skipped when the Postgres test database is not
// reachable — the property under test is the shared store's real atomicity,
// which an in-memory fake cannot exercise.
func TestClusterRateCounter_ConcurrentRequestsNeverExceedLimit(t *testing.T) {
	// Two independent stores, each its own DatabaseProvider instance (own
	// connection pool) against the same test database — modelling two
	// controller nodes that share nothing but the database, exactly as
	// production cluster nodes share only the database.
	storeA := tryNewDatabaseRateCounterStore(t)
	if storeA == nil {
		t.Skip("PostgreSQL test database not reachable — run `make test-integration-setup && make test-integration-db` to exercise the cluster-mode path")
	}
	storeB := tryNewDatabaseRateCounterStore(t)
	require.NotNil(t, storeB, "second connection to the same reachable test database must also succeed")

	const limit = 5
	const window = time.Minute
	const attempts = 40
	// Unique per run: the counter table is a shared Postgres database that
	// persists rows across test runs within their window, so a fixed key
	// could inherit count from a previous run and make the exact-limit
	// assertion below flaky.
	source := fmt.Sprintf("203.0.113.77-%d", time.Now().UnixNano())

	nodeA := &Server{
		haManager:                 newNonAuthoritativeHAManager(t),
		enrolmentTokenMintLimiter: newSourceRateLimiter(limit, window),
	}
	nodeA.SetRateCounterStore(storeA)

	nodeB := &Server{
		haManager:                 newNonAuthoritativeHAManager(t),
		enrolmentTokenMintLimiter: newSourceRateLimiter(limit, window),
	}
	nodeB.SetRateCounterStore(storeB)

	// Both limiters must have picked up the shared backend before the race
	// below is meaningful — otherwise each node would fall back to its own
	// in-memory map and this test would pass for the wrong reason.
	require.NotNil(t, nodeA.enrolmentTokenMintLimiter.sharedCounter,
		"nodeA must be wired onto the shared counter store")
	require.NotNil(t, nodeB.enrolmentTokenMintLimiter.sharedCounter,
		"nodeB must be wired onto the shared counter store")

	var wg sync.WaitGroup
	var allowed int32
	for i := 0; i < attempts; i++ {
		node := nodeA
		if i%2 == 0 {
			node = nodeB
		}
		wg.Add(1)
		go func(node *Server) {
			defer wg.Done()
			ok, _ := node.enrolmentTokenMintLimiter.allow(source)
			if ok {
				atomic.AddInt32(&allowed, 1)
			}
		}(node)
	}
	wg.Wait()

	require.LessOrEqual(t, int(allowed), limit,
		"two nodes racing the same source against a shared counter must never together allow more than the configured limit")
	require.Equal(t, limit, int(allowed),
		"with attempts far exceeding the limit, exactly limit calls should have been admitted")
}
