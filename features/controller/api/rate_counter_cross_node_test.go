// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3896 (ADR-031 follow-up to Issue #3761): [REQUIRED TEST]
// cross-node budget-exhaustion coverage for sourceRateLimiter's shared-counter
// path. TestSourceRateLimiter_ClusterModeUsesSharedCounter
// (rate_limiter_test.go) already proves the wiring picks the shared backend in
// ClusterMode; this file proves the resulting behavior is actually safe under
// concurrency: two nodes serving the same source against one shared
// business.RateCounterStore instance (mirroring the
// setupTwoNodeSharedStoreServers pattern in cas_cross_node_test.go — two
// independent servers sharing one store) must never together grant more than
// the configured limit, regardless of which node each attempt lands on. Run
// with -race.
//
// The shared store here is pkgtesting.SetupTestRateCounterStore() — a real,
// mutex-guarded implementation of business.RateCounterStore (not a mock), so
// this test runs unconditionally in CI rather than skipping when a Postgres
// test database isn't reachable. It proves the property this test is actually
// responsible for: sourceRateLimiter.allow correctly serializes concurrent
// callers through whatever shared counter it is wired to. The database
// implementation's own atomicity under concurrent writers is proven
// separately and for real in
// pkg/storage/providers/database/rate_counter_store_test.go's
// TestDatabaseRateCounterStore_ConcurrentIncrementsNeverLoseAnAttempt.
package api

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// TestClusterRateCounter_ConcurrentRequestsNeverExceedLimit is the
// [REQUIRED TEST] for Issue #3896: a budget-exhaustion race from two nodes
// serving the same source concurrently must never grant more than the
// configured limit total.
func TestClusterRateCounter_ConcurrentRequestsNeverExceedLimit(t *testing.T) {
	// One shared store standing in for the database both cluster nodes would
	// otherwise share — modelling two controller nodes that share nothing but
	// the counter store, exactly as production cluster nodes share only the
	// database.
	sharedStore := pkgtesting.SetupTestRateCounterStore()

	const limit = 5
	const window = time.Minute
	const attempts = 40
	// Unique per run: guards against any cross-test leakage of the shared
	// package-level store's keys making the exact-limit assertion flaky.
	source := fmt.Sprintf("203.0.113.77-%d", time.Now().UnixNano())

	nodeA := &Server{
		haManager:                 newNonAuthoritativeHAManager(t),
		enrolmentTokenMintLimiter: newSourceRateLimiter(limit, window),
	}
	nodeA.SetRateCounterStore(sharedStore)

	nodeB := &Server{
		haManager:                 newNonAuthoritativeHAManager(t),
		enrolmentTokenMintLimiter: newSourceRateLimiter(limit, window),
	}
	nodeB.SetRateCounterStore(sharedStore)

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
