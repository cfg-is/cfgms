// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/ha"
)

// clusterBudgetDivisorCacheTTL bounds how often clusterBudgetDivisor calls into
// haManager.GetClusterNodes() — a live cluster query — rather than reusing the
// last-seen node count. Abuse budgets are approximate by nature (see the package
// doc comment on clusterBudgetDivisor), so a few seconds of staleness after a
// membership change is an acceptable trade for not adding a cluster query to every
// rate-limited request.
const clusterBudgetDivisorCacheTTL = 5 * time.Second

// clusterBudgetDivisorMinClusterNodes floors the divisor used in ClusterMode. A
// freshly-formed or partially-observed cluster reporting fewer than this many nodes
// still divides by this floor rather than by the transient low count, so a momentary
// membership gap does not multiply every configured budget back up towards the
// single-node limit.
const clusterBudgetDivisorMinClusterNodes = 3

// clusterBudgetDivisorCache holds the last-computed divisor so concurrent
// request-path callers do not each pay a live cluster-membership query.
type clusterBudgetDivisorCache struct {
	mu       sync.Mutex
	value    int
	computed time.Time
}

// clusterBudgetDivisor returns the number of cluster nodes that can serve a given
// request today, per Server.haManager's deployment mode: 1 for SingleServerMode,
// BlueGreenMode and un-clustered deployments; live cluster membership floored at
// clusterBudgetDivisorMinClusterNodes in ClusterMode, cached for
// clusterBudgetDivisorCacheTTL.
//
// Per-process abuse budgets — the source rate limiters (rate_limiter.go) and the
// sign-ceremony backoff (recordSignFailure) — divide their configured limit by this
// value. Before ADR-031 Decision 1's any-node service, the leadership gate funneled
// every mutating attempt through one process, which made a per-process budget a
// fleet-wide budget incidentally; any-node service would otherwise grant node-count
// times the configured budget, since each node tracks its own in-memory counters.
// Dividing by clusterBudgetDivisor keeps the configured value the fleet-wide budget
// in both cases.
//
// This is an interim measure (Issue #3761 residual review): it approximates a
// shared counter by assuming attempts spread evenly across nodes, which an
// adversary deliberately targeting one node can defeat. The durable fix is to back
// these counters with the shared database — follow-up under epic #3751.
func (s *Server) clusterBudgetDivisor() int {
	if s.haManager == nil || s.haManager.GetDeploymentMode() != ha.ClusterMode {
		// SingleServerMode: the only process serving requests. BlueGreenMode: the
		// standby instance is a cutover target, not a concurrently-serving peer —
		// only one of the pair takes live traffic at a time.
		return 1
	}

	s.clusterBudgetDivisorCache.mu.Lock()
	defer s.clusterBudgetDivisorCache.mu.Unlock()
	if s.clusterBudgetDivisorCache.value > 0 &&
		time.Since(s.clusterBudgetDivisorCache.computed) < clusterBudgetDivisorCacheTTL {
		return s.clusterBudgetDivisorCache.value
	}

	divisor := clusterBudgetDivisorMinClusterNodes
	if nodes, err := s.haManager.GetClusterNodes(); err == nil && len(nodes) > clusterBudgetDivisorMinClusterNodes {
		divisor = len(nodes)
	}
	s.clusterBudgetDivisorCache.value = divisor
	s.clusterBudgetDivisorCache.computed = time.Now()
	return divisor
}
