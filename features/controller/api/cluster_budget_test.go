// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestClusterBudgetDivisor_ReflectsDeploymentShape is the [REQUIRED TEST] for Issue
// #3761: clusterBudgetDivisor must return 1 for every deployment shape where at most
// one process can serve mutating traffic (nil haManager, SingleServerMode,
// BlueGreenMode), and the live cluster-membership count (floored at
// clusterBudgetDivisorMinClusterNodes) only in ClusterMode. Uses a real *ha.Manager
// in each shape — the same helpers the leader-gate continuity tests use — not a stub.
func TestClusterBudgetDivisor_ReflectsDeploymentShape(t *testing.T) {
	t.Run("nil haManager", func(t *testing.T) {
		s := &Server{}
		assert.Equal(t, 1, s.clusterBudgetDivisor())
	})

	t.Run("SingleServerMode", func(t *testing.T) {
		s := &Server{haManager: newAuthoritativeHAManager(t)}
		assert.Equal(t, 1, s.clusterBudgetDivisor())
	})

	t.Run("BlueGreenMode", func(t *testing.T) {
		cfg := ha.DefaultConfig()
		cfg.Mode = ha.BlueGreenMode
		cfg.Node.ID = "test-bluegreen-node"
		manager, err := ha.NewManager(cfg, logging.NewNoopLogger(), nil, nil, "")
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, manager.Stop(context.Background())) })

		s := &Server{haManager: manager}
		assert.Equal(t, 1, s.clusterBudgetDivisor(),
			"BlueGreenMode's standby instance is a cutover target, not a concurrently-serving peer")
	})

	t.Run("ClusterMode floors at the minimum", func(t *testing.T) {
		// A real ClusterMode manager that has never Started sees no cluster
		// membership beyond itself — exactly the sparse-membership case the floor
		// exists for.
		s := &Server{haManager: newNonAuthoritativeHAManager(t)}
		assert.Equal(t, clusterBudgetDivisorMinClusterNodes, s.clusterBudgetDivisor())
	})
}

// TestOperatorPayloadSignThrottle_ScalesWithClusterSize is the [REQUIRED TEST] for
// Issue #3761: recordSignFailure must scale the failure count it feeds to
// elevateBackoff by clusterBudgetDivisor, so the configured backoff schedule applies
// fleet-wide rather than being divided away by node count the way any-node service
// would otherwise allow. A single recorded failure must not yet throttle on a
// SingleServerMode node (divisor 1: elevateBackoff(1) == 0) but must throttle on a
// ClusterMode node (divisor floored at 3: elevateBackoff(3) > 0).
func TestOperatorPayloadSignThrottle_ScalesWithClusterSize(t *testing.T) {
	t.Run("single-server: one failure does not yet throttle", func(t *testing.T) {
		s := &Server{haManager: newAuthoritativeHAManager(t)}
		s.recordSignFailure("session:x")
		blocked, _ := s.checkSignThrottle("session:x")
		assert.False(t, blocked, "a single failure must not throttle a single-server node")
	})

	t.Run("cluster mode: one failure is scaled up to the floor and throttles", func(t *testing.T) {
		s := &Server{haManager: newNonAuthoritativeHAManager(t)}
		s.recordSignFailure("session:y")
		blocked, retryAfter := s.checkSignThrottle("session:y")
		assert.True(t, blocked, "a single failure scaled by the cluster-size floor (3) must throttle")
		assert.Greater(t, retryAfter, time.Duration(0))
	})
}
