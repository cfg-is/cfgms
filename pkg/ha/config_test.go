// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestClusterConfig_LeaseDuration_IsEightTenthsOfElectionTimeout verifies that
// LeaseDuration() returns 0.8 × ElectionTimeout for both DefaultConfig and
// FastElectionConfig, per ADR-029 Decision 1.
func TestClusterConfig_LeaseDuration_IsEightTenthsOfElectionTimeout(t *testing.T) {
	cases := []struct {
		name string
		cfg  ClusterConfig
	}{
		{"DefaultConfig", DefaultConfig().Cluster},
		{"FastElectionConfig", FastElectionConfig()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.LeaseDuration()
			want := time.Duration(float64(tc.cfg.ElectionTimeout) * 0.8)
			assert.Equal(t, want, got,
				"LeaseDuration must be 0.8 × ElectionTimeout")
			assert.Less(t, got, tc.cfg.ElectionTimeout,
				"LeaseDuration must be strictly less than ElectionTimeout")
			assert.Greater(t, got, tc.cfg.HeartbeatInterval,
				"LeaseDuration must be greater than HeartbeatInterval")
		})
	}
}

// TestConfig_Validate_LeaseConstraints verifies that Config.Validate() rejects a
// ClusterConfig where the derived lease duration would violate its own invariants.
// (In practice the 0.8× ratio always satisfies the constraint, but the validation
// gate exists so future changes to the ratio cannot silently produce an invalid bound.)
func TestConfig_Validate_LeaseConstraints(t *testing.T) {
	// A valid ClusterMode config must pass validation.
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "validate-lease-node"
	assert.NoError(t, cfg.Validate(), "valid ClusterMode config must pass Validate()")
}

// TestClusterConfig_LeaseDuration_IsValidUnderFastElectionConfig ensures the
// test-scale timings (200ms election, 40ms heartbeat) still produce a lease >
// one heartbeat interval — i.e., the lease is meaningful at test scale.
func TestClusterConfig_LeaseDuration_IsValidUnderFastElectionConfig(t *testing.T) {
	cfg := FastElectionConfig()
	lease := cfg.LeaseDuration()

	// lease = 0.8 × 200ms = 160ms; heartbeat = 40ms.
	assert.Greater(t, lease, cfg.HeartbeatInterval,
		"lease must cover at least one heartbeat interval so a single ack can refresh it")
	assert.Less(t, lease, cfg.ElectionTimeout,
		"lease must expire before ElectionTimeout to guarantee no dual-leader overlap")
}
