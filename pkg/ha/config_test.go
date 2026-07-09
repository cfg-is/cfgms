// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFastElectionConfig_ElectionTickInvariant asserts that the values returned by
// FastElectionConfig satisfy the ElectionTick ≥ 5 invariant enforced by
// NewRaftConsensus (raft_consensus.go:111). A ratio below 5 causes NewRaftConsensus
// to return an error, which would silently break every test that calls
// newClusterModeHAManager.
func TestFastElectionConfig_ElectionTickInvariant(t *testing.T) {
	cfg := FastElectionConfig()
	electionTick := int(cfg.ElectionTimeout / cfg.HeartbeatInterval)
	assert.GreaterOrEqual(t, electionTick, 5,
		"ElectionTimeout (%v) / HeartbeatInterval (%v) = ElectionTick %d must be ≥5",
		cfg.ElectionTimeout, cfg.HeartbeatInterval, electionTick)
}
