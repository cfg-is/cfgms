//go:build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz
// +build commercial

package ha

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestRaftConsensus_propose_logsError(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{
		ID:    "test-node",
		State: NodeStateHealthy,
		Role:  NodeRoleFollower,
	}

	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, mock)
	require.NoError(t, err)

	// Stop the underlying raft node so that Propose returns ErrStopped.
	// The runRaft goroutine continues running (stopC and ctx not closed),
	// so it will read from proposeC, call Propose, get ErrStopped, and log.
	rc.node.Stop()

	// Send a proposal in a goroutine; the runRaft loop will try to Propose
	// on the stopped node, receive ErrStopped, and log the error.
	go func() {
		select {
		case rc.proposeC <- []byte("trigger error"):
		case <-time.After(2 * time.Second):
		}
	}()

	// Poll until the error log appears — no fixed sleep, race-detector safe.
	require.Eventually(t, func() bool {
		for _, entry := range mock.GetLogs("error") {
			if entry.Message == "Failed to propose to Raft" {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "expected 'Failed to propose to Raft' error log")
}
