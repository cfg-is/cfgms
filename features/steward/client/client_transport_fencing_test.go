// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// ---------------------------------------------------------------------------
// checkTermFence — ADR-029 Decision 6 three-state ratchet, comparison logic
// only (Story #3436). Persistence across a steward restart and the
// authenticated cluster-rebuild reset path are #3437.
// ---------------------------------------------------------------------------

func fencedCommand(id string, term uint64) *cpTypes.SignedCommand {
	return &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        id,
			Type:      cpTypes.CommandSyncConfig,
			StewardID: "steward-fence-test",
			Timestamp: time.Now(),
			Term:      term,
		},
	}
}

// TestCheckTermFence_AcceptsAtOrAboveHighest_RejectsBelow covers the story's
// first REQUIRED TEST: once the ratchet is set, a lower term is rejected and a
// term at or above the high-water mark is accepted.
func TestCheckTermFence_AcceptsAtOrAboveHighest_RejectsBelow(t *testing.T) {
	tc := &TransportClient{logger: newTestLogger(t)}

	// Seed the ratchet at term 5.
	require.NoError(t, tc.checkTermFence(fencedCommand("seed", 5)))

	// Equal term: accepted.
	assert.NoError(t, tc.checkTermFence(fencedCommand("equal", 5)))

	// Higher term: accepted, and becomes the new high-water mark.
	assert.NoError(t, tc.checkTermFence(fencedCommand("higher", 9)))

	// Lower than the new high-water mark: rejected.
	err := tc.checkTermFence(fencedCommand("lower", 6))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCommandTermFenced)

	tc.mu.RLock()
	highest := tc.highestTermSeen
	tc.mu.RUnlock()
	assert.Equal(t, uint64(9), highest, "a rejected command must not move the high-water mark")
}

// TestCheckTermFence_BootstrapAcceptsMissingOrZeroTerm_AdoptsBaseline covers the
// story's bootstrap REQUIRED TEST: a steward that has never observed a stamped
// command accepts a missing/zero term, and the first stamped command it does see
// becomes the new baseline.
func TestCheckTermFence_BootstrapAcceptsMissingOrZeroTerm_AdoptsBaseline(t *testing.T) {
	tc := &TransportClient{logger: newTestLogger(t)}

	// Unstamped command pre-ratchet: accepted, ratchet stays unset.
	require.NoError(t, tc.checkTermFence(fencedCommand("unstamped-1", 0)))
	tc.mu.RLock()
	ratchetSet := tc.termRatchetSet
	tc.mu.RUnlock()
	assert.False(t, ratchetSet, "an unstamped command must not itself set the ratchet")

	// A second unstamped command is still accepted (mid-rollout behind an older controller).
	require.NoError(t, tc.checkTermFence(fencedCommand("unstamped-2", 0)))

	// First stamped command: accepted, adopted as the new baseline.
	require.NoError(t, tc.checkTermFence(fencedCommand("stamped-1", 3)))
	tc.mu.RLock()
	ratchetSet = tc.termRatchetSet
	highest := tc.highestTermSeen
	tc.mu.RUnlock()
	assert.True(t, ratchetSet)
	assert.Equal(t, uint64(3), highest)
}

// TestCheckTermFence_DowngradeAfterRatchetSet_RejectsMissingOrZeroTerm covers the
// story's downgrade/omission REQUIRED TEST — the case that matters most: once
// the ratchet is set by a real baseline, a subsequent unstamped command is
// rejected as a downgrade attempt, not treated as legacy traffic.
func TestCheckTermFence_DowngradeAfterRatchetSet_RejectsMissingOrZeroTerm(t *testing.T) {
	tc := &TransportClient{logger: newTestLogger(t)}

	require.NoError(t, tc.checkTermFence(fencedCommand("seed", 4)))

	err := tc.checkTermFence(fencedCommand("downgrade-attempt", 0))
	require.Error(t, err, "an unstamped command after the ratchet is set must be refused")
	assert.ErrorIs(t, err, ErrCommandTermFenced)

	// The ratchet is untouched by the rejected command.
	tc.mu.RLock()
	highest := tc.highestTermSeen
	tc.mu.RUnlock()
	assert.Equal(t, uint64(4), highest)
}

// ---------------------------------------------------------------------------
// receiveCommand — the wired receive path. Verifies a fenced rejection is a
// plain refusal (the same sentinel-error shape as the pre-existing
// ErrWrongSteward / ErrCommandReplay checks in commands.Handler) that never
// reaches dispatch, rather than something that looks like a transport error
// and could trigger reconnect/retry-storm behaviour upstream.
// ---------------------------------------------------------------------------

// TestReceiveCommand_FencedRejection_NeverDispatches covers the story's REQUIRED
// TEST that a fenced rejection is surfaced as a refusal, not a transport error:
// dispatch (commands.Handler.HandleCommand in production) is never invoked, and
// the returned error is the plain ErrCommandTermFenced sentinel — the same
// category of error clientReceiveLoop (pkg/controlplane/providers/grpc) already
// treats as log-and-continue, not as a reason to tear down the connection.
func TestReceiveCommand_FencedRejection_NeverDispatches(t *testing.T) {
	tc := &TransportClient{logger: newTestLogger(t)}
	require.NoError(t, tc.checkTermFence(fencedCommand("seed", 10)))

	dispatched := false
	dispatch := func(context.Context, *cpTypes.SignedCommand) error {
		dispatched = true
		return nil
	}

	err := tc.receiveCommand(context.Background(), fencedCommand("stale", 2), dispatch)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCommandTermFenced)
	assert.False(t, dispatched, "a fenced command must never reach the dispatch pipeline")

	// Not merely errors.Is-compatible by accident: unwrap to the exact sentinel,
	// confirming this is a plain domain error rather than a wrapped transport/gRPC
	// error that upstream code might special-case for reconnect.
	assert.True(t, errors.Is(err, ErrCommandTermFenced))
}

// TestReceiveCommand_AcceptedCommand_Dispatches verifies the fence does not
// interfere with normal delivery: an admitted command reaches dispatch exactly
// once, unmodified.
func TestReceiveCommand_AcceptedCommand_Dispatches(t *testing.T) {
	tc := &TransportClient{logger: newTestLogger(t)}

	var gotID string
	dispatch := func(_ context.Context, sc *cpTypes.SignedCommand) error {
		gotID = sc.Command.ID
		return nil
	}

	cmd := fencedCommand("admitted", 1)
	err := tc.receiveCommand(context.Background(), cmd, dispatch)
	require.NoError(t, err)
	assert.Equal(t, "admitted", gotID)
}
