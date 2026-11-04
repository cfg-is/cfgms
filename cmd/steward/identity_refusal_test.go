// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const identityRefusedCode = "identity.refused"

func (h *lifecycleHarness) completes() int {
	h.controller.mu.Lock()
	defer h.controller.mu.Unlock()
	return h.controller.completes
}

func (h *lifecycleHarness) runRefusalLifecycle(t *testing.T, rejectedRetry, pendingPoll time.Duration) {
	t.Helper()
	lc := h.lifecycle(t)
	// Certificate renewal must not fire: only the refusal path is under test.
	lc.renewWindow = func(time.Duration) time.Duration { return time.Second }
	lc.rejectedRetry = rejectedRetry
	lc.pendingPoll = pendingPoll
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { lc.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	// No wait for Run to register its handler: a refusal that lands first stays
	// outstanding, and SetIdentityRejectedHandler replays it on registration.
}

// A mid-session revocation triggers one re-admission cycle: the request lands in
// the controller's refresh queue, and once an operator approves it the SAME
// client is connected again with the new certificate — no restart.
func TestIdentityLifecycle_RevokedMidSessionReadmitsInProcess(t *testing.T) {
	h := newLifecycleHarnessMode(t, "queue", time.Minute, time.Hour, 3*time.Hour)
	tcBefore := h.tc
	original := h.newestClientSerial(t)
	h.runRefusalLifecycle(t, time.Hour, 100*time.Millisecond)

	require.NoError(t, h.controller.certMgr.Revoke(original))

	require.Eventually(t, func() bool {
		h.controller.mu.Lock()
		defer h.controller.mu.Unlock()
		return h.controller.pendingCSR != nil
	}, 20*time.Second, 50*time.Millisecond, "a refresh request appears in the pending queue")
	assert.Contains(t, reasonCodes(h.tc), identityRefusedCode, "the refusal reason is reported while waiting")
	assert.False(t, h.tc.ControlStreamConnected(), "a revoked steward stays out until approved")

	h.controller.approve()

	require.Eventually(t, func() bool {
		return h.newestClientSerial(t) != original && h.tc.ControlStreamConnected()
	}, 30*time.Second, 100*time.Millisecond, "the steward is connected again in the same process")
	assert.Same(t, tcBefore, h.tc)
	require.Eventually(t, func() bool { return len(reasonCodes(h.tc)) == 0 }, 10*time.Second, 50*time.Millisecond,
		"approval clears the reason")
	assert.Equal(t, 1, h.completes(), "one re-admission request for the whole episode")
}

// A refused re-admission keeps the steward alive and asking at the slow interval,
// with the reason set; once the controller relents the reason clears.
func TestIdentityLifecycle_RefusedReadmissionRetriesSlowlyThenRecovers(t *testing.T) {
	h := newLifecycleHarnessMode(t, "reject", time.Minute, time.Hour, 3*time.Hour)
	original := h.newestClientSerial(t)
	const retry = 700 * time.Millisecond
	h.runRefusalLifecycle(t, retry, 100*time.Millisecond)

	require.NoError(t, h.controller.certMgr.Revoke(original))

	require.Eventually(t, func() bool { return h.completes() >= 1 }, 20*time.Second, 20*time.Millisecond)
	assert.Contains(t, reasonCodes(h.tc), identityRefusedCode)

	// Slow retry, never a hot loop: well under one request per 100ms.
	start, startN := time.Now(), h.completes()
	time.Sleep(2 * time.Second)
	n := h.completes() - startN
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, n, 1, "the steward keeps asking")
	assert.LessOrEqual(t, n, int(elapsed/retry)+1, "retries are paced by the rejected interval")
	assert.Contains(t, reasonCodes(h.tc), identityRefusedCode, "the reason holds while refused")

	h.controller.setCompleteMode("issue")
	require.Eventually(t, func() bool {
		return h.newestClientSerial(t) != original && h.tc.ControlStreamConnected()
	}, 30*time.Second, 100*time.Millisecond, "recovers without a restart once the controller approves")
	require.Eventually(t, func() bool { return len(reasonCodes(h.tc)) == 0 }, 10*time.Second, 50*time.Millisecond)
}
