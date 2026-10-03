// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ScriptRunStoreContract verifies a ScriptRunStore round-trips runs, jobs and
// grants (Issue #4528). IDs are unique per call, so the store need not be empty.
func ScriptRunStoreContract(t *testing.T, store ScriptRunStore) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	runID := "run-" + suffix
	tenant := "tenant-" + suffix
	created := time.Now().UTC().Truncate(time.Millisecond)

	_, err := store.GetRun(ctx, runID)
	require.ErrorIs(t, err, ErrScriptRunNotFound, "a missing run reports ErrScriptRunNotFound")

	require.NoError(t, store.CreateRun(ctx, &ScriptRun{
		RunID: runID, TenantID: tenant, CreatedBy: "admin", CreatedAt: created, Status: "pending",
		FilterJSON: []byte(`{"IDs":["steward-1"]}`), InlineContent: "hostname", Shell: "powershell", JobCount: 2,
	}))
	got, err := store.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, tenant, got.TenantID)
	assert.Equal(t, "admin", got.CreatedBy)
	assert.True(t, created.Equal(got.CreatedAt), "created_at round-trips")
	assert.Equal(t, "hostname", got.InlineContent)
	assert.Equal(t, "powershell", got.Shell)
	assert.Equal(t, 2, got.JobCount)
	assert.JSONEq(t, `{"IDs":["steward-1"]}`, string(got.FilterJSON))

	runs, err := store.ListRuns(ctx, tenant, 10, 0)
	require.NoError(t, err)
	require.Len(t, runs, 1)
	assert.Equal(t, runID, runs[0].RunID)

	for i, id := range []string{"job-a-" + suffix, "job-b-" + suffix} {
		require.NoError(t, store.CreateJob(ctx, &ScriptRunJob{
			JobID: id, RunID: runID, DeviceID: fmt.Sprintf("steward-%d", i), Status: "pending",
			CreatedAt: created.Add(time.Duration(i) * time.Second),
		}))
	}
	done := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, store.UpdateJobStatus(ctx, "job-a-"+suffix, "running", "exec-a", nil))
	require.NoError(t, store.UpdateJobResult(ctx, "job-a-"+suffix, "completed", "", "out", "err", 0, &done))
	require.NoError(t, store.UpdateJobResult(ctx, "job-b-"+suffix, "failed", "exec-b", "", "boom", 3, &done))

	jobs, err := store.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	require.Len(t, jobs, 2)
	assert.Equal(t, "job-a-"+suffix, jobs[0].JobID, "jobs are ordered oldest first")
	assert.Equal(t, "completed", jobs[0].Status)
	assert.Equal(t, "exec-a", jobs[0].ExecutionID, "an empty executionID keeps the stored one")
	assert.Equal(t, "out", jobs[0].Output)
	require.NotNil(t, jobs[0].CompletedAt)
	assert.Equal(t, 3, jobs[1].ExitCode)
	assert.Equal(t, "boom", jobs[1].Stderr)

	require.NoError(t, store.UpdateRunCounts(ctx, runID, 1, 1))
	require.NoError(t, store.UpdateRunStatus(ctx, runID, "failed"))
	got, err = store.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, "failed", got.Status)
	assert.Equal(t, 1, got.CompletedJobs)
	assert.Equal(t, 1, got.FailedJobs)

	execID := "grant-exec-" + suffix
	require.NoError(t, store.CreateExecutionGrant(ctx, &ExecutionGrant{
		DeviceID: "steward-0", TenantID: tenant, ExecutionID: execID, Scope: []string{"config:read"},
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}))
	g, err := store.LookupGrant(ctx, "steward-0", execID)
	require.NoError(t, err)
	assert.Equal(t, []string{"config:read"}, g.Scope)
	_, err = store.LookupGrant(ctx, "other-device", execID)
	assert.ErrorIs(t, err, ErrExecutionGrantNotFound, "a grant is bound to its device")
	require.NoError(t, store.ConsumeGrant(ctx, execID))
	_, err = store.LookupGrant(ctx, "steward-0", execID)
	assert.ErrorIs(t, err, ErrExecutionGrantConsumed)

	expiredID := "grant-expired-" + suffix
	require.NoError(t, store.CreateExecutionGrant(ctx, &ExecutionGrant{
		DeviceID: "steward-0", TenantID: tenant, ExecutionID: expiredID, Scope: []string{},
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour), ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}))
	_, err = store.LookupGrant(ctx, "steward-0", expiredID)
	assert.ErrorIs(t, err, ErrExecutionGrantNotFound, "an expired grant is not found")
}

// ExecutionQueueStoreContract verifies an ExecutionQueueStore's state machine
// and its multi-node claim guarantee (Issue #4528). Device IDs are unique per
// call, so the store need not be empty.
func ExecutionQueueStoreContract(t *testing.T, store ExecutionQueueStore) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Millisecond)

	entry := func(device, exec, hash string, expires time.Time) *ExecutionQueueEntry {
		return &ExecutionQueueEntry{
			ExecutionID: exec, DeviceID: device, ParamHash: hash, State: ExecutionQueueStateQueued,
			QueuedAt: now, ExpiresAt: expires, Payload: []byte(fmt.Sprintf(`{"execution_id":%q}`, exec)),
		}
	}

	t.Run("lifecycle", func(t *testing.T) {
		dev := "dev-life-" + suffix
		require.NoError(t, store.Enqueue(ctx, entry(dev, "e1-"+suffix, "h1", now.Add(time.Hour))))
		err := store.Enqueue(ctx, entry(dev, "e1dup-"+suffix, "h1", now.Add(time.Hour)))
		require.ErrorIs(t, err, ErrDuplicateQueuedExecution, "same device+hash while queued is a duplicate")
		require.NoError(t, store.Enqueue(ctx, entry(dev, "e2-"+suffix, "h2", now.Add(-time.Minute))))

		active, err := store.List(ctx, dev)
		require.NoError(t, err)
		assert.Len(t, active, 2)

		got, err := store.Dequeue(ctx, dev, now)
		require.NoError(t, err)
		require.Len(t, got, 1, "the expired entry is not dispatched")
		assert.Equal(t, "e1-"+suffix, got[0].ExecutionID)
		assert.Equal(t, ExecutionQueueStateDispatched, got[0].State)
		require.NotNil(t, got[0].DispatchedAt)
		assert.JSONEq(t, fmt.Sprintf(`{"execution_id":%q}`, "e1-"+suffix), string(got[0].Payload), "payload round-trips")

		again, err := store.Dequeue(ctx, dev, now.Add(time.Second))
		require.NoError(t, err)
		require.Len(t, again, 1, "dispatched-unacknowledged work is returned for re-dispatch")
		assert.True(t, now.Equal(*again[0].DispatchedAt), "re-dispatch keeps the original dispatch time")

		require.NoError(t, store.Enqueue(ctx, entry(dev, "e1b-"+suffix, "h1", now.Add(time.Hour))),
			"a hash is free again once its entry left the queued state")

		require.NoError(t, store.AcknowledgeCompletion(ctx, "e1-"+suffix, dev, ExecutionQueueStateCompleted, now))
		err = store.AcknowledgeCompletion(ctx, "e1-"+suffix, dev, ExecutionQueueStateCompleted, now)
		assert.ErrorIs(t, err, ErrExecutionQueueEntryNotFound, "a completed entry cannot be acknowledged twice")
		assert.Error(t, store.AcknowledgeCompletion(ctx, "e1b-"+suffix, dev, ExecutionQueueStateQueued, now),
			"only completed or failed are valid completion states")

		require.NoError(t, store.Cancel(ctx, dev, "e1b-"+suffix))
		assert.ErrorIs(t, store.Cancel(ctx, dev, "e1b-"+suffix), ErrExecutionQueueEntryNotFound)

		active, err = store.List(ctx, dev)
		require.NoError(t, err)
		assert.Empty(t, active)
	})

	t.Run("maintenance", func(t *testing.T) {
		dev := "dev-maint-" + suffix
		require.NoError(t, store.Enqueue(ctx, entry(dev, "m1-"+suffix, "h1", now.Add(time.Hour))))
		// m2 has already expired when the dequeue below runs, so it is never dispatched.
		require.NoError(t, store.Enqueue(ctx, entry(dev, "m2-"+suffix, "h2", now.Add(-20*time.Minute))))
		_, err := store.Dequeue(ctx, dev, now.Add(-10*time.Minute))
		require.NoError(t, err)

		n, err := store.RequeueStale(ctx, now.Add(-5*time.Minute))
		require.NoError(t, err)
		assert.GreaterOrEqual(t, n, 1, "a dispatch older than the cutoff is re-queued")
		active, err := store.List(ctx, dev)
		require.NoError(t, err)
		require.Len(t, active, 1)
		assert.Equal(t, ExecutionQueueStateQueued, active[0].State)
		assert.Nil(t, active[0].DispatchedAt)

		require.NoError(t, store.Enqueue(ctx, entry(dev, "m3-"+suffix, "h3", now.Add(-time.Second))))
		_, err = store.CleanupExpired(ctx, now)
		require.NoError(t, err)
		active, err = store.List(ctx, dev)
		require.NoError(t, err)
		for _, e := range active {
			assert.NotEqual(t, "m3-"+suffix, e.ExecutionID, "an expired queued entry leaves the active set")
		}

		stats, err := store.GetStats(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, stats.DeviceQueueDepths[dev], 1)
		assert.GreaterOrEqual(t, stats.CountsByState[ExecutionQueueStateExpired], 1)
	})

	t.Run("concurrent dequeue claims each entry once", func(t *testing.T) {
		dev := "dev-race-" + suffix
		const entries, callers = 20, 6
		for i := 0; i < entries; i++ {
			require.NoError(t, store.Enqueue(ctx, entry(dev, fmt.Sprintf("r%d-%s", i, suffix), fmt.Sprintf("h%d", i), now.Add(time.Hour))))
		}
		var mu sync.Mutex
		claimedBy := map[string]int{}
		var wg sync.WaitGroup
		errs := make(chan error, callers)
		for c := 0; c < callers; c++ {
			wg.Add(1)
			go func(c int) {
				defer wg.Done()
				callerNow := now.Add(time.Duration(c+1) * time.Millisecond)
				got, err := store.Dequeue(ctx, dev, callerNow)
				if err != nil {
					errs <- err
					return
				}
				mu.Lock()
				defer mu.Unlock()
				for _, e := range got {
					// Only entries this caller moved to dispatched carry its own time.
					if e.DispatchedAt != nil && e.DispatchedAt.Equal(callerNow) {
						claimedBy[e.ExecutionID]++
					}
				}
			}(c)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		assert.Len(t, claimedBy, entries, "every queued entry is claimed")
		for id, n := range claimedBy {
			assert.Equal(t, 1, n, "entry %s claimed by more than one caller", id)
		}
	})
}
