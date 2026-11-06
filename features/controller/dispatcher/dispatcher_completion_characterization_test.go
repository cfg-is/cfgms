// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dispatcher

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"

	"github.com/cfgis/cfgms/features/controller/run"
	script "github.com/cfgis/cfgms/features/modules/stdlib/script"
)

// dispatchercompletionCharRun wires a dispatcher to a real run manager with one
// dispatched, run-tracked execution on device-1 and returns what a test needs to
// inject a terminal event and read the recorded job.
type dispatchercompletionCharRun struct {
	cp      *testControlPlane
	q       *script.ExecutionQueue
	manager *run.Manager
	runID   string
}

func dispatchercompletionCharSetup(t *testing.T, execID string, idempotent bool) *dispatchercompletionCharRun {
	t.Helper()
	store := run.NewRunStoreSQL(mustOpenMemDB(t))
	require.NoError(t, store.Init(context.Background()))
	manager := run.NewManager(store, nil)

	runID := "run-" + execID
	require.NoError(t, store.CreateRun(&run.RunRecord{
		RunID: runID, TenantID: "tenant-abc", CreatedAt: time.Now().UTC(),
		Status: run.RunStatusRunning, JobCount: 1,
	}))
	require.NoError(t, store.CreateJob(&run.JobRecord{
		JobID: "job-" + execID, RunID: runID, DeviceID: "device-1",
		ExecutionID: execID, Status: run.JobStatusPending, CreatedAt: time.Now().UTC(),
	}))

	cp := &testControlPlane{}
	q := newTestQueue(t, nil)
	d := newTestDispatcher(t, q, cp)
	d.SetRunCompletionSink(manager)
	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)

	qe := runTrackedExec(execID, "script-"+execID, runID, "job-"+execID)
	if idempotent {
		qe.Metadata["idempotent"] = true
	}
	require.NoError(t, q.QueueExecution("device-1", qe))
	d.OnHeartbeat("device-1")
	require.Eventually(t, func() bool { return cp.sentCount() >= 1 }, 2*time.Second, 10*time.Millisecond)
	return &dispatchercompletionCharRun{cp: cp, q: q, manager: manager, runID: runID}
}

func (r *dispatchercompletionCharRun) job(t *testing.T) *run.JobRecord {
	t.Helper()
	jobs, err := r.manager.ListRunJobs(context.Background(), r.runID)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	return jobs[0]
}

func (r *dispatchercompletionCharRun) waitTerminal(t *testing.T) *run.JobRecord {
	t.Helper()
	require.Eventually(t, func() bool {
		jobs, err := r.manager.ListRunJobs(context.Background(), r.runID)
		return err == nil && len(jobs) == 1 &&
			(jobs[0].Status == run.JobStatusCompleted || jobs[0].Status == run.JobStatusFailed)
	}, 2*time.Second, 10*time.Millisecond)
	return r.job(t)
}

func dispatchercompletionCharEvent(typ controlplaneTypes.EventType, details map[string]interface{}) *controlplaneTypes.Event {
	return &controlplaneTypes.Event{
		ID: "evt-char", Type: typ, StewardID: "device-1", Timestamp: time.Now(), Details: details,
	}
}

func TestDispatcherCompletionChar_PreviewKeysUsedWhenFullKeysAbsent(t *testing.T) {
	r := dispatchercompletionCharSetup(t, "exec-char-preview", false)
	require.NoError(t, r.cp.injectEvent(context.Background(), dispatchercompletionCharEvent(
		controlplaneTypes.EventScriptCompleted, map[string]interface{}{
			"execution_id":   "exec-char-preview",
			"exit_code":      float64(0),
			"stdout_preview": "old-out",
			"stderr_preview": "old-err",
		})))
	got := r.waitTerminal(t)
	assert.Equal(t, run.JobStatusCompleted, got.Status)
	assert.Equal(t, "old-out", got.Output)
	assert.Equal(t, "old-err", got.Stderr)
}

func TestDispatcherCompletionChar_FullKeysWinOverPreviewKeys(t *testing.T) {
	r := dispatchercompletionCharSetup(t, "exec-char-full", false)
	require.NoError(t, r.cp.injectEvent(context.Background(), dispatchercompletionCharEvent(
		controlplaneTypes.EventScriptCompleted, map[string]interface{}{
			"execution_id":   "exec-char-full",
			"exit_code":      float64(3),
			"stdout":         "full-out",
			"stderr":         "full-err",
			"stdout_preview": "prev-out",
			"stderr_preview": "prev-err",
		})))
	got := r.waitTerminal(t)
	assert.Equal(t, run.JobStatusFailed, got.Status)
	assert.Equal(t, "full-out", got.Output)
	assert.Equal(t, "full-err", got.Stderr)
	assert.Equal(t, 3, got.ExitCode)
}

func TestDispatcherCompletionChar_CommandFailedSurfacesErrorAsStderr(t *testing.T) {
	r := dispatchercompletionCharSetup(t, "exec-char-cmdfail", false)
	require.NoError(t, r.cp.injectCommandFailed(context.Background(), "device-1", "exec-char-cmdfail", "unsupported shell"))
	got := r.waitTerminal(t)
	assert.Equal(t, run.JobStatusFailed, got.Status)
	assert.Equal(t, "unsupported shell", got.Stderr)
	assert.Empty(t, got.Output)
}

func TestDispatcherCompletionChar_CommandFailedKeepsExistingStderr(t *testing.T) {
	r := dispatchercompletionCharSetup(t, "exec-char-cmdfail-err", false)
	require.NoError(t, r.cp.injectEvent(context.Background(), dispatchercompletionCharEvent(
		controlplaneTypes.EventCommandFailed, map[string]interface{}{
			"execution_id": "exec-char-cmdfail-err",
			"stderr":       "real stderr",
			"error":        "ignored",
		})))
	got := r.waitTerminal(t)
	assert.Equal(t, run.JobStatusFailed, got.Status)
	assert.Equal(t, "real stderr", got.Stderr)
}

func TestDispatcherCompletionChar_OutputAboveCeilingDroppedAcrossStreams(t *testing.T) {
	r := dispatchercompletionCharSetup(t, "exec-char-ceiling", false)
	// Each stream is under 4 MB; only the sum exceeds the ceiling.
	half := strings.Repeat("X", 2*1024*1024+1)
	require.NoError(t, r.cp.injectEvent(context.Background(), dispatchercompletionCharEvent(
		controlplaneTypes.EventScriptCompleted, map[string]interface{}{
			"execution_id": "exec-char-ceiling",
			"exit_code":    float64(0),
			"stdout":       half,
			"stderr":       half,
		})))
	got := r.waitTerminal(t)
	assert.Equal(t, run.JobStatusCompleted, got.Status)
	assert.Empty(t, got.Output)
	assert.Empty(t, got.Stderr)
}

func TestDispatcherCompletionChar_OutputAtCeilingKept(t *testing.T) {
	r := dispatchercompletionCharSetup(t, "exec-char-atcap", false)
	out := strings.Repeat("Y", 4*1024*1024)
	require.NoError(t, r.cp.injectEvent(context.Background(), dispatchercompletionCharEvent(
		controlplaneTypes.EventScriptCompleted, map[string]interface{}{
			"execution_id": "exec-char-atcap",
			"exit_code":    float64(0),
			"stdout":       out,
		})))
	got := r.waitTerminal(t)
	assert.Len(t, got.Output, len(out))
}

func TestDispatcherCompletionChar_RunMetadataSurvivesAcknowledgement(t *testing.T) {
	r := dispatchercompletionCharSetup(t, "exec-char-meta", false)
	require.NoError(t, r.cp.injectCompletion(context.Background(), "device-1", "exec-char-meta", 0))
	got := r.waitTerminal(t)
	// The queue entry is gone after acknowledgement, yet the job linked through
	// workflow_run_id/job_id metadata was still advanced.
	assert.Equal(t, "job-exec-char-meta", got.JobID)
	assert.Equal(t, run.JobStatusCompleted, got.Status)
	assert.Empty(t, r.q.PeekForDevice("device-1"))
}

func TestDispatcherCompletionChar_NonTerminalEventTypeIgnored(t *testing.T) {
	r := dispatchercompletionCharSetup(t, "exec-char-ignore", false)
	require.NoError(t, r.cp.injectEvent(context.Background(), dispatchercompletionCharEvent(
		controlplaneTypes.EventType("something_else"), map[string]interface{}{
			"execution_id": "exec-char-ignore", "exit_code": float64(0),
		})))
	assert.Equal(t, run.JobStatusPending, r.job(t).Status)
	assert.Len(t, r.q.PeekForDevice("device-1"), 1)
}

func TestDispatcherCompletionChar_EmptyStewardAndMissingExecutionIgnored(t *testing.T) {
	r := dispatchercompletionCharSetup(t, "exec-char-empty", false)
	noSteward := dispatchercompletionCharEvent(controlplaneTypes.EventScriptCompleted,
		map[string]interface{}{"execution_id": "exec-char-empty", "exit_code": float64(0)})
	noSteward.StewardID = ""
	require.NoError(t, r.cp.injectEvent(context.Background(), noSteward))
	require.NoError(t, r.cp.injectEvent(context.Background(), dispatchercompletionCharEvent(
		controlplaneTypes.EventScriptCompleted, map[string]interface{}{"exit_code": float64(0)})))
	require.NoError(t, r.cp.injectEvent(context.Background(), dispatchercompletionCharEvent(
		controlplaneTypes.EventScriptCompleted, nil)))
	assert.Equal(t, run.JobStatusPending, r.job(t).Status)
}

func TestDispatcherCompletionChar_IdempotentRetriesOnceThenFails(t *testing.T) {
	r := dispatchercompletionCharSetup(t, "exec-char-idem", true)
	require.NoError(t, r.cp.injectCompletion(context.Background(), "device-1", "exec-char-idem", 1))
	require.Eventually(t, func() bool { return r.q.GetQueueDepth("device-1") == 1 }, 2*time.Second, 10*time.Millisecond)
	assert.Equal(t, run.JobStatusPending, r.job(t).Status, "job stays open while the retry is queued")
}

func TestDispatcherCompletionChar_StewardActionFailureIsNeverRetried(t *testing.T) {
	h := newActionHarness(t)
	const device = "steward-char-noretry"
	runID, job := h.enqueueAction(t, device, "service.stop", x509ActionProof)
	h.d.dispatchForDevice(context.Background(), device)
	require.Equal(t, 1, h.cp.sentCount())
	// Even an entry marked idempotent is not retried: an action was authorized once.
	for _, qe := range h.q.PeekForDevice(device) {
		qe.Metadata["idempotent"] = true
	}

	h.completeAction(t, device, job.ExecutionID, map[string]interface{}{"result_code": "failed"})

	got := h.onlyJob(t, runID)
	assert.Equal(t, run.JobStatusFailed, got.Status)
	assert.Equal(t, run.ResultCodeFailed, got.ResultCode)
	assert.Zero(t, h.q.GetQueueDepth(device), "an action is never re-queued")
	assert.Equal(t, 1, h.cp.sentCount())
}

func TestDispatcherCompletionChar_StewardActionResultCodeDecidesOutcome(t *testing.T) {
	h := newActionHarness(t)
	const device = "steward-char-ok"
	runID, job := h.enqueueAction(t, device, "service.stop", x509ActionProof)
	h.d.dispatchForDevice(context.Background(), device)

	// A non-zero exit code is ignored when the steward reported result_code ok.
	h.completeAction(t, device, job.ExecutionID, map[string]interface{}{"result_code": "ok", "exit_code": float64(7)})

	got := h.onlyJob(t, runID)
	assert.Equal(t, run.JobStatusCompleted, got.Status)
	assert.Equal(t, run.ResultCodeOK, got.ResultCode)
}
