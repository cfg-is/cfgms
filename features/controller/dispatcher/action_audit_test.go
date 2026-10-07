// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dispatcher

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/run"
	script "github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newFlatfileAuditManager returns a real audit.Manager over a real flat-file
// audit store rooted in t.TempDir(). Stop is registered after Close so the
// drain goroutine quiesces before the store closes.
func newFlatfileAuditManager(t *testing.T) (*audit.Manager, business.AuditStore) {
	t.Helper()
	provider, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)
	store, err := provider.CreateAuditStore(map[string]interface{}{"root": t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	mgr, err := audit.NewManager(store, "dispatcher-test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop(context.Background()) })
	return mgr, store
}

func TestNewAuditManagerSink_NilManagerIsNilInterface(t *testing.T) {
	assert.Nil(t, NewAuditManagerSink(nil, logging.NewNoopLogger()),
		"a nil manager must yield a nil interface, not a typed nil the dispatcher would call")
}

// TestDispatcher_PollLoopSweepsStaleActionIntoAuditLog drives the expiry sweep
// through Start/pollLoop (not sweepActionJobsAt directly) with the production
// audit sink: a steward action left pending past its TTL is closed as expired,
// its run reaches a terminal state, and the closure lands in the durable audit
// log attributed to the issuing operator.
func TestDispatcher_PollLoopSweepsStaleActionIntoAuditLog(t *testing.T) {
	db := mustOpenMemDB(t)
	db.SetMaxOpenConns(1) // an in-memory sqlite database is per connection
	store := run.NewRunStoreSQL(db)
	require.NoError(t, store.Init(context.Background()))

	keys := script.NewEphemeralKeyManager()
	t.Cleanup(keys.Stop)
	q := script.NewExecutionQueue(script.NewExecutionMonitor(), keys, time.Hour, "https://localhost:8080", nil, nil, time.Hour)
	t.Cleanup(q.Stop)

	auditMgr, auditStore := newFlatfileAuditManager(t)

	d, err := New(&Config{
		Queue:        q,
		ControlPlane: &testControlPlane{},
		Signer:       testCommandSigner{},
		TermSource:   staticTermSource{term: testActionTerm},
		ActionAudit:  NewAuditManagerSink(auditMgr, logging.NewNoopLogger()),
		PollInterval: 10 * time.Millisecond,
		Logger:       logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	manager := run.NewManager(store, q)
	manager.SetDeviceLockReleaser(d)
	d.SetRunCompletionSink(manager)

	// A steward-action run whose only job has waited past StewardActionTTL.
	created := time.Now().UTC().Add(-script.StewardActionTTL - time.Minute)
	actionJSON, err := json.Marshal(script.StewardActionSpec{Verb: "service.stop", TargetKind: "service", TargetName: "spooler"})
	require.NoError(t, err)
	const runID, jobID = "run-poll-stale", "job-poll-stale"
	require.NoError(t, store.CreateRun(&run.RunRecord{
		RunID: runID, TenantID: "tenant-a", CreatedBy: "admin", CreatedAt: created,
		Status: run.RunStatusRunning, JobCount: 1, Kind: run.RunKindStewardAction, ActionJSON: actionJSON,
	}))
	require.NoError(t, store.CreateJob(&run.JobRecord{
		JobID: jobID, RunID: runID, DeviceID: "steward-poll", ExecutionID: "exec-poll-stale",
		Status: run.JobStatusPending, CreatedAt: created,
	}))

	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)

	// The audit write is the last step of a sweep, so once it is visible the job
	// and run have already been closed.
	var entries []*business.AuditEntry
	require.Eventually(t, func() bool {
		if flushErr := auditMgr.Flush(context.Background()); flushErr != nil {
			return false
		}
		var listErr error
		entries, listErr = auditStore.GetAuditsByAction(context.Background(), "steward_action_expired", nil)
		return listErr == nil && len(entries) > 0
	}, 5*time.Second, 10*time.Millisecond, "the poll loop must sweep the stale action into the audit log")

	jobs, err := manager.ListRunJobs(context.Background(), runID)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	assert.Equal(t, run.JobStatusExpired, jobs[0].Status)
	assert.Equal(t, run.ResultCodeExpired, jobs[0].ResultCode)
	r, err := manager.GetRun(context.Background(), runID)
	require.NoError(t, err)
	assert.Equal(t, run.RunStatusFailed, r.Status, "the run reaches a terminal state")

	require.Len(t, entries, 1, "the closure is written to the audit log exactly once")
	e := entries[0]
	assert.Equal(t, "tenant-a", e.TenantID)
	assert.Equal(t, "admin", e.UserID)
	assert.Equal(t, business.AuditUserTypeHuman, e.UserType)
	assert.Equal(t, "steward_action", e.ResourceType)
	assert.Equal(t, "exec-poll-stale", e.ResourceID)
	assert.Equal(t, business.AuditResultFailure, e.Result)
	assert.Equal(t, "service.stop", e.Details["verb"])
	assert.Equal(t, "steward-poll", e.Details["device_id"])
	assert.Equal(t, "expired, not run", e.Details["detail"])
}
