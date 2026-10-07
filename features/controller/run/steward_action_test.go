// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package run

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// singleConnRunStore opens an in-memory sqlite run store on one connection (an
// in-memory database exists per connection).
func singleConnRunStore(t *testing.T) *RunStoreSQL {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	store := NewRunStoreSQL(db)
	require.NoError(t, store.Init(context.Background()))
	return store
}

// sqliteScriptRunStore presents the single-node RunStoreSQL as a
// business.ScriptRunStore so the shared ScriptRunStoreContract can run against it.
// It only adapts signatures; every operation executes on the real sqlite store.
type sqliteScriptRunStore struct{ s *RunStoreSQL }

var _ business.ScriptRunStore = sqliteScriptRunStore{}

func (a sqliteScriptRunStore) CreateRun(_ context.Context, r *business.ScriptRun) error {
	rec := fromBusinessRun(r)
	if r.Kind == "" {
		rec.Kind = ""
	}
	return a.s.CreateRun(rec)
}

func (a sqliteScriptRunStore) CreateJob(_ context.Context, j *business.ScriptRunJob) error {
	return a.s.CreateJob(fromBusinessJob(j))
}

func (a sqliteScriptRunStore) GetRun(_ context.Context, runID string) (*business.ScriptRun, error) {
	r, err := a.s.GetRun(runID)
	if errors.Is(err, ErrNotFound) {
		return nil, business.ErrScriptRunNotFound
	}
	if err != nil {
		return nil, err
	}
	return toBusinessRun(r)
}

func (a sqliteScriptRunStore) ListRuns(_ context.Context, tenantID string, limit, offset int) ([]*business.ScriptRun, error) {
	rs, err := a.s.ListRuns(tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	out := make([]*business.ScriptRun, 0, len(rs))
	for _, r := range rs {
		b, err := toBusinessRun(r)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func (a sqliteScriptRunStore) ListRunJobs(_ context.Context, runID string) ([]*business.ScriptRunJob, error) {
	js, err := a.s.ListRunJobs(runID)
	if err != nil {
		return nil, err
	}
	out := make([]*business.ScriptRunJob, 0, len(js))
	for _, j := range js {
		out = append(out, toBusinessJob(j))
	}
	return out, nil
}

func (a sqliteScriptRunStore) UpdateJobStatus(_ context.Context, jobID, status, executionID string, _ *time.Time) error {
	return a.s.UpdateJobStatus(jobID, JobStatus(status), executionID)
}

func (a sqliteScriptRunStore) UpdateJobResult(_ context.Context, jobID, status, executionID, output, stderr string, exitCode int, _ *time.Time) error {
	return a.s.UpdateJobResult(jobID, JobStatus(status), executionID, output, stderr, exitCode)
}

func (a sqliteScriptRunStore) UpdateJobResultCode(_ context.Context, jobID, code string) error {
	return a.s.UpdateJobResultCode(jobID, code)
}

func (a sqliteScriptRunStore) MarkJobDispatched(_ context.Context, jobID string, at time.Time) (bool, error) {
	return a.s.MarkJobDispatched(jobID, at)
}

func (a sqliteScriptRunStore) ListStaleActionJobs(_ context.Context, pendingBefore, dispatchedBefore time.Time) ([]*business.ScriptRunJob, error) {
	js, err := a.s.ListStaleActionJobs(pendingBefore, dispatchedBefore)
	if err != nil {
		return nil, err
	}
	out := make([]*business.ScriptRunJob, 0, len(js))
	for _, j := range js {
		out = append(out, toBusinessJob(j))
	}
	return out, nil
}

func (a sqliteScriptRunStore) ExpireJobIfStatus(_ context.Context, jobID, fromStatus, resultCode string, at time.Time) (bool, error) {
	return a.s.ExpireJobIfStatus(jobID, JobStatus(fromStatus), resultCode, at)
}

func (a sqliteScriptRunStore) UpdateRunStatus(_ context.Context, runID, status string) error {
	return a.s.UpdateRunStatus(runID, RunStatus(status))
}

func (a sqliteScriptRunStore) UpdateRunCounts(_ context.Context, runID string, completed, failed int) error {
	return a.s.UpdateRunCounts(runID, completed, failed)
}

func (a sqliteScriptRunStore) CreateExecutionGrant(_ context.Context, g *business.ExecutionGrant) error {
	return a.s.CreateExecutionGrant(g.DeviceID, g.TenantID, g.ExecutionID, g.Scope, time.Until(g.ExpiresAt))
}

func (a sqliteScriptRunStore) LookupGrant(_ context.Context, deviceID, executionID string) (*business.ExecutionGrant, error) {
	g, err := a.s.LookupGrant(deviceID, executionID)
	switch {
	case errors.Is(err, ErrGrantNotFound):
		return nil, business.ErrExecutionGrantNotFound
	case errors.Is(err, ErrGrantConsumed):
		return nil, business.ErrExecutionGrantConsumed
	case err != nil:
		return nil, err
	}
	return &business.ExecutionGrant{DeviceID: g.DeviceID, TenantID: g.TenantID, ExecutionID: g.ExecutionID,
		Scope: g.Scope, CreatedAt: g.CreatedAt, ExpiresAt: g.ExpiresAt, Consumed: g.Consumed}, nil
}

func (a sqliteScriptRunStore) ConsumeGrant(_ context.Context, executionID string) error {
	return a.s.ConsumeGrant(executionID)
}

// TestRunStoreSQL_ScriptRunStoreContract runs the shared ScriptRunStoreContract
// against the single-node store: new fields round-trip, existing script runs
// read back as script, stale listing and compare-and-set expiry behave as in the
// database provider (Issue #4625).
func TestRunStoreSQL_ScriptRunStoreContract(t *testing.T) {
	business.ScriptRunStoreContract(t, sqliteScriptRunStore{s: singleConnRunStore(t)})
}

// TestRunStore_Init_OldSchema_MigratesStewardActionColumns upgrades a database
// created before steward actions: its existing runs read back as script.
func TestRunStore_Init_OldSchema_MigratesStewardActionColumns(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`CREATE TABLE script_runs (
    run_id TEXT NOT NULL PRIMARY KEY, tenant_id TEXT NOT NULL, created_by TEXT, created_at DATETIME NOT NULL,
    status TEXT NOT NULL, filter_json TEXT, script_ref TEXT, inline_content TEXT, shell TEXT,
    job_count INTEGER DEFAULT 0, completed_jobs INTEGER DEFAULT 0, failed_jobs INTEGER DEFAULT 0);`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO script_runs (run_id, tenant_id, created_at, status) VALUES ('legacy', 't', ?, 'completed')`, time.Now().UTC())
	require.NoError(t, err)

	store := NewRunStoreSQL(db)
	require.NoError(t, store.Init(context.Background()))
	require.NoError(t, store.Init(context.Background()), "idempotent")

	got, err := store.GetRun("legacy")
	require.NoError(t, err)
	assert.Equal(t, RunKindScript, got.Kind, "a pre-existing run reads back as script")
	assert.Empty(t, got.ActionJSON)

	cols, err := store.jobColumns()
	require.NoError(t, err)
	assert.True(t, cols["result_code"])
	assert.True(t, cols["dispatched_at"])
}

func actionTestManager(t *testing.T) (*Manager, *scriptmodule.ExecutionQueue, *RunStoreSQL) {
	t.Helper()
	store := singleConnRunStore(t)
	queue := scriptmodule.NewExecutionQueue(scriptmodule.NewExecutionMonitor(), scriptmodule.NewEphemeralKeyManager(), 0, "", nil, nil, 0)
	t.Cleanup(queue.Stop)
	return NewManager(store, queue), queue, store
}

func TestSynthesizeActionRunForDevices_CreatesActionRunJobsAndEntries(t *testing.T) {
	for name, proof := range map[string]*CommandSignature{
		"x509": {Algorithm: "ecdsa-sha256", Value: "val", PublicKey: "pub"},
		"webauthn": {
			WebAuthnAuthenticatorData: "ad", WebAuthnClientDataJSON: "cd", WebAuthnSignature: "sg",
			WebAuthnCredentialID: "id", WebAuthnManifest: `{"m":1}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			manager, queue, _ := actionTestManager(t)
			expiresAt := time.Now().Add(time.Minute)
			targets := []string{"dev-a", "dev-b"}
			spec := scriptmodule.StewardActionSpec{Verb: "service.stop", TargetKind: "service", TargetName: "spooler"}

			before := time.Now()
			runID, err := SynthesizeActionRunForDevices(context.Background(), manager, queue,
				[]fleet.StewardResult{{ID: "dev-a"}, {ID: "dev-b"}}, "tenant-1", "admin", fleet.Filter{IDs: targets},
				spec, proof, targets, "nonce-1", expiresAt)
			require.NoError(t, err)

			r, err := manager.GetRun(context.Background(), runID)
			require.NoError(t, err)
			assert.Equal(t, RunKindStewardAction, r.Kind)
			assert.Equal(t, RunStatusRunning, r.Status)
			assert.Equal(t, 2, r.JobCount)
			assert.JSONEq(t, `{"verb":"service.stop","target_kind":"service","target_name":"spooler"}`, string(r.ActionJSON))
			assert.NotContains(t, string(r.ActionJSON), "nonce", "the run record carries the action, not the envelope")

			jobs, err := manager.ListRunJobs(context.Background(), runID)
			require.NoError(t, err)
			require.Len(t, jobs, 2)

			for _, device := range targets {
				queued := queue.PeekForDevice(device)
				require.Len(t, queued, 1)
				qe := queued[0]
				assert.Equal(t, scriptmodule.QueueKindStewardAction, qe.Kind)
				require.NotNil(t, qe.Action)
				assert.Equal(t, spec, *qe.Action)
				assert.Equal(t, scriptmodule.StewardActionTimeout, qe.Timeout)
				assert.WithinDuration(t, before.Add(scriptmodule.StewardActionTTL), qe.ExpiresAt, 5*time.Second)
				assert.Equal(t, runID, qe.Metadata["workflow_run_id"])
				assert.Equal(t, "nonce-1", qe.Metadata["nonce"])
				assert.Equal(t, expiresAt.UTC().Format(time.RFC3339), qe.Metadata["expires_at"])
				assert.Equal(t, targets, qe.Metadata["targets"])
				if proof.Value != "" {
					assert.Equal(t, proof.Value, qe.Metadata["signature_value"])
					assert.Equal(t, proof.PublicKey, qe.Metadata["signature_public_key"])
					assert.NotContains(t, qe.Metadata, "webauthn_signature")
				} else {
					assert.Equal(t, proof.WebAuthnManifest, qe.Metadata["webauthn_manifest"])
					assert.Equal(t, proof.WebAuthnSignature, qe.Metadata["webauthn_signature"])
					assert.NotContains(t, qe.Metadata, "signature_value")
				}
			}
		})
	}
}

func TestSynthesizeActionRunForDevices_RequiresOperatorProof(t *testing.T) {
	manager, queue, _ := actionTestManager(t)
	for name, proof := range map[string]*CommandSignature{
		"nil":             nil,
		"empty":           {},
		"x509 no key":     {Algorithm: "a", Value: "v"},
		"webauthn no sig": {WebAuthnAuthenticatorData: "a", WebAuthnClientDataJSON: "c", WebAuthnCredentialID: "i"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := SynthesizeActionRunForDevices(context.Background(), manager, queue,
				[]fleet.StewardResult{{ID: "dev-a"}}, "t", "admin", fleet.Filter{},
				scriptmodule.StewardActionSpec{Verb: "service.stop", TargetKind: "service", TargetName: "x"},
				proof, []string{"dev-a"}, "n", time.Now().Add(time.Minute))
			require.Error(t, err)
			assert.Empty(t, queue.PeekForDevice("dev-a"), "nothing is queued without a proof")
		})
	}
}

func TestSynthesizeActionRunForDevices_DifferentVerbsOnOneTargetDoNotDedupe(t *testing.T) {
	manager, queue, _ := actionTestManager(t)
	proof := &CommandSignature{Algorithm: "a", Value: "v", PublicKey: "k"}
	for _, verb := range []string{"service.stop", "service.start"} {
		_, err := SynthesizeActionRunForDevices(context.Background(), manager, queue,
			[]fleet.StewardResult{{ID: "dev-a"}}, "t", "admin", fleet.Filter{},
			scriptmodule.StewardActionSpec{Verb: verb, TargetKind: "service", TargetName: "x"},
			proof, []string{"dev-a"}, "n-"+verb, time.Now().Add(time.Minute))
		require.NoError(t, err)
	}
	assert.Len(t, queue.PeekForDevice("dev-a"), 2)
}

func TestManager_ExpireActionJobs_ConcurrentCallersCloseOnce(t *testing.T) {
	manager, queue, _ := actionTestManager(t)
	proof := &CommandSignature{Algorithm: "a", Value: "v", PublicKey: "k"}
	runID, err := SynthesizeActionRunForDevices(context.Background(), manager, queue,
		[]fleet.StewardResult{{ID: "dev-a"}}, "t", "admin", fleet.Filter{},
		scriptmodule.StewardActionSpec{Verb: "service.stop", TargetKind: "service", TargetName: "x"},
		proof, []string{"dev-a"}, "n", time.Now().Add(time.Minute))
	require.NoError(t, err)

	at := time.Now().Add(scriptmodule.StewardActionTTL + time.Second)
	var closed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jobs, err := manager.ExpireActionJobs(context.Background(), at)
			assert.NoError(t, err)
			closed.Add(int32(len(jobs)))
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), closed.Load(), "exactly one caller is handed the closed job")
	jobs, err := manager.ListRunJobs(context.Background(), runID)
	require.NoError(t, err)
	assert.Equal(t, JobStatusExpired, jobs[0].Status)
	assert.Equal(t, ResultCodeExpired, jobs[0].ResultCode)
	assert.Empty(t, queue.PeekForDevice("dev-a"), "the entry of an expired action is cancelled")
}

func TestManager_ClaimActionDispatch(t *testing.T) {
	manager, queue, store := actionTestManager(t)
	proof := &CommandSignature{Algorithm: "a", Value: "v", PublicKey: "k"}
	runID, err := SynthesizeActionRunForDevices(context.Background(), manager, queue,
		[]fleet.StewardResult{{ID: "dev-a"}}, "t", "admin", fleet.Filter{},
		scriptmodule.StewardActionSpec{Verb: "service.stop", TargetKind: "service", TargetName: "x"},
		proof, []string{"dev-a"}, "n", time.Now().Add(time.Minute))
	require.NoError(t, err)
	jobs, err := store.ListRunJobs(runID)
	require.NoError(t, err)
	jobID := jobs[0].JobID

	claimed, status, err := manager.ClaimActionDispatch(context.Background(), runID, jobID, time.Now())
	require.NoError(t, err)
	assert.True(t, claimed)
	assert.Equal(t, "dispatched", status)

	claimed, status, err = manager.ClaimActionDispatch(context.Background(), runID, jobID, time.Now())
	require.NoError(t, err)
	assert.False(t, claimed, "a job is claimed for dispatch once")
	assert.Equal(t, "dispatched", status)

	_, _, err = manager.ClaimActionDispatch(context.Background(), runID, "no-such-job", time.Now())
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestNormalizeResultCode(t *testing.T) {
	for _, code := range []string{"ok", "self_protect", "process_changed", "unsupported", "failed", "not_found", "permission_denied"} {
		assert.Equal(t, code, NormalizeResultCode(code))
	}
	for _, code := range []string{"", "expired", "no_result", "anything else", "<b>x</b>"} {
		assert.Equal(t, ResultCodeFailed, NormalizeResultCode(code), "%q is not a steward-reportable code", code)
	}
}

// TestJobSelectColsQualifiedMatchesJobSelectCols keeps the literal alias-qualified
// column list in step with jobSelectCols: scanJob reads both in this order.
func TestJobSelectColsQualifiedMatchesJobSelectCols(t *testing.T) {
	split := func(cols string) []string {
		var out []string
		for _, c := range strings.Split(cols, ",") {
			out = append(out, strings.TrimSpace(c))
		}
		return out
	}
	plain, qualified := split(jobSelectCols), split(jobSelectColsQualified)
	require.Len(t, qualified, len(plain))
	for i := range plain {
		assert.Equal(t, "j."+plain[i], qualified[i])
	}
}
