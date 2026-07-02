// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/batchjob"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/fleet"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ----------------------------------------------------------------------------
// Test control plane — real ControlPlaneProvider implementation, no mocks.
// ----------------------------------------------------------------------------

var _ cpinterfaces.ControlPlaneProvider = (*executorTestCP)(nil)

// executorTestCP records sent commands and allows tests to inject completion events.
type executorTestCP struct {
	mu           sync.Mutex
	sent         []*controlplaneTypes.SignedCommand
	sentByID     map[string]*controlplaneTypes.SignedCommand
	eventHandler cpinterfaces.EventHandler
}

func newExecutorTestCP() *executorTestCP {
	return &executorTestCP{sentByID: make(map[string]*controlplaneTypes.SignedCommand)}
}

func (p *executorTestCP) Name() string      { return "executor-test" }
func (p *executorTestCP) IsConnected() bool { return true }
func (p *executorTestCP) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (p *executorTestCP) Start(_ context.Context) error     { return nil }
func (p *executorTestCP) Stop(_ context.Context) error      { return nil }
func (p *executorTestCP) Reconnect(_ context.Context) error { return nil }
func (p *executorTestCP) FanOutCommand(_ context.Context, cmd *controlplaneTypes.SignedCommand, ids []string) (*controlplaneTypes.FanOutResult, error) {
	return &controlplaneTypes.FanOutResult{Succeeded: ids, Failed: map[string]error{}}, nil
}
func (p *executorTestCP) SubscribeCommands(_ context.Context, _ string, _ cpinterfaces.CommandHandler) error {
	return nil
}
func (p *executorTestCP) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}
func (p *executorTestCP) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}
func (p *executorTestCP) SubscribeHeartbeats(_ context.Context, _ cpinterfaces.HeartbeatHandler) error {
	return nil
}
func (p *executorTestCP) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}
func (p *executorTestCP) SendCommand(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
	p.mu.Lock()
	p.sent = append(p.sent, cmd)
	p.sentByID[cmd.Command.ID] = cmd
	p.mu.Unlock()
	return nil
}
func (p *executorTestCP) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, handler cpinterfaces.EventHandler) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.eventHandler = handler
	return nil
}

func (p *executorTestCP) injectCommandCompleted(ctx context.Context, cmd *controlplaneTypes.SignedCommand) error {
	p.mu.Lock()
	h := p.eventHandler
	p.mu.Unlock()
	if h == nil {
		return nil
	}
	return h(ctx, &controlplaneTypes.Event{
		ID:        "evt-" + cmd.Command.ID,
		Type:      controlplaneTypes.EventCommandCompleted,
		StewardID: cmd.Command.StewardID,
		CommandID: cmd.Command.ID,
		Timestamp: time.Now(),
	})
}

func (p *executorTestCP) injectCommandFailed(ctx context.Context, cmd *controlplaneTypes.SignedCommand) error {
	p.mu.Lock()
	h := p.eventHandler
	p.mu.Unlock()
	if h == nil {
		return nil
	}
	return h(ctx, &controlplaneTypes.Event{
		ID:        "fail-" + cmd.Command.ID,
		Type:      controlplaneTypes.EventCommandFailed,
		StewardID: cmd.Command.StewardID,
		CommandID: cmd.Command.ID,
		Timestamp: time.Now(),
	})
}

func (p *executorTestCP) getByID(cmdID string) *controlplaneTypes.SignedCommand {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sentByID[cmdID]
}

func (p *executorTestCP) sentCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sent)
}

// sentWithParam returns sent commands that have the given string param key=value.
func (p *executorTestCP) sentWithParam(key, value string) []*controlplaneTypes.SignedCommand {
	p.mu.Lock()
	defer p.mu.Unlock()
	var result []*controlplaneTypes.SignedCommand
	for _, cmd := range p.sent {
		if v, ok := cmd.Command.Params[key]; ok {
			if sv, ok2 := v.(string); ok2 && sv == value {
				result = append(result, cmd)
			}
		}
	}
	return result
}

// ----------------------------------------------------------------------------
// Fleet adapter — bridges fleet.FleetQuery to batchjob.FleetQuery.
// The import from fleet is only in this test file; executor.go avoids it to
// prevent the cycle: batchjob → fleet → business → batchjob.
// ----------------------------------------------------------------------------

type fleetQueryAdapter struct {
	q fleet.FleetQuery
}

func (a *fleetQueryAdapter) Search(ctx context.Context, selector, tenantID string) ([]batchjob.StewardMeta, error) {
	filter, err := fleet.ParseTargetSelector(selector)
	if err != nil {
		return nil, err
	}
	filter.TenantID = tenantID
	results, err := a.q.Search(ctx, filter)
	if err != nil {
		return nil, err
	}
	metas := make([]batchjob.StewardMeta, len(results))
	for i, r := range results {
		metas[i] = batchjob.StewardMeta{
			ID:            r.ID,
			DNAAttributes: r.DNAAttributes,
		}
	}
	return metas, nil
}

type staticFleetProvider struct {
	stewards []fleet.StewardData
}

func (p *staticFleetProvider) GetAllStewards() []fleet.StewardData { return p.stewards }

func makeStewards(ids ...string) []fleet.StewardData {
	out := make([]fleet.StewardData, len(ids))
	for i, id := range ids {
		out[i] = fleet.StewardData{
			ID:            id,
			TenantID:      "tenant-1",
			Status:        "online",
			LastHeartbeat: time.Now(),
		}
	}
	return out
}

func newTestFleetQuery(ids ...string) batchjob.FleetQuery {
	return &fleetQueryAdapter{
		q: fleet.NewMemoryQuery(&staticFleetProvider{stewards: makeStewards(ids...)}),
	}
}

// ----------------------------------------------------------------------------
// Completion driver — polls publisher pending commands and injects events.
// Using GetPendingCommands() instead of a cmdCh avoids the race where the
// event is injected before PublishCommandWithCallback registers the pending entry.
// ----------------------------------------------------------------------------

// completionDriver polls a Publisher for pending commands and injects completion
// events. shouldFail(stewardID) controls whether each steward succeeds or fails.
type completionDriver struct {
	t          testing.TB
	cp         *executorTestCP
	publisher  *commands.Publisher
	shouldFail func(stewardID string) bool
	cancel     context.CancelFunc
	done       chan struct{}
}

func newCompletionDriver(t testing.TB, cp *executorTestCP, pub *commands.Publisher, shouldFail func(string) bool) *completionDriver {
	t.Helper()
	return &completionDriver{
		t:          t,
		cp:         cp,
		publisher:  pub,
		shouldFail: shouldFail,
		done:       make(chan struct{}),
	}
}

// start begins the polling loop in a goroutine. Call stop() when done.
func (d *completionDriver) start(parentCtx context.Context) {
	ctx, cancel := context.WithCancel(parentCtx)
	d.cancel = cancel
	go func() {
		defer close(d.done)
		defer cancel()
		completed := make(map[string]bool)
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Millisecond):
			}
			for _, cmdID := range d.publisher.GetPendingCommands() {
				if completed[cmdID] {
					continue
				}
				cmd := d.cp.getByID(cmdID)
				if cmd == nil {
					continue
				}
				completed[cmdID] = true
				var injectErr error
				if d.shouldFail(cmd.Command.StewardID) {
					injectErr = d.cp.injectCommandFailed(ctx, cmd)
				} else {
					injectErr = d.cp.injectCommandCompleted(ctx, cmd)
				}
				if injectErr != nil {
					d.t.Logf("completionDriver: inject event for %s: %v", cmdID, injectErr)
				}
			}
		}
	}()
}

func (d *completionDriver) stop() {
	d.cancel()
	<-d.done
}

// ----------------------------------------------------------------------------
// Shared test setup.
// ----------------------------------------------------------------------------

type executorFixture struct {
	cp        *executorTestCP
	store     batchjob.BatchJobStore
	publisher *commands.Publisher
	executor  *batchjob.RollingBatchExecutor
	ctx       context.Context
	cancel    context.CancelFunc
}

func newExecutorFixture(t *testing.T, stewardIDs ...string) *executorFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

	cp := newExecutorTestCP()
	logger := logging.NewNoopLogger()

	pub, err := commands.New(&commands.Config{
		ControlPlane: cp,
		Logger:       logger,
	})
	require.NoError(t, err)
	require.NoError(t, pub.Start(ctx))

	store := newTestBatchJobStore()
	require.NoError(t, store.Initialize(ctx))

	exec := batchjob.NewRollingBatchExecutor(
		store,
		newTestFleetQuery(stewardIDs...),
		pub,
		nil, // no quorum checker
		logger,
	)

	return &executorFixture{
		cp:        cp,
		store:     store,
		publisher: pub,
		executor:  exec,
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (f *executorFixture) cleanup() { f.cancel() }

// driveAllSucceed starts a completion driver that succeeds all stewards.
func (f *executorFixture) driveAllSucceed(t testing.TB) *completionDriver {
	t.Helper()
	d := newCompletionDriver(t, f.cp, f.publisher, func(_ string) bool { return false })
	d.start(f.ctx)
	return d
}

// driveFirstFails starts a driver that fails the first unique steward it sees
// and succeeds the rest.
func (f *executorFixture) driveFirstFails(t testing.TB) *completionDriver {
	t.Helper()
	var mu sync.Mutex
	failedOne := false
	d := newCompletionDriver(t, f.cp, f.publisher, func(stewardID string) bool {
		mu.Lock()
		defer mu.Unlock()
		if !failedOne {
			failedOne = true
			return true
		}
		return false
	})
	d.start(f.ctx)
	return d
}

func newPendingJob(id string, batchSize int) *batchjob.BatchJob {
	now := time.Now().UTC()
	return &batchjob.BatchJob{
		ID:          id,
		TenantID:    "tenant-1",
		Selector:    "all",
		Config:      batchjob.BatchJobConfig{BatchSize: batchSize},
		Status:      batchjob.BatchJobStatusPending,
		CreatedAt:   now,
		UpdatedAt:   now,
		InitiatedBy: "test-operator",
	}
}

// ----------------------------------------------------------------------------
// Tests.
// ----------------------------------------------------------------------------

// TestRollingBatchExecutor_SequentialBatches is the REQUIRED test:
// 4 stewards, BatchSize=2 → batch 0 timestamps must precede batch 1 timestamps.
func TestRollingBatchExecutor_SequentialBatches(t *testing.T) {
	f := newExecutorFixture(t, "s-0", "s-1", "s-2", "s-3")
	defer f.cleanup()

	job := newPendingJob("job-seq", 2)
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	d := f.driveAllSucceed(t)
	defer d.stop()

	require.NoError(t, f.executor.Execute(f.ctx, job))

	got, err := f.store.GetBatchJob(f.ctx, "job-seq")
	require.NoError(t, err)
	assert.Equal(t, batchjob.BatchJobStatusCompleted, got.Status)
	require.Len(t, got.Steps, 2, "4 stewards / batch 2 = 2 steps")

	// [REQUIRED]: batch 0 timestamps precede batch 1 timestamps (no parallel dispatch).
	s0 := got.Steps[0]
	s1 := got.Steps[1]
	require.NotNil(t, s0.StartedAt, "step 0 must have StartedAt")
	require.NotNil(t, s0.CompletedAt, "step 0 must have CompletedAt")
	require.NotNil(t, s1.StartedAt, "step 1 must have StartedAt")

	assert.False(t, s0.StartedAt.After(*s1.StartedAt),
		"step 0 StartedAt must not be after step 1 StartedAt")
	assert.False(t, s0.CompletedAt.After(*s1.StartedAt),
		"step 0 CompletedAt must not be after step 1 StartedAt — batches must be sequential")

	// Exactly 4 commands must have been sent (2 per batch).
	assert.Equal(t, 4, f.cp.sentCount())
}

// TestRollingBatchExecutor_FailurePausesBatchZero is the REQUIRED test:
// injected failure on one steward in batch 0 → job paused, batch 1 never dispatched.
func TestRollingBatchExecutor_FailurePausesBatchZero(t *testing.T) {
	f := newExecutorFixture(t, "s-0", "s-1", "s-2", "s-3")
	defer f.cleanup()

	job := newPendingJob("job-fail", 2)
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	d := f.driveFirstFails(t)
	defer d.stop()

	require.NoError(t, f.executor.Execute(f.ctx, job))

	got, err := f.store.GetBatchJob(f.ctx, "job-fail")
	require.NoError(t, err)

	// [REQUIRED]: job must be paused after batch 0 failure.
	assert.Equal(t, batchjob.BatchJobStatusPaused, got.Status,
		"job must be paused when a steward in batch 0 fails")

	// [REQUIRED]: only 2 commands sent (batch 0 only), none to batch 1 stewards.
	assert.Equal(t, 2, f.cp.sentCount(),
		"no CommandSyncConfig must be sent to batch 1 stewards")

	// Step 0 must be failed with the failing steward recorded.
	require.Len(t, got.Steps, 1, "only step 0 should be persisted")
	assert.Equal(t, batchjob.BatchStepStatusFailed, got.Steps[0].Status)
	assert.NotEmpty(t, got.Steps[0].FailedIDs, "failed IDs must be recorded")
}

// TestRollingBatchExecutor_AllCompleted validates end-to-end completion
// with a single batch of 3 stewards.
func TestRollingBatchExecutor_AllCompleted(t *testing.T) {
	f := newExecutorFixture(t, "s-0", "s-1", "s-2")
	defer f.cleanup()

	job := newPendingJob("job-all", 10) // batch size > steward count → single batch
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	d := f.driveAllSucceed(t)
	defer d.stop()

	require.NoError(t, f.executor.Execute(f.ctx, job))

	got, err := f.store.GetBatchJob(f.ctx, "job-all")
	require.NoError(t, err)
	assert.Equal(t, batchjob.BatchJobStatusCompleted, got.Status)
	require.Len(t, got.Steps, 1)
	assert.Equal(t, batchjob.BatchStepStatusCompleted, got.Steps[0].Status)
	assert.Len(t, got.Steps[0].StewardIDs, 3)
}

// TestRollingBatchExecutor_TargetsPersisted verifies that Execute resolves and
// persists the fleet selector's resolved steward IDs in job.Targets.
func TestRollingBatchExecutor_TargetsPersisted(t *testing.T) {
	f := newExecutorFixture(t, "s-a", "s-b", "s-c")
	defer f.cleanup()

	job := newPendingJob("job-targets", 10)
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	d := f.driveAllSucceed(t)
	defer d.stop()

	require.NoError(t, f.executor.Execute(f.ctx, job))

	got, err := f.store.GetBatchJob(f.ctx, "job-targets")
	require.NoError(t, err)
	assert.Len(t, got.Targets, 3, "resolved targets must be persisted")
}

// TestRollingBatchExecutor_RollbackOnBatchFailure is the REQUIRED test:
// 4 stewards, 2 batches of 2, PreviousConfigRef="v1"; batch 0 succeeds, batch 1 fails
// → CommandSyncConfig with config_ref="v1" dispatched to batch-0 stewards,
// batch-0 step status = rolled_back, job status = rolled_back.
func TestRollingBatchExecutor_RollbackOnBatchFailure(t *testing.T) {
	f := newExecutorFixture(t, "s-0", "s-1", "s-2", "s-3")
	defer f.cleanup()

	job := newPendingJob("job-rollback", 2)
	job.Config.PreviousConfigRef = "v1"
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	// Fail s-2 and s-3 (batch 1) on every dispatch; succeed s-0 and s-1 (batch 0) always.
	batch1 := map[string]bool{"s-2": true, "s-3": true}
	d := newCompletionDriver(t, f.cp, f.publisher, func(stewardID string) bool {
		return batch1[stewardID]
	})
	d.start(f.ctx)
	defer d.stop()

	require.NoError(t, f.executor.Execute(f.ctx, job))

	got, err := f.store.GetBatchJob(f.ctx, "job-rollback")
	require.NoError(t, err)

	// [REQUIRED]: job must be rolled_back.
	assert.Equal(t, batchjob.BatchJobStatusRolledBack, got.Status)

	// [REQUIRED]: batch-0 step must be rolled_back.
	require.Len(t, got.Steps, 2, "step 0 (rolled_back) + step 1 (failed) must be persisted")
	var step0 *batchjob.BatchStep
	for i := range got.Steps {
		if got.Steps[i].Index == 0 {
			step0 = &got.Steps[i]
		}
	}
	require.NotNil(t, step0, "step 0 must be persisted")
	assert.Equal(t, batchjob.BatchStepStatusRolledBack, step0.Status)

	// [REQUIRED]: 6 total commands — 2 forward batch 0, 2 forward batch 1, 2 rollback batch 0.
	assert.Equal(t, 6, f.cp.sentCount())

	// [REQUIRED]: 2 rollback commands carry config_ref="v1", targeting s-0 and s-1.
	rollbackCmds := f.cp.sentWithParam("config_ref", "v1")
	require.Len(t, rollbackCmds, 2, "exactly 2 rollback dispatches must carry config_ref=v1")
	targets := map[string]bool{}
	for _, cmd := range rollbackCmds {
		targets[cmd.Command.StewardID] = true
	}
	assert.True(t, targets["s-0"], "rollback must target s-0")
	assert.True(t, targets["s-1"], "rollback must target s-1")
}

// TestRollingBatchExecutor_NoRollbackWhenNoPreviousConfigRef is the REQUIRED test:
// PreviousConfigRef empty → batch failure transitions job to paused only;
// no rollback dispatch is sent.
func TestRollingBatchExecutor_NoRollbackWhenNoPreviousConfigRef(t *testing.T) {
	f := newExecutorFixture(t, "s-0", "s-1", "s-2", "s-3")
	defer f.cleanup()

	job := newPendingJob("job-no-rollback", 2)
	// PreviousConfigRef intentionally left empty.
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	batch1 := map[string]bool{"s-2": true, "s-3": true}
	d := newCompletionDriver(t, f.cp, f.publisher, func(stewardID string) bool {
		return batch1[stewardID]
	})
	d.start(f.ctx)
	defer d.stop()

	require.NoError(t, f.executor.Execute(f.ctx, job))

	got, err := f.store.GetBatchJob(f.ctx, "job-no-rollback")
	require.NoError(t, err)

	// [REQUIRED]: job must be paused — not rolled_back, not failed.
	assert.Equal(t, batchjob.BatchJobStatusPaused, got.Status)

	// [REQUIRED]: only 4 commands sent (batch 0 + batch 1 forward), no rollback dispatch.
	assert.Equal(t, 4, f.cp.sentCount(),
		"no rollback commands must be sent when PreviousConfigRef is empty")

	// No command carries a config_ref param.
	assert.Empty(t, f.cp.sentWithParam("config_ref", "v1"),
		"no rollback dispatch must be sent when PreviousConfigRef is empty")
}

// TestRollingBatchExecutor_RollbackBatchZeroFailurePauses is the REQUIRED test for
// the len(completedSteps) == 0 branch in rollbackAppliedSteps: PreviousConfigRef is
// set AND batch 0 itself fails, so rollbackAppliedSteps is invoked but finds no
// completed steps to undo → job → paused, no compensating dispatch is sent.
func TestRollingBatchExecutor_RollbackBatchZeroFailurePauses(t *testing.T) {
	f := newExecutorFixture(t, "s-0", "s-1", "s-2", "s-3")
	defer f.cleanup()

	job := newPendingJob("job-rollback-batch0", 2)
	job.Config.PreviousConfigRef = "v1" // baseline set → routes through rollbackAppliedSteps
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	// Fail the first steward seen (in batch 0), so batch 0 fails before any step completes.
	d := f.driveFirstFails(t)
	defer d.stop()

	require.NoError(t, f.executor.Execute(f.ctx, job))

	got, err := f.store.GetBatchJob(f.ctx, "job-rollback-batch0")
	require.NoError(t, err)

	// [REQUIRED]: rollbackAppliedSteps entered with zero completed steps → job paused.
	assert.Equal(t, batchjob.BatchJobStatusPaused, got.Status,
		"job must be paused when batch 0 fails with no prior completed steps")

	// [REQUIRED]: only batch 0 dispatched (2 commands); batch 1 never dispatched and
	// no compensating rollback dispatch is sent (nothing to undo).
	assert.Equal(t, 2, f.cp.sentCount(),
		"only batch 0 forward dispatch; no rollback or batch 1 commands")

	// No command carries a config_ref param — no compensating dispatch occurred.
	assert.Empty(t, f.cp.sentWithParam("config_ref", "v1"),
		"no rollback dispatch when there are no completed steps to undo")

	// Only step 0 persisted, and it is failed.
	require.Len(t, got.Steps, 1, "only step 0 should be persisted")
	assert.Equal(t, batchjob.BatchStepStatusFailed, got.Steps[0].Status)
	assert.NotEmpty(t, got.Steps[0].FailedIDs, "failed IDs must be recorded")
}

// TestRollingBatchExecutor_RollbackDispatchFailureTransitionsJobFailed verifies that
// when compensating dispatch fails for all target stewards, the job transitions to
// failed rather than rolled_back.
func TestRollingBatchExecutor_RollbackDispatchFailureTransitionsJobFailed(t *testing.T) {
	f := newExecutorFixture(t, "s-0", "s-1", "s-2", "s-3")
	defer f.cleanup()

	job := newPendingJob("job-rollback-fail", 2)
	job.Config.PreviousConfigRef = "v1"
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	// Stateful driver: track per-steward dispatch count.
	// s-2, s-3: always fail (trigger rollback).
	// s-0, s-1: succeed forward (1st dispatch), fail rollback (2nd dispatch).
	var mu sync.Mutex
	dispatchCount := make(map[string]int)
	d := newCompletionDriver(t, f.cp, f.publisher, func(stewardID string) bool {
		mu.Lock()
		defer mu.Unlock()
		dispatchCount[stewardID]++
		n := dispatchCount[stewardID]
		if stewardID == "s-2" || stewardID == "s-3" {
			return true // always fail
		}
		return n > 1 // s-0, s-1: fail on 2nd dispatch (rollback)
	})
	d.start(f.ctx)
	defer d.stop()

	require.NoError(t, f.executor.Execute(f.ctx, job))

	got, err := f.store.GetBatchJob(f.ctx, "job-rollback-fail")
	require.NoError(t, err)

	// Rollback dispatch failed → job must be failed, not rolled_back.
	assert.Equal(t, batchjob.BatchJobStatusFailed, got.Status)

	// 6 total commands: 2 forward batch 0, 2 forward batch 1, 2 rollback batch 0.
	assert.Equal(t, 6, f.cp.sentCount())
}

// TestRollingBatchExecutor_ContextCancellation verifies that Execute returns
// ctx.Err() when the context is cancelled while waiting for batch completion.
func TestRollingBatchExecutor_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cp := newExecutorTestCP()
	logger := logging.NewNoopLogger()
	pub, err := commands.New(&commands.Config{ControlPlane: cp, Logger: logger})
	require.NoError(t, err)
	require.NoError(t, pub.Start(ctx))

	store := newTestBatchJobStore()
	require.NoError(t, store.Initialize(ctx))

	exec := batchjob.NewRollingBatchExecutor(
		store,
		newTestFleetQuery("s-0"),
		pub,
		nil,
		logger,
	)

	job := newPendingJob("job-cancel", 10)
	require.NoError(t, store.CreateBatchJob(ctx, job))

	// Run Execute in a goroutine (no driver — commands never complete).
	errCh := make(chan error, 1)
	go func() { errCh <- exec.Execute(ctx, job) }()

	// Cancel once the first command is dispatched so Execute is blocked in dispatchBatch.
	require.Eventually(t, func() bool { return cp.sentCount() > 0 }, 5*time.Second, time.Millisecond,
		"command must be dispatched before cancellation")
	cancel()

	select {
	case execErr := <-errCh:
		require.ErrorIs(t, execErr, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("Execute did not return after context cancellation")
	}
}
