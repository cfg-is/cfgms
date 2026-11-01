// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob_test

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/batchjob"
	"github.com/cfgis/cfgms/features/controller/commands"
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

// recordingFleetQuery is a real FleetQuery that serves metadata from a fixed
// fleet and records every Lookup call. It deliberately holds more stewards
// than any job targets, so a lookup that is wider than requested is visible.
type recordingFleetQuery struct {
	mu     sync.Mutex
	fleet  []batchjob.StewardMeta
	lookup [][]string
	// err, when set, is returned by every Lookup call (fleet source unavailable).
	err error
}

func (q *recordingFleetQuery) Lookup(_ context.Context, ids []string) ([]batchjob.StewardMeta, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.lookup = append(q.lookup, append([]string(nil), ids...))
	if q.err != nil {
		return nil, q.err
	}
	// Intentionally returns the whole fleet: the executor must not trust it
	// to choose recipients.
	return append([]batchjob.StewardMeta(nil), q.fleet...), nil
}

func (q *recordingFleetQuery) calls() [][]string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([][]string(nil), q.lookup...)
}

func newTestFleetQuery(ids ...string) *recordingFleetQuery {
	q := &recordingFleetQuery{}
	for _, id := range ids {
		q.fleet = append(q.fleet, batchjob.StewardMeta{ID: id})
	}
	return q
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
	ids       []string
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
		ids:       stewardIDs,
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
	job.Targets = f.ids
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
	job.Targets = f.ids
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
	job.Targets = f.ids
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

// sentStewards returns the sorted steward IDs that received a command.
func (p *executorTestCP) sentStewards() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for _, cmd := range p.sent {
		ids = append(ids, cmd.Command.StewardID)
	}
	sort.Strings(ids)
	return ids
}

// recordingQuorumChecker is a QuorumChecker that records the stewards it was handed
// and returns them as one batch.
type recordingQuorumChecker struct {
	got []batchjob.StewardMeta
}

func (c *recordingQuorumChecker) Partition(stewards []batchjob.StewardMeta, _ int) [][]string {
	c.got = stewards
	ids := make([]string, len(stewards))
	for i, s := range stewards {
		ids[i] = s.ID
	}
	return [][]string{ids}
}

// TestRollingBatchExecutor_TargetsAreAuthorizedSet verifies that Execute
// dispatches only to job.Targets and persists them unchanged, even when the
// fleet query knows about many more stewards and the job's TenantID is empty.
func TestRollingBatchExecutor_TargetsAreAuthorizedSet(t *testing.T) {
	for _, tenantID := range []string{"tenant-1", ""} {
		t.Run("tenant="+tenantID, func(t *testing.T) {
			f := newExecutorFixture(t, "s-a", "s-b", "s-c", "s-d", "s-e")
			defer f.cleanup()

			job := newPendingJob("job-targets", 10)
			job.TenantID = tenantID
			job.Targets = []string{"s-a", "s-c"}
			require.NoError(t, f.store.CreateBatchJob(f.ctx, job))
			require.NoError(t, f.store.UpdateBatchTargets(f.ctx, job.ID, job.Targets))

			d := f.driveAllSucceed(t)
			defer d.stop()

			require.NoError(t, f.executor.Execute(f.ctx, job))

			assert.Equal(t, []string{"s-a", "s-c"}, f.cp.sentStewards())
			assert.Equal(t, []string{"s-a", "s-c"}, job.Targets)
			got, err := f.store.GetBatchJob(f.ctx, job.ID)
			require.NoError(t, err)
			assert.Equal(t, []string{"s-a", "s-c"}, got.Targets)
			assert.Equal(t, batchjob.BatchJobStatusCompleted, got.Status)
		})
	}
}

// TestRollingBatchExecutor_QuorumCheckerOnlyTargets verifies the quorum checker
// is handed metadata for the targets only, and an unknown target is still
// partitioned (with no metadata) and dispatched.
func TestRollingBatchExecutor_QuorumCheckerOnlyTargets(t *testing.T) {
	f := newExecutorFixture(t, "s-a", "s-b", "s-c")
	defer f.cleanup()
	qc := &recordingQuorumChecker{}
	fq := newTestFleetQuery("s-a", "s-b", "s-c")
	exec := batchjob.NewRollingBatchExecutor(f.store, fq, f.publisher, qc, logging.NewNoopLogger())

	job := newPendingJob("job-quorum", 10)
	job.Targets = []string{"s-b", "s-ghost"}
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	d := f.driveAllSucceed(t)
	defer d.stop()

	require.NoError(t, exec.Execute(f.ctx, job))

	var partitioned []string
	for _, m := range qc.got {
		partitioned = append(partitioned, m.ID)
	}
	assert.Equal(t, []string{"s-b", "s-ghost"}, partitioned)
	assert.Equal(t, []string{"s-b", "s-ghost"}, f.cp.sentStewards())
}

// TestRollingBatchExecutor_FleetQueryGetsTargetIDsOnly verifies the fleet query
// is called with the target IDs (deduplicated) and never with the selector.
func TestRollingBatchExecutor_FleetQueryGetsTargetIDsOnly(t *testing.T) {
	f := newExecutorFixture(t, "s-a", "s-b")
	defer f.cleanup()
	fq := newTestFleetQuery("s-a", "s-b")
	exec := batchjob.NewRollingBatchExecutor(f.store, fq, f.publisher, &recordingQuorumChecker{}, logging.NewNoopLogger())

	job := newPendingJob("job-lookup", 10)
	job.Selector = "tag:never-resolved"
	job.Targets = []string{"s-a", "s-a", "s-b"}
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	d := f.driveAllSucceed(t)
	defer d.stop()

	require.NoError(t, exec.Execute(f.ctx, job))

	assert.Equal(t, [][]string{{"s-a", "s-b"}}, fq.calls())
	assert.Equal(t, []string{"s-a", "s-b"}, f.cp.sentStewards(), "duplicates dispatched once")
}

// TestRollingBatchExecutor_FleetLookupErrorDispatchesNothing verifies that when
// the quorum-aware path cannot look up target metadata, Execute returns the
// lookup error, dispatches no commands, and leaves the job pending.
func TestRollingBatchExecutor_FleetLookupErrorDispatchesNothing(t *testing.T) {
	f := newExecutorFixture(t, "s-a", "s-b")
	defer f.cleanup()
	lookupErr := errors.New("fleet source unavailable")
	fq := newTestFleetQuery("s-a", "s-b")
	fq.err = lookupErr
	qc := &recordingQuorumChecker{}
	exec := batchjob.NewRollingBatchExecutor(f.store, fq, f.publisher, qc, logging.NewNoopLogger())

	job := newPendingJob("job-lookup-err", 10)
	job.Targets = []string{"s-a", "s-b"}
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	err := exec.Execute(f.ctx, job)
	require.Error(t, err)
	assert.ErrorIs(t, err, lookupErr)
	assert.Contains(t, err.Error(), "fleet lookup")

	assert.Equal(t, [][]string{{"s-a", "s-b"}}, fq.calls(), "lookup attempted with the targets")
	assert.Empty(t, qc.got, "quorum checker must not partition after a failed lookup")
	assert.Zero(t, f.cp.sentCount(), "no commands dispatched after a failed lookup")

	got, getErr := f.store.GetBatchJob(f.ctx, job.ID)
	require.NoError(t, getErr)
	assert.Equal(t, batchjob.BatchJobStatusPending, got.Status)
	assert.Empty(t, got.Steps)
}

// TestRollingBatchExecutor_EmptyTargetsCompletes verifies a job with no targets
// completes without dispatching to anyone in the fleet.
func TestRollingBatchExecutor_EmptyTargetsCompletes(t *testing.T) {
	f := newExecutorFixture(t, "s-a", "s-b")
	defer f.cleanup()

	job := newPendingJob("job-empty", 10)
	require.NoError(t, f.store.CreateBatchJob(f.ctx, job))

	require.NoError(t, f.executor.Execute(f.ctx, job))

	assert.Zero(t, f.cp.sentCount())
	got, err := f.store.GetBatchJob(f.ctx, job.ID)
	require.NoError(t, err)
	assert.Equal(t, batchjob.BatchJobStatusCompleted, got.Status)
}

// TestRollingBatchExecutor_RollbackOnBatchFailure is the REQUIRED test:
// 4 stewards, 2 batches of 2, PreviousConfigRef="v1"; batch 0 succeeds, batch 1 fails
// → CommandSyncConfig with config_ref="v1" dispatched to batch-0 stewards,
// batch-0 step status = rolled_back, job status = rolled_back.
func TestRollingBatchExecutor_RollbackOnBatchFailure(t *testing.T) {
	f := newExecutorFixture(t, "s-0", "s-1", "s-2", "s-3")
	defer f.cleanup()

	job := newPendingJob("job-rollback", 2)
	job.Targets = f.ids
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
	job.Targets = f.ids
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
	job.Targets = f.ids
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
	job.Targets = f.ids
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

// staticTermSource is a minimal TermSource test double that returns a fixed term.
// It is not a mock of commands.Publisher — it only satisfies the commands.TermSource
// interface, exactly as the pattern established by #3390.
type staticTermSource struct {
	term uint64
}

func (s *staticTermSource) GetTerm() uint64 { return s.term }

// TestRollingBatchExecutor_DispatchBatch_StampsRaftTerm is the REQUIRED test
// (Issue #3545): proves that every CommandSyncConfig published via
// RollingBatchExecutor.dispatchBatch carries the current Raft term as stamped
// by the configured TermSource, using a real commands.Publisher and only a
// minimal TermSource test double.
func TestRollingBatchExecutor_DispatchBatch_StampsRaftTerm(t *testing.T) {
	const wantTerm uint64 = 99

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cp := newExecutorTestCP()
	logger := logging.NewNoopLogger()

	pub, err := commands.New(&commands.Config{
		ControlPlane: cp,
		TermSource:   &staticTermSource{term: wantTerm},
		Logger:       logger,
	})
	require.NoError(t, err)
	require.NoError(t, pub.Start(ctx))

	store := newTestBatchJobStore()
	require.NoError(t, store.Initialize(ctx))

	exec := batchjob.NewRollingBatchExecutor(
		store,
		newTestFleetQuery("s-0", "s-1", "s-2"),
		pub,
		nil,
		logger,
	)

	job := newPendingJob("job-term", 10)
	job.Targets = []string{"s-0", "s-1", "s-2"}
	require.NoError(t, store.CreateBatchJob(ctx, job))

	d := newCompletionDriver(t, cp, pub, func(_ string) bool { return false })
	d.start(ctx)
	defer d.stop()

	require.NoError(t, exec.Execute(ctx, job))

	// All 3 stewards dispatched in a single batch.
	require.Equal(t, 3, cp.sentCount(), "all 3 stewards must receive a command")

	cp.mu.Lock()
	sent := make([]*controlplaneTypes.SignedCommand, len(cp.sent))
	copy(sent, cp.sent)
	cp.mu.Unlock()

	for _, cmd := range sent {
		assert.Equal(t, wantTerm, cmd.Command.Term,
			"command to steward %s must carry term %d from TermSource",
			cmd.Command.StewardID, wantTerm)
	}
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
	job.Targets = []string{"s-0"}
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
