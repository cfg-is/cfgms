// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dispatcher

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/run"
	script "github.com/cfgis/cfgms/features/modules/stdlib/script"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// lockedSet is the lockdown predicate for the dispatcher tests.
type lockedSet struct {
	mu     sync.Mutex
	locked map[string]bool
	err    error
}

func (l *lockedSet) IsLockedDown(_ context.Context, id string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return true, l.err
	}
	return l.locked[id], nil
}

func (l *lockedSet) lock(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.locked[id] = true
}

type gateAudit struct {
	mu      sync.Mutex
	allowed []string
	refused []string
}

func (g *gateAudit) CommandRefused(_ context.Context, id string, t controlplaneTypes.CommandType, _ string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refused = append(g.refused, id+"|"+string(t))
}

func (g *gateAudit) OperatorCommandAllowed(_ context.Context, op, id string, t controlplaneTypes.CommandType) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.allowed = append(g.allowed, op+"|"+id+"|"+string(t))
}

// gatedControlPlane puts the real command gate in front of the recording control
// plane, so the dispatcher sees exactly what the gRPC provider would return.
type gatedControlPlane struct {
	*testControlPlane
	gate *cpinterfaces.LockdownGate
}

func (g *gatedControlPlane) SendCommand(ctx context.Context, cmd *controlplaneTypes.SignedCommand) error {
	if err := g.gate.Check(ctx, cmd.Command.StewardID, cmd.Command.Type); err != nil {
		return err
	}
	return g.testControlPlane.SendCommand(ctx, cmd)
}

type lockdownHarness struct {
	*actionHarness
	pred  *lockedSet
	audit *gateAudit
}

// newLockdownHarness wires a dispatcher whose control plane is gated. withPrecheck
// controls whether the dispatcher also holds the predicate (the production wiring).
func newLockdownHarness(t *testing.T, withPrecheck bool) *lockdownHarness {
	t.Helper()
	db := mustOpenMemDB(t)
	db.SetMaxOpenConns(1)
	store := run.NewRunStoreSQL(db)
	require.NoError(t, store.Init(context.Background()))

	keys := script.NewEphemeralKeyManager()
	t.Cleanup(keys.Stop)
	repo := newTestScriptRepo()
	repo.addScript("lib-script", "echo library")
	q := script.NewExecutionQueue(script.NewExecutionMonitor(), keys, time.Hour, "https://localhost:8080", nil, repo, time.Hour)
	t.Cleanup(q.Stop)

	pred := &lockedSet{locked: map[string]bool{}}
	audit := &gateAudit{}
	inner := &testControlPlane{}
	cp := &gatedControlPlane{testControlPlane: inner, gate: cpinterfaces.NewLockdownGate(pred, audit)}

	cfg := &Config{
		Queue: q, ControlPlane: cp, Signer: testCommandSigner{}, TermSource: staticTermSource{term: testActionTerm},
		PollInterval: 24 * time.Hour, Logger: logging.NewNoopLogger(),
	}
	if withPrecheck {
		cfg.Lockdown = pred
	}
	d, err := New(cfg)
	require.NoError(t, err)
	manager := run.NewManager(store, q)
	manager.SetDeviceLockReleaser(d)
	d.SetRunCompletionSink(manager)
	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(d.Stop)

	return &lockdownHarness{
		actionHarness: &actionHarness{cp: inner, q: q, keys: keys, store: store, manager: manager, d: d},
		pred:          pred, audit: audit,
	}
}

func (h *lockdownHarness) trackedJob(t *testing.T, device, execID string, meta map[string]interface{}, qe *script.QueuedExecution) *run.JobRecord {
	t.Helper()
	now := time.Now().UTC()
	runID, jobID := "run-"+execID, "job-"+execID
	require.NoError(t, h.store.CreateRun(&run.RunRecord{RunID: runID, TenantID: "tenant-a", CreatedAt: now, Status: run.RunStatusRunning, JobCount: 1}))
	require.NoError(t, h.store.CreateJob(&run.JobRecord{JobID: jobID, RunID: runID, DeviceID: device, ExecutionID: execID, Status: run.JobStatusPending, CreatedAt: now}))
	if qe.Metadata == nil {
		qe.Metadata = map[string]interface{}{}
	}
	qe.Metadata["workflow_run_id"], qe.Metadata["job_id"], qe.Metadata["tenant_id"] = runID, jobID, "tenant-a"
	for k, v := range meta {
		qe.Metadata[k] = v
	}
	qe.ExecutionID = execID
	require.NoError(t, h.q.QueueExecution(device, qe))
	return h.onlyJob(t, runID)
}

func inlineExec() *script.QueuedExecution {
	return &script.QueuedExecution{
		Shell: script.ShellBash, Timeout: time.Minute, GenerateAPIKey: true,
		Environment: map[string]string{"A": "b"},
		Metadata:    map[string]interface{}{"inline_script_content": "echo hi", "secret_bindings": `[{"param":"p","secret":"vault/x"}]`},
	}
}

// An operator-created run reaches a locked steward with an audit event naming the
// operator, and nothing the controller resolves goes into the payload.
func TestDispatcher_Lockdown_OperatorScriptDeliveredWithoutResolvedSecrets(t *testing.T) {
	for _, precheck := range []bool{true, false} {
		h := newLockdownHarness(t, precheck)
		h.pred.lock("locked-1")
		h.trackedJob(t, "locked-1", "exec-op", map[string]interface{}{script.MetaOperatorPrincipal: "alice"}, inlineExec())

		h.d.dispatchForDevice(context.Background(), "locked-1")

		require.Equal(t, 1, h.cp.sentCount(), "precheck=%v", precheck)
		sent := h.cp.lastSent()
		assert.Equal(t, controlplaneTypes.CommandExecuteScript, sent.Command.Type)
		if precheck { // the production wiring: the dispatcher holds the predicate
			assert.NotContains(t, sent.Command.Params, "environment", "no credential or resolved value is minted for a locked steward")
			assert.Zero(t, h.keys.GetKeyCount(), "no ephemeral API key is minted for a locked steward")
		}
		assert.Equal(t, []string{"alice|locked-1|execute_script"}, h.audit.allowed)
	}
}

// The same run on a normal steward still gets its prepared environment: the
// stripping is specific to a locked steward.
func TestDispatcher_Lockdown_NormalStewardStillGetsPreparedEnvironment(t *testing.T) {
	h := newLockdownHarness(t, true)
	h.trackedJob(t, "normal-1", "exec-n", map[string]interface{}{script.MetaOperatorPrincipal: "alice"}, inlineExec())
	h.d.dispatchForDevice(context.Background(), "normal-1")
	require.Equal(t, 1, h.cp.sentCount())
	assert.Contains(t, h.cp.lastSent().Command.Params, "environment")
	assert.Equal(t, 1, h.keys.GetKeyCount())
	assert.Empty(t, h.audit.allowed, "only commands to a locked steward are audited as operator-allowed")
}

// A workflow or scheduled execution carries no principal: refused, nothing prepared,
// the job records "refused" (not failed-by-steward), and the entry is not re-queued.
func TestDispatcher_Lockdown_AutomatedExecutionRefusedAndRecorded(t *testing.T) {
	for _, precheck := range []bool{true, false} {
		h := newLockdownHarness(t, precheck)
		h.pred.lock("locked-1")
		job := h.trackedJob(t, "locked-1", "exec-auto", nil, inlineExec())
		require.Empty(t, job.ResultCode)

		h.d.dispatchForDevice(context.Background(), "locked-1")

		assert.Zero(t, h.cp.sentCount(), "precheck=%v", precheck)
		if precheck {
			assert.Zero(t, h.keys.GetKeyCount(), "nothing is prepared for a refused execution")
		}
		got := h.onlyJob(t, "run-exec-auto")
		assert.Equal(t, run.ResultCodeRefused, got.ResultCode)
		assert.True(t, got.Status.IsTerminal())
		assert.Empty(t, h.q.PeekForDevice("locked-1"), "a refusal is not retried")
		assert.False(t, h.lockHeld("locked-1"))
	}
}

// A lookup error is treated as locked by the dispatcher pre-check.
func TestDispatcher_Lockdown_LookupErrorRefuses(t *testing.T) {
	h := newLockdownHarness(t, true)
	h.pred.err = errors.New("store unavailable")
	h.trackedJob(t, "any", "exec-err", map[string]interface{}{script.MetaOperatorPrincipal: "alice"}, inlineExec())
	// Operator-origin scripts are allowed even on a lookup error only if the gate allows them;
	// the gate treats a lookup error as a refusal, so nothing is sent.
	h.d.dispatchForDevice(context.Background(), "any")
	assert.Zero(t, h.cp.sentCount())
	assert.Equal(t, run.ResultCodeRefused, h.onlyJob(t, "run-exec-err").ResultCode)
}

// An execution queued while the steward was normal is refused at send time once it
// is locked, even though the dispatcher's own pre-check did not see the change.
func TestDispatcher_Lockdown_QueuedBeforeTamper_RefusedAtSend(t *testing.T) {
	h := newLockdownHarness(t, false)
	h.trackedJob(t, "s1", "exec-q", nil, inlineExec())
	h.pred.lock("s1")

	h.d.dispatchForDevice(context.Background(), "s1")

	assert.Zero(t, h.cp.sentCount())
	assert.Equal(t, run.ResultCodeRefused, h.onlyJob(t, "run-exec-q").ResultCode)
	assert.Empty(t, h.q.PeekForDevice("s1"))
}

// A library-script run an operator API call created is stamped; a scheduled one is not.
func TestSynthesis_LibraryScriptRun_OriginStampOnlyForOperatorCall(t *testing.T) {
	h := newLockdownHarness(t, true)
	h.pred.lock("locked-lib")
	h.pred.lock("locked-sched")
	devices := func(id string) []fleet.StewardResult { return []fleet.StewardResult{{ID: id, TenantID: "tenant-a"}} }

	// Operator API call: createdBy is the authenticated principal.
	_, err := run.SynthesizeScriptRunForDevices(context.Background(), h.manager, h.q, devices("locked-lib"),
		"tenant-a", "alice", fleet.Filter{}, "lib-script", "", script.ShellBash, nil, nil, nil, nil)
	require.NoError(t, err)
	// Scheduled run: no operator principal.
	_, err = run.SynthesizeScriptRunForDevices(context.Background(), h.manager, h.q, devices("locked-sched"),
		"tenant-a", "", fleet.Filter{}, "lib-script", "", script.ShellBash, nil, nil, nil, nil)
	require.NoError(t, err)

	h.d.dispatchForDevice(context.Background(), "locked-lib")
	h.d.dispatchForDevice(context.Background(), "locked-sched")

	require.Equal(t, 1, h.cp.sentCount(), "only the operator-created library run reaches a locked steward")
	assert.Equal(t, "locked-lib", h.cp.lastSent().Command.StewardID)
	assert.Equal(t, []string{"alice|locked-lib|execute_script"}, h.audit.allowed)
}

// The operator-origin marker comes only from an operator-created run: a workflow
// node's queue entry has the same shape but no principal.
func TestSynthesis_WorkflowExecutionNeverStamped(t *testing.T) {
	h := newLockdownHarness(t, true)
	h.pred.lock("locked-wf")
	// What features/workflow/nodes/script_node.go queues.
	require.NoError(t, h.q.QueueExecution("locked-wf", &script.QueuedExecution{
		ExecutionID: "exec-wf", ScriptRef: "lib-script", Shell: script.ShellBash,
		Metadata: map[string]interface{}{"tenant_id": "tenant-a", "workflow_run_id": "wf-1", "workflow_name": "nightly"},
	}))
	h.d.dispatchForDevice(context.Background(), "locked-wf")
	assert.Zero(t, h.cp.sentCount())
	_, marked := cpinterfaces.OperatorOriginFrom(h.d.withExecutionOrigin(context.Background(), &script.QueuedExecution{Metadata: map[string]interface{}{"workflow_run_id": "wf-1"}}))
	assert.False(t, marked)
}

// Operator-origin steward_action is delivered with an audit event; an action with
// no principal is refused and its job records refused.
func TestDispatcher_Lockdown_StewardAction(t *testing.T) {
	h := newLockdownHarness(t, true)
	h.pred.lock("locked-act")
	runID, _ := h.enqueueAction(t, "locked-act", "service.stop", x509ActionProof)

	h.d.dispatchForDevice(context.Background(), "locked-act")

	require.Equal(t, 1, h.cp.sentCount())
	assert.Equal(t, controlplaneTypes.CommandStewardAction, h.cp.lastSent().Command.Type)
	assert.Equal(t, []string{"admin|locked-act|steward_action"}, h.audit.allowed)
	assert.Equal(t, run.JobStatusDispatched, h.onlyJob(t, runID).Status)
}

func TestDispatcher_Lockdown_StewardActionWithoutPrincipalRefused(t *testing.T) {
	h := newLockdownHarness(t, true)
	h.pred.lock("locked-act")
	runID, _ := h.enqueueAction(t, "locked-act", "service.stop", x509ActionProof)
	// Strip the principal as a non-operator creation path would leave it.
	h.dropPrincipal(t, "locked-act")

	h.d.dispatchForDevice(context.Background(), "locked-act")

	assert.Zero(t, h.cp.sentCount())
	assert.Equal(t, run.ResultCodeRefused, h.onlyJob(t, runID).ResultCode)
}

func (h *lockdownHarness) dropPrincipal(t *testing.T, device string) {
	t.Helper()
	entries := h.q.ListQueuedExecutions()[device]
	require.Len(t, entries, 1)
	for _, e := range entries {
		require.NoError(t, h.q.CancelExecution(device, e.ExecutionID))
		delete(e.Metadata, script.MetaOperatorPrincipal)
		e.State = ""
		require.NoError(t, h.q.QueueExecution(device, e))
	}
}

// relay_response carries the marker only for an open execution an operator started.
func TestDispatcher_OperatorOriginForRelay(t *testing.T) {
	h := newLockdownHarness(t, true)
	h.trackedJob(t, "dev", "exec-open", map[string]interface{}{script.MetaOperatorPrincipal: "alice"}, inlineExec())
	h.trackedJob(t, "dev-wf", "exec-wf", nil, inlineExec())

	h.d.dispatchForDevice(context.Background(), "dev")
	h.d.dispatchForDevice(context.Background(), "dev-wf")
	ctx := context.Background()

	got := func(c context.Context) (string, bool) { return cpinterfaces.OperatorOriginFrom(c) }

	p, ok := got(h.d.OperatorOriginForRelay(ctx, "dev", "exec-open"))
	assert.True(t, ok)
	assert.Equal(t, "alice", p)

	_, ok = got(h.d.OperatorOriginForRelay(ctx, "dev-wf", "exec-wf"))
	assert.False(t, ok, "a workflow execution is never operator-started")
	_, ok = got(h.d.OperatorOriginForRelay(ctx, "dev", "exec-other"))
	assert.False(t, ok, "a relay request for an execution the operator did not start on this steward")
	_, ok = got(h.d.OperatorOriginForRelay(ctx, "other-dev", "exec-open"))
	assert.False(t, ok, "the execution is bound to the steward it was started on")

	require.NoError(t, h.cp.injectCompletion(ctx, "dev", "exec-open", 0))
	_, ok = got(h.d.OperatorOriginForRelay(ctx, "dev", "exec-open"))
	assert.False(t, ok, "a closed execution gets no marker")
}
