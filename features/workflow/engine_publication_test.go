// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package workflow

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Script steps outside an automation grant (Issue #5899): the engine runs one only for
// a version whose Publication it verified at start. A Publication here is a real
// signature from a real P-256 key over the version's envelope, verified through
// VerifyPublication; the WebAuthn ceremony that produces one in production, and the
// queue behind the script step, are covered by the controller API and nodes tests.

// enginePublisher is a signer account holding a real P-256 key.
type enginePublisher struct {
	key       *ecdsa.PrivateKey
	accountID string
}

func newEnginePublisher(t *testing.T) *enginePublisher {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &enginePublisher{key: key, accountID: "publisher-1"}
}

func (p *enginePublisher) Enabled() bool { return true }

func (p *enginePublisher) VerifyAssertion(envelope operatorpayload.Envelope, pub *Publication) error {
	hash, err := operatorpayload.ChallengeHash(envelope)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(pub.Signature)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(&p.key.PublicKey, hash[:], sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

func (p *enginePublisher) publish(t *testing.T, vw *VersionedWorkflow) {
	t.Helper()
	expires := time.Now().Add(time.Hour).UTC()
	env, hash, err := PublicationEnvelope(approvalTestTenant, vw, "nonce-1", expires)
	require.NoError(t, err)
	challenge, err := operatorpayload.ChallengeHash(env)
	require.NoError(t, err)
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, challenge[:])
	require.NoError(t, err)
	vw.Publication = &Publication{
		ContentHash: hash, Nonce: "nonce-1", ExpiresAt: expires,
		Signature: base64.RawURLEncoding.EncodeToString(sig), SignerAccountID: p.accountID, SignedAt: time.Now().UTC(),
	}
}

// verifier counts its calls, so a test can see when the engine asked.
func (p *enginePublisher) verifier(calls *atomic.Int32) PublicationVerifier {
	return func(ctx context.Context, vw *VersionedWorkflow) error {
		calls.Add(1)
		tenantID, _ := ctx.Value(ctxkeys.TenantID).(string)
		return VerifyPublication(ctx, tenantID, vw,
			func(_ context.Context, id string) (PublicationSigner, error) {
				if id != p.accountID {
					return nil, nil
				}
				return p, nil
			},
			func(_ context.Context, id, permission, _ string) bool {
				return id == p.accountID && permission == PublishPermission
			})
	}
}

type publicationHarness struct {
	engine    *Engine
	scripts   *countingScriptExecutor
	publisher *enginePublisher
	verifies  *atomic.Int32
}

func newPublicationHarness(t *testing.T, opts ...EngineOption) *publicationHarness {
	t.Helper()
	h := &publicationHarness{
		scripts:   &countingScriptExecutor{},
		publisher: newEnginePublisher(t),
		verifies:  &atomic.Int32{},
	}
	all := append([]EngineOption{WithScriptStepExecutor(h.scripts), WithPublicationVerifier(h.publisher.verifier(h.verifies))}, opts...)
	h.engine = NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil, all...)
	t.Cleanup(h.engine.Shutdown)
	return h
}

func versionOf(wf Workflow, major int) *VersionedWorkflow {
	return &VersionedWorkflow{Workflow: wf, SemanticVersion: SemanticVersion{Major: major}}
}

// start runs vw naming it as the stored version being run.
func (h *publicationHarness) start(vw *VersionedWorkflow) (*WorkflowExecution, error) {
	return h.engine.ExecuteWorkflow(WithExecutingVersion(tenantCtx(), vw), vw.Workflow, nil)
}

func (h *publicationHarness) run(t *testing.T, vw *VersionedWorkflow) *WorkflowExecution {
	t.Helper()
	exec, err := h.start(vw)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, exec, 10*time.Second)
	return exec
}

// afterDelay puts step behind a delay step, so a refusal before the first step is
// visible as an empty trace.
func afterDelay(steps ...Step) []Step {
	return append([]Step{delayStep("first", time.Millisecond)}, steps...)
}

// scriptLocations are workflows with one script step at each place a step can hide.
func scriptLocations() map[string][]Step {
	script := scriptStep("hidden")
	locations := map[string][]Step{
		"top level": {script},
		"child steps": {
			{Name: "outer", Type: StepTypeSequential, Steps: []Step{script}},
		},
		"try block": {
			{Name: "t", Type: StepTypeTry, Try: &TryConfig{Try: []Step{script}}},
		},
		"catch block": {
			{Name: "t", Type: StepTypeTry, Try: &TryConfig{
				Try:   []Step{delayStep("try", time.Millisecond)},
				Catch: []CatchBlock{{Steps: []Step{script}}},
			}},
		},
		"finally block": {
			{Name: "t", Type: StepTypeTry, Try: &TryConfig{
				Try:     []Step{delayStep("try", time.Millisecond)},
				Finally: []Step{script},
			}},
		},
		"retry fallback": {
			{Name: "risky", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Millisecond},
				ErrorHandling: &ErrorHandlingConfig{FallbackStep: &script}},
		},
		"switch case": {
			{Name: "sw", Type: StepTypeSwitch, Switch: &SwitchConfig{
				Variable: "v", Cases: []SwitchCase{{Value: "a", Steps: []Step{script}}},
			}},
		},
		"switch default": {
			{Name: "sw", Type: StepTypeSwitch, Switch: &SwitchConfig{
				Variable: "v", Default: []Step{script},
			}},
		},
		"fan-out worker template": {
			{Name: "fan", Type: StepTypeFanOut, FanOut: &FanOutConfig{DataSource: "items", WorkerTemplate: script}},
		},
	}
	// A definition nested deeper than the walk's bound is treated as holding one.
	deep := script
	for i := 0; i < maxScriptWalkDepth+5; i++ {
		deep = Step{Name: "level", Type: StepTypeSequential, Steps: []Step{deep}}
	}
	locations["nested beyond the walk bound"] = []Step{deep}
	return locations
}

// [REQUIRED TEST] A script step in a catch block, a finally block, a retry fallback or
// a fan-out worker template (and everywhere else a step can hide) of an unpublished
// workflow is refused before any step runs, and nothing reaches the executor.
func TestPublication_UnpublishedScriptStepRefusedBeforeAnyStep(t *testing.T) {
	h := newPublicationHarness(t)
	for name, steps := range scriptLocations() {
		t.Run(name, func(t *testing.T) {
			wf := Workflow{Name: "unpublished", Steps: afterDelay(steps...)}

			for how, start := range map[string]func() (*WorkflowExecution, error){
				"no version named": func() (*WorkflowExecution, error) { return h.engine.ExecuteWorkflow(tenantCtx(), wf, nil) },
				"version without a publication": func() (*WorkflowExecution, error) {
					return h.start(versionOf(wf, 1))
				},
			} {
				exec, err := start()

				require.ErrorIs(t, err, ErrScriptStepNotRestricted, how)
				require.NotNil(t, exec, how)
				assert.Equal(t, StatusFailed, exec.GetStatus(), how)
				assert.Empty(t, exec.GetExecutionTrace(), "%s: no step ran", how)
				assert.Zero(t, h.scripts.runs.Load(), how)
			}
		})
	}
}

// The same locations in a published version run: the Publication covers the whole
// definition.
func TestPublication_PublishedScriptStepRuns(t *testing.T) {
	for _, name := range []string{"top level", "child steps", "try block", "finally block", "switch default"} {
		t.Run(name, func(t *testing.T) {
			h := newPublicationHarness(t)
			steps := scriptLocations()[name]
			wf := Workflow{Name: "published", Variables: map[string]interface{}{"v": "x"}, Steps: afterDelay(steps...)}
			vw := versionOf(wf, 1)
			h.publisher.publish(t, vw)

			exec := h.run(t, vw)

			require.Equal(t, StatusCompleted, exec.GetStatus(), exec.GetError())
			assert.True(t, exec.PublicationVerified)
			assert.Equal(t, int32(1), h.scripts.runs.Load())
			assert.Equal(t, int32(1), h.verifies.Load(), "the Publication is verified once per start")
		})
	}
}

// The Publication is verified at each start; nothing is cached.
func TestPublication_VerifiedAtEachStart(t *testing.T) {
	h := newPublicationHarness(t)
	vw := versionOf(Workflow{Name: "published", Steps: []Step{scriptStep("s")}}, 1)
	h.publisher.publish(t, vw)

	for i := 1; i <= 3; i++ {
		h.run(t, vw)
		assert.Equal(t, int32(i), h.verifies.Load())
	}
	assert.Equal(t, int32(3), h.scripts.runs.Load())
}

// A workflow with no script step is unaffected: it starts with or without a version,
// and the verifier is never asked.
func TestPublication_WorkflowWithoutScriptStepIsUnaffected(t *testing.T) {
	h := newPublicationHarness(t)
	wf := Workflow{Name: "plain", Steps: []Step{delayStep("d", time.Millisecond)}}

	plain, err := h.engine.ExecuteWorkflow(tenantCtx(), wf, nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, plain, 5*time.Second)
	named := h.run(t, versionOf(wf, 1))

	assert.Equal(t, StatusCompleted, plain.GetStatus())
	assert.Equal(t, StatusCompleted, named.GetStatus())
	assert.False(t, plain.PublicationVerified)
	assert.Zero(t, h.verifies.Load())
}

// An engine built without a verifier verifies nothing: a script step stays refused.
func TestPublication_NoVerifierRefusesEveryScriptStep(t *testing.T) {
	scripts := &countingScriptExecutor{}
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil, WithScriptStepExecutor(scripts))
	t.Cleanup(engine.Shutdown)
	wf := Workflow{Name: "published", Steps: []Step{scriptStep("s")}}
	vw := versionOf(wf, 1)
	newEnginePublisher(t).publish(t, vw)

	_, err := engine.ExecuteWorkflow(WithExecutingVersion(tenantCtx(), vw), wf, nil)

	require.ErrorIs(t, err, ErrScriptStepNotRestricted)
	assert.Zero(t, scripts.runs.Load())
}

// The backstop: a script step that reaches the dispatcher in an execution that is
// neither restricted nor publication-verified fails closed, whatever the walk saw.
func TestPublication_ScriptCaseRefusesUnlessRestrictedOrVerified(t *testing.T) {
	h := newPublicationHarness(t)
	step := scriptStep("missed-by-the-walk")

	for name, tc := range map[string]struct {
		exec    *WorkflowExecution
		refused bool
	}{
		"plain":      {exec: &WorkflowExecution{ID: "e1", TenantID: approvalTestTenant}, refused: true},
		"verified":   {exec: &WorkflowExecution{ID: "e2", TenantID: approvalTestTenant, PublicationVerified: true}},
		"restricted": {exec: &WorkflowExecution{ID: "e3", TenantID: approvalTestTenant, Restricted: &RestrictedRun{RunID: "r", GrantID: "g"}}},
	} {
		t.Run(name, func(t *testing.T) {
			before := h.scripts.runs.Load()
			tc.exec.StepResults = map[string]StepResult{}

			err := h.engine.executeScriptStep(tenantCtx(), step, tc.exec, "s1")

			if tc.refused {
				require.ErrorIs(t, err, ErrScriptStepNotRestricted)
				assert.Equal(t, before, h.scripts.runs.Load())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, before+1, h.scripts.runs.Load())
		})
	}
}

// [REQUIRED TEST] A published workflow whose step calls an unpublished workflow (by
// name) that contains a script step is refused, in both the workflow and error_workflow
// forms: a nested run never inherits the parent's Publication.
func TestPublication_NestedRunDoesNotInheritPublication(t *testing.T) {
	calls := map[string]Step{
		"workflow": {Name: "call", Type: StepTypeWorkflow, WorkflowCall: &WorkflowCallConfig{WorkflowName: "child"}},
		"error_workflow": {Name: "call", Type: StepTypeErrorWorkflow, ErrorWorkflow: &ErrorWorkflowConfig{
			WorkflowName: "child",
		}},
		"composite component": {Name: "call", Type: StepTypeComposite, Composite: &CompositeConfig{
			Strategy:   CompositionStrategySequential,
			Components: []WorkflowComponent{{Name: "c1", WorkflowName: "child"}},
		}},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			h := newPublicationHarness(t)
			h.engine.RegisterWorkflow(Workflow{Name: "child", Steps: []Step{scriptStep("nested-script")}})
			// The parent holds a script step of its own, so it is itself published and
			// verified: the nested run still does not get to use that.
			parent := versionOf(Workflow{Name: "parent", Steps: afterDelay(scriptStep("own"), call)}, 1)
			h.publisher.publish(t, parent)

			exec := h.run(t, parent)

			assert.True(t, exec.PublicationVerified, "the parent run itself is verified")
			assert.Equal(t, StatusFailed, exec.GetStatus(), "the nested run was refused")
			assert.Contains(t, exec.GetError(), ErrScriptStepNotRestricted.Error())
			assert.Equal(t, int32(1), h.scripts.runs.Load(), "only the parent's own script step ran")
		})
	}
}

// A composite component or nested workflow with a script step, called from an
// unpublished workflow that has none of its own, is refused when the nested run starts.
func TestPublication_UnpublishedParentCannotReachScriptThroughNestedRun(t *testing.T) {
	h := newPublicationHarness(t)
	h.engine.RegisterWorkflow(Workflow{Name: "child", Steps: []Step{scriptStep("nested-script")}})
	parent := Workflow{Name: "parent", Steps: afterDelay(Step{
		Name: "call", Type: StepTypeComposite, Composite: &CompositeConfig{
			Strategy:   CompositionStrategySequential,
			Components: []WorkflowComponent{{Name: "c1", WorkflowName: "child"}},
		},
	})}

	exec, err := h.start(versionOf(parent, 1))
	require.NoError(t, err, "the parent has no script step of its own")
	waitForWorkflowCompletion(t, exec, 10*time.Second)

	assert.Equal(t, StatusFailed, exec.GetStatus())
	assert.Zero(t, h.scripts.runs.Load())
}

// [REQUIRED TEST] A script step in the tail resumed by ResumeFromApproval is refused:
// the resumed execution is built fresh and carries no publication.
func TestPublication_ScriptStepInResumedTailIsRefused(t *testing.T) {
	approvals := newApprovalHarness(t)
	scripts := &countingScriptExecutor{}
	publisher := newEnginePublisher(t)
	var verifies atomic.Int32
	engine := approvals.engine(WithScriptStepExecutor(scripts), WithPublicationVerifier(publisher.verifier(&verifies)))

	vw := versionOf(Workflow{Name: "gated-script", Steps: []Step{
		delayStep("before", time.Millisecond),
		gateStep("gate", time.Hour),
		scriptStep("after-the-gate"),
	}}, 1)
	publisher.publish(t, vw)

	exec, err := engine.ExecuteWorkflow(WithExecutingVersion(tenantCtx(), vw), vw.Workflow, nil)
	require.NoError(t, err, "the version is published, so the run starts and reaches the gate")
	waitForWorkflowCompletion(t, exec, 5*time.Second)
	require.Equal(t, StatusAwaitingApproval, exec.GetStatus(), exec.GetError())
	assert.True(t, exec.PublicationVerified)

	pending, err := approvals.store.ListPending(context.Background(), approvalTestTenant)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	approvals.decide(pending[0], business.ApprovalStatusApproved)

	resumed, err := engine.ResumeFromApproval(context.Background(), approvalTestTenant, pending[0].ApprovalID)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, resumed, 5*time.Second)

	assert.Equal(t, StatusFailed, resumed.GetStatus())
	assert.Contains(t, resumed.GetError(), ErrScriptStepNotRestricted.Error())
	assert.Zero(t, scripts.runs.Load(), "the script step in the resumed tail never ran")
}

// [REQUIRED TEST] The registration approval workflow with a script step is refused: its
// caller names no version, so the run is never publication-verified.
func TestPublication_CallerNamingNoVersionIsRefused(t *testing.T) {
	h := newPublicationHarness(t)
	vw := versionOf(Workflow{Name: "registration-approval", Steps: []Step{scriptStep("s")}}, 1)
	h.publisher.publish(t, vw)

	// The registration approval hook runs vw.Workflow with no version in the context,
	// published or not.
	exec, err := h.engine.ExecuteWorkflow(tenantCtx(), vw.Workflow, map[string]interface{}{"registration_id": "r-1"})

	require.ErrorIs(t, err, ErrScriptStepNotRestricted)
	require.NotNil(t, exec)
	assert.Zero(t, h.scripts.runs.Load())
	assert.Zero(t, h.verifies.Load(), "no version, nothing to verify")
}

// The version a caller names is for that execution only: it is not in the context the
// execution's steps run under.
func TestPublication_ExecutingVersionIsRemovedFromTheExecutionContext(t *testing.T) {
	h := newPublicationHarness(t)
	vw := versionOf(Workflow{Name: "plain", Steps: []Step{delayStep("d", time.Millisecond)}}, 1)

	exec := h.run(t, vw)

	got, _ := exec.Context.Value(executingVersionKey{}).(*VersionedWorkflow)
	assert.Nil(t, got)
	assert.Nil(t, WithExecutingVersion(tenantCtx(), nil).Value(executingVersionKey{}), "a nil version names nothing")
}

// A restricted run ignores a named version: it keeps the grant path and is never
// publication-verified.
func TestPublication_RestrictedRunNeverUsesThePublicationPath(t *testing.T) {
	h := newPublicationHarness(t)
	vw := versionOf(Workflow{Name: "grant", Steps: []Step{scriptStep("s")}}, 1)
	h.publisher.publish(t, vw)

	exec, err := h.engine.ExecuteRestrictedWorkflow(WithExecutingVersion(tenantCtx(), vw), vw.Workflow, nil,
		RestrictedRun{RunID: "run-1", GrantID: "grant-1", Ceiling: approvalTestTenant})
	require.NoError(t, err)
	waitForWorkflowCompletion(t, exec, 5*time.Second)

	assert.False(t, exec.PublicationVerified)
	assert.Zero(t, h.verifies.Load(), "a grant run never consults the Publication")
}

// Editing a published workflow stores a version with no Publication, and a Publication
// over another version's hash does not carry over.
func TestPublication_EditedOrOtherVersionIsRefused(t *testing.T) {
	h := newPublicationHarness(t)
	v1 := versionOf(Workflow{Name: "wf", Steps: []Step{scriptStep("s")}}, 1)
	h.publisher.publish(t, v1)
	require.Equal(t, StatusCompleted, h.run(t, v1).GetStatus())

	edited := versionOf(Workflow{Name: "wf", Steps: []Step{scriptStep("s"), delayStep("added", time.Millisecond)}}, 1)
	edited.Publication = v1.Publication
	other := versionOf(v1.Workflow, 2)
	other.Publication = v1.Publication

	for name, vw := range map[string]*VersionedWorkflow{"edited": edited, "other version": other, "no publication": versionOf(edited.Workflow, 3)} {
		_, err := h.start(vw)
		require.ErrorIs(t, err, ErrScriptStepNotRestricted, name)
	}
	assert.Equal(t, int32(1), h.scripts.runs.Load())

	h.publisher.publish(t, edited)
	assert.Equal(t, StatusCompleted, h.run(t, edited).GetStatus(), "published again, it runs")
}

// The Publication speaks only for the definition it signed: a run of different steps
// under a verified version's name is refused.
func TestPublication_VersionMustBeTheRunsDefinition(t *testing.T) {
	h := newPublicationHarness(t)
	signed := versionOf(Workflow{Name: "wf", Steps: []Step{delayStep("d", time.Millisecond)}}, 1)
	h.publisher.publish(t, signed)
	swapped := Workflow{Name: "wf", Steps: []Step{scriptStep("smuggled")}}

	_, err := h.engine.ExecuteWorkflow(WithExecutingVersion(tenantCtx(), signed), swapped, nil)

	require.ErrorIs(t, err, ErrScriptStepNotRestricted)
	assert.Zero(t, h.scripts.runs.Load())
}

func TestContainsScriptStep(t *testing.T) {
	assert.False(t, containsScriptStep(nil))
	assert.False(t, containsScriptStep([]Step{delayStep("d", time.Millisecond)}))
	for name, steps := range scriptLocations() {
		assert.True(t, containsScriptStep(steps), name)
	}
}
