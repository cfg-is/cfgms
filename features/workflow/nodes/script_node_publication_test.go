// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package nodes

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

	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// Script steps outside an automation grant (Issue #5899). These tests run the real
// workflow engine, execution queue, tenant script library (over real storage) and
// fleet query. A Publication is a real signature over the version's envelope from a
// real P-256 key, verified through workflow.VerifyPublication; the WebAuthn ceremony
// that produces one in production is covered by the controller API tests.

// testPublisher is a signer account holding a real P-256 key. It implements
// workflow.PublicationSigner: it verifies a stored signature under its own public key.
type testPublisher struct {
	key       *ecdsa.PrivateKey
	accountID string
	holdsPerm atomic.Bool
}

func newTestPublisher(t *testing.T) *testPublisher {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p := &testPublisher{key: key, accountID: "publisher-1"}
	p.holdsPerm.Store(true)
	return p
}

func (p *testPublisher) Enabled() bool { return true }

func (p *testPublisher) VerifyAssertion(envelope operatorpayload.Envelope, pub *workflow.Publication) error {
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

// publish signs vw in tenantID and stores the Publication on it.
func (p *testPublisher) publish(t *testing.T, tenantID string, vw *workflow.VersionedWorkflow) {
	t.Helper()
	expires := time.Now().Add(time.Hour).UTC()
	env, hash, err := workflow.PublicationEnvelope(tenantID, vw, "nonce-1", expires)
	require.NoError(t, err)
	challenge, err := operatorpayload.ChallengeHash(env)
	require.NoError(t, err)
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, challenge[:])
	require.NoError(t, err)
	vw.Publication = &workflow.Publication{
		ContentHash: hash, Nonce: "nonce-1", ExpiresAt: expires,
		Signature: base64.RawURLEncoding.EncodeToString(sig), SignerAccountID: p.accountID, SignedAt: time.Now().UTC(),
	}
}

// verifier is the engine's publication verifier, as the controller builds it: the
// tenant is the one on the context.
func (p *testPublisher) verifier() workflow.PublicationVerifier {
	return func(ctx context.Context, vw *workflow.VersionedWorkflow) error {
		tenantID, _ := ctx.Value(ctxkeys.TenantID).(string)
		return workflow.VerifyPublication(ctx, tenantID, vw,
			func(_ context.Context, id string) (workflow.PublicationSigner, error) {
				if id != p.accountID {
					return nil, nil
				}
				return p, nil
			},
			func(_ context.Context, id, permission, _ string) bool {
				return id == p.accountID && permission == workflow.PublishPermission && p.holdsPerm.Load()
			})
	}
}

// publishedFixture is a restrictedFixture whose library holds two scripts in the run
// tenant and whose engine can verify Publications.
type publishedFixture struct {
	*restrictedFixture
	publisher *testPublisher
	engine    *workflow.Engine
}

func newPublishedFixture(t *testing.T) *publishedFixture {
	t.Helper()
	f := &publishedFixture{restrictedFixture: newRestrictedFixture(t), publisher: newTestPublisher(t)}
	f.put(t, rsRunTenant, "inventory", "echo inventory\n")
	f.put(t, rsRunTenant, "patch-check", "echo patch\n")
	f.engine = workflow.NewEngine(nil, logging.NewNoopLogger(), nil, nil, nil, nil, nil,
		workflow.WithScriptStepExecutor(f.executor()),
		workflow.WithPublicationVerifier(f.publisher.verifier()))
	t.Cleanup(f.engine.Shutdown)
	return f
}

// publishedStep is a script step selecting devices by a fleet filter in the run tenant.
func publishedStep(name, scriptID string) workflow.Step {
	return workflow.Step{Name: name, Type: workflow.StepTypeScript, Config: map[string]interface{}{
		"script_id": scriptID, "script_version": "1.0.0",
		"device_filter": map[string]interface{}{"status": "online"},
	}}
}

// twoScriptVersion is a version with two script steps.
func twoScriptVersion(version int) *workflow.VersionedWorkflow {
	return &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{Name: "gather-and-check", Steps: []workflow.Step{
			publishedStep("collect", "inventory"),
			publishedStep("check", "patch-check"),
		}},
		SemanticVersion: workflow.SemanticVersion{Major: version},
	}
}

// start runs vw outside a grant, naming it as the version being run, the way the
// execute handler and the trigger adapter do.
func (f *publishedFixture) start(t *testing.T, vw *workflow.VersionedWorkflow) (*workflow.WorkflowExecution, error) {
	t.Helper()
	return f.engine.ExecuteWorkflow(workflow.WithExecutingVersion(tenantCtx(), vw), vw.Workflow, nil)
}

// stewardRuns collects n runs a steward session receives for the run-tenant device.
func stewardRuns(t *testing.T, runs <-chan stewardRun, n int) []stewardRun {
	t.Helper()
	got := make([]stewardRun, 0, n)
	for len(got) < n {
		select {
		case r := <-runs:
			got = append(got, r)
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d queued runs reached the steward", len(got), n)
		}
	}
	return got
}

// [REQUIRED TEST] A human-started execution of a published workflow with two script
// steps queues both library runs, with no approval evaluation and no further check.
func TestPublished_TwoScriptStepsQueueBothLibraryRuns(t *testing.T) {
	f := newPublishedFixture(t)
	vw := twoScriptVersion(1)
	f.publisher.publish(t, rsRunTenant, vw)

	exec, err := f.start(t, vw)
	require.NoError(t, err)
	waitExecution(t, exec)

	require.Equal(t, workflow.StatusCompleted, exec.GetStatus(), exec.GetError())
	assert.True(t, exec.PublicationVerified)
	assert.Zero(t, f.approver.askedCount(), "a published run never consults the approval evaluator")
	assert.Equal(t, 2, f.queued(), "both library runs are queued")

	// The steward connects once the run has queued: a step sets the queue's tracker as
	// it starts, which must not overlap a steward acknowledging.
	got := stewardRuns(t, f.serveSteward(t, rsDevice, "ok\n"), 2)
	contents := map[string]string{}
	for _, r := range got {
		require.NoError(t, r.prepErr, "the steward receives the library script the step pinned")
		assert.Equal(t, "1.0.0", r.prepared.ScriptVersion)
		assert.Equal(t, rsRunTenant, r.entry.Metadata["tenant_id"], "the library is the execution's tenant")
		contents[r.entry.ScriptRef] = r.prepared.ScriptContent
	}
	assert.Equal(t, map[string]string{"inventory": "echo inventory\n", "patch-check": "echo patch\n"}, contents)
}

// [REQUIRED TEST] A scheduled or API-key-started execution of the same published
// version queues its script steps with no tap. Such a run has no principal on its
// context, only the tenant and the version the caller loaded.
func TestPublished_UnattendedStartQueuesScriptSteps(t *testing.T) {
	f := newPublishedFixture(t)
	vw := twoScriptVersion(1)
	f.publisher.publish(t, rsRunTenant, vw)

	// What workflowEngineAdapter.TriggerWorkflow builds: detached from any request,
	// carrying the trigger's tenant and the stored version.
	ctx := context.WithValue(context.WithoutCancel(context.Background()), ctxkeys.TenantID, rsRunTenant)
	ctx = workflow.WithExecutingVersion(ctx, vw)
	exec, err := f.engine.ExecuteWorkflow(ctx, vw.Workflow, nil)
	require.NoError(t, err)
	waitExecution(t, exec)

	require.Equal(t, workflow.StatusCompleted, exec.GetStatus(), exec.GetError())
	assert.Equal(t, 2, f.queued())
	assert.Len(t, stewardRuns(t, f.serveSteward(t, rsDevice, "ok\n"), 2), 2)
}

// [REQUIRED TEST] A version with a script step and no Publication, a tampered
// Publication, or a Publication over another version's hash is refused before any
// step runs, and nothing is queued.
func TestPublished_RefusedWithoutValidPublication(t *testing.T) {
	f := newPublishedFixture(t)

	published := twoScriptVersion(1)
	f.publisher.publish(t, rsRunTenant, published)

	tampered := twoScriptVersion(1)
	tampered.Publication = published.Publication
	tampered.Steps[0].Config["script_id"] = "patch-check" // edited after it was published

	otherVersion := twoScriptVersion(2)
	otherVersion.Publication = published.Publication // a Publication over version 1's hash

	forged := twoScriptVersion(3)
	f.publisher.publish(t, rsRunTenant, forged)
	forged.Publication.Signature = published.Publication.Signature

	revoked := twoScriptVersion(4)
	f.publisher.publish(t, rsRunTenant, revoked)

	cases := map[string]*workflow.VersionedWorkflow{
		"no publication":                 twoScriptVersion(1),
		"edited after publishing":        tampered,
		"publication over other version": otherVersion,
		"signature of another version":   forged,
	}
	for name, vw := range cases {
		t.Run(name, func(t *testing.T) {
			exec, err := f.start(t, vw)

			require.ErrorIs(t, err, workflow.ErrScriptStepNotRestricted)
			require.NotNil(t, exec)
			assert.Equal(t, workflow.StatusFailed, exec.GetStatus())
			assert.Empty(t, exec.GetExecutionTrace(), "no step ran")
			assert.Zero(t, f.queued())
			assert.Zero(t, f.approver.askedCount())
		})
	}

	t.Run("signer lost workflow:publish", func(t *testing.T) {
		f.publisher.holdsPerm.Store(false)
		defer f.publisher.holdsPerm.Store(true)

		_, err := f.start(t, revoked)

		require.ErrorIs(t, err, workflow.ErrScriptStepNotRestricted)
		assert.Zero(t, f.queued())
	})

	t.Run("caller names no version", func(t *testing.T) {
		exec, err := f.engine.ExecuteWorkflow(tenantCtx(), published.Workflow, nil)

		require.ErrorIs(t, err, workflow.ErrScriptStepNotRestricted)
		require.NotNil(t, exec)
		assert.Zero(t, f.queued())
	})

	t.Run("version names a different definition", func(t *testing.T) {
		// A verified Publication speaks only for the definition it signed.
		_, err := f.engine.ExecuteWorkflow(workflow.WithExecutingVersion(tenantCtx(), published), tampered.Workflow, nil)

		require.ErrorIs(t, err, workflow.ErrScriptStepNotRestricted)
		assert.Zero(t, f.queued())
	})
}

// [REQUIRED TEST] Editing a published workflow produces a version that cannot run its
// script steps outside a grant until it is published again.
func TestPublished_EditedVersionNeedsPublishingAgain(t *testing.T) {
	f := newPublishedFixture(t)
	v1 := twoScriptVersion(1)
	f.publisher.publish(t, rsRunTenant, v1)

	exec, err := f.start(t, v1)
	require.NoError(t, err)
	waitExecution(t, exec)
	require.Equal(t, workflow.StatusCompleted, exec.GetStatus(), exec.GetError())
	require.Equal(t, 2, f.queued())

	// The edit is stored as a new version: it carries no Publication.
	v2 := twoScriptVersion(2)
	v2.Steps = append(v2.Steps, publishedStep("again", "inventory"))
	_, err = f.start(t, v2)
	require.ErrorIs(t, err, workflow.ErrScriptStepNotRestricted)

	f.publisher.publish(t, rsRunTenant, v2)
	exec, err = f.start(t, v2)
	require.NoError(t, err)
	waitExecution(t, exec)
	assert.Equal(t, workflow.StatusCompleted, exec.GetStatus(), exec.GetError())
}

// [REQUIRED TEST] In a non-restricted execution, a script step with an empty version,
// with SecretBindings, or with a fleet filter naming another tenant is refused, with
// nothing queued.
func TestPublished_StepRefusals(t *testing.T) {
	f := newPublishedFixture(t)
	f.put(t, "client-2", "inventory", "echo other\n")

	filterOf := func(m map[string]interface{}) map[string]interface{} { return m }
	cases := map[string]map[string]interface{}{
		"empty version": {
			"script_id": "inventory", "device_filter": filterOf(map[string]interface{}{"status": "online"}),
		},
		"secret bindings": {
			"script_id": "inventory", "script_version": "1.0.0", "device_filter": filterOf(map[string]interface{}{"status": "online"}),
			"secret_bindings": []interface{}{map[string]interface{}{"name": "TOKEN", "from": "secret", "key": "api-token"}},
		},
		"filter naming another tenant": {
			"script_id": "inventory", "script_version": "1.0.0",
			"device_filter": filterOf(map[string]interface{}{"tenant_id": "client-2"}),
		},
		"no script id": {
			"script_version": "1.0.0", "device_filter": filterOf(map[string]interface{}{"status": "online"}),
		},
		"inline script": {
			"script_id": "inventory", "script_version": "1.0.0", "inline_script": "echo hi",
			"device_filter": filterOf(map[string]interface{}{"status": "online"}),
		},
		"version missing from the tenant's library": {
			"script_id": "inventory", "script_version": "9.9.9", "device_filter": filterOf(map[string]interface{}{"status": "online"}),
		},
		"script only in another tenant's library": {
			"script_id": "other-tenant-only", "script_version": "1.0.0", "device_filter": filterOf(map[string]interface{}{"status": "online"}),
		},
		"explicit device of another tenant": {
			"script_id": "inventory", "script_version": "1.0.0", "devices": []interface{}{"dev-of-client-2"},
		},
	}
	executor := NewScriptStepExecutor(f.repo, f.monitor, nil)
	executor.SetExecutionQueue(f.queue)
	executor.SetFleetQuery(fleetOf(map[string]string{rsDevice: rsRunTenant, "dev-of-client-2": "client-2"}))

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			exec := &workflow.WorkflowExecution{
				ID: "exec-1", TenantID: rsRunTenant, PublicationVerified: true,
				StepResults: map[string]workflow.StepResult{}, Variables: map[string]interface{}{}, Done: make(chan struct{}),
			}

			res, err := executor.ExecuteStep(context.Background(), workflow.Step{Name: "collect", Type: workflow.StepTypeScript, Config: cfg}, exec)

			require.Error(t, err)
			assert.Equal(t, workflow.StatusFailed, res.Status)
			assert.Zero(t, f.queued(), "a refused step leaves nothing queued")
			assert.Empty(t, f.monitor.ListExecutions(""), "no execution was started")
		})
	}
}

// The library script is resolved from the execution's tenant, never from the step:
// a tenant named in the step's filter or a script that exists only in another
// tenant's library does not run.
func TestPublished_LibraryIsTheExecutionTenants(t *testing.T) {
	f := newPublishedFixture(t)
	f.put(t, "client-2", "other-only", "echo other\n")
	vw := &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{Name: "cross", Steps: []workflow.Step{publishedStep("collect", "other-only")}},
	}
	f.publisher.publish(t, rsRunTenant, vw)

	exec, err := f.start(t, vw)
	require.NoError(t, err)
	waitExecution(t, exec)

	assert.Equal(t, workflow.StatusFailed, exec.GetStatus())
	assert.Contains(t, exec.GetError(), "could not be read from the tenant's library")
	assert.Zero(t, f.queued())
}

// [REQUIRED TEST] A restricted (grant) execution still goes through the approval
// evaluator: a Publication alone does not let a grant run an unapproved script.
func TestPublished_GrantStillNeedsApproval(t *testing.T) {
	f := newPublishedFixture(t)
	f.put(t, rsOwnerTenant, "inventory", "echo inventory\n")
	f.approver.state = workflow.ScriptApprovalPending
	vw := &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{Name: "grant-run", Steps: []workflow.Step{{
			Name: "collect", Type: workflow.StepTypeScript, Config: map[string]interface{}{
				"script_id": "inventory", "script_version": "1.0.0", "devices": []interface{}{rsDevice},
			},
		}}},
	}
	f.publisher.publish(t, rsRunTenant, vw)

	// The caller names the published version, as a grant run's caller might.
	ctx := workflow.WithExecutingVersion(tenantCtx(), vw)
	exec, err := f.engine.ExecuteRestrictedWorkflow(ctx, vw.Workflow, nil,
		workflow.RestrictedRun{RunID: "run-1", GrantID: "grant-1", Ceiling: rsOwnerTenant})
	require.NoError(t, err)
	waitExecution(t, exec)

	assert.Equal(t, workflow.StatusFailed, exec.GetStatus())
	assert.Contains(t, exec.GetError(), "pending approval")
	assert.False(t, exec.PublicationVerified, "a restricted run never takes the publication path")
	assert.Equal(t, 1, f.approver.askedCount(), "the approval evaluator decided")
	assert.Zero(t, f.queued())

	// The node of a restricted execution also ignores the flag when it is set.
	res, err := f.executor().ExecuteStep(context.Background(), vw.Steps[0], &workflow.WorkflowExecution{
		ID: "exec-2", TenantID: rsRunTenant, PublicationVerified: true,
		Restricted:  &workflow.RestrictedRun{RunID: "run-1", GrantID: "grant-1", Ceiling: rsOwnerTenant},
		StepResults: map[string]workflow.StepResult{}, Variables: map[string]interface{}{}, Done: make(chan struct{}),
	})
	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, res.Status)
	assert.Equal(t, 2, f.approver.askedCount())
	assert.Zero(t, f.queued())
}

// A published step queues the library version it read, pinned by content hash: a
// version edited after the step queued never reaches the steward.
func TestPublished_QueuedCommandIsPinnedToTheVersionRead(t *testing.T) {
	f := newPublishedFixture(t)
	vw := &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{Name: "pinned", Steps: []workflow.Step{publishedStep("collect", "inventory")}},
	}
	f.publisher.publish(t, rsRunTenant, vw)

	exec, err := f.start(t, vw)
	require.NoError(t, err)
	waitExecution(t, exec)
	require.Equal(t, workflow.StatusCompleted, exec.GetStatus(), exec.GetError())
	require.Equal(t, 1, f.queued())

	f.replace(t, rsRunTenant, "inventory", "echo tampered\n")

	entries, err := f.queue.DequeueForDevice(rsDevice)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	_, err = f.queue.PrepareExecutionForDevice(context.Background(), rsDevice, rsRunTenant, entries[0])
	require.ErrorIs(t, err, script.ErrPinMismatch, "the edited script must not be delivered")
}
