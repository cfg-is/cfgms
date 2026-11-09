// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Tests for ContentApprovalEvaluator.EvaluateWorkflow (ADR-036 section 4). They use
// a real WorkflowStore, the real publish ceremony and real generated signing keys.
package api

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/workflow"
)

const (
	wfOwner = publishTenant // the tenant the publish fixture stores workflows in
	wfChild = publishTenant + "/child"
	wfName  = "publish-wf"
)

type wfEvalEnv struct {
	*evalEnv
	f    *publishFixture
	next int
}

func newWFEvalEnv(t *testing.T) *wfEvalEnv {
	t.Helper()
	env := newEvalEnv(t)
	f := newPublishFixture(t)
	env.ev = env.ev.WithWorkflowPublicationVerifier(f.server.VerifyWorkflowPublication)
	return &wfEvalEnv{evalEnv: env, f: f}
}

func (e *wfEvalEnv) setWFMode(m ApprovalMode) {
	e.t.Helper()
	require.NoError(e.t, e.store.SetMode(context.Background(), wfOwner, LibraryKindWorkflow, m, "admin"))
}

// stage stores a fresh version of the workflow in the owner tenant and returns it
// as read back from the store.
func (e *wfEvalEnv) stage(optIn bool, sig func(hash string) *script.ScriptSignature) *workflow.VersionedWorkflow {
	e.t.Helper()
	e.next++
	version := fmt.Sprintf("1.0.%d", e.next)
	vw := publishTestWorkflow(version)
	vw.PreapprovedForAutomation = optIn
	if sig != nil {
		hash, err := workflow.CanonicalWorkflowHash(vw)
		require.NoError(e.t, err)
		vw.Signature = sig(hash)
	}
	require.NoError(e.t, e.f.store.StoreWorkflow(context.Background(), vw))
	return e.f.stored(e.t, version)
}

// stagePublished stores a version and publishes it with a real passkey ceremony.
func (e *wfEvalEnv) stagePublished(optIn bool) *workflow.VersionedWorkflow {
	e.t.Helper()
	vw := e.stage(optIn, nil)
	rec := e.f.publish(e.t, vw.SemanticVersion.String())
	require.Equal(e.t, 200, rec.Code, rec.Body.String())
	published := e.f.stored(e.t, vw.SemanticVersion.String())
	require.NotNil(e.t, published.Publication)
	return published
}

func (e *wfEvalEnv) approveWF(owner string, vw *workflow.VersionedWorkflow) {
	e.t.Helper()
	hash, err := workflow.CanonicalWorkflowHash(vw)
	require.NoError(e.t, err)
	require.NoError(e.t, e.store.PutApproval(context.Background(), ContentApproval{
		TenantID: owner, Kind: LibraryKindWorkflow, ContentID: vw.Name, Version: vw.SemanticVersion.String(),
		ContentHash: WorkflowApprovalHash(owner, vw.Name, vw.SemanticVersion.String(), hash),
		ApprovedBy:  "admin", Method: ApprovalMethodApproveTap,
	}))
}

func (e *wfEvalEnv) evalWF(run string, vw *workflow.VersionedWorkflow, owner string) Decision {
	e.t.Helper()
	d, err := e.ev.EvaluateWorkflow(context.Background(), run, vw, owner)
	require.NoError(e.t, err)
	return d
}

func signWorkflowWith(t *testing.T, s evalSigner) func(string) *script.ScriptSignature {
	return func(hash string) *script.ScriptSignature {
		return s.sign(t, string(workflow.WorkflowSignatureMessage(hash)))
	}
}

func TestEvaluateWorkflow_StateTable(t *testing.T) {
	signer := newEvalSigner(t)
	other := newEvalSigner(t)

	type tc struct {
		name     string
		mode     ApprovalMode
		keys     []script.TrustedKeyEntry
		build    func(e *wfEvalEnv) *workflow.VersionedWorkflow
		runTen   string
		state    ContentDecisionState
		method   ApprovalMethod
		awaiting bool
	}
	plain := func(optIn bool) func(e *wfEvalEnv) *workflow.VersionedWorkflow {
		return func(e *wfEvalEnv) *workflow.VersionedWorkflow { return e.stage(optIn, nil) }
	}
	approved := func(e *wfEvalEnv) *workflow.VersionedWorkflow {
		vw := e.stage(true, nil)
		e.approveWF(wfOwner, vw)
		return vw
	}
	signedBy := func(s evalSigner) func(e *wfEvalEnv) *workflow.VersionedWorkflow {
		return func(e *wfEvalEnv) *workflow.VersionedWorkflow { return e.stage(true, signWorkflowWith(t, s)) }
	}
	trusted := []script.TrustedKeyEntry{signer.entry()}

	var cases []tc
	for _, m := range []ApprovalMode{ApprovalModeSigned, ApprovalModeApprove, ApprovalModeComment} {
		cases = append(cases,
			tc{name: "published valid " + string(m), mode: m, keys: trusted,
				build: func(e *wfEvalEnv) *workflow.VersionedWorkflow { return e.stagePublished(true) },
				state: ContentDecisionApproved, method: ApprovalMethodWorkflowPublish},
			tc{name: "published valid without opt-in " + string(m), mode: m, keys: trusted,
				build: func(e *wfEvalEnv) *workflow.VersionedWorkflow { return e.stagePublished(false) },
				state: ContentDecisionPending},
			tc{name: "published invalid " + string(m), mode: m, keys: trusted,
				build: func(e *wfEvalEnv) *workflow.VersionedWorkflow {
					vw := e.stagePublished(true)
					vw.Steps[0].Name = "edited after publication"
					return vw
				},
				state: ContentDecisionDenied},
			tc{name: "unpublished without opt-in " + string(m), mode: m, keys: trusted,
				build: plain(false), state: ContentDecisionPending},
		)
	}
	cases = append(cases,
		tc{name: "comment with opt-in", mode: ApprovalModeComment, build: plain(true),
			state: ContentDecisionApproved, method: ApprovalMethodComment},
		tc{name: "approve without approval", mode: ApprovalModeApprove, build: plain(true),
			state: ContentDecisionPending, awaiting: true},
		tc{name: "approve with approval", mode: ApprovalModeApprove, build: approved,
			state: ContentDecisionApproved, method: ApprovalMethodApproveTap},
		tc{name: "signed trusted key", mode: ApprovalModeSigned, keys: trusted, build: signedBy(signer),
			state: ContentDecisionApproved, method: ApprovalMethodSignature},
		tc{name: "signed untrusted key", mode: ApprovalModeSigned, keys: trusted, build: signedBy(other),
			state: ContentDecisionDenied},
		tc{name: "signed unsigned falls back to approve, no approval", mode: ApprovalModeSigned, keys: trusted,
			build: plain(true), state: ContentDecisionPending, awaiting: true},
		tc{name: "signed unsigned falls back to approve, approved", mode: ApprovalModeSigned, keys: trusted,
			build: approved, state: ContentDecisionApproved, method: ApprovalMethodApproveTap},
		tc{name: "signed with no trusted keys falls back to approve", mode: ApprovalModeSigned,
			build: signedBy(signer), state: ContentDecisionPending, awaiting: true},
		tc{name: "signed by trusted owner key but run tenant trusts another", mode: ApprovalModeSigned, keys: trusted,
			build: signedBy(signer), runTen: wfChild, state: ContentDecisionDenied},
	)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := newWFEvalEnv(t)
			env.setWFMode(c.mode)
			env.keys[wfOwner] = c.keys
			if c.runTen == wfChild {
				env.keys[wfChild] = []script.TrustedKeyEntry{other.entry()}
			}
			vw := c.build(env)
			run := c.runTen
			if run == "" {
				run = wfOwner
			}
			d := env.evalWF(run, vw, wfOwner)
			assert.Equal(t, c.state, d.State, d.Reason)
			assert.Equal(t, c.method, d.Method)
			assert.Equal(t, c.awaiting, d.AwaitingApproval)
			assert.Equal(t, wfOwner, d.OwnerTenant)
			assert.NotEmpty(t, d.ContentHash)
			assert.NotEmpty(t, d.ApprovalHash)
		})
	}
}

func TestEvaluateWorkflow_EditAfterPublicationIsUnapproved(t *testing.T) {
	env := newWFEvalEnv(t)
	env.setWFMode(ApprovalModeApprove)
	vw := env.stagePublished(true)
	require.Equal(t, ContentDecisionApproved, env.evalWF(wfOwner, vw, wfOwner).State)

	// The edit is made in place and stored again under the same name and version.
	vw.Steps[0].Name = "edited"
	require.NoError(t, env.f.store.StoreWorkflow(context.Background(), vw))
	edited := env.f.stored(t, vw.SemanticVersion.String())
	require.NotNil(t, edited.Publication, "the stored Publication is still attached to the edited version")

	d := env.evalWF(wfOwner, edited, wfOwner)
	assert.Equal(t, ContentDecisionDenied, d.State)
	assert.NotEqual(t, ContentDecisionApproved, d.State)

	// Dropping the stale Publication does not help: the edit is unapproved.
	edited.Publication = nil
	d = env.evalWF(wfOwner, edited, wfOwner)
	assert.Equal(t, ContentDecisionPending, d.State)
	assert.True(t, d.AwaitingApproval)
}

func TestEvaluateWorkflow_OptInIsPartOfWhatPublicationCovers(t *testing.T) {
	env := newWFEvalEnv(t)
	vw := env.stagePublished(false)
	vw.PreapprovedForAutomation = true
	d := env.evalWF(wfOwner, vw, wfOwner)
	assert.Equal(t, ContentDecisionDenied, d.State, "flipping the opt-in after publication invalidates the publication")
}

func TestEvaluateWorkflow_CommentModeNeverApprovesWithoutOptIn(t *testing.T) {
	env := newWFEvalEnv(t)
	env.setWFMode(ApprovalModeComment)
	d := env.evalWF(wfOwner, env.stage(false, nil), wfOwner)
	assert.Equal(t, ContentDecisionPending, d.State)
	assert.False(t, d.AwaitingApproval, "an admin cannot resolve a missing opt-in by approving")
	assert.Empty(t, d.Method)
}

func TestEvaluateWorkflow_PublishedWithoutOptInIsNotApprovedInAnyMode(t *testing.T) {
	signer := newEvalSigner(t)
	env := newWFEvalEnv(t)
	env.keys[wfOwner] = []script.TrustedKeyEntry{signer.entry()}
	vw := env.stagePublished(false)
	env.approveWF(wfOwner, vw)
	for _, m := range []ApprovalMode{ApprovalModeSigned, ApprovalModeApprove, ApprovalModeComment} {
		env.setWFMode(m)
		d := env.evalWF(wfOwner, vw, wfOwner)
		assert.NotEqual(t, ContentDecisionApproved, d.State, "mode %s", m)
		assert.Equal(t, ContentDecisionPending, d.State, "mode %s", m)
	}
}

func TestEvaluateWorkflow_ScriptAndWorkflowSignaturesDoNotCrossVerify(t *testing.T) {
	signer := newEvalSigner(t)
	env := newWFEvalEnv(t)
	env.setWFMode(ApprovalModeSigned)
	env.keys[wfOwner] = []script.TrustedKeyEntry{signer.entry()}
	trust := script.ModuleSigningConfig{TrustMode: script.TrustModeTrustedKeys, TrustedKeys: []script.TrustedKeyEntry{signer.entry()}}

	base := env.stage(true, nil)
	hash, err := workflow.CanonicalWorkflowHash(base)
	require.NoError(t, err)
	canon, err := workflow.CanonicalWorkflowBytes(base)
	require.NoError(t, err)

	// Control: the key and the verifier are fine, a workflow signature is approved.
	wfSig := signer.sign(t, string(workflow.WorkflowSignatureMessage(hash)))
	signed := *base
	signed.Signature = wfSig
	assert.Equal(t, ContentDecisionApproved, env.evalWF(wfOwner, &signed, wfOwner).State)

	// A script signature (raw content, no prefix) over the same content bytes, and
	// over the bare hash, never approves a workflow.
	for name, content := range map[string]string{"canonical bytes": string(canon), "bare hash": hash} {
		forged := *base
		forged.Signature = signer.sign(t, content)
		d := env.evalWF(wfOwner, &forged, wfOwner)
		assert.Equal(t, ContentDecisionDenied, d.State, "script-style signature over the %s", name)
	}

	// A workflow signature never verifies as a script signature over the same
	// content bytes with the same key.
	assert.Error(t, script.VerifyScriptSignature(canon, wfSig, script.ShellBash, trust))
	assert.Error(t, script.VerifyScriptSignature([]byte(hash), wfSig, script.ShellBash, trust))
	assert.NoError(t, script.VerifyScriptSignature(workflow.WorkflowSignatureMessage(hash), wfSig, script.ShellBash, trust),
		"the signature is genuine; only the message differs")
	assert.Equal(t, workflow.WorkflowSignatureDomain+"\n"+hash, string(workflow.WorkflowSignatureMessage(hash)))
}

func TestEvaluateWorkflow_ChildCopyGetsNoApprovalFromOwnersRecord(t *testing.T) {
	env := newWFEvalEnv(t)
	for _, m := range []ApprovalMode{ApprovalModeApprove, ApprovalModeSigned} {
		env.setWFMode(m)
		vw := env.stage(true, nil)
		env.approveWF(wfOwner, vw)
		require.Equal(t, ContentDecisionApproved, env.evalWF(wfOwner, vw, wfOwner).State, "the owner's own record approves")

		// A child tenant stores the same name, version and content; it resolves to
		// the child as owner, so the MSP record does not apply.
		copied := *vw
		d := env.evalWF(wfChild, &copied, wfChild)
		assert.Equal(t, ContentDecisionPending, d.State, "mode %s", m)
		assert.True(t, d.AwaitingApproval)
		assert.NotEqual(t, env.evalWF(wfOwner, vw, wfOwner).ApprovalHash, d.ApprovalHash)
	}
}

func TestEvaluateWorkflow_ChildCopyOfPublishedVersionIsDenied(t *testing.T) {
	env := newWFEvalEnv(t)
	vw := env.stagePublished(true)
	copied := *vw
	d := env.evalWF(wfChild, &copied, wfChild)
	assert.Equal(t, ContentDecisionDenied, d.State, "the publication is bound to the tenant it was signed for")
}

func TestEvaluateWorkflow_ModeAndKeysAreTheOwners(t *testing.T) {
	signer := newEvalSigner(t)
	env := newWFEvalEnv(t)
	require.NoError(t, env.store.SetMode(context.Background(), wfChild, LibraryKindWorkflow, ApprovalModeComment, "admin"))
	env.setWFMode(ApprovalModeApprove)
	env.keys[wfChild] = []script.TrustedKeyEntry{signer.entry()}

	d := env.evalWF(wfChild, env.stage(true, nil), wfOwner)
	assert.Equal(t, ContentDecisionPending, d.State, "the run tenant's comment mode does not apply to the owner's workflow")
}

func TestEvaluateWorkflow_FailsClosed(t *testing.T) {
	ctx := context.Background()
	env := newWFEvalEnv(t)
	vw := env.stage(true, nil)
	published := env.stagePublished(true)

	t.Run("invalid input", func(t *testing.T) {
		for name, call := range map[string]func() (Decision, error){
			"no run tenant":   func() (Decision, error) { return env.ev.EvaluateWorkflow(ctx, "", vw, wfOwner) },
			"no owner tenant": func() (Decision, error) { return env.ev.EvaluateWorkflow(ctx, wfOwner, vw, "") },
			"nil workflow":    func() (Decision, error) { return env.ev.EvaluateWorkflow(ctx, wfOwner, nil, wfOwner) },
			"unnamed": func() (Decision, error) {
				return env.ev.EvaluateWorkflow(ctx, wfOwner, &workflow.VersionedWorkflow{}, wfOwner)
			},
		} {
			d, err := call()
			assert.Error(t, err, name)
			assert.Equal(t, ContentDecisionDenied, d.State, name)
		}
	})

	t.Run("mode unreadable", func(t *testing.T) {
		store, err := NewContentApprovalStore(namespaceFailStore{ConfigStore: env.cs, namespace: contentApprovalModeNamespace})
		require.NoError(t, err)
		ev, err := NewContentApprovalEvaluator(store, env.resolveKeys, env.cs)
		require.NoError(t, err)
		d, err := ev.EvaluateWorkflow(ctx, wfOwner, vw, wfOwner)
		assert.Error(t, err)
		assert.Equal(t, ContentDecisionDenied, d.State)
	})

	t.Run("approval unreadable", func(t *testing.T) {
		env.setWFMode(ApprovalModeApprove)
		store, err := NewContentApprovalStore(namespaceFailStore{ConfigStore: env.cs, namespace: contentApprovalNamespace})
		require.NoError(t, err)
		ev, err := NewContentApprovalEvaluator(store, env.resolveKeys, env.cs)
		require.NoError(t, err)
		d, err := ev.EvaluateWorkflow(ctx, wfOwner, vw, wfOwner)
		assert.Error(t, err)
		assert.Equal(t, ContentDecisionDenied, d.State)
	})

	t.Run("trusted keys unresolvable", func(t *testing.T) {
		env.setWFMode(ApprovalModeSigned)
		ev, err := NewContentApprovalEvaluator(env.store,
			func(context.Context, string) ([]script.TrustedKeyEntry, error) { return nil, errors.New("down") }, env.cs)
		require.NoError(t, err)
		d, err := ev.EvaluateWorkflow(ctx, wfOwner, vw, wfOwner)
		assert.Error(t, err)
		assert.Equal(t, ContentDecisionDenied, d.State)
	})

	t.Run("publication verifier not wired", func(t *testing.T) {
		env.setWFMode(ApprovalModeComment)
		ev, err := NewContentApprovalEvaluator(env.store, env.resolveKeys, env.cs)
		require.NoError(t, err)
		d, err := ev.EvaluateWorkflow(ctx, wfOwner, published, wfOwner)
		assert.Error(t, err)
		assert.Equal(t, ContentDecisionDenied, d.State)
	})

	t.Run("publication verifier refuses", func(t *testing.T) {
		env.setWFMode(ApprovalModeComment)
		ev, err := NewContentApprovalEvaluator(env.store, env.resolveKeys, env.cs)
		require.NoError(t, err)
		ev.WithWorkflowPublicationVerifier(func(context.Context, string, *workflow.VersionedWorkflow) error {
			return workflow.ErrPublicationInvalid
		})
		d, err := ev.EvaluateWorkflow(ctx, wfOwner, published, wfOwner)
		require.NoError(t, err)
		assert.Equal(t, ContentDecisionDenied, d.State)
	})

	t.Run("publication revoked with the signer", func(t *testing.T) {
		env.setWFMode(ApprovalModeComment)
		require.Equal(t, ContentDecisionApproved, env.evalWF(wfOwner, published, wfOwner).State)
		env.f.mutateAccount(t, func(a *account) { a.Disabled = true })
		assert.Equal(t, ContentDecisionDenied, env.evalWF(wfOwner, published, wfOwner).State)
	})
}

func TestEvaluateWorkflow_WritesAndSendsNothing(t *testing.T) {
	signer := newEvalSigner(t)
	env := newWFEvalEnv(t)
	env.keys[wfOwner] = []script.TrustedKeyEntry{signer.entry()}
	published := env.stagePublished(true)
	signed := env.stage(true, signWorkflowWith(t, signer))
	plain := env.stage(true, nil)

	before := env.cs.writes.Load()
	for _, m := range []ApprovalMode{ApprovalModeSigned, ApprovalModeApprove, ApprovalModeComment} {
		env.setWFMode(m)
		before++ // the SetMode above is the test's own write
		for _, vw := range []*workflow.VersionedWorkflow{published, signed, plain} {
			env.evalWF(wfOwner, vw, wfOwner)
			env.evalWF(wfChild, vw, wfChild)
		}
	}
	assert.Equal(t, before, env.cs.writes.Load(), "EvaluateWorkflow must not write to the config store")

	pending, err := env.store.ListApprovals(context.Background(), wfOwner, LibraryKindWorkflow)
	require.NoError(t, err)
	assert.Empty(t, pending, "evaluating records no approval")
}

func TestEvaluateWorkflow_SignedDecisionIsStableAcrossStorageRoundTrip(t *testing.T) {
	signer := newEvalSigner(t)
	env := newWFEvalEnv(t)
	env.setWFMode(ApprovalModeSigned)
	env.keys[wfOwner] = []script.TrustedKeyEntry{signer.entry()}
	vw := env.stage(true, signWorkflowWith(t, signer))
	require.NotNil(t, vw.Signature, "the detached signature survives the store")
	d := env.evalWF(wfOwner, vw, wfOwner)
	assert.Equal(t, ContentDecisionApproved, d.State, d.Reason)
	assert.Equal(t, ApprovalMethodSignature, d.Method)

	vw.Steps[0].Name = "edited"
	assert.Equal(t, ContentDecisionDenied, env.evalWF(wfOwner, vw, wfOwner).State, "an edit breaks the signature")
}
