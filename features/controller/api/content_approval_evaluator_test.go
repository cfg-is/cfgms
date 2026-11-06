// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const (
	evalMSP    = "msp"
	evalClient = "msp/client-1"
	evalOther  = "msp/client-2"

	requestedBody = "#!/bin/bash\n# cfgms-preapproved: automation\necho hello\n"
	silentBody    = "#!/bin/bash\necho hello\n"
)

// evalSigner is a real generated signing key.
type evalSigner struct {
	key        *ecdsa.PrivateKey
	pemKey     string
	thumbprint string
}

func newEvalSigner(t *testing.T) evalSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(der)
	return evalSigner{
		key:        k,
		pemKey:     string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		thumbprint: hex.EncodeToString(sum[:]),
	}
}

func (s evalSigner) sign(t *testing.T, content string) *script.ScriptSignature {
	t.Helper()
	h := sha256.Sum256([]byte(content))
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	require.NoError(t, err)
	return &script.ScriptSignature{Algorithm: "ecdsa-sha256", Signature: base64.StdEncoding.EncodeToString(sig), PublicKey: s.pemKey}
}

func (s evalSigner) entry() script.TrustedKeyEntry {
	return script.TrustedKeyEntry{Name: "k", Thumbprint: s.thumbprint}
}

// countingConfigStore counts the writes made through it.
type countingConfigStore struct {
	cfgconfig.ConfigStore
	writes atomic.Int64
}

func (c *countingConfigStore) StoreConfig(ctx context.Context, e *cfgconfig.ConfigEntry) error {
	c.writes.Add(1)
	return c.ConfigStore.StoreConfig(ctx, e)
}

func (c *countingConfigStore) DeleteConfig(ctx context.Context, k *cfgconfig.ConfigKey) error {
	c.writes.Add(1)
	return c.ConfigStore.DeleteConfig(ctx, k)
}

// namespaceFailStore fails reads in one namespace only.
type namespaceFailStore struct {
	cfgconfig.ConfigStore
	namespace string
}

func (n namespaceFailStore) GetConfig(ctx context.Context, k *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	if k.Namespace == n.namespace {
		return nil, errors.New("backend unavailable")
	}
	return n.ConfigStore.GetConfig(ctx, k)
}

type evalEnv struct {
	t     *testing.T
	cs    *countingConfigStore
	store *ContentApprovalStore
	repo  *script.TenantScriptRepository
	keys  map[string][]script.TrustedKeyEntry
	ev    *ContentApprovalEvaluator
}

func newEvalEnv(t *testing.T) *evalEnv {
	t.Helper()
	_, raw := newApprovalStore(t)
	cs := &countingConfigStore{ConfigStore: raw}
	store, err := NewContentApprovalStore(cs)
	require.NoError(t, err)
	repo, err := script.NewTenantScriptRepository(cs)
	require.NoError(t, err)
	env := &evalEnv{t: t, cs: cs, store: store, repo: repo, keys: map[string][]script.TrustedKeyEntry{}}
	env.ev, err = NewContentApprovalEvaluator(store, env.resolveKeys, cs)
	require.NoError(t, err)
	return env
}

func (e *evalEnv) resolveKeys(_ context.Context, tenant string) ([]script.TrustedKeyEntry, error) {
	return e.keys[tenant], nil
}

// publish stores a script in the tenant's library and returns it as resolved.
func (e *evalEnv) publish(tenant, id, content string, sig *script.ScriptSignature) *script.VersionedScript {
	e.t.Helper()
	r, err := e.repo.ForTenant(tenant)
	require.NoError(e.t, err)
	require.NoError(e.t, r.Create(&script.VersionedScript{
		Metadata: &script.ScriptMetadata{
			ID: id, Name: id, Description: "d", Version: &script.Version{Major: 1}, Author: "a",
			Platform: []string{"linux"}, Shell: script.ShellBash, Timeout: time.Minute,
			Parameters: []script.ScriptParameter{{Name: "p", Type: "string", AllowedValues: []string{"a"}}},
		},
		Content: content, Signature: sig,
	}))
	vs, err := e.repo.GetForTenant(tenant, id, "1.0.0")
	require.NoError(e.t, err)
	return vs
}

func (e *evalEnv) setMode(tenant string, m ApprovalMode) {
	e.t.Helper()
	require.NoError(e.t, e.store.SetMode(context.Background(), tenant, LibraryKindScript, m, "admin"))
}

func (e *evalEnv) approve(tenant string, vs *script.VersionedScript) {
	e.t.Helper()
	require.NoError(e.t, e.store.PutApproval(context.Background(), ContentApproval{
		TenantID: tenant, Kind: LibraryKindScript, ContentID: vs.Metadata.ID, Version: vs.Metadata.Version.String(),
		ContentHash: script.ScriptApprovalHash(tenant, vs), ApprovedBy: "admin", Method: ApprovalMethodApproveTap,
	}))
}

func (e *evalEnv) eval(run string, vs *script.VersionedScript, owner string) Decision {
	e.t.Helper()
	d, err := e.ev.Evaluate(context.Background(), run, vs, owner)
	require.NoError(e.t, err)
	return d
}

func TestContentApprovalEvaluator_ModeTable(t *testing.T) {
	signer := newEvalSigner(t)
	other := newEvalSigner(t)

	cases := []struct {
		name    string
		mode    ApprovalMode
		keys    []script.TrustedKeyEntry
		body    string
		sign    func(*testing.T, string) *script.ScriptSignature
		approve bool
		want    ContentDecisionState
		method  ApprovalMethod
	}{
		{"signed valid signature", ApprovalModeSigned, []script.TrustedKeyEntry{signer.entry()}, requestedBody, signer.sign, false, ContentDecisionApproved, ApprovalMethodSignature},
		{"signed unsigned falls to approve, no record", ApprovalModeSigned, []script.TrustedKeyEntry{signer.entry()}, requestedBody, nil, false, ContentDecisionPending, ""},
		{"signed unsigned falls to approve, record", ApprovalModeSigned, []script.TrustedKeyEntry{signer.entry()}, requestedBody, nil, true, ContentDecisionApproved, ApprovalMethodApproveTap},
		{"signed no trusted keys falls to approve", ApprovalModeSigned, nil, requestedBody, signer.sign, false, ContentDecisionPending, ""},
		{"signed invalid signature", ApprovalModeSigned, []script.TrustedKeyEntry{signer.entry()}, requestedBody,
			func(t *testing.T, c string) *script.ScriptSignature { return signer.sign(t, c+"tampered") }, true, ContentDecisionDenied, ""},
		{"signed untrusted key", ApprovalModeSigned, []script.TrustedKeyEntry{signer.entry()}, requestedBody, other.sign, true, ContentDecisionDenied, ""},
		{"approve matching record", ApprovalModeApprove, nil, requestedBody, nil, true, ContentDecisionApproved, ApprovalMethodApproveTap},
		{"approve no record", ApprovalModeApprove, nil, requestedBody, nil, false, ContentDecisionPending, ""},
		{"approve ignores a valid signature", ApprovalModeApprove, []script.TrustedKeyEntry{signer.entry()}, requestedBody, signer.sign, false, ContentDecisionPending, ""},
		{"comment declared", ApprovalModeComment, nil, requestedBody, nil, false, ContentDecisionApproved, ApprovalMethodComment},
		{"comment not declared", ApprovalModeComment, nil, silentBody, nil, false, ContentDecisionPending, ""},
		{"approve not declared despite record", ApprovalModeApprove, nil, silentBody, nil, true, ContentDecisionPending, ""},
		{"signed valid signature not declared", ApprovalModeSigned, []script.TrustedKeyEntry{signer.entry()}, silentBody, signer.sign, false, ContentDecisionPending, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := newEvalEnv(t)
			env.setMode(evalMSP, c.mode)
			env.keys[evalMSP] = c.keys
			var sig *script.ScriptSignature
			if c.sign != nil {
				sig = c.sign(t, c.body)
			}
			vs := env.publish(evalMSP, "s1", c.body, sig)
			if c.approve {
				env.approve(evalMSP, vs)
			}
			d := env.eval(evalMSP, vs, evalMSP)
			assert.Equal(t, c.want, d.State, d.Reason)
			assert.Equal(t, c.method, d.Method)
			assert.NotEmpty(t, d.Reason)
			assert.Equal(t, evalMSP, d.OwnerTenant)
			assert.Equal(t, vs.Hash, d.ContentHash)
			assert.Equal(t, script.ScriptApprovalHash(evalMSP, vs), d.ApprovalHash)
		})
	}
}

func TestContentApprovalEvaluator_DefaultModeIsSigned(t *testing.T) {
	env := newEvalEnv(t)
	signer := newEvalSigner(t)
	env.keys[evalMSP] = []script.TrustedKeyEntry{signer.entry()}
	vs := env.publish(evalMSP, "s1", requestedBody, signer.sign(t, requestedBody))
	assert.Equal(t, ContentDecisionApproved, env.eval(evalMSP, vs, evalMSP).State)
}

func TestContentApprovalEvaluator_SignatureWithoutDetachedMaterialIsUnsigned(t *testing.T) {
	env := newEvalEnv(t)
	signer := newEvalSigner(t)
	env.keys[evalMSP] = []script.TrustedKeyEntry{signer.entry()}
	vs := env.publish(evalMSP, "s1", requestedBody, nil)
	vs.Signature = &script.ScriptSignature{Thumbprint: signer.thumbprint}
	d := env.eval(evalMSP, vs, evalMSP)
	assert.Equal(t, ContentDecisionPending, d.State, "no detached material is unsigned, not a bad signature")
}

func TestContentApprovalEvaluator_PresentButUnverifiableSignatureIsDenied(t *testing.T) {
	env := newEvalEnv(t)
	signer := newEvalSigner(t)
	env.keys[evalMSP] = []script.TrustedKeyEntry{signer.entry()}
	vs := env.publish(evalMSP, "s1", requestedBody, signer.sign(t, requestedBody))
	env.approve(evalMSP, vs)
	vs.Signature.Signature = "!!!not base64!!!" // the verifier errors rather than reporting a mismatch
	d := env.eval(evalMSP, vs, evalMSP)
	assert.Equal(t, ContentDecisionDenied, d.State, "a verifier error is not a fallback to the record")
}

func TestContentApprovalEvaluator_NeverApprovesWithoutHeaderRequest(t *testing.T) {
	signer := newEvalSigner(t)
	for _, mode := range []ApprovalMode{ApprovalModeSigned, ApprovalModeApprove, ApprovalModeComment} {
		t.Run(string(mode), func(t *testing.T) {
			env := newEvalEnv(t)
			env.setMode(evalMSP, mode)
			env.keys[evalMSP] = []script.TrustedKeyEntry{signer.entry()}
			vs := env.publish(evalMSP, "s1", silentBody, signer.sign(t, silentBody))
			env.approve(evalMSP, vs)
			assert.NotEqual(t, ContentDecisionApproved, env.eval(evalMSP, vs, evalMSP).State)
		})
	}
}

func TestContentApprovalEvaluator_MalformedHeaderIsDenied(t *testing.T) {
	env := newEvalEnv(t)
	env.setMode(evalMSP, ApprovalModeComment)
	vs := env.publish(evalMSP, "s1", "#!/bin/bash\n# cfgms-preapprove: automation\necho x\n", nil)
	assert.Equal(t, ContentDecisionDenied, env.eval(evalMSP, vs, evalMSP).State)
}

func TestContentApprovalEvaluator_EvaluateWritesAndSendsNothing(t *testing.T) {
	signer := newEvalSigner(t)
	for _, mode := range []ApprovalMode{ApprovalModeSigned, ApprovalModeApprove, ApprovalModeComment} {
		env := newEvalEnv(t)
		env.setMode(evalMSP, mode)
		env.keys[evalMSP] = []script.TrustedKeyEntry{signer.entry()}
		vs := env.publish(evalMSP, "s1", requestedBody, nil)
		before := env.cs.writes.Load()
		for i := 0; i < 3; i++ {
			env.eval(evalMSP, vs, evalMSP)
		}
		assert.Equal(t, before, env.cs.writes.Load(), "mode %s: Evaluate must not write", mode)
		pending, err := env.store.ListApprovals(context.Background(), evalMSP, LibraryKindScript)
		require.NoError(t, err)
		assert.Empty(t, pending, "Evaluate must not record an approval")
	}
	// The evaluator has no notifier or queue dependency at all.
	assert.NotContains(t, readEvaluatorSource(t), "notif")
}

func TestContentApprovalEvaluator_ContentChangedAfterApprovalIsPending(t *testing.T) {
	env := newEvalEnv(t)
	env.setMode(evalMSP, ApprovalModeApprove)
	vs := env.publish(evalMSP, "s1", requestedBody, nil)
	env.approve(evalMSP, vs)
	require.Equal(t, ContentDecisionApproved, env.eval(evalMSP, vs, evalMSP).State)

	changed := *vs
	changed.Content = requestedBody + "echo more\n"
	sum := sha256.Sum256([]byte(changed.Content))
	changed.Hash = hex.EncodeToString(sum[:])
	assert.NotEqual(t, script.ScriptApprovalHash(evalMSP, vs), script.ScriptApprovalHash(evalMSP, &changed))
	d := env.eval(evalMSP, &changed, evalMSP)
	assert.Equal(t, ContentDecisionPending, d.State, "the old record must not approve changed content")
}

func TestContentApprovalEvaluator_ExecutionSettingsChangeAfterApprovalIsPending(t *testing.T) {
	mutations := map[string]func(*script.VersionedScript){
		"shell":          func(v *script.VersionedScript) { v.Metadata.Shell = script.ShellSh },
		"timeout":        func(v *script.VersionedScript) { v.Metadata.Timeout = 2 * time.Hour },
		"allowed values": func(v *script.VersionedScript) { v.Metadata.Parameters[0].AllowedValues = []string{"a", "b"} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			env := newEvalEnv(t)
			env.setMode(evalMSP, ApprovalModeApprove)
			vs := env.publish(evalMSP, "s1", requestedBody, nil)
			env.approve(evalMSP, vs)
			require.Equal(t, ContentDecisionApproved, env.eval(evalMSP, vs, evalMSP).State)

			again, err := env.repo.GetForTenant(evalMSP, "s1", "1.0.0")
			require.NoError(t, err)
			mutate(again)
			assert.Equal(t, ContentDecisionPending, env.eval(evalMSP, again, evalMSP).State)
		})
	}
}

func TestContentApprovalEvaluator_HashMismatchIsDenied(t *testing.T) {
	env := newEvalEnv(t)
	env.setMode(evalMSP, ApprovalModeComment)
	vs := env.publish(evalMSP, "s1", requestedBody, nil)
	vs.Content += "echo injected\n" // content no longer matches the stored hash
	d := env.eval(evalMSP, vs, evalMSP)
	assert.Equal(t, ContentDecisionDenied, d.State)

	vs2 := env.publish(evalMSP, "s2", requestedBody, nil)
	vs2.Hash = strings.Repeat("0", 64)
	assert.Equal(t, ContentDecisionDenied, env.eval(evalMSP, vs2, evalMSP).State)
}

func TestContentApprovalEvaluator_FailsClosed(t *testing.T) {
	signer := newEvalSigner(t)
	ctx := context.Background()

	t.Run("mode read failure", func(t *testing.T) {
		env := newEvalEnv(t)
		vs := env.publish(evalMSP, "s1", requestedBody, nil)
		failing, err := NewContentApprovalStore(approvalReadFailStore{env.cs})
		require.NoError(t, err)
		ev, err := NewContentApprovalEvaluator(failing, env.resolveKeys, env.cs)
		require.NoError(t, err)
		d, err := ev.Evaluate(ctx, evalMSP, vs, evalMSP)
		require.Error(t, err)
		assert.Equal(t, ContentDecisionDenied, d.State)
	})
	t.Run("corrupt stored mode", func(t *testing.T) {
		env := newEvalEnv(t)
		vs := env.publish(evalMSP, "s1", requestedBody, nil)
		require.NoError(t, env.cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
			Key: modeKey(evalMSP, LibraryKindScript), Data: []byte(`{"mode":"yes"}`), Format: cfgconfig.ConfigFormatJSON, Checksum: "x",
		}))
		d, err := env.ev.Evaluate(ctx, evalMSP, vs, evalMSP)
		require.Error(t, err)
		assert.Equal(t, ContentDecisionDenied, d.State)
	})
	t.Run("trusted key resolution failure", func(t *testing.T) {
		env := newEvalEnv(t)
		vs := env.publish(evalMSP, "s1", requestedBody, signer.sign(t, requestedBody))
		env.approve(evalMSP, vs)
		ev, err := NewContentApprovalEvaluator(env.store, func(context.Context, string) ([]script.TrustedKeyEntry, error) {
			return nil, errors.New("config service down")
		}, env.cs)
		require.NoError(t, err)
		d, err := ev.Evaluate(ctx, evalMSP, vs, evalMSP)
		require.Error(t, err)
		assert.Equal(t, ContentDecisionDenied, d.State, "must not fall back to the approval record")
	})
	t.Run("run tenant key resolution failure", func(t *testing.T) {
		env := newEvalEnv(t)
		env.keys[evalMSP] = []script.TrustedKeyEntry{signer.entry()}
		vs := env.publish(evalMSP, "s1", requestedBody, signer.sign(t, requestedBody))
		ev, err := NewContentApprovalEvaluator(env.store, func(_ context.Context, tenant string) ([]script.TrustedKeyEntry, error) {
			if tenant == evalClient {
				return nil, errors.New("config service down")
			}
			return env.keys[tenant], nil
		}, env.cs)
		require.NoError(t, err)
		d, err := ev.Evaluate(ctx, evalClient, vs, evalMSP)
		require.Error(t, err)
		assert.Equal(t, ContentDecisionDenied, d.State)
	})
	t.Run("approval repository error", func(t *testing.T) {
		env := newEvalEnv(t)
		env.setMode(evalMSP, ApprovalModeApprove)
		vs := env.publish(evalMSP, "s1", requestedBody, nil)
		env.approve(evalMSP, vs)
		failing, err := NewContentApprovalStore(namespaceFailStore{env.cs, contentApprovalNamespace})
		require.NoError(t, err)
		ev, err := NewContentApprovalEvaluator(failing, env.resolveKeys, env.cs)
		require.NoError(t, err)
		d, err := ev.Evaluate(ctx, evalMSP, vs, evalMSP)
		require.Error(t, err)
		assert.Equal(t, ContentDecisionDenied, d.State)
	})
	t.Run("privilege metadata read failure", func(t *testing.T) {
		env := newEvalEnv(t)
		env.setMode(evalMSP, ApprovalModeComment)
		vs := env.publish(evalMSP, "s1", requestedBody, nil)
		ev, err := NewContentApprovalEvaluator(env.store, env.resolveKeys, namespaceFailStore{env.cs, privilegeNamespace})
		require.NoError(t, err)
		d, err := ev.Evaluate(ctx, evalMSP, vs, evalMSP)
		require.Error(t, err)
		assert.Equal(t, ContentDecisionDenied, d.State)
	})
	t.Run("incomplete input", func(t *testing.T) {
		env := newEvalEnv(t)
		vs := env.publish(evalMSP, "s1", requestedBody, nil)
		for _, c := range []struct {
			run, owner string
			vs         *script.VersionedScript
		}{{"", evalMSP, vs}, {evalMSP, "", vs}, {evalMSP, evalMSP, nil}, {evalMSP, evalMSP, &script.VersionedScript{}}} {
			d, err := env.ev.Evaluate(ctx, c.run, c.vs, c.owner)
			require.Error(t, err)
			assert.Equal(t, ContentDecisionDenied, d.State)
		}
	})
	t.Run("constructor requires dependencies", func(t *testing.T) {
		env := newEvalEnv(t)
		_, err := NewContentApprovalEvaluator(nil, env.resolveKeys, env.cs)
		assert.Error(t, err)
		_, err = NewContentApprovalEvaluator(env.store, nil, env.cs)
		assert.Error(t, err)
		_, err = NewContentApprovalEvaluator(env.store, env.resolveKeys, nil)
		assert.Error(t, err)
	})
}

func TestContentApprovalEvaluator_ShadowingCopyGetsNoApprovalFromParent(t *testing.T) {
	env := newEvalEnv(t)
	env.setMode(evalMSP, ApprovalModeApprove)
	env.setMode(evalClient, ApprovalModeApprove)
	msp := env.publish(evalMSP, "s1", requestedBody, nil)
	env.approve(evalMSP, msp)
	child := env.publish(evalClient, "s1", requestedBody, nil)

	require.Equal(t, msp.Hash, child.Hash, "same id, version and content")
	assert.Equal(t, ContentDecisionApproved, env.eval(evalClient, msp, evalMSP).State)
	d := env.eval(evalClient, child, evalClient)
	assert.Equal(t, ContentDecisionPending, d.State, "the child copy is judged under its own owner's records")
	assert.Equal(t, evalClient, d.OwnerTenant)
}

func TestContentApprovalEvaluator_ModeAndKeysAreTheOwners(t *testing.T) {
	signer := newEvalSigner(t)
	env := newEvalEnv(t)
	env.setMode(evalMSP, ApprovalModeApprove)
	env.setMode(evalClient, ApprovalModeComment)
	vs := env.publish(evalMSP, "s1", requestedBody, nil)
	d := env.eval(evalClient, vs, evalMSP)
	assert.Equal(t, ContentDecisionPending, d.State, "the run tenant's comment mode does not approve an MSP script")
	assert.Equal(t, evalMSP, d.OwnerTenant)

	env.keys[evalClient] = []script.TrustedKeyEntry{signer.entry()}
	signed := env.publish(evalMSP, "s2", requestedBody, signer.sign(t, requestedBody))
	env.setMode(evalMSP, ApprovalModeSigned)
	env.keys[evalMSP] = nil
	assert.Equal(t, ContentDecisionPending, env.eval(evalClient, signed, evalMSP).State,
		"the owner has no trusted keys, so the run tenant's keys do not make it a signed approval")
}

func TestContentApprovalEvaluator_SignedNeedsOwnerAndRunTenantKeys(t *testing.T) {
	a, b := newEvalSigner(t), newEvalSigner(t)
	cases := []struct {
		name         string
		owner, run   []script.TrustedKeyEntry
		runTenant    string
		want         ContentDecisionState
		wantApproved bool
	}{
		{"run tenant has no keys", []script.TrustedKeyEntry{a.entry()}, nil, evalClient, ContentDecisionApproved, true},
		{"run tenant trusts the key", []script.TrustedKeyEntry{a.entry()}, []script.TrustedKeyEntry{a.entry(), b.entry()}, evalClient, ContentDecisionApproved, true},
		{"run tenant narrowed to another key", []script.TrustedKeyEntry{a.entry()}, []script.TrustedKeyEntry{b.entry()}, evalClient, ContentDecisionDenied, false},
		{"owner is the run tenant", []script.TrustedKeyEntry{a.entry()}, []script.TrustedKeyEntry{a.entry()}, evalMSP, ContentDecisionApproved, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := newEvalEnv(t)
			env.keys[evalMSP] = c.owner
			env.keys[c.runTenant] = c.run
			if c.runTenant == evalMSP {
				env.keys[evalMSP] = c.owner
			}
			vs := env.publish(evalMSP, "s1", requestedBody, a.sign(t, requestedBody))
			d := env.eval(c.runTenant, vs, evalMSP)
			assert.Equal(t, c.want, d.State, d.Reason)
			assert.Equal(t, c.wantApproved, d.State == ContentDecisionApproved)
		})
	}
}

func TestContentApprovalEvaluator_RequiredAPIScopeIsDeniedForAutomation(t *testing.T) {
	for _, mode := range []ApprovalMode{ApprovalModeSigned, ApprovalModeApprove, ApprovalModeComment} {
		env := newEvalEnv(t)
		env.setMode(evalMSP, mode)
		vs := env.publish(evalMSP, "s1", requestedBody, nil)
		env.approve(evalMSP, vs)

		meta, err := json.Marshal(ScriptPrivilegeMetadata{ScriptID: "s1", RequiredAPIScope: []string{"steward:read-scripts"}})
		require.NoError(t, err)
		require.NoError(t, env.cs.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
			Key:  &cfgconfig.ConfigKey{TenantID: evalMSP, Namespace: privilegeNamespace, Name: "s1"},
			Data: meta, Format: cfgconfig.ConfigFormatJSON, Checksum: "x",
		}))
		assert.Equal(t, ContentDecisionDenied, env.eval(evalMSP, vs, evalMSP).State, "mode %s", mode)
	}

	// An empty scope list is no scope; another tenant's metadata is not read.
	env := newEvalEnv(t)
	env.setMode(evalMSP, ApprovalModeComment)
	vs := env.publish(evalMSP, "s1", requestedBody, nil)
	meta, err := json.Marshal(ScriptPrivilegeMetadata{ScriptID: "s1", RequiredAPIScope: []string{"x"}})
	require.NoError(t, err)
	require.NoError(t, env.cs.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key:  &cfgconfig.ConfigKey{TenantID: evalOther, Namespace: privilegeNamespace, Name: "s1"},
		Data: meta, Format: cfgconfig.ConfigFormatJSON, Checksum: "x",
	}))
	assert.Equal(t, ContentDecisionApproved, env.eval(evalMSP, vs, evalMSP).State)
}

func TestTrustedKeyEntries(t *testing.T) {
	refs := []stewardtypes.TrustedKeyRef{
		{Name: "a", Thumbprint: "AA"},
		{Name: "ref-only", PublicKeyRef: "secret://k"},
		{Name: "b", Thumbprint: "BB", PublicKeyRef: "secret://b"},
	}
	for _, mode := range []stewardtypes.ScriptTrustMode{stewardtypes.TrustModeTrustedKeys, stewardtypes.TrustModeTrustedKeysAndPublic} {
		got := trustedKeyEntries(stewardtypes.ScriptSigningConfig{TrustMode: mode, TrustedKeys: refs, AllowPublicCA: true})
		require.Len(t, got, 2, "mode %s: only entries with a thumbprint count", mode)
		assert.Equal(t, "AA", got[0].Thumbprint)
		assert.Equal(t, "BB", got[1].Thumbprint)
		assert.Empty(t, got[1].PublicKeyRef)
	}
	for _, mode := range []stewardtypes.ScriptTrustMode{stewardtypes.TrustModeAnyValid, "", "bogus"} {
		assert.Empty(t, trustedKeyEntries(stewardtypes.ScriptSigningConfig{TrustMode: mode, TrustedKeys: refs}), "mode %q", mode)
	}
	assert.Empty(t, trustedKeyEntries(stewardtypes.ScriptSigningConfig{TrustMode: stewardtypes.TrustModeTrustedKeys}))
	assert.Empty(t, trustedKeyEntries(stewardtypes.ScriptSigningConfig{
		TrustMode: stewardtypes.TrustModeTrustedKeys, TrustedKeys: []stewardtypes.TrustedKeyRef{{Name: "x", PublicKeyRef: "r"}},
	}))
}

func TestConfigServiceTrustedKeyResolver(t *testing.T) {
	server := setupTestServer(t)
	resolve := NewConfigServiceTrustedKeyResolver(server.configService)
	keys, err := resolve(context.Background(), testRootTenantID)
	require.NoError(t, err)
	assert.Empty(t, keys, "a tenant that declares no script_signing has no trusted keys")

	_, err = NewConfigServiceTrustedKeyResolver(nil)(context.Background(), testRootTenantID)
	assert.Error(t, err, "an unavailable configuration service fails closed")
}

func readEvaluatorSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("content_approval_evaluator.go")
	require.NoError(t, err)
	return string(b)
}

func TestContentApprovalEvaluator_UsesTheStewardVerifierOnly(t *testing.T) {
	src := readEvaluatorSource(t)
	assert.Contains(t, src, "script.VerifyScriptSignature(")
	for _, banned := range []string{"VerifyPKCS1v15", "VerifyASN1", "x509.Parse", "pem.Decode", "TrustModeAnyValid"} {
		assert.NotContains(t, src, banned)
	}
}
