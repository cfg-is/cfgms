// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	script "github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

const pinDevice = "steward-1"

// jsonRoundTripStore is a QueueStore that keeps entries exactly as a durable
// provider does: every entry crosses a JSON encode/decode on the way in and out,
// so only what survives serialization survives the store. Rebuilding a queue
// over the same value models a restart. (The shared PostgreSQL queue store needs
// a cluster database that the unit tier does not have.)
type jsonRoundTripStore struct {
	script.QueueStore
}

func roundTrip(e *script.QueueEntry) (*script.QueueEntry, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	out := &script.QueueEntry{}
	return out, json.Unmarshal(b, out)
}

func (s *jsonRoundTripStore) Enqueue(e *script.QueueEntry) error {
	c, err := roundTrip(e)
	if err != nil {
		return err
	}
	return s.QueueStore.Enqueue(c)
}

func (s *jsonRoundTripStore) copies(es []*script.QueueEntry, err error) ([]*script.QueueEntry, error) {
	if err != nil {
		return nil, err
	}
	out := make([]*script.QueueEntry, 0, len(es))
	for _, e := range es {
		c, err := roundTrip(e)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *jsonRoundTripStore) Dequeue(d string) ([]*script.QueueEntry, error) {
	return s.copies(s.QueueStore.Dequeue(d))
}

func (s *jsonRoundTripStore) List(d string) ([]*script.QueueEntry, error) {
	return s.copies(s.QueueStore.List(d))
}

type pinFixture struct {
	sm    *interfaces.StorageManager
	repo  *script.TenantScriptRepository
	store script.QueueStore
}

func newPinFixture(t *testing.T) *pinFixture {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	repo, err := script.NewTenantScriptRepository(sm.GetConfigStore())
	require.NoError(t, err)
	return &pinFixture{sm: sm, repo: repo, store: &jsonRoundTripStore{script.NewInMemoryQueueStore()}}
}

// queue builds a queue over the durable execution queue store; calling it twice
// models a controller restart over the same store.
func (f *pinFixture) queue(t *testing.T) *script.ExecutionQueue {
	t.Helper()
	q := script.NewExecutionQueue(nil, nil, 0, "", f.store, f.repo, 0)
	t.Cleanup(q.Stop)
	return q
}

func pinScript(id, content string) *script.VersionedScript {
	return &script.VersionedScript{
		Metadata: &script.ScriptMetadata{
			ID: id, Name: id, Version: &script.Version{Major: 1},
			Shell: script.ShellBash, Platform: []string{"linux"},
		},
		Content:   content,
		Signature: &script.ScriptSignature{Algorithm: "rsa-sha256", Signature: "c2ln", PublicKey: "pem"},
	}
}

func (f *pinFixture) put(t *testing.T, tenant, id, content string) *script.VersionedScript {
	t.Helper()
	gr, err := f.repo.ForTenant(tenant)
	require.NoError(t, err)
	require.NoError(t, gr.Create(pinScript(id, content)))
	vs, err := gr.Get(id, "1.0.0")
	require.NoError(t, err)
	return vs
}

func (f *pinFixture) replace(t *testing.T, tenant, id, content string) {
	t.Helper()
	gr, err := f.repo.ForTenant(tenant)
	require.NoError(t, err)
	require.NoError(t, gr.Delete(id, "1.0.0"))
	require.NoError(t, gr.Create(pinScript(id, content)))
}

func pinned(execID string, owner string, vs *script.VersionedScript) *script.QueuedExecution {
	return (&script.QueuedExecution{
		ExecutionID: execID, ScriptID: vs.Metadata.ID, ScriptRef: vs.Metadata.ID,
		Shell: script.ShellBash, Timeout: time.Minute,
	}).WithPin(owner, vs.Metadata.Version.String(), script.ScriptApprovalHash(owner, vs))
}

func TestQueuePin_RunsPinnedOwnerVersionAndForwardsSignature(t *testing.T) {
	f := newPinFixture(t)
	vs := f.put(t, "msp", "clean", "echo ok\n")
	q := f.queue(t)

	require.NoError(t, q.QueueExecution(pinDevice, pinned("e1", "msp", vs)))
	got, err := q.DequeueForDevice(pinDevice)
	require.NoError(t, err)
	require.Len(t, got, 1)

	prep, err := q.PrepareExecutionForDevice(context.Background(), pinDevice, "client-1", got[0])
	require.NoError(t, err)
	assert.Equal(t, "echo ok\n", prep.ScriptContent)
	assert.Equal(t, "1.0.0", prep.ScriptVersion)
	assert.Equal(t, "rsa-sha256", prep.SignatureAlgorithm)
	assert.Equal(t, "c2ln", prep.SignatureValue)
	assert.Equal(t, "pem", prep.SignaturePublicKey)
}

func TestQueuePin_ContentChangedBeforePrepareRefusesAndSendsNothing(t *testing.T) {
	f := newPinFixture(t)
	vs := f.put(t, "msp", "clean", "echo ok\n")
	q := f.queue(t)
	require.NoError(t, q.QueueExecution(pinDevice, pinned("e1", "msp", vs)))
	got, err := q.DequeueForDevice(pinDevice)
	require.NoError(t, err)
	require.Len(t, got, 1)

	f.replace(t, "msp", "clean", "echo evil\n")

	prep, err := q.PrepareExecutionForDevice(context.Background(), pinDevice, "client-1", got[0])
	require.ErrorIs(t, err, script.ErrPinMismatch)
	assert.Nil(t, prep)
}

func TestQueuePin_NearerShadowCopyIsNeverRun(t *testing.T) {
	f := newPinFixture(t)
	vs := f.put(t, "msp", "clean", "echo owner\n")
	q := f.queue(t)
	require.NoError(t, q.QueueExecution(pinDevice, pinned("e1", "msp", vs)))
	got, err := q.DequeueForDevice(pinDevice)
	require.NoError(t, err)

	f.put(t, "client-1", "clean", "echo shadow\n")

	prep, err := q.PrepareExecutionForDevice(context.Background(), pinDevice, "client-1", got[0])
	require.NoError(t, err)
	assert.Equal(t, "echo owner\n", prep.ScriptContent)
}

func TestQueuePin_ChangedPrivilegeScopeRefuses(t *testing.T) {
	f := newPinFixture(t)
	vs := f.put(t, "msp", "clean", "echo ok\n")
	q := f.queue(t)
	var scope atomic.Value
	scope.Store([]string{})
	q.SetPrivilegeScopeLookup(func(_ context.Context, _, _ string) ([]string, error) {
		return scope.Load().([]string), nil
	})
	require.NoError(t, q.QueueExecution(pinDevice, pinned("e1", "msp", vs)))
	got, err := q.DequeueForDevice(pinDevice)
	require.NoError(t, err)

	scope.Store([]string{"steward:read-scripts"})

	prep, err := q.PrepareExecutionForDevice(context.Background(), pinDevice, "client-1", got[0])
	require.ErrorIs(t, err, script.ErrAPIScopeNotGrantable)
	assert.Nil(t, prep)
}

func TestQueueGuard_FailureAtDequeueAndBeforeDispatchCancel(t *testing.T) {
	f := newPinFixture(t)
	vs := f.put(t, "msp", "clean", "echo ok\n")
	q := f.queue(t)
	var live atomic.Bool
	live.Store(true)
	q.SetGuardResolver(func(_ context.Context, runID, grantID string) error {
		if runID != "run-1" || grantID != "grant-1" {
			return errors.New("unknown reference")
		}
		if !live.Load() {
			return errors.New("grant revoked")
		}
		return nil
	})
	guarded := func(id string) *script.QueuedExecution {
		return pinned(id, "msp", vs).WithGuard("run-1", "grant-1")
	}

	// Failure at dequeue.
	require.NoError(t, q.QueueExecution(pinDevice, guarded("e1")))
	live.Store(false)
	got, err := q.DequeueForDevice(pinDevice)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, 0, q.GetQueueDepth(pinDevice))

	// Failure just before dispatch.
	live.Store(true)
	require.NoError(t, q.QueueExecution(pinDevice, guarded("e2")))
	got, err = q.DequeueForDevice(pinDevice)
	require.NoError(t, err)
	require.Len(t, got, 1)
	live.Store(false)
	prep, err := q.PrepareExecutionForDevice(context.Background(), pinDevice, "", got[0])
	require.ErrorIs(t, err, script.ErrGuardFailed)
	assert.Nil(t, prep)
	assert.Equal(t, 0, q.GetQueueDepth(pinDevice))
}

func TestQueueGuard_RestartCancelsRevokedAndUnresolvedCommands(t *testing.T) {
	f := newPinFixture(t)
	vs := f.put(t, "msp", "clean", "echo ok\n")
	q1 := f.queue(t)
	require.NoError(t, q1.QueueExecution(pinDevice, pinned("e1", "msp", vs).WithGuard("run-1", "grant-1")))

	// Rebuilt over the same durable store, with a resolver that reports revocation.
	q2 := f.queue(t)
	q2.SetGuardResolver(func(context.Context, string, string) error { return errors.New("run ended") })
	got, err := q2.DequeueForDevice(pinDevice)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, 0, q2.GetQueueDepth(pinDevice))

	// A guard reference with no resolver registered fails closed.
	require.NoError(t, q2.QueueExecution(pinDevice, pinned("e2", "msp", vs).WithGuard("run-2", "grant-2")))
	q3 := f.queue(t)
	got, err = q3.DequeueForDevice(pinDevice)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, 0, q3.GetQueueDepth(pinDevice))
}

func TestQueuePin_KeysSurviveRestartOnDurableStore(t *testing.T) {
	f := newPinFixture(t)
	vs := f.put(t, "msp", "clean", "echo ok\n")
	q1 := f.queue(t)
	require.NoError(t, q1.QueueExecution(pinDevice, pinned("e1", "msp", vs).WithGuard("run-1", "grant-1")))

	q2 := f.queue(t)
	peek := q2.PeekForDevice(pinDevice)
	require.Len(t, peek, 1)
	assert.Equal(t, "msp", peek[0].Metadata[script.MetaPinOwnerTenant])
	assert.Equal(t, "1.0.0", peek[0].Metadata[script.MetaPinVersion])
	assert.Equal(t, script.ScriptApprovalHash("msp", vs), peek[0].Metadata[script.MetaPinApprovalHash])
	assert.Equal(t, "run-1", peek[0].Metadata[script.MetaGuardRunID])
	assert.Equal(t, "grant-1", peek[0].Metadata[script.MetaGuardGrantID])
}

func TestQueueReservedKeys_RawMetadataRejected(t *testing.T) {
	f := newPinFixture(t)
	q := f.queue(t)
	for _, key := range []string{
		script.MetaPinOwnerTenant, script.MetaPinVersion, script.MetaPinApprovalHash,
		script.MetaGuardRunID, script.MetaGuardGrantID, "pin_other", "guard_other",
	} {
		qe := &script.QueuedExecution{
			ExecutionID: "e-" + key, ScriptRef: "clean", Shell: script.ShellBash,
			Metadata: map[string]interface{}{key: "x"},
		}
		require.ErrorIs(t, q.QueueExecution(pinDevice, qe), script.ErrReservedMetadataKey, key)
	}

	// Metadata built from workflow-controlled values cannot smuggle a key in.
	workflowName := "guard_run_id"
	qe := &script.QueuedExecution{
		ExecutionID: "e-wf", ScriptRef: "clean", Shell: script.ShellBash,
		Metadata: map[string]interface{}{"workflow_name": workflowName, workflowName: "run-x"},
	}
	require.ErrorIs(t, q.QueueExecution(pinDevice, qe), script.ErrReservedMetadataKey)
	assert.Equal(t, 0, q.GetQueueDepth(pinDevice))
}

func TestQueuePin_IncompletePinRejectedAtQueue(t *testing.T) {
	f := newPinFixture(t)
	q := f.queue(t)
	qe := (&script.QueuedExecution{ExecutionID: "e1", ScriptRef: "clean", Shell: script.ShellBash}).WithPin("msp", "", "h")
	require.ErrorIs(t, q.QueueExecution(pinDevice, qe), script.ErrPinMismatch)
}

func TestQueuePin_NeverMintsAnAPIKey(t *testing.T) {
	f := newPinFixture(t)
	vs := f.put(t, "msp", "clean", "echo ok\n")
	q := f.queue(t)
	qe := pinned("e1", "msp", vs)
	qe.GenerateAPIKey = true
	require.NoError(t, q.QueueExecution(pinDevice, qe))
	got, err := q.DequeueForDevice(pinDevice)
	require.NoError(t, err)
	require.Len(t, got, 1)

	prep, err := q.PrepareExecutionForDevice(context.Background(), pinDevice, "client-1", got[0])
	require.ErrorIs(t, err, script.ErrAPIScopeNotGrantable)
	assert.Nil(t, prep)
}
