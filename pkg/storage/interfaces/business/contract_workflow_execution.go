// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WorkflowExecutionStoreContract verifies a WorkflowExecutionStore: round-trip,
// in-place update, the terminal-status guard, tenant isolation (including the root
// tenant's empty key) and bounded retention. Tenant and execution ids are unique per
// call, so the store need not be empty. Every provider runs it.
func WorkflowExecutionStoreContract(t *testing.T, store WorkflowExecutionStore) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	base := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Hour)

	rec := func(tenant, id, workflow, status string, started time.Time) *WorkflowExecutionRecord {
		r := &WorkflowExecutionRecord{
			TenantID: tenant, ExecutionID: id, WorkflowName: workflow, Status: status,
			StartTime: started, Payload: []byte(`{"error":"boom","step_results":{"s1":{"status":"` + status + `"}}}`),
		}
		if IsTerminalWorkflowExecutionStatus(status) {
			r.EndTime = started.Add(time.Second)
		}
		return r
	}
	save := func(t *testing.T, r *WorkflowExecutionRecord) {
		t.Helper()
		require.NoError(t, store.Save(ctx, r))
	}

	t.Run("save then get round-trips every field", func(t *testing.T) {
		tenant, id := "t-rt-"+suffix, "e-rt-"+suffix
		want := rec(tenant, id, "deploy", WorkflowExecutionStatusFailed, base)
		save(t, want)

		got, err := store.Get(ctx, tenant, id)
		require.NoError(t, err)
		assert.Equal(t, tenant, got.TenantID)
		assert.Equal(t, id, got.ExecutionID)
		assert.Equal(t, "deploy", got.WorkflowName)
		assert.Equal(t, WorkflowExecutionStatusFailed, got.Status)
		assert.True(t, want.StartTime.Equal(got.StartTime), "start time %v != %v", want.StartTime, got.StartTime)
		assert.True(t, want.EndTime.Equal(got.EndTime), "end time %v != %v", want.EndTime, got.EndTime)
		assert.JSONEq(t, string(want.Payload), string(got.Payload))
	})

	t.Run("an unfinished run has a zero end time", func(t *testing.T) {
		tenant, id := "t-zero-"+suffix, "e-zero-"+suffix
		save(t, rec(tenant, id, "deploy", "running", base))
		got, err := store.Get(ctx, tenant, id)
		require.NoError(t, err)
		assert.True(t, got.EndTime.IsZero())
	})

	t.Run("get of an unknown id is not found", func(t *testing.T) {
		_, err := store.Get(ctx, "t-none-"+suffix, "missing")
		assert.True(t, errors.Is(err, ErrWorkflowExecutionNotFound), "got %v", err)
	})

	t.Run("a second save of the same id updates in place", func(t *testing.T) {
		tenant, id := "t-upd-"+suffix, "e-upd-"+suffix
		save(t, rec(tenant, id, "deploy", "running", base))
		save(t, rec(tenant, id, "deploy", WorkflowExecutionStatusCompleted, base))

		got, err := store.Get(ctx, tenant, id)
		require.NoError(t, err)
		assert.Equal(t, WorkflowExecutionStatusCompleted, got.Status)
		assert.JSONEq(t, `{"error":"boom","step_results":{"s1":{"status":"completed"}}}`, string(got.Payload))
		list, err := store.List(ctx, tenant, "", 0)
		require.NoError(t, err)
		assert.Len(t, list, 1, "an update must not add a second record")
	})

	t.Run("a terminal record is never overwritten by a non-terminal one", func(t *testing.T) {
		tenant, id := "t-term-"+suffix, "e-term-"+suffix
		save(t, rec(tenant, id, "deploy", WorkflowExecutionStatusCompleted, base))
		save(t, rec(tenant, id, "deploy", "running", base))

		got, err := store.Get(ctx, tenant, id)
		require.NoError(t, err)
		assert.Equal(t, WorkflowExecutionStatusCompleted, got.Status)
		assert.False(t, got.EndTime.IsZero())
	})

	t.Run("a terminal record may be replaced by another terminal write", func(t *testing.T) {
		tenant, id := "t-term2-"+suffix, "e-term2-"+suffix
		save(t, rec(tenant, id, "deploy", WorkflowExecutionStatusFailed, base))
		save(t, rec(tenant, id, "deploy", WorkflowExecutionStatusCancelled, base))
		got, err := store.Get(ctx, tenant, id)
		require.NoError(t, err)
		assert.Equal(t, WorkflowExecutionStatusCancelled, got.Status)
	})

	t.Run("get and list never cross tenants", func(t *testing.T) {
		tenantA, tenantB, id := "t-a-"+suffix, "t-b-"+suffix, "e-iso-"+suffix
		save(t, rec(tenantA, id, "deploy", WorkflowExecutionStatusCompleted, base))

		_, err := store.Get(ctx, tenantB, id)
		assert.True(t, errors.Is(err, ErrWorkflowExecutionNotFound), "tenant B must not read tenant A's record, got %v", err)
		listB, err := store.List(ctx, tenantB, "", 0)
		require.NoError(t, err)
		assert.Empty(t, listB)
		listA, err := store.List(ctx, tenantA, "", 0)
		require.NoError(t, err)
		require.Len(t, listA, 1)
		assert.Equal(t, id, listA[0].ExecutionID)
	})

	t.Run("the same id under two tenants is two records", func(t *testing.T) {
		tenantA, tenantB, id := "t-sa-"+suffix, "t-sb-"+suffix, "e-same-"+suffix
		save(t, rec(tenantA, id, "wf-a", WorkflowExecutionStatusCompleted, base))
		save(t, rec(tenantB, id, "wf-b", WorkflowExecutionStatusFailed, base))

		a, err := store.Get(ctx, tenantA, id)
		require.NoError(t, err)
		b, err := store.Get(ctx, tenantB, id)
		require.NoError(t, err)
		assert.Equal(t, "wf-a", a.WorkflowName)
		assert.Equal(t, "wf-b", b.WorkflowName)
	})

	t.Run("the empty tenant is the root tenant's key, not all tenants", func(t *testing.T) {
		id := "e-root-" + suffix
		save(t, rec("", id, "deploy", WorkflowExecutionStatusCompleted, base))
		save(t, rec("t-notroot-"+suffix, "e-notroot-"+suffix, "deploy", WorkflowExecutionStatusCompleted, base))

		got, err := store.Get(ctx, "", id)
		require.NoError(t, err)
		assert.Equal(t, "", got.TenantID)
		list, err := store.List(ctx, "", "", 0)
		require.NoError(t, err)
		for _, r := range list {
			assert.Equal(t, "", r.TenantID, "root listing must hold only root records")
			assert.NotEqual(t, "e-notroot-"+suffix, r.ExecutionID)
		}
		_, err = store.Get(ctx, "t-notroot-"+suffix, id)
		assert.True(t, errors.Is(err, ErrWorkflowExecutionNotFound))
	})

	t.Run("list is newest first, filters by workflow and honours the limit", func(t *testing.T) {
		tenant := "t-list-" + suffix
		save(t, rec(tenant, "e1", "wf-x", WorkflowExecutionStatusCompleted, base))
		save(t, rec(tenant, "e2", "wf-y", WorkflowExecutionStatusCompleted, base.Add(time.Minute)))
		save(t, rec(tenant, "e3", "wf-x", "running", base.Add(2*time.Minute)))

		all, err := store.List(ctx, tenant, "", 0)
		require.NoError(t, err)
		require.Len(t, all, 3)
		assert.Equal(t, []string{"e3", "e2", "e1"}, []string{all[0].ExecutionID, all[1].ExecutionID, all[2].ExecutionID})

		onlyX, err := store.List(ctx, tenant, "wf-x", 0)
		require.NoError(t, err)
		require.Len(t, onlyX, 2)
		assert.Equal(t, "e3", onlyX[0].ExecutionID)

		limited, err := store.List(ctx, tenant, "", 2)
		require.NoError(t, err)
		require.Len(t, limited, 2)
		assert.Equal(t, "e3", limited[0].ExecutionID)
	})

	t.Run("prune keeps the newest N terminal records and never deletes a non-terminal one", func(t *testing.T) {
		tenant, other := "t-prune-"+suffix, "t-prune-other-"+suffix
		// Oldest first: three terminal, one very old non-terminal.
		save(t, rec(tenant, "stuck", "deploy", "running", base.Add(-time.Hour)))
		save(t, rec(tenant, "old", "deploy", WorkflowExecutionStatusCompleted, base))
		save(t, rec(tenant, "mid", "deploy", WorkflowExecutionStatusFailed, base.Add(time.Minute)))
		save(t, rec(tenant, "new", "deploy", WorkflowExecutionStatusCancelled, base.Add(2*time.Minute)))
		save(t, rec(other, "other-old", "deploy", WorkflowExecutionStatusCompleted, base))

		deleted, err := store.Prune(ctx, tenant, 2)
		require.NoError(t, err)
		assert.Equal(t, 1, deleted)

		_, err = store.Get(ctx, tenant, "old")
		assert.True(t, errors.Is(err, ErrWorkflowExecutionNotFound), "the oldest terminal record is pruned")
		for _, id := range []string{"mid", "new", "stuck"} {
			_, err := store.Get(ctx, tenant, id)
			assert.NoError(t, err, "%s must survive", id)
		}
		_, err = store.Get(ctx, other, "other-old")
		assert.NoError(t, err, "prune must not touch another tenant")

		deleted, err = store.Prune(ctx, tenant, 2)
		require.NoError(t, err)
		assert.Equal(t, 0, deleted, "a second prune at the same limit deletes nothing")

		deleted, err = store.Prune(ctx, tenant, 0)
		require.NoError(t, err)
		assert.Equal(t, 2, deleted)
		_, err = store.Get(ctx, tenant, "stuck")
		assert.NoError(t, err, "a non-terminal record is never pruned, even with keep=0")
	})

	t.Run("save requires an execution id", func(t *testing.T) {
		assert.Error(t, store.Save(ctx, &WorkflowExecutionRecord{TenantID: "t", Status: "running", StartTime: base}))
		assert.Error(t, store.Save(ctx, nil))
	})
}
