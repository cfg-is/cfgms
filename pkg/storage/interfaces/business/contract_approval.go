// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ApprovalStoreContract verifies an ApprovalStore's tenant isolation, its
// compare-and-set transitions and their multi-node guarantees. Tenant and
// approval IDs are unique per call, so the store need not be empty; the
// cross-tenant methods (ExpireDue, ListUnresumed) are asserted only on this
// call's own approvals.
func ApprovalStoreContract(t *testing.T, store ApprovalStore) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Millisecond)

	newApproval := func(tenant, id string, expires time.Time) *WorkflowApproval {
		return &WorkflowApproval{
			ApprovalID: id, TenantID: tenant, WorkflowName: "deploy", ExecutionID: "exec-" + id,
			StepID: "step-1", StepName: "Approve rollout", Message: "ok to proceed?",
			ApproverPermission: "workflow:approve", RequestedBy: "alice",
			Status: ApprovalStatusPending, RequestedAt: now, ExpiresAt: expires,
			CheckpointRef: "secret://" + tenant + "/" + id,
		}
	}
	create := func(t *testing.T, tenant, id string, expires time.Time) {
		t.Helper()
		require.NoError(t, store.CreateApproval(ctx, newApproval(tenant, id, expires)))
	}

	t.Run("holds a checkpoint reference and never checkpoint bytes", func(t *testing.T) {
		typ := reflect.TypeOf(WorkflowApproval{})
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if strings.Contains(strings.ToLower(f.Name), "checkpoint") {
				assert.Equal(t, "CheckpointRef", f.Name, "only a reference may be stored")
				assert.Equal(t, reflect.String, f.Type.Kind(), "CheckpointRef is a string reference")
			}
		}
	})

	t.Run("create and get round-trip", func(t *testing.T) {
		tenant, id := "t-rt-"+suffix, "a-rt-"+suffix
		expires := now.Add(time.Hour)
		create(t, tenant, id, expires)

		got, err := store.GetApproval(ctx, tenant, id)
		require.NoError(t, err)
		assert.Equal(t, id, got.ApprovalID)
		assert.Equal(t, tenant, got.TenantID)
		assert.Equal(t, "deploy", got.WorkflowName)
		assert.Equal(t, "exec-"+id, got.ExecutionID)
		assert.Equal(t, "step-1", got.StepID)
		assert.Equal(t, "Approve rollout", got.StepName)
		assert.Equal(t, "ok to proceed?", got.Message)
		assert.Equal(t, "workflow:approve", got.ApproverPermission)
		assert.Equal(t, "alice", got.RequestedBy)
		assert.Equal(t, ApprovalStatusPending, got.Status)
		assert.True(t, now.Equal(got.RequestedAt), "requested_at round-trips")
		assert.True(t, expires.Equal(got.ExpiresAt), "expires_at round-trips")
		assert.Equal(t, "secret://"+tenant+"/"+id, got.CheckpointRef)
		assert.True(t, got.DecidedAt.IsZero())
		assert.True(t, got.ResumeClaimedAt.IsZero())
		assert.True(t, got.ResumedAt.IsZero())

		err = store.CreateApproval(ctx, newApproval(tenant, id, expires))
		assert.ErrorIs(t, err, ErrApprovalAlreadyExists, "a second create of the same key is rejected")

		_, err = store.GetApproval(ctx, tenant, "missing-"+suffix)
		assert.ErrorIs(t, err, ErrApprovalNotFound)

		bad := newApproval(tenant, "a-bad-"+suffix, expires)
		bad.Status = ApprovalStatusApproved
		assert.Error(t, store.CreateApproval(ctx, bad), "an approval is created pending")
		assert.Error(t, store.CreateApproval(ctx, newApproval("", "a-notenant-"+suffix, expires)), "tenant is required")
		assert.Error(t, store.CreateApproval(ctx, newApproval(tenant, "", expires)), "approval id is required")
	})

	t.Run("tenant isolation", func(t *testing.T) {
		tenantA, tenantB := "t-iso-a-"+suffix, "t-iso-b-"+suffix
		create(t, tenantA, "a-a1-"+suffix, now.Add(time.Hour))
		create(t, tenantA, "a-a2-"+suffix, now.Add(time.Hour))
		create(t, tenantB, "a-b1-"+suffix, now.Add(time.Hour))

		listA, err := store.ListPending(ctx, tenantA)
		require.NoError(t, err)
		require.Len(t, listA, 2)
		for _, a := range listA {
			assert.Equal(t, tenantA, a.TenantID, "ListPending must never return another tenant's approval")
		}
		listB, err := store.ListPending(ctx, tenantB)
		require.NoError(t, err)
		require.Len(t, listB, 1)
		assert.Equal(t, "a-b1-"+suffix, listB[0].ApprovalID)

		none, err := store.ListPending(ctx, "t-iso-none-"+suffix)
		require.NoError(t, err)
		assert.NotNil(t, none)
		assert.Empty(t, none)

		_, err = store.GetApproval(ctx, tenantA, "a-b1-"+suffix)
		assert.ErrorIs(t, err, ErrApprovalNotFound, "GetApproval never crosses tenants")
		err = store.DecideApproval(ctx, tenantA, "a-b1-"+suffix, ApprovalStatusApproved, "bob", "", now)
		assert.ErrorIs(t, err, ErrApprovalNotFound, "DecideApproval never crosses tenants")
		still, err := store.GetApproval(ctx, tenantB, "a-b1-"+suffix)
		require.NoError(t, err)
		assert.Equal(t, ApprovalStatusPending, still.Status)

		// The same approval id in two tenants is two approvals.
		create(t, tenantA, "a-shared-"+suffix, now.Add(time.Hour))
		create(t, tenantB, "a-shared-"+suffix, now.Add(time.Hour))
		require.NoError(t, store.DecideApproval(ctx, tenantA, "a-shared-"+suffix, ApprovalStatusRejected, "bob", "no", now))
		other, err := store.GetApproval(ctx, tenantB, "a-shared-"+suffix)
		require.NoError(t, err)
		assert.Equal(t, ApprovalStatusPending, other.Status)
	})

	t.Run("decide records the decision and leaves the pending list", func(t *testing.T) {
		tenant, id := "t-dec-"+suffix, "a-dec-"+suffix
		create(t, tenant, id, now.Add(time.Hour))
		decidedAt := now.Add(time.Minute)

		assert.Error(t, store.DecideApproval(ctx, tenant, id, ApprovalStatusPending, "bob", "", decidedAt),
			"only approved or rejected are valid decisions")
		assert.Error(t, store.DecideApproval(ctx, tenant, id, ApprovalStatusExpired, "bob", "", decidedAt),
			"expiry is not a decision a principal can make")
		require.NoError(t, store.DecideApproval(ctx, tenant, id, ApprovalStatusApproved, "bob", "looks good", decidedAt))

		got, err := store.GetApproval(ctx, tenant, id)
		require.NoError(t, err)
		assert.Equal(t, ApprovalStatusApproved, got.Status)
		assert.Equal(t, "bob", got.DecidedBy)
		assert.Equal(t, "looks good", got.Justification)
		assert.True(t, decidedAt.Equal(got.DecidedAt), "decided_at round-trips")

		pending, err := store.ListPending(ctx, tenant)
		require.NoError(t, err)
		assert.Empty(t, pending)

		err = store.DecideApproval(ctx, tenant, id, ApprovalStatusRejected, "carol", "changed my mind", decidedAt)
		assert.ErrorIs(t, err, ErrApprovalAlreadyDecided)
		got, err = store.GetApproval(ctx, tenant, id)
		require.NoError(t, err)
		assert.Equal(t, ApprovalStatusApproved, got.Status, "a lost decision does not overwrite the winner")
		assert.Equal(t, "bob", got.DecidedBy)

		err = store.DecideApproval(ctx, tenant, "missing-"+suffix, ApprovalStatusApproved, "bob", "", decidedAt)
		assert.ErrorIs(t, err, ErrApprovalNotFound)
	})

	t.Run("concurrent decisions: exactly one wins", func(t *testing.T) {
		tenant, id := "t-race-"+suffix, "a-race-"+suffix
		create(t, tenant, id, now.Add(time.Hour))
		const callers = 8
		var won, lost atomic.Int32
		errs := make(chan error, callers)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for c := 0; c < callers; c++ {
			wg.Add(1)
			go func(c int) {
				defer wg.Done()
				<-start
				status := ApprovalStatusApproved
				if c%2 == 1 {
					status = ApprovalStatusRejected
				}
				err := store.DecideApproval(ctx, tenant, id, status, fmt.Sprintf("p%d", c), "", now.Add(time.Duration(c)*time.Second))
				switch {
				case err == nil:
					won.Add(1)
				case errors.Is(err, ErrApprovalAlreadyDecided):
					lost.Add(1)
				default:
					errs <- err
				}
			}(c)
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		assert.EqualValues(t, 1, won.Load(), "exactly one concurrent decision succeeds")
		assert.EqualValues(t, callers-1, lost.Load(), "every other decision gets ErrApprovalAlreadyDecided")
		got, err := store.GetApproval(ctx, tenant, id)
		require.NoError(t, err)
		assert.NotEqual(t, ApprovalStatusPending, got.Status)
		assert.NotEmpty(t, got.DecidedBy)
	})

	t.Run("ExpireDue flips only pending approvals past expiry", func(t *testing.T) {
		tenant := "t-exp-" + suffix
		due, notDue, never, decided := "a-due-"+suffix, "a-notdue-"+suffix, "a-never-"+suffix, "a-decided-"+suffix
		create(t, tenant, due, now.Add(-time.Minute))
		create(t, tenant, notDue, now.Add(time.Hour))
		create(t, tenant, never, time.Time{})
		create(t, tenant, decided, now.Add(-time.Minute))
		require.NoError(t, store.DecideApproval(ctx, tenant, decided, ApprovalStatusApproved, "bob", "", now.Add(-2*time.Minute)))

		flipped, err := store.ExpireDue(ctx, now)
		require.NoError(t, err)
		var ours []string
		for _, a := range flipped {
			if a.TenantID == tenant {
				ours = append(ours, a.ApprovalID)
				assert.Equal(t, ApprovalStatusExpired, a.Status, "the returned approval reflects its new state")
				assert.Equal(t, "exec-"+a.ApprovalID, a.ExecutionID, "the caller can find the run to fail")
			}
		}
		assert.Equal(t, []string{due}, ours, "only the pending, past-expiry approval is flipped")

		for id, want := range map[string]string{
			due: ApprovalStatusExpired, notDue: ApprovalStatusPending,
			never: ApprovalStatusPending, decided: ApprovalStatusApproved,
		} {
			got, err := store.GetApproval(ctx, tenant, id)
			require.NoError(t, err)
			assert.Equal(t, want, got.Status, id)
		}

		again, err := store.ExpireDue(ctx, now)
		require.NoError(t, err)
		for _, a := range again {
			assert.NotEqual(t, tenant, a.TenantID, "an approval is flipped at most once")
		}

		err = store.DecideApproval(ctx, tenant, due, ApprovalStatusApproved, "bob", "", now)
		assert.ErrorIs(t, err, ErrApprovalAlreadyDecided, "an expired approval cannot be decided")
		pending, err := store.ListPending(ctx, tenant)
		require.NoError(t, err)
		assert.Len(t, pending, 2, "expired and decided approvals leave the pending list")
	})

	t.Run("resume claim lifecycle", func(t *testing.T) {
		tenant, id := "t-claim-"+suffix, "a-claim-"+suffix
		const lease = time.Minute
		create(t, tenant, id, now.Add(time.Hour))

		err := store.ClaimResume(ctx, tenant, id, "node-1", now, lease)
		assert.ErrorIs(t, err, ErrApprovalNotDecided, "a pending approval cannot be claimed")
		err = store.ClaimResume(ctx, tenant, "missing-"+suffix, "node-1", now, lease)
		assert.ErrorIs(t, err, ErrApprovalNotFound)
		assert.ErrorIs(t, store.MarkResumed(ctx, tenant, id, now), ErrApprovalNotDecided)

		require.NoError(t, store.DecideApproval(ctx, tenant, id, ApprovalStatusApproved, "bob", "", now))
		assertListed := func(want bool, at time.Time) {
			t.Helper()
			list, err := store.ListUnresumed(ctx, at, lease)
			require.NoError(t, err)
			found := false
			for _, a := range list {
				if a.TenantID == tenant && a.ApprovalID == id {
					found = true
				}
			}
			assert.Equal(t, want, found, "ListUnresumed at %s", at)
		}
		assertListed(true, now)

		require.NoError(t, store.ClaimResume(ctx, tenant, id, "node-1", now, lease))
		got, err := store.GetApproval(ctx, tenant, id)
		require.NoError(t, err)
		assert.Equal(t, "node-1", got.ResumeClaimedBy)
		assert.True(t, now.Equal(got.ResumeClaimedAt))
		assertListed(false, now.Add(30*time.Second))

		err = store.ClaimResume(ctx, tenant, id, "node-2", now.Add(30*time.Second), lease)
		assert.ErrorIs(t, err, ErrApprovalAlreadyClaimed, "a live claim blocks another node")
		got, err = store.GetApproval(ctx, tenant, id)
		require.NoError(t, err)
		assert.Equal(t, "node-1", got.ResumeClaimedBy)

		later := now.Add(lease + time.Second)
		assertListed(true, later)
		require.NoError(t, store.ClaimResume(ctx, tenant, id, "node-2", later, lease), "a claim older than the lease is re-claimed")
		got, err = store.GetApproval(ctx, tenant, id)
		require.NoError(t, err)
		assert.Equal(t, "node-2", got.ResumeClaimedBy)
		assert.True(t, later.Equal(got.ResumeClaimedAt))

		require.NoError(t, store.MarkResumed(ctx, tenant, id, later.Add(time.Second)))
		require.NoError(t, store.MarkResumed(ctx, tenant, id, later.Add(time.Hour)), "MarkResumed is idempotent")
		got, err = store.GetApproval(ctx, tenant, id)
		require.NoError(t, err)
		assert.True(t, later.Add(time.Second).Equal(got.ResumedAt), "the first resume time is kept")

		err = store.ClaimResume(ctx, tenant, id, "node-3", later.Add(time.Hour), lease)
		assert.ErrorIs(t, err, ErrApprovalAlreadyClaimed, "MarkResumed ends further claims, even past the lease")
		assertListed(false, later.Add(time.Hour))
	})

	t.Run("a rejected approval is claimable and an expired one is not", func(t *testing.T) {
		tenant := "t-claimrej-" + suffix
		create(t, tenant, "a-rej-"+suffix, now.Add(time.Hour))
		create(t, tenant, "a-expd-"+suffix, now.Add(-time.Minute))
		require.NoError(t, store.DecideApproval(ctx, tenant, "a-rej-"+suffix, ApprovalStatusRejected, "bob", "no", now))
		_, err := store.ExpireDue(ctx, now)
		require.NoError(t, err)

		require.NoError(t, store.ClaimResume(ctx, tenant, "a-rej-"+suffix, "node-1", now, time.Minute))
		err = store.ClaimResume(ctx, tenant, "a-expd-"+suffix, "node-1", now, time.Minute)
		assert.ErrorIs(t, err, ErrApprovalNotDecided)
		list, err := store.ListUnresumed(ctx, now.Add(time.Hour), time.Minute)
		require.NoError(t, err)
		for _, a := range list {
			assert.NotEqual(t, "a-expd-"+suffix, a.ApprovalID, "expired approvals are not recovered for resume")
		}
	})

	t.Run("concurrent claims: exactly one wins", func(t *testing.T) {
		tenant, id := "t-cclaim-"+suffix, "a-cclaim-"+suffix
		create(t, tenant, id, now.Add(time.Hour))
		require.NoError(t, store.DecideApproval(ctx, tenant, id, ApprovalStatusApproved, "bob", "", now))
		const callers = 8
		var won, lost atomic.Int32
		errs := make(chan error, callers)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for c := 0; c < callers; c++ {
			wg.Add(1)
			go func(c int) {
				defer wg.Done()
				<-start
				err := store.ClaimResume(ctx, tenant, id, fmt.Sprintf("node-%d", c), now, time.Minute)
				switch {
				case err == nil:
					won.Add(1)
				case errors.Is(err, ErrApprovalAlreadyClaimed):
					lost.Add(1)
				default:
					errs <- err
				}
			}(c)
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		assert.EqualValues(t, 1, won.Load(), "exactly one concurrent claim succeeds")
		assert.EqualValues(t, callers-1, lost.Load(), "every other claim gets ErrApprovalAlreadyClaimed")
	})
}
