// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/batchjob"
)

// TenantStoreLifecycleContract verifies that the suspension provenance fields
// (DirectlySuspended, CascadeSuspendedFrom — ADR-027 Decision 2) survive a
// round-trip through the store: the values written by UpdateTenant must be
// readable back from GetTenant on a fresh call. Call from each TenantStore
// provider's tests:
//
//	func TestMyTenantStore_LifecycleContract(t *testing.T) {
//	    business.TenantStoreLifecycleContract(t, openStore(t))
//	}
//
// The store must be initialized and empty (no pre-existing tenants). Lifecycle
// (Initialize/Close) stays with the caller.
func TenantStoreLifecycleContract(t *testing.T, store TenantStore) {
	t.Helper()
	ctx := context.Background()

	const ancID = "lc-ancestor"
	const descID = "lc-descendant"
	now := time.Now().UTC().Truncate(time.Second)

	anc := &TenantData{
		ID:        ancID,
		Name:      "LifecycleAncestor",
		Status:    TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	desc := &TenantData{
		ID:        descID,
		Name:      "LifecycleDescendant",
		ParentID:  ancID,
		Status:    TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, store.CreateTenant(ctx, anc))
	require.NoError(t, store.CreateTenant(ctx, desc))

	t.Run("DirectlySuspended persists after UpdateTenant", func(t *testing.T) {
		anc.DirectlySuspended = true
		anc.Status = TenantStatusSuspended
		anc.UpdatedAt = now
		require.NoError(t, store.UpdateTenant(ctx, anc))

		got, err := store.GetTenant(ctx, ancID)
		require.NoError(t, err)
		assert.True(t, got.DirectlySuspended, "DirectlySuspended must survive a store round-trip")
		assert.Equal(t, TenantStatusSuspended, got.Status)
	})

	t.Run("CascadeSuspendedFrom persists after UpdateTenant", func(t *testing.T) {
		from := ancID
		desc.CascadeSuspendedFrom = &from
		desc.Status = TenantStatusSuspended
		desc.UpdatedAt = now
		require.NoError(t, store.UpdateTenant(ctx, desc))

		got, err := store.GetTenant(ctx, descID)
		require.NoError(t, err)
		require.NotNil(t, got.CascadeSuspendedFrom, "CascadeSuspendedFrom must survive a store round-trip")
		assert.Equal(t, ancID, *got.CascadeSuspendedFrom)
	})

	t.Run("both provenance flags can be set simultaneously", func(t *testing.T) {
		from := ancID
		desc.DirectlySuspended = true
		desc.CascadeSuspendedFrom = &from
		desc.UpdatedAt = now
		require.NoError(t, store.UpdateTenant(ctx, desc))

		got, err := store.GetTenant(ctx, descID)
		require.NoError(t, err)
		assert.True(t, got.DirectlySuspended, "DirectlySuspended must be set")
		require.NotNil(t, got.CascadeSuspendedFrom, "CascadeSuspendedFrom must be set")
		assert.Equal(t, ancID, *got.CascadeSuspendedFrom)
	})

	t.Run("clearing CascadeSuspendedFrom to nil persists", func(t *testing.T) {
		desc.CascadeSuspendedFrom = nil
		desc.UpdatedAt = now
		require.NoError(t, store.UpdateTenant(ctx, desc))

		got, err := store.GetTenant(ctx, descID)
		require.NoError(t, err)
		assert.Nil(t, got.CascadeSuspendedFrom, "nil CascadeSuspendedFrom must round-trip as nil")
	})

	t.Run("clearing DirectlySuspended to false persists", func(t *testing.T) {
		desc.DirectlySuspended = false
		desc.Status = TenantStatusActive
		desc.UpdatedAt = now
		require.NoError(t, store.UpdateTenant(ctx, desc))

		got, err := store.GetTenant(ctx, descID)
		require.NoError(t, err)
		assert.False(t, got.DirectlySuspended, "cleared DirectlySuspended must round-trip as false")
		assert.Equal(t, TenantStatusActive, got.Status)
	})
}

// TenantStoreBillingLabelContract verifies the opaque billing label (ADR-025
// Amendment 6 A6.2): a label supplied at create round-trips through GetTenant,
// ListTenants and GetChildTenants, survives UpdateTenant (including an update
// that carries no label), and is unique across tenants. Call from each
// TenantStore provider's tests. The store must be initialized and empty.
func TenantStoreBillingLabelContract(t *testing.T, store TenantStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	parent := &TenantData{ID: "bl-parent", Name: "BLParent", Status: TenantStatusActive, BillingLabel: "bl-contractlabelaaaa1", CreatedAt: now, UpdatedAt: now}
	child := &TenantData{ID: "bl-child", Name: "BLChild", ParentID: "bl-parent", Status: TenantStatusActive, BillingLabel: "bl-contractlabelbbbb2", CreatedAt: now, UpdatedAt: now}
	require.NoError(t, store.CreateTenant(ctx, parent))
	require.NoError(t, store.CreateTenant(ctx, child))

	t.Run("label round-trips on get, list and child list", func(t *testing.T) {
		got, err := store.GetTenant(ctx, "bl-parent")
		require.NoError(t, err)
		assert.Equal(t, "bl-contractlabelaaaa1", got.BillingLabel)

		all, err := store.ListTenants(ctx, nil)
		require.NoError(t, err)
		byID := map[string]string{}
		for _, td := range all {
			byID[td.ID] = td.BillingLabel
		}
		assert.Equal(t, "bl-contractlabelaaaa1", byID["bl-parent"])
		assert.Equal(t, "bl-contractlabelbbbb2", byID["bl-child"])

		kids, err := store.GetChildTenants(ctx, "bl-parent")
		require.NoError(t, err)
		require.Len(t, kids, 1)
		assert.Equal(t, "bl-contractlabelbbbb2", kids[0].BillingLabel)
	})

	t.Run("label survives UpdateTenant", func(t *testing.T) {
		upd := &TenantData{ID: "bl-parent", Name: "BLParentRenamed", Status: TenantStatusSuspended, DirectlySuspended: true, BillingLabel: "bl-attemptedoverwrite", UpdatedAt: now}
		require.NoError(t, store.UpdateTenant(ctx, upd))
		got, err := store.GetTenant(ctx, "bl-parent")
		require.NoError(t, err)
		assert.Equal(t, "BLParentRenamed", got.Name)
		assert.Equal(t, "bl-contractlabelaaaa1", got.BillingLabel, "update must not overwrite the label")

		upd = &TenantData{ID: "bl-parent", Name: "BLParentRenamed", Status: TenantStatusActive, UpdatedAt: now}
		require.NoError(t, store.UpdateTenant(ctx, upd))
		got, err = store.GetTenant(ctx, "bl-parent")
		require.NoError(t, err)
		assert.Equal(t, "bl-contractlabelaaaa1", got.BillingLabel, "update with an empty label must not clear it")
	})

	t.Run("label is unique across tenants", func(t *testing.T) {
		dup := &TenantData{ID: "bl-dup", Name: "BLDup", Status: TenantStatusActive, BillingLabel: "bl-contractlabelaaaa1", CreatedAt: now, UpdatedAt: now}
		assert.Error(t, store.CreateTenant(ctx, dup), "a second tenant with the same label must be rejected")
		_, err := store.GetTenant(ctx, "bl-dup")
		assert.ErrorIs(t, err, ErrTenantDoesNotExist)
	})

	t.Run("unlabelled create is assigned a distinct label", func(t *testing.T) {
		a := &TenantData{ID: "bl-auto-a", Name: "Auto", Status: TenantStatusActive, CreatedAt: now, UpdatedAt: now}
		b := &TenantData{ID: "bl-auto-b", Name: "Auto", Status: TenantStatusActive, CreatedAt: now, UpdatedAt: now}
		require.NoError(t, store.CreateTenant(ctx, a))
		require.NoError(t, store.CreateTenant(ctx, b))
		ga, err := store.GetTenant(ctx, "bl-auto-a")
		require.NoError(t, err)
		gb, err := store.GetTenant(ctx, "bl-auto-b")
		require.NoError(t, err)
		assert.NotEmpty(t, ga.BillingLabel)
		assert.NotEmpty(t, gb.BillingLabel)
		assert.NotEqual(t, ga.BillingLabel, gb.BillingLabel)
	})
}

// TenantStoreTopLevelContract verifies CreateTopLevelTenant's atomic single
// parentless-tenant guarantee (Issue #4547): concurrent calls through separate
// handles over one backing database produce exactly one success, the rest
// returning ErrTopLevelTenantExists. newHandle must return a fresh handle onto
// the same database on every call. Parentless tenants already in the database
// are deleted first so the race starts from none.
func TenantStoreTopLevelContract(t *testing.T, newHandle func() TenantStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	setup := newHandle()
	existing, err := setup.ListTenants(ctx, nil)
	require.NoError(t, err)
	children := map[string][]string{}
	for _, tn := range existing {
		children[tn.ParentID] = append(children[tn.ParentID], tn.ID)
	}
	// Delete each parentless tenant's subtree children-first: the parent_id
	// foreign key refuses to remove a tenant that still has children.
	var deleteSubtree func(id string)
	deleteSubtree = func(id string) {
		for _, child := range children[id] {
			deleteSubtree(child)
		}
		require.NoError(t, setup.DeleteTenant(ctx, id))
	}
	for _, id := range children[""] {
		deleteSubtree(id)
	}

	// The backing database may be shared with other tests; leave nothing behind.
	t.Cleanup(func() {
		// Children first, for the same foreign-key reason as above.
		for _, id := range []string{"top-under", "top-late", "top-child"} {
			_ = setup.DeleteTenant(ctx, id)
		}
		for i := 0; i < 8; i++ {
			_ = setup.DeleteTenant(ctx, fmt.Sprintf("top-%d", i))
		}
	})

	const racers = 8
	handles := make([]TenantStore, racers)
	for i := range handles {
		handles[i] = newHandle()
	}

	t.Run("concurrent creates through independent handles yield one success", func(t *testing.T) {
		errs := make([]error, racers)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = handles[i].CreateTopLevelTenant(ctx, &TenantData{
					ID: fmt.Sprintf("top-%d", i), Name: "Top", Status: TenantStatusActive, CreatedAt: now, UpdatedAt: now})
			}(i)
		}
		close(start)
		wg.Wait()

		successes := 0
		for _, e := range errs {
			if e == nil {
				successes++
			} else {
				assert.ErrorIs(t, e, ErrTopLevelTenantExists)
				assert.NotErrorIs(t, e, ErrTenantAlreadyExists)
			}
		}
		assert.Equal(t, 1, successes, "exactly one concurrent top-level create succeeds")

		all, err := setup.ListTenants(ctx, nil)
		require.NoError(t, err)
		parentless := 0
		for _, tn := range all {
			if tn.ParentID == "" {
				parentless++
			}
		}
		assert.Equal(t, 1, parentless)
	})

	t.Run("a later top-level create is refused", func(t *testing.T) {
		err := setup.CreateTopLevelTenant(ctx, &TenantData{ID: "top-late", Name: "Late", Status: TenantStatusActive, CreatedAt: now, UpdatedAt: now})
		assert.ErrorIs(t, err, ErrTopLevelTenantExists)
	})

	t.Run("a non-empty ParentID is rejected", func(t *testing.T) {
		err := setup.CreateTopLevelTenant(ctx, &TenantData{ID: "top-child", Name: "Child", ParentID: "top-late", Status: TenantStatusActive, CreatedAt: now, UpdatedAt: now})
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrTopLevelTenantExists)
		_, getErr := setup.GetTenant(ctx, "top-child")
		assert.ErrorIs(t, getErr, ErrTenantDoesNotExist)
	})

	t.Run("plain CreateTenant still accepts a tenant with a parent", func(t *testing.T) {
		all, err := setup.ListTenants(ctx, nil)
		require.NoError(t, err)
		var rootID string
		for _, tn := range all {
			if tn.ParentID == "" {
				rootID = tn.ID
			}
		}
		require.NotEmpty(t, rootID)
		require.NoError(t, setup.CreateTenant(ctx, &TenantData{ID: "top-under", Name: "Under", ParentID: rootID, Status: TenantStatusActive, CreatedAt: now, UpdatedAt: now}))
	})
}

// TenantStoreMissingTenantContract asserts that store signals "this tenant has no
// row" with the ErrTenantDoesNotExist sentinel from every operation that addresses a
// tenant by ID. Call it from each TenantStore provider's tests:
//
//	func TestMyTenantStore_MissingTenantContract(t *testing.T) {
//	    business.TenantStoreMissingTenantContract(t, openStore(t))
//	}
//
// Providers are free to phrase the message however they like — callers must use
// errors.Is, and this contract is what makes that safe. It exists because message
// phrasing diverged between providers once before: an API handler classifying a
// missing tenant by substring returned 404 on one provider and 500 on another, while
// an out-of-scope tenant returned 404 on both, so the status code disclosed the
// existence of tenants outside the caller's subtree.
//
// The store must be initialized and must not contain a tenant named by the probe ID.
// Lifecycle (Initialize/Close) stays with the caller.
func TenantStoreMissingTenantContract(t *testing.T, store TenantStore) {
	t.Helper()
	ctx := context.Background()
	const missingID = "contract-probe-tenant-absent"

	t.Run("GetTenant reports the sentinel", func(t *testing.T) {
		got, err := store.GetTenant(ctx, missingID)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.ErrorIs(t, err, ErrTenantDoesNotExist,
			"GetTenant on an absent tenant must wrap ErrTenantDoesNotExist so callers need not match message text")
	})

	t.Run("UpdateTenant reports the sentinel", func(t *testing.T) {
		err := store.UpdateTenant(ctx, &TenantData{
			ID:        missingID,
			Name:      "absent",
			Status:    TenantStatusActive,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTenantDoesNotExist,
			"UpdateTenant on an absent tenant must wrap ErrTenantDoesNotExist")
	})

	t.Run("DeleteTenant reports the sentinel", func(t *testing.T) {
		err := store.DeleteTenant(ctx, missingID)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTenantDoesNotExist,
			"DeleteTenant on an absent tenant must wrap ErrTenantDoesNotExist")
	})
}

// TenantCrossingStoreContract exercises TenantCrossingStore's full lifecycle: create,
// get, list, active-lookup, expiry, revoke, and the not-found sentinel. Call it from
// each provider's tests:
//
//	func TestMyTenantCrossingStore_Contract(t *testing.T) {
//	    business.TenantCrossingStoreContract(t, openStore(t))
//	}
//
// The store must be initialized and must not already contain a crossing for the probe
// tenant/principal IDs used here. Lifecycle (Initialize/Close) stays with the caller.
func TenantCrossingStoreContract(t *testing.T, store TenantCrossingStore) {
	t.Helper()
	ctx := context.Background()
	const tenantID = "contract-probe-msp"
	const principalID = "contract-probe-root-operator"

	t.Run("GetTenantCrossing on an absent ID reports the sentinel", func(t *testing.T) {
		got, err := store.GetTenantCrossing(ctx, "contract-probe-crossing-absent")
		require.Error(t, err)
		assert.Nil(t, got)
		assert.ErrorIs(t, err, ErrTenantCrossingNotFound)
	})

	t.Run("HasActiveTenantCrossing is false before any crossing exists", func(t *testing.T) {
		active, err := store.HasActiveTenantCrossing(ctx, principalID, tenantID)
		require.NoError(t, err)
		assert.False(t, active)
	})

	now := time.Now().UTC()
	crossing := &TenantCrossing{
		ID:          "contract-probe-crossing-1",
		TenantID:    tenantID,
		PrincipalID: principalID,
		Kind:        TenantCrossingKindGrant,
		GrantedBy:   "contract-probe-msp-admin",
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Hour),
	}
	require.NoError(t, store.CreateTenantCrossing(ctx, crossing))

	t.Run("GetTenantCrossing round-trips the created record", func(t *testing.T) {
		got, err := store.GetTenantCrossing(ctx, crossing.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, crossing.TenantID, got.TenantID)
		assert.Equal(t, crossing.PrincipalID, got.PrincipalID)
		assert.Equal(t, crossing.Kind, got.Kind)
		assert.Equal(t, crossing.GrantedBy, got.GrantedBy)
		assert.Nil(t, got.RevokedAt)
	})

	t.Run("HasActiveTenantCrossing is true once an unexpired, unrevoked crossing exists", func(t *testing.T) {
		active, err := store.HasActiveTenantCrossing(ctx, principalID, tenantID)
		require.NoError(t, err)
		assert.True(t, active)
	})

	t.Run("HasActiveTenantCrossing does not match a different principal or tenant", func(t *testing.T) {
		active, err := store.HasActiveTenantCrossing(ctx, "someone-else", tenantID)
		require.NoError(t, err)
		assert.False(t, active)

		active, err = store.HasActiveTenantCrossing(ctx, principalID, "some-other-tenant")
		require.NoError(t, err)
		assert.False(t, active)
	})

	t.Run("ListTenantCrossings returns the created record", func(t *testing.T) {
		list, err := store.ListTenantCrossings(ctx, tenantID)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, crossing.ID, list[0].ID)
	})

	t.Run("expired crossings are not active", func(t *testing.T) {
		expired := &TenantCrossing{
			ID:            "contract-probe-crossing-expired",
			TenantID:      tenantID,
			PrincipalID:   "contract-probe-root-operator-expired",
			Kind:          TenantCrossingKindBreakGlass,
			GrantedBy:     "contract-probe-root-operator-expired",
			Justification: "contract probe",
			CreatedAt:     now.Add(-2 * time.Hour),
			ExpiresAt:     now.Add(-time.Hour),
		}
		require.NoError(t, store.CreateTenantCrossing(ctx, expired))
		active, err := store.HasActiveTenantCrossing(ctx, expired.PrincipalID, tenantID)
		require.NoError(t, err)
		assert.False(t, active, "an expired crossing must not grant access")
	})

	t.Run("RevokeTenantCrossing ends an active crossing immediately", func(t *testing.T) {
		require.NoError(t, store.RevokeTenantCrossing(ctx, crossing.ID))
		active, err := store.HasActiveTenantCrossing(ctx, principalID, tenantID)
		require.NoError(t, err)
		assert.False(t, active, "a revoked crossing must not grant access even before its ExpiresAt")

		got, err := store.GetTenantCrossing(ctx, crossing.ID)
		require.NoError(t, err)
		require.NotNil(t, got.RevokedAt)
	})

	t.Run("RevokeTenantCrossing on an absent ID reports the sentinel", func(t *testing.T) {
		err := store.RevokeTenantCrossing(ctx, "contract-probe-crossing-absent")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTenantCrossingNotFound)
	})
}

func newContractBatchJob(id, tenantID string) *batchjob.BatchJob {
	now := time.Now().UTC()
	return &batchjob.BatchJob{
		ID:       id,
		TenantID: tenantID,
		Selector: "tag:prod",
		Config: batchjob.BatchJobConfig{
			BatchSize:         5,
			PreviousConfigRef: "cfg-v1",
		},
		Targets:     []string{"s-1", "s-2", "s-3"},
		Status:      batchjob.BatchJobStatusPending,
		Steps:       []batchjob.BatchStep{{Index: 0, StewardIDs: []string{"s-1"}, Status: batchjob.BatchStepStatusPending}},
		CreatedAt:   now,
		UpdatedAt:   now,
		InitiatedBy: "operator@example.com",
	}
}

// BatchJobStoreContract runs the full BatchJobStore contract test suite against store.
// Call from provider-specific test files to validate a new BatchJobStore implementation:
//
//	func TestMySQLiteBatchJobStore_Contract(t *testing.T) {
//	    store := openStore(t)
//	    business.BatchJobStoreContract(t, store)
//	}
func BatchJobStoreContract(t *testing.T, store BatchJobStore) {
	t.Helper()
	ctx := context.Background()

	require.NoError(t, store.Initialize(ctx))
	require.NoError(t, store.HealthCheck(ctx))

	t.Run("create and get round-trip", func(t *testing.T) {
		job := newContractBatchJob("ctr-job-1", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		got, err := store.GetBatchJob(ctx, "ctr-job-1")
		require.NoError(t, err)
		assert.Equal(t, "ctr-job-1", got.ID)
		assert.Equal(t, "tenant-1", got.TenantID)
		assert.Equal(t, batchjob.BatchJobStatusPending, got.Status)
		assert.Equal(t, "tag:prod", got.Selector)
		assert.Equal(t, 5, got.Config.BatchSize)
		assert.Equal(t, "cfg-v1", got.Config.PreviousConfigRef)
		assert.Equal(t, []string{"s-1", "s-2", "s-3"}, got.Targets)
		assert.Equal(t, "operator@example.com", got.InitiatedBy)
		assert.Len(t, got.Steps, 1)
	})

	t.Run("duplicate ID returns error", func(t *testing.T) {
		job := newContractBatchJob("ctr-job-dup", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))
		err := store.CreateBatchJob(ctx, job)
		require.Error(t, err)
	})

	t.Run("get not found returns ErrBatchJobNotFound", func(t *testing.T) {
		_, err := store.GetBatchJob(ctx, "ctr-no-such-id")
		assert.ErrorIs(t, err, ErrBatchJobNotFound)
	})

	t.Run("UpdateBatchJobStatus reflects in Get", func(t *testing.T) {
		job := newContractBatchJob("ctr-job-status", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		require.NoError(t, store.UpdateBatchJobStatus(ctx, "ctr-job-status", batchjob.BatchJobStatusRunning))
		got, err := store.GetBatchJob(ctx, "ctr-job-status")
		require.NoError(t, err)
		assert.Equal(t, batchjob.BatchJobStatusRunning, got.Status)

		require.NoError(t, store.UpdateBatchJobStatus(ctx, "ctr-job-status", batchjob.BatchJobStatusCompleted))
		got, err = store.GetBatchJob(ctx, "ctr-job-status")
		require.NoError(t, err)
		assert.Equal(t, batchjob.BatchJobStatusCompleted, got.Status)
	})

	t.Run("UpdateBatchJobStatus not found", func(t *testing.T) {
		err := store.UpdateBatchJobStatus(ctx, "ctr-ghost", batchjob.BatchJobStatusFailed)
		assert.ErrorIs(t, err, ErrBatchJobNotFound)
	})

	t.Run("UpdateBatchTargets reflects in Get", func(t *testing.T) {
		job := newContractBatchJob("ctr-job-targets", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		newTargets := []string{"s-10", "s-11", "s-12"}
		require.NoError(t, store.UpdateBatchTargets(ctx, "ctr-job-targets", newTargets))

		got, err := store.GetBatchJob(ctx, "ctr-job-targets")
		require.NoError(t, err)
		assert.Equal(t, newTargets, got.Targets)
	})

	t.Run("UpdateBatchTargets not found", func(t *testing.T) {
		err := store.UpdateBatchTargets(ctx, "ctr-ghost-targets", []string{"s-1"})
		assert.ErrorIs(t, err, ErrBatchJobNotFound)
	})

	t.Run("UpdateBatchStep round-trips step fields", func(t *testing.T) {
		job := newContractBatchJob("ctr-job-step", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		now := time.Now().UTC()
		step := batchjob.BatchStep{
			Index:         0,
			StewardIDs:    []string{"s-1"},
			Status:        batchjob.BatchStepStatusRunning,
			StartedAt:     &now,
			FailedIDs:     []string{"s-1"},
			RollbackJobID: "rj-001",
		}
		require.NoError(t, store.UpdateBatchStep(ctx, "ctr-job-step", step))

		got, err := store.GetBatchJob(ctx, "ctr-job-step")
		require.NoError(t, err)
		require.Len(t, got.Steps, 1)
		s := got.Steps[0]
		assert.Equal(t, 0, s.Index)
		assert.Equal(t, batchjob.BatchStepStatusRunning, s.Status)
		assert.Equal(t, []string{"s-1"}, s.FailedIDs)
		assert.Equal(t, "rj-001", s.RollbackJobID)
		require.NotNil(t, s.StartedAt)
	})

	t.Run("UpdateBatchStep not found", func(t *testing.T) {
		step := batchjob.BatchStep{Index: 0, Status: batchjob.BatchStepStatusFailed}
		err := store.UpdateBatchStep(ctx, "ctr-ghost-step", step)
		assert.ErrorIs(t, err, ErrBatchJobNotFound)
	})

	t.Run("UpdateBatchStep appends step with new index", func(t *testing.T) {
		job := newContractBatchJob("ctr-job-step-append", "tenant-1")
		require.NoError(t, store.CreateBatchJob(ctx, job))

		newStep := batchjob.BatchStep{
			Index:      1,
			StewardIDs: []string{"s-2"},
			Status:     batchjob.BatchStepStatusPending,
		}
		require.NoError(t, store.UpdateBatchStep(ctx, "ctr-job-step-append", newStep))

		got, err := store.GetBatchJob(ctx, "ctr-job-step-append")
		require.NoError(t, err)
		assert.Len(t, got.Steps, 2, "new index must be appended, not replace existing")
	})

	t.Run("ListBatchJobsByTenant scopes by tenant", func(t *testing.T) {
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-job-ta-1", "ctr-tenant-A")))
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-job-ta-2", "ctr-tenant-A")))
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-job-tb-1", "ctr-tenant-B")))

		listA, err := store.ListBatchJobsByTenant(ctx, "ctr-tenant-A")
		require.NoError(t, err)
		assert.Len(t, listA, 2)

		listB, err := store.ListBatchJobsByTenant(ctx, "ctr-tenant-B")
		require.NoError(t, err)
		assert.Len(t, listB, 1)
		assert.Equal(t, "ctr-job-tb-1", listB[0].ID)

		listNone, err := store.ListBatchJobsByTenant(ctx, "ctr-tenant-unknown")
		require.NoError(t, err)
		assert.Empty(t, listNone)
	})

	t.Run("ListBatchJobs scopes by tenant and paginates", func(t *testing.T) {
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-list-ta-1", "ctr-list-tenant-A")))
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-list-ta-2", "ctr-list-tenant-A")))
		require.NoError(t, store.CreateBatchJob(ctx, newContractBatchJob("ctr-list-tb-1", "ctr-list-tenant-B")))

		// Tenant-scoped: only tenant-A's jobs.
		listA, err := store.ListBatchJobs(ctx, "ctr-list-tenant-A", 50, 0)
		require.NoError(t, err)
		assert.Len(t, listA, 2)

		// Tenant-scoped with limit=1: pagination works.
		listA1, err := store.ListBatchJobs(ctx, "ctr-list-tenant-A", 1, 0)
		require.NoError(t, err)
		assert.Len(t, listA1, 1)

		// Global (empty tenant): returns all jobs including both tenants.
		listAll, err := store.ListBatchJobs(ctx, "", 500, 0)
		require.NoError(t, err)
		// At least the 3 we just inserted (other test cases may have inserted more).
		assert.GreaterOrEqual(t, len(listAll), 3)

		// Unknown tenant returns empty slice, not nil.
		listNone, err := store.ListBatchJobs(ctx, "ctr-list-tenant-unknown", 50, 0)
		require.NoError(t, err)
		assert.NotNil(t, listNone)
		assert.Empty(t, listNone)
	})

	require.NoError(t, store.Close())
}
