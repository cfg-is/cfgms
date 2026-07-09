// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package completion_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/features/modules/hyperv/completion"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestCompletionReconciler_MatchAdvancesToReady verifies that OnConnect with a
// stewardID matching a finalizing record's CorrelationID advances that record
// to ready.
func TestCompletionReconciler_MatchAdvancesToReady(t *testing.T) {
	ctx := context.Background()
	store := hyperv.NewMemProvisionStore()
	now := time.Now()

	rec := &hyperv.ProvisionRecord{
		VMName:        "vm-01",
		State:         hyperv.ProvisionStateFinalizing,
		CorrelationID: "vm-01",
		StartedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, store.SetProvision(ctx, rec))

	r := completion.New(store, logging.NewNoopLogger())
	require.NoError(t, r.OnConnect(ctx, "vm-01"))

	got, err := store.GetProvision(ctx, "vm-01")
	require.NoError(t, err)
	assert.Equal(t, hyperv.ProvisionStateReady, got.State, "matching stewardID must advance record to ready")
}

// TestCompletionReconciler_MatchIsCaseInsensitive verifies that CorrelationID
// matching is case-insensitive.
func TestCompletionReconciler_MatchIsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	store := hyperv.NewMemProvisionStore()
	now := time.Now()

	rec := &hyperv.ProvisionRecord{
		VMName:        "vm-02",
		State:         hyperv.ProvisionStateFinalizing,
		CorrelationID: "VM-02",
		StartedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, store.SetProvision(ctx, rec))

	r := completion.New(store, logging.NewNoopLogger())
	require.NoError(t, r.OnConnect(ctx, "vm-02"))

	got, err := store.GetProvision(ctx, "vm-02")
	require.NoError(t, err)
	assert.Equal(t, hyperv.ProvisionStateReady, got.State, "CorrelationID match must be case-insensitive")
}

// TestCompletionReconciler_NoMatchLeavesRecordUnchanged verifies that a
// non-matching stewardID leaves the finalizing record unchanged.
func TestCompletionReconciler_NoMatchLeavesRecordUnchanged(t *testing.T) {
	ctx := context.Background()
	store := hyperv.NewMemProvisionStore()
	now := time.Now()

	rec := &hyperv.ProvisionRecord{
		VMName:        "vm-03",
		State:         hyperv.ProvisionStateFinalizing,
		CorrelationID: "vm-03",
		StartedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, store.SetProvision(ctx, rec))

	r := completion.New(store, logging.NewNoopLogger())
	require.NoError(t, r.OnConnect(ctx, "vm-other"))

	got, err := store.GetProvision(ctx, "vm-03")
	require.NoError(t, err)
	assert.Equal(t, hyperv.ProvisionStateFinalizing, got.State, "non-matching stewardID must leave record unchanged")
}

// TestCompletionReconciler_TimeoutSweepAdvancesToFailed injects a short timeout
// and verifies that overdue non-terminal records are advanced to failed.
func TestCompletionReconciler_TimeoutSweepAdvancesToFailed(t *testing.T) {
	ctx := context.Background()
	store := hyperv.NewMemProvisionStore()

	pastTime := time.Now().Add(-2 * time.Second)
	rec := &hyperv.ProvisionRecord{
		VMName:        "vm-04",
		State:         hyperv.ProvisionStateInstalling,
		CorrelationID: "vm-04",
		StartedAt:     pastTime,
		UpdatedAt:     pastTime,
	}
	require.NoError(t, store.SetProvision(ctx, rec))

	r := completion.New(store, logging.NewNoopLogger(), completion.WithCompletionTimeout(time.Second))
	require.NoError(t, r.OnConnect(ctx, "vm-unrelated"))

	got, err := store.GetProvision(ctx, "vm-04")
	require.NoError(t, err)
	assert.Equal(t, hyperv.ProvisionStateFailed, got.State, "overdue record must be advanced to failed")
	assert.Contains(t, got.LastError, "completion.timeout", "LastError must mention completion.timeout")
}

// TestCompletionReconciler_TimeoutSweepSkipsTerminalRecords verifies that
// terminal records (ready, failed) are not modified by the timeout sweep.
func TestCompletionReconciler_TimeoutSweepSkipsTerminalRecords(t *testing.T) {
	ctx := context.Background()
	store := hyperv.NewMemProvisionStore()

	pastTime := time.Now().Add(-10 * time.Minute)
	recReady := &hyperv.ProvisionRecord{
		VMName:        "vm-ready",
		State:         hyperv.ProvisionStateReady,
		CorrelationID: "vm-ready",
		StartedAt:     pastTime,
		UpdatedAt:     pastTime,
	}
	recFailed := &hyperv.ProvisionRecord{
		VMName:        "vm-failed",
		State:         hyperv.ProvisionStateFailed,
		CorrelationID: "vm-failed",
		StartedAt:     pastTime,
		UpdatedAt:     pastTime,
		LastError:     "prior error",
	}
	require.NoError(t, store.SetProvision(ctx, recReady))
	require.NoError(t, store.SetProvision(ctx, recFailed))

	r := completion.New(store, logging.NewNoopLogger(), completion.WithCompletionTimeout(time.Millisecond))
	require.NoError(t, r.OnConnect(ctx, "vm-unrelated"))

	gotReady, err := store.GetProvision(ctx, "vm-ready")
	require.NoError(t, err)
	assert.Equal(t, hyperv.ProvisionStateReady, gotReady.State, "ready record must not be touched")

	gotFailed, err := store.GetProvision(ctx, "vm-failed")
	require.NoError(t, err)
	assert.Equal(t, hyperv.ProvisionStateFailed, gotFailed.State, "failed record must not be touched")
	assert.Equal(t, "prior error", gotFailed.LastError, "prior error must not be overwritten")
}

// TestCompletionReconciler_TimeoutWinsOverCorrelationMatch verifies that a
// timed-out finalizing record is advanced to failed even when the connecting
// stewardID matches its CorrelationID.
func TestCompletionReconciler_TimeoutWinsOverCorrelationMatch(t *testing.T) {
	ctx := context.Background()
	store := hyperv.NewMemProvisionStore()

	pastTime := time.Now().Add(-2 * time.Second)
	rec := &hyperv.ProvisionRecord{
		VMName:        "vm-05",
		State:         hyperv.ProvisionStateFinalizing,
		CorrelationID: "vm-05",
		StartedAt:     pastTime,
		UpdatedAt:     pastTime,
	}
	require.NoError(t, store.SetProvision(ctx, rec))

	r := completion.New(store, logging.NewNoopLogger(), completion.WithCompletionTimeout(time.Second))
	require.NoError(t, r.OnConnect(ctx, "vm-05"))

	got, err := store.GetProvision(ctx, "vm-05")
	require.NoError(t, err)
	assert.Equal(t, hyperv.ProvisionStateFailed, got.State, "timeout must win over correlationID match")
}

// TestCompletionReconciler_NilStoreIsNoOp verifies that a nil store in the
// reconciler does not panic.
func TestCompletionReconciler_NilStoreIsNoOp(t *testing.T) {
	r := completion.New(nil, logging.NewNoopLogger())
	require.NoError(t, r.OnConnect(context.Background(), "some-steward"))
}
