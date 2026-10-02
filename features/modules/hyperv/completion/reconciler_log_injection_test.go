// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package completion_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/features/modules/hyperv/completion"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ─── Issue #4341: log-injection coverage for reconciler.go's SetProvision
// failure Warn calls ────────────────────────────────────────────────────────
//
// CLAUDE.md's sanitization rule ("error", logging.SanitizeLogValue(err.Error()),
// never "error", err) applies to error values, not just the vm_name field
// already sanitized at each of these call sites. A store error can carry
// externally-influenced content back out inside its message text. Each test
// below forces a CR/LF-laden error out of ProvisionStore.SetProvision and
// asserts the "error" field reaching the captured log record has no raw \r
// or \n.

// injectedStoreError is a CR/LF-laden error standing in for a tainted value a
// compromised or malicious backing store could surface.
const injectedStoreError = "store fault\r\nINJECTED forged-log-line: evil=1\r\nmore"

// setFailProvisionStore wraps a real hyperv.ProvisionStore and forces every
// SetProvision call to fail with err, delegating every other method
// (GetProvision, DeleteProvision, ListProvisions) to the wrapped store
// unchanged. A plain always-erroring store cannot be used here because
// OnConnect's own read paths (ListProvisions, and — on the match path —
// nothing extra) must keep succeeding for execution to ever reach the
// SetProvision call this file targets.
type setFailProvisionStore struct {
	hyperv.ProvisionStore
	err error
}

func (s *setFailProvisionStore) SetProvision(context.Context, *hyperv.ProvisionRecord) error {
	return s.err
}

// TestOnConnect_TimeoutSweepSetProvisionFailure_LogsSanitizedError covers the
// timeout-sweep branch's Warn call ("hyperv completion: failed to mark
// timed-out record"), which previously logged the raw error value directly
// instead of logging.SanitizeLogValue(setErr.Error()).
func TestOnConnect_TimeoutSweepSetProvisionFailure_LogsSanitizedError(t *testing.T) {
	ctx := context.Background()
	past := time.Now().Add(-2 * time.Hour)

	base := hyperv.NewMemProvisionStore()
	rec := &hyperv.ProvisionRecord{
		VMName:    "vm-timeout-logsan",
		State:     hyperv.ProvisionStateFinalizing,
		StartedAt: past,
		UpdatedAt: past,
	}
	require.NoError(t, base.SetProvision(ctx, rec))

	store := &setFailProvisionStore{ProvisionStore: base, err: errors.New(injectedStoreError)}
	capLog := logging.NewCapturingLogger()
	r := completion.New(store, capLog, completion.WithCompletionTimeout(time.Minute))

	require.NoError(t, r.OnConnect(ctx, "irrelevant-steward"))

	entry, found := capLog.FindWarn("hyperv completion: failed to mark timed-out record")
	require.True(t, found, "a SetProvision failure during the timeout sweep must be logged")

	errVal, ok := entry["error"].(string)
	require.True(t, ok, "error field must be a sanitized string, not a raw error value")
	assert.NotContains(t, errVal, "\r", "sanitized error must not carry a raw CR")
	assert.NotContains(t, errVal, "\n", "sanitized error must not carry a raw LF")
}

// TestOnConnect_AdvanceToReadySetProvisionFailure_LogsSanitizedError covers
// the CorrelationID-match branch's Warn call ("hyperv completion: failed to
// advance record to ready"), which previously logged the raw error value
// directly instead of logging.SanitizeLogValue(setErr.Error()).
func TestOnConnect_AdvanceToReadySetProvisionFailure_LogsSanitizedError(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	base := hyperv.NewMemProvisionStore()
	rec := &hyperv.ProvisionRecord{
		VMName:        "vm-ready-logsan",
		State:         hyperv.ProvisionStateFinalizing,
		CorrelationID: "vm-ready-logsan",
		StartedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, base.SetProvision(ctx, rec))

	store := &setFailProvisionStore{ProvisionStore: base, err: errors.New(injectedStoreError)}
	capLog := logging.NewCapturingLogger()
	r := completion.New(store, capLog)

	err := r.OnConnect(ctx, "vm-ready-logsan")
	require.Error(t, err, "a SetProvision failure on the match path must propagate")

	entry, found := capLog.FindWarn("hyperv completion: failed to advance record to ready")
	require.True(t, found)

	errVal, ok := entry["error"].(string)
	require.True(t, ok, "error field must be a sanitized string, not a raw error value")
	assert.NotContains(t, errVal, "\r", "sanitized error must not carry a raw CR")
	assert.NotContains(t, errVal, "\n", "sanitized error must not carry a raw LF")
}
