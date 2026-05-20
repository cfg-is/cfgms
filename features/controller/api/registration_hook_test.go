// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newTestApprovalHook builds a WorkflowApprovalHook backed by real git storage and workflow engine.
func newTestApprovalHook(t *testing.T) (*WorkflowApprovalHook, cfgconfig.ConfigStore) {
	t.Helper()

	storageManager := pkgtesting.SetupTestStorage(t)
	configStore := storageManager.GetConfigStore()

	registry := make(discovery.ModuleRegistry)
	errorConfig := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure: stewardconfig.ActionContinue,
	}
	moduleFactory := factory.New(registry, errorConfig, logging.NewNoopLogger())
	logger := logging.NewNoopLogger()
	engine := workflow.NewEngine(moduleFactory, logger, nil)

	hook := NewWorkflowApprovalHook(engine, configStore, logger)
	return hook, configStore
}

// sampleInput returns a RegistrationInput with typical test values.
func sampleInput() RegistrationInput {
	return RegistrationInput{
		Token: &registration.Token{
			Token:     "testtoken12345",
			TenantID:  "test-tenant",
			Group:     "prod",
			SingleUse: false,
		},
		SourceIP: "192.168.1.100",
	}
}

// storeApprovalWorkflow stores a workflow with the given variables under the well-known name,
// scoped to the test tenant ID used by sampleInput().
func storeApprovalWorkflow(t *testing.T, configStore cfgconfig.ConfigStore, variables map[string]interface{}) {
	t.Helper()

	// Minimal steps list — always include a noop sequential so the engine has something to run.
	steps := []workflow.Step{{
		Name:  "noop",
		Type:  workflow.StepTypeSequential,
		Steps: []workflow.Step{},
	}}

	wf := &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{
			Name:      registrationWorkflowName,
			Variables: variables,
			Steps:     steps,
		},
		SemanticVersion: workflow.SemanticVersion{Major: 1, Minor: 0, Patch: 0},
	}

	// Use the same tenant ID as sampleInput() so the hook finds the workflow.
	store := workflow.NewWorkflowStore(configStore, "test-tenant")
	err := store.StoreWorkflow(context.Background(), wf)
	require.NoError(t, err)
}

// rejectHook is a test-only RegistrationApprovalHook that always rejects.
type rejectHook struct{}

func (*rejectHook) Evaluate(_ context.Context, _ RegistrationInput) (ApprovalDecision, string, error) {
	return DecisionReject, "automated rejection for test", nil
}

// errorHook is a test-only RegistrationApprovalHook that always returns an error.
type errorHook struct{}

func (*errorHook) Evaluate(_ context.Context, _ RegistrationInput) (ApprovalDecision, string, error) {
	return DecisionApprove, "", fmt.Errorf("hook failure injected by test")
}

// --- DefaultApprovalHook ---

func TestDefaultApprovalHook_AlwaysApproves(t *testing.T) {
	hook := &DefaultApprovalHook{}
	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decision)
	assert.Empty(t, reason)
}

func TestDefaultApprovalHook_ApprovesWithExpiredToken(t *testing.T) {
	hook := &DefaultApprovalHook{}
	exp := time.Now().Add(-1 * time.Hour) // expired
	input := sampleInput()
	input.Token.ExpiresAt = &exp
	decision, _, err := hook.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decision)
}

// --- WorkflowApprovalHook: no workflow configured ---

func TestWorkflowApprovalHook_NoWorkflowConfigured_Approves(t *testing.T) {
	hook, _ := newTestApprovalHook(t)
	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decision)
	assert.Empty(t, reason)
}

// --- WorkflowApprovalHook: policy: accept shorthand ---

func TestWorkflowApprovalHook_PolicyAccept_ApprovesWithoutRunningEngine(t *testing.T) {
	hook, configStore := newTestApprovalHook(t)
	storeApprovalWorkflow(t, configStore, map[string]interface{}{
		"policy": "accept",
	})

	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decision)
	assert.Empty(t, reason)
}

// --- WorkflowApprovalHook: explicit approve ---

func TestWorkflowApprovalHook_WorkflowSetsApprove_Approves(t *testing.T) {
	hook, configStore := newTestApprovalHook(t)
	storeApprovalWorkflow(t, configStore, map[string]interface{}{
		registrationDecisionVar: "approve",
	})

	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decision)
	assert.Empty(t, reason)
}

// --- WorkflowApprovalHook: reject ---

func TestWorkflowApprovalHook_WorkflowRejects_ReturnsReject(t *testing.T) {
	hook, configStore := newTestApprovalHook(t)
	storeApprovalWorkflow(t, configStore, map[string]interface{}{
		registrationDecisionVar:        "reject",
		registrationRejectionReasonVar: "automated rejection policy",
	})

	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionReject, decision)
	assert.Equal(t, "automated rejection policy", reason)
}

func TestWorkflowApprovalHook_WorkflowRejectsNoReason_ReturnsReject(t *testing.T) {
	hook, configStore := newTestApprovalHook(t)
	storeApprovalWorkflow(t, configStore, map[string]interface{}{
		registrationDecisionVar: "reject",
	})

	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionReject, decision)
	assert.Empty(t, reason)
}

// --- WorkflowApprovalHook: quarantine ---

func TestWorkflowApprovalHook_WorkflowQuarantines_ReturnsQuarantine(t *testing.T) {
	hook, configStore := newTestApprovalHook(t)
	storeApprovalWorkflow(t, configStore, map[string]interface{}{
		registrationDecisionVar: "quarantine",
	})

	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionQuarantine, decision)
	assert.Empty(t, reason)
}

// --- WorkflowApprovalHook: no decision variable set ---

func TestWorkflowApprovalHook_WorkflowSetsNoDecision_Approves(t *testing.T) {
	hook, configStore := newTestApprovalHook(t)
	// Workflow runs successfully but doesn't set registration_decision
	storeApprovalWorkflow(t, configStore, map[string]interface{}{})

	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decision)
	assert.Empty(t, reason)
}

// --- WorkflowApprovalHook: unknown decision value defaults to approve ---

func TestWorkflowApprovalHook_UnknownDecisionValue_Approves(t *testing.T) {
	hook, configStore := newTestApprovalHook(t)
	storeApprovalWorkflow(t, configStore, map[string]interface{}{
		registrationDecisionVar: "unknown-policy",
	})

	decision, _, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decision)
}

// --- WorkflowApprovalHook: context cancellation fails open ---

// TestWorkflowApprovalHook_ContextCancelled_DefaultsToApprove verifies that context
// cancellation results in the fail-open approve decision.  A cancelled context may
// cause the workflow engine to return an error or the select to pick ctx.Done();
// either way the hook falls back to approve to avoid blocking legitimate registrations.
func TestWorkflowApprovalHook_ContextCancelled_DefaultsToApprove(t *testing.T) {
	hook, configStore := newTestApprovalHook(t)
	storeApprovalWorkflow(t, configStore, map[string]interface{}{
		registrationDecisionVar: "reject", // would reject if context were healthy
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel the context

	// With a cancelled context, the hook must not block and must fail open.
	decision, _, _ := hook.Evaluate(ctx, sampleInput())
	assert.Equal(t, DecisionApprove, decision,
		"context cancellation must fail open (approve) to avoid blocking registrations")
}

// --- WorkflowApprovalHook: token metadata with expiry is handled ---

// TestWorkflowApprovalHook_TokenWithExpiry_WorkflowRuns verifies that a token with
// an expiry date is correctly marshalled into workflow input variables and the workflow
// runs to completion.  The reject outcome confirms the engine was invoked (not the
// no-workflow fallback path) and that the result is correctly interpreted.
func TestWorkflowApprovalHook_TokenWithExpiry_WorkflowRuns(t *testing.T) {
	hook, configStore := newTestApprovalHook(t)
	storeApprovalWorkflow(t, configStore, map[string]interface{}{
		registrationDecisionVar: "reject", // confirms workflow ran, not no-workflow fallback
	})

	exp := time.Now().Add(24 * time.Hour)
	input := RegistrationInput{
		Token: &registration.Token{
			Token:     "sometoken",
			TenantID:  "test-tenant", // must match stored workflow tenant
			Group:     "servers",
			SingleUse: true,
			ExpiresAt: &exp,
		},
		SourceIP: "10.0.0.1",
	}

	decision, _, err := hook.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, DecisionReject, decision,
		"workflow ran and returned reject, confirming token metadata with expiry was accepted")
}

// --- WorkflowHandler.NewRegistrationApprovalHook ---

func TestWorkflowHandler_NewRegistrationApprovalHook_ReturnsHook(t *testing.T) {
	handler, _ := newTestWorkflowHandler(t)
	logger := logging.NewNoopLogger()
	hook := handler.NewRegistrationApprovalHook(logger)
	require.NotNil(t, hook)

	// The hook should work: no workflow configured → approve
	decision, _, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decision)
}

func TestWorkflowHandler_NewRegistrationApprovalHook_NilEngine_ReturnsDefault(t *testing.T) {
	h := NewWorkflowHandler(nil, nil, nil, logging.NewNoopLogger())
	logger := logging.NewNoopLogger()
	hook := h.NewRegistrationApprovalHook(logger)
	require.NotNil(t, hook)

	// Should be the DefaultApprovalHook (nil engine → always approve)
	decision, _, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decision)
}

// --- Handler integration: hook decisions reach handleRegister ---

// TestHandleRegister_HookRejects_Returns403 verifies that when the approval hook returns
// DecisionReject, handleRegister returns HTTP 403 Forbidden.  This is the key handler-level
// test for the reject code path added by Issue #422.
func TestHandleRegister_HookRejects_Returns403(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	server.SetApprovalHook(&rejectHook{})

	// Create a valid token in the store.
	token := &registration.Token{
		Token:     "validtoken123456",
		TenantID:  "test-tenant",
		Group:     "prod",
		CreatedAt: time.Now(),
		SingleUse: false,
	}
	err := tokenStore.SaveToken(context.Background(), token)
	require.NoError(t, err)

	body, _ := json.Marshal(RegistrationRequest{Token: token.Token})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"reject decision must produce 403 Forbidden")

	// Verify audit entry for hook-rejected registration
	require.NotNil(t, server.auditManager, "audit manager must be wired by setupTestServerWithTokenStore")
	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "test-tenant"})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "registration_rejected", entries[0].Action)
	assert.Equal(t, string(business.AuditResultDenied), string(entries[0].Result))
	assert.Equal(t, string(business.AuditEventSecurityEvent), string(entries[0].EventType))
}

// TestHandleRegister_HookError_FailsOpen verifies that when the approval hook returns an
// error, handleRegister falls back to approve (fail-open) and continues with normal
// registration processing (not 403 Forbidden).
func TestHandleRegister_HookError_FailsOpen(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	server.SetApprovalHook(&errorHook{})

	// Create a valid token in the store.
	token := &registration.Token{
		Token:     "validtoken789012",
		TenantID:  "test-tenant",
		Group:     "prod",
		CreatedAt: time.Now(),
		SingleUse: false,
	}
	err := tokenStore.SaveToken(context.Background(), token)
	require.NoError(t, err)

	body, _ := json.Marshal(RegistrationRequest{Token: token.Token})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	// The hook error causes fail-open: the request should not be rejected (403).
	// Without a cert manager, the handler returns 500 at certificate generation.
	// Either way it must NOT be 403 Forbidden (which would mean the hook error was
	// incorrectly treated as a rejection).
	assert.NotEqual(t, http.StatusForbidden, rec.Code,
		"hook error must fail open — not treated as a rejection")
}

// --- ManualReviewApprovalHook ---

// newTestManualReviewHook builds a ManualReviewApprovalHook backed by a real SQLite store.
func newTestManualReviewHook(t *testing.T) (*ManualReviewApprovalHook, business.PendingRegistrationStore) {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	pendingStore := sm.GetPendingRegistrationStore()
	require.NotNil(t, pendingStore, "OSS storage manager must provide a PendingRegistrationStore")
	hook := NewManualReviewApprovalHook(pendingStore, 24*time.Hour, logging.NewNoopLogger())
	t.Cleanup(func() { hook.Stop() })
	return hook, pendingStore
}

func TestManualReviewApprovalHook_StoresPendingAndReturnsQuarantine(t *testing.T) {
	hook, pendingStore := newTestManualReviewHook(t)

	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionQuarantine, decision, "manual-review hook must return quarantine")
	assert.Empty(t, reason)

	// Verify the pending record was created in the store.
	pending := business.PendingRegistrationStatusPending
	records, err := pendingStore.ListPending(context.Background(), &business.PendingRegistrationFilter{Status: &pending})
	require.NoError(t, err)
	require.Len(t, records, 1, "one pending registration must be stored")
	assert.Equal(t, "test-tenant", records[0].TenantID)
	assert.Equal(t, "192.168.1.100", records[0].SourceIP)
	assert.Equal(t, business.PendingRegistrationStatusPending, records[0].Status)
	// The full token must NOT be stored — only the redacted prefix.
	assert.Empty(t, records[0].StewardID, "StewardID must be empty until operator approves")
	assert.NotEmpty(t, records[0].TokenPrefix, "TokenPrefix must hold the redacted token prefix")
	assert.NotContains(t, records[0].TokenPrefix, "testtoken12345", "full token must not appear in TokenPrefix")
}

func TestManualReviewApprovalHook_ExpiresAtSetToTimeout(t *testing.T) {
	hook, pendingStore := newTestManualReviewHook(t)
	before := time.Now().UTC()

	_, _, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)

	after := time.Now().UTC()

	pending := business.PendingRegistrationStatusPending
	records, err := pendingStore.ListPending(context.Background(), &business.PendingRegistrationFilter{Status: &pending})
	require.NoError(t, err)
	require.Len(t, records, 1)

	// ExpiresAt should be approximately 24 hours from now.
	expectedMin := before.Add(23 * time.Hour)
	expectedMax := after.Add(25 * time.Hour)
	assert.True(t, records[0].ExpiresAt.After(expectedMin),
		"expires_at must be at least 23h from now, got %v", records[0].ExpiresAt)
	assert.True(t, records[0].ExpiresAt.Before(expectedMax),
		"expires_at must be at most 25h from now, got %v", records[0].ExpiresAt)
}

func TestManualReviewApprovalHook_ContextCancelled_FailsOpen(t *testing.T) {
	hook, _ := newTestManualReviewHook(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	decision, _, _ := hook.Evaluate(ctx, sampleInput())
	assert.Equal(t, DecisionApprove, decision,
		"cancelled context must fail open (approve) to avoid blocking registrations")
}

func TestManualReviewApprovalHook_MultipleRegistrationsSameTenant(t *testing.T) {
	hook, pendingStore := newTestManualReviewHook(t)
	ctx := context.Background()

	// Simulate two stewards registering.
	for i := 0; i < 3; i++ {
		decision, _, err := hook.Evaluate(ctx, sampleInput())
		require.NoError(t, err)
		assert.Equal(t, DecisionQuarantine, decision)
	}

	records, err := pendingStore.ListPending(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, records, 3, "each registration must create a separate pending record")
}

func TestManualReviewApprovalHook_ExpireTimedOut(t *testing.T) {
	_, pendingStore := newTestManualReviewHook(t)
	ctx := context.Background()

	// Manually create a record that already expired.
	record := &business.PendingRegistrationData{
		ID:        "pr-expired-test",
		StewardID: "steward-x",
		TenantID:  "test-tenant",
		SourceIP:  "10.0.0.1",
		Status:    business.PendingRegistrationStatusPending,
		CreatedAt: time.Now().UTC().Add(-25 * time.Hour),
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	require.NoError(t, pendingStore.CreatePending(ctx, record))

	// Create the hook with a very short sweep interval — we'll call expiry directly
	// via a hook with access to its internal method, but here we simulate by using
	// the store's filter. Use a fresh hook to trigger expiry via expireTimedOut.
	hook := NewManualReviewApprovalHook(pendingStore, 24*time.Hour, logging.NewNoopLogger())
	defer hook.Stop()

	// Manually invoke the expiry sweep.
	hook.expireTimedOut(ctx)

	// The expired record must now be timed-out.
	got, err := pendingStore.GetPending(ctx, "pr-expired-test")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusTimedOut, got.Status)
}
