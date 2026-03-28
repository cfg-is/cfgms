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
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Auto-register git storage provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

// newTestApprovalHook builds a WorkflowApprovalHook backed by real git storage and workflow engine.
func newTestApprovalHook(t *testing.T) (*WorkflowApprovalHook, interfaces.ConfigStore) {
	t.Helper()

	storageConfig := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":          "main",
		"auto_init":       true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", storageConfig)
	require.NoError(t, err)
	configStore := storageManager.GetConfigStore()

	registry := make(discovery.ModuleRegistry)
	errorConfig := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure: stewardconfig.ActionContinue,
	}
	moduleFactory := factory.New(registry, errorConfig)
	logger := logging.NewNoopLogger()
	engine := workflow.NewEngine(moduleFactory, logger)

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
func storeApprovalWorkflow(t *testing.T, configStore interfaces.ConfigStore, variables map[string]interface{}) {
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
