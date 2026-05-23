// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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

// testIPTrustStore is a minimal in-memory IPTrustStore for hook unit tests.
type testIPTrustStore struct {
	mu      sync.RWMutex
	trusted map[string]bool // key: tenantID+"\x00"+ip
	err     error           // when non-nil, IsTrusted returns this error
}

func newTestIPTrustStore() *testIPTrustStore {
	return &testIPTrustStore{trusted: make(map[string]bool)}
}

func (s *testIPTrustStore) key(tenantID, ip string) string { return tenantID + "\x00" + ip }

func (s *testIPTrustStore) AddTrustedRange(_ context.Context, tenantID, cidr string, _ bool) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	// For testing simplicity, record the network address as "trusted".
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trusted[s.key(tenantID, ipNet.IP.String())] = true
	return nil
}

func (s *testIPTrustStore) IsTrusted(_ context.Context, tenantID, ip string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.err != nil {
		return false, s.err
	}
	return s.trusted[s.key(tenantID, ip)], nil
}

func (s *testIPTrustStore) ListTrustedRanges(_ context.Context, _ string) ([]*business.IPTrustEntry, error) {
	return nil, nil
}
func (s *testIPTrustStore) RevokeTrustedRange(_ context.Context, _, _ string) error { return nil }
func (s *testIPTrustStore) RecordHealthySteward(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}
func (s *testIPTrustStore) GetLastActivity(_ context.Context, _, _ string) (*business.IPTrustActivity, error) {
	return nil, nil
}

// setTrusted marks an IP as trusted for a tenant.
func (s *testIPTrustStore) setTrusted(tenantID, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trusted[s.key(tenantID, ip)] = true
}

// setError makes IsTrusted return the given error.
func (s *testIPTrustStore) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

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
			Token:    "testtoken12345",
			TenantID: "test-tenant",
			Group:    "prod",
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

// --- AlwaysApproveHook (replaces removed DefaultApprovalHook) ---

func TestAlwaysApproveHook_AlwaysApproves(t *testing.T) {
	hook := &AlwaysApproveHook{}
	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decision)
	assert.Empty(t, reason)
}

func TestAlwaysApproveHook_ApprovesWithExpiredToken(t *testing.T) {
	hook := &AlwaysApproveHook{}
	exp := time.Now().Add(-1 * time.Hour) // expired
	input := sampleInput()
	input.Token.ExpiresAt = &exp
	decision, _, err := hook.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decision)
}

// --- IPTrustApprovalHook ---

func TestIPTrustApprovalHook_TrustedIP_ReturnsApprove(t *testing.T) {
	store := newTestIPTrustStore()
	store.setTrusted("test-tenant", "192.168.1.100")

	hook := NewIPTrustApprovalHook(store, logging.NewNoopLogger())
	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())

	require.NoError(t, err, "Evaluate must not return an error for trusted IP")
	assert.Equal(t, DecisionApprove, decision, "trusted IP must get DecisionApprove")
	assert.Empty(t, reason)
}

func TestIPTrustApprovalHook_UntrustedIP_ReturnsQuarantine(t *testing.T) {
	store := newTestIPTrustStore()
	// "192.168.1.100" is NOT added as trusted.

	hook := NewIPTrustApprovalHook(store, logging.NewNoopLogger())
	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())

	require.NoError(t, err, "Evaluate must not return an error for untrusted IP")
	assert.Equal(t, DecisionQuarantine, decision, "untrusted IP must get DecisionQuarantine")
	assert.Empty(t, reason)
}

func TestIPTrustApprovalHook_StoreError_ReturnsQuarantine(t *testing.T) {
	store := newTestIPTrustStore()
	store.setError(fmt.Errorf("store unavailable"))

	hook := NewIPTrustApprovalHook(store, logging.NewNoopLogger())
	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())

	// Fail-closed: store error must produce quarantine with nil error so the
	// registration handler honours the quarantine decision instead of defaulting to approve.
	require.NoError(t, err, "Evaluate must return nil error on store failure (fail-closed)")
	assert.Equal(t, DecisionQuarantine, decision, "store error must fail closed (quarantine)")
	assert.Empty(t, reason)
}

// TestIPTrustApprovalHook_StoreError_SanitizesLogValue verifies the store-error
// Warn log sanitizes the error string. The trust store echoes the request-derived
// source IP back in its error; an attacker-injected CR/LF must not reach the log
// verbatim (closes the CodeQL go/log-injection alert).
func TestIPTrustApprovalHook_StoreError_SanitizesLogValue(t *testing.T) {
	store := newTestIPTrustStore()
	store.setError(fmt.Errorf("invalid IP address: 10.0.0.1\nforged-log-line key=value"))

	logger := pkgtesting.NewMockLogger(true)
	hook := NewIPTrustApprovalHook(store, logger)
	decision, _, err := hook.Evaluate(context.Background(), sampleInput())

	require.NoError(t, err)
	assert.Equal(t, DecisionQuarantine, decision)

	warnLogs := logger.GetLogs("warn")
	require.Len(t, warnLogs, 1, "store error must emit exactly one Warn log")

	var errVal string
	var found bool
	data := warnLogs[0].Data
	for i := 0; i+1 < len(data); i += 2 {
		if key, ok := data[i].(string); ok && key == "error" {
			errVal, _ = data[i+1].(string)
			found = true
		}
	}
	require.True(t, found, "Warn log must carry an 'error' key")
	assert.NotContains(t, errVal, "\n", "logged error must not contain a raw newline (log-injection)")
	assert.NotContains(t, errVal, "\r", "logged error must not contain a raw carriage return")
}

func TestIPTrustApprovalHook_NilStore_ReturnsQuarantine(t *testing.T) {
	hook := NewIPTrustApprovalHook(nil, logging.NewNoopLogger())
	decision, _, err := hook.Evaluate(context.Background(), sampleInput())

	require.NoError(t, err)
	assert.Equal(t, DecisionQuarantine, decision, "nil store must fail closed (quarantine)")
}

func TestIPTrustApprovalHook_DifferentTenants_Isolated(t *testing.T) {
	store := newTestIPTrustStore()
	// Only trust the IP under "tenant-a", not "tenant-b".
	store.setTrusted("tenant-a", "10.0.0.1")

	hook := NewIPTrustApprovalHook(store, logging.NewNoopLogger())

	inputA := RegistrationInput{
		Token:    &registration.Token{Token: "tok", TenantID: "tenant-a"},
		SourceIP: "10.0.0.1",
	}
	inputB := RegistrationInput{
		Token:    &registration.Token{Token: "tok", TenantID: "tenant-b"},
		SourceIP: "10.0.0.1",
	}

	decA, _, err := hook.Evaluate(context.Background(), inputA)
	require.NoError(t, err)
	assert.Equal(t, DecisionApprove, decA, "tenant-a trusts this IP")

	decB, _, err := hook.Evaluate(context.Background(), inputB)
	require.NoError(t, err)
	assert.Equal(t, DecisionQuarantine, decB, "tenant-b does not trust this IP")
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

	// nil engine → AlwaysApproveHook (always approve)
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

func TestManualReviewApprovalHook_ReturnsQuarantine(t *testing.T) {
	hook, _ := newTestManualReviewHook(t)

	decision, reason, err := hook.Evaluate(context.Background(), sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionQuarantine, decision, "manual-review hook must always return quarantine")
	assert.Empty(t, reason)
}

func TestManualReviewApprovalHook_ContextCancelled_FailsClosed(t *testing.T) {
	hook, _ := newTestManualReviewHook(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	decision, _, err := hook.Evaluate(ctx, sampleInput())
	require.NoError(t, err,
		"a nil error must be returned so the handler honours the quarantine decision")
	assert.Equal(t, DecisionQuarantine, decision,
		"cancelled context must fail closed (quarantine) — never admit without operator review")
}

func TestManualReviewApprovalHook_ClosedStore_EvaluateStillQuarantines(t *testing.T) {
	hook, pendingStore := newTestManualReviewHook(t)
	ctx := context.Background()

	// Close the underlying store.
	if closer, ok := pendingStore.(interface{ Close() error }); ok {
		require.NoError(t, closer.Close())
	}

	// Evaluate no longer calls the store, so a closed store must not affect the decision.
	decision, _, err := hook.Evaluate(ctx, sampleInput())
	require.NoError(t, err)
	assert.Equal(t, DecisionQuarantine, decision,
		"Evaluate must return quarantine regardless of store state")
}

func TestManualReviewApprovalHook_MultipleRegistrationsSameTenant(t *testing.T) {
	hook, _ := newTestManualReviewHook(t)
	ctx := context.Background()

	// Three stewards register — all must be quarantined.
	for i := 0; i < 3; i++ {
		decision, _, err := hook.Evaluate(ctx, sampleInput())
		require.NoError(t, err)
		assert.Equal(t, DecisionQuarantine, decision)
	}
}

func TestManualReviewApprovalHook_ExpireTimedOut(t *testing.T) {
	_, pendingStore := newTestManualReviewHook(t)
	ctx := context.Background()

	// Add a pending entry that has already expired.
	now := time.Now().UTC()
	entry := &business.PendingRegistrationEntry{
		PendingID:    "pending-expired-test",
		StewardID:    "steward-x",
		TenantID:     "test-tenant",
		TokenStr:     "tok-expired",
		SourceIP:     "10.0.0.1",
		RegisteredAt: now.Add(-25 * time.Hour),
		ExpiresAt:    now.Add(-1 * time.Hour),
		Status:       business.PendingRegistrationStatusPending,
	}
	require.NoError(t, pendingStore.AddPending(ctx, entry))

	// Use a fresh hook so the background goroutine is fresh.
	hook := NewManualReviewApprovalHook(pendingStore, 24*time.Hour, logging.NewNoopLogger())
	defer hook.Stop()

	// Manually invoke the expiry sweep.
	hook.expireTimedOut(ctx)

	// The expired record must now be marked "expired".
	got, err := pendingStore.GetPendingByID(ctx, "pending-expired-test")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusExpired, got.Status)
}
