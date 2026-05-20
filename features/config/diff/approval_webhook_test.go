// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package diff

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

func newWebhookTestServer(t *testing.T) (*httptest.Server, func() []map[string]interface{}) {
	t.Helper()
	var mu sync.Mutex
	var payloads []map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p map[string]interface{}
		if err := json.Unmarshal(body, &p); err == nil {
			mu.Lock()
			payloads = append(payloads, p)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	return srv, func() []map[string]interface{} {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]map[string]interface{}, len(payloads))
		copy(cp, payloads)
		return cp
	}
}

func baseApprovalFixtures() (*ComparisonResult, *RiskAssessment) {
	result := &ComparisonResult{
		FromRef: ConfigurationReference{Commit: "abc12345"},
		ToRef:   ConfigurationReference{Commit: "def67890"},
		Summary: DiffSummary{TotalChanges: 1},
	}
	// Use RequiredApprovals so we control exactly who must approve.
	assessment := &RiskAssessment{
		OverallRisk: ImpactLevelLow,
		RequiredApprovals: []ApprovalRequirement{
			{Type: "test", Required: true, Approvers: []string{"approver-1"}},
		},
	}
	return result, assessment
}

func TestDefaultApprovalIntegration_webhookDeliversApprovalRequested(t *testing.T) {
	srv, payloads := newWebhookTestServer(t)

	ai := NewDefaultApprovalIntegrationWithWebhookConfig(srv.URL, nil, ApprovalWebhookConfig{RetryBase: time.Millisecond})
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
	result, assessment := baseApprovalFixtures()

	_, err := ai.CreateApprovalRequest(ctx, result, assessment)
	require.NoError(t, err)

	got := payloads()
	require.Len(t, got, 1)
	assert.Equal(t, "approval.requested", got[0]["event"])
	assert.Equal(t, "alice@example.com", got[0]["initiator"])
	assert.NotEmpty(t, got[0]["diff_id"])
	assert.NotEmpty(t, got[0]["timestamp"])
}

func TestDefaultApprovalIntegration_webhookDeliversApprovalUpdated(t *testing.T) {
	srv, payloads := newWebhookTestServer(t)

	ai := NewDefaultApprovalIntegrationWithWebhookConfig(srv.URL, nil, ApprovalWebhookConfig{RetryBase: time.Millisecond})
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
	result, assessment := baseApprovalFixtures()

	req, err := ai.CreateApprovalRequest(ctx, result, assessment)
	require.NoError(t, err)

	// Clear the first payload (approval.requested) by noting the count.
	before := len(payloads())

	err = ai.UpdateApprovalRequest(ctx, req.ID, result)
	require.NoError(t, err)

	got := payloads()
	require.Greater(t, len(got), before, "expected a new webhook payload for update")
	last := got[len(got)-1]
	assert.Equal(t, "approval.updated", last["event"])
	assert.Equal(t, req.ID, last["diff_id"])
}

func TestDefaultApprovalIntegration_webhookDeliversApprovalCancelled(t *testing.T) {
	srv, payloads := newWebhookTestServer(t)

	ai := NewDefaultApprovalIntegrationWithWebhookConfig(srv.URL, nil, ApprovalWebhookConfig{RetryBase: time.Millisecond})
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
	result, assessment := baseApprovalFixtures()

	req, err := ai.CreateApprovalRequest(ctx, result, assessment)
	require.NoError(t, err)

	before := len(payloads())

	err = ai.CancelApprovalRequest(ctx, req.ID)
	require.NoError(t, err)

	got := payloads()
	require.Greater(t, len(got), before)
	last := got[len(got)-1]
	assert.Equal(t, "approval.cancelled", last["event"])
	assert.Equal(t, req.ID, last["diff_id"])
}

func TestDefaultApprovalIntegration_webhookDeliversApprovalApproved(t *testing.T) {
	srv, payloads := newWebhookTestServer(t)

	ai := NewDefaultApprovalIntegrationWithWebhookConfig(srv.URL, nil, ApprovalWebhookConfig{RetryBase: time.Millisecond})
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
	result, assessment := baseApprovalFixtures()

	req, err := ai.CreateApprovalRequest(ctx, result, assessment)
	require.NoError(t, err)

	before := len(payloads())

	err = ai.AddApproval(ctx, req.ID, "approver-1", "approved", "looks good")
	require.NoError(t, err)

	got := payloads()
	require.Greater(t, len(got), before)
	last := got[len(got)-1]
	assert.Equal(t, "approval.approved", last["event"])
	assert.Equal(t, req.ID, last["diff_id"])

	// Verify the request status changed.
	status, err := ai.GetApprovalStatus(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, "approved", status.Status)
}

func TestDefaultApprovalIntegration_webhookDeliversApprovalRejected(t *testing.T) {
	srv, payloads := newWebhookTestServer(t)

	ai := NewDefaultApprovalIntegrationWithWebhookConfig(srv.URL, nil, ApprovalWebhookConfig{RetryBase: time.Millisecond})
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
	result, assessment := baseApprovalFixtures()

	req, err := ai.CreateApprovalRequest(ctx, result, assessment)
	require.NoError(t, err)

	before := len(payloads())

	err = ai.AddApproval(ctx, req.ID, "approver-1", "rejected", "not ready")
	require.NoError(t, err)

	got := payloads()
	require.Greater(t, len(got), before)
	last := got[len(got)-1]
	assert.Equal(t, "approval.rejected", last["event"])
	assert.Equal(t, req.ID, last["diff_id"])

	status, err := ai.GetApprovalStatus(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, "rejected", status.Status)
}

func TestDefaultApprovalIntegration_webhookRetriesOn5xx(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := callCount.Add(1)
		if cur < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	ai := NewDefaultApprovalIntegrationWithWebhookConfig(srv.URL, nil, ApprovalWebhookConfig{RetryBase: time.Millisecond})
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
	result, assessment := baseApprovalFixtures()

	_, err := ai.CreateApprovalRequest(ctx, result, assessment)
	require.NoError(t, err)
	assert.Equal(t, int32(3), callCount.Load(), "expected 3 attempts (2 failures + 1 success)")
}

func TestDefaultApprovalIntegration_webhookPermanentFailureLogged(t *testing.T) {
	// Server always returns 503.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	ai := NewDefaultApprovalIntegrationWithWebhookConfig(srv.URL, nil, ApprovalWebhookConfig{RetryBase: time.Millisecond})
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
	result, assessment := baseApprovalFixtures()

	// CreateApprovalRequest logs the webhook error and continues — it must not fail the whole operation.
	req, err := ai.CreateApprovalRequest(ctx, result, assessment)
	require.NoError(t, err, "permanent webhook failure must not propagate to caller")
	assert.NotNil(t, req)
}

func TestDefaultApprovalIntegration_webhookInvalidSchemeRejected(t *testing.T) {
	// file:// and ftp:// schemes must be rejected before any network I/O (SSRF prevention).
	for _, badURL := range []string{"file:///etc/passwd", "ftp://internal/path", "javascript://evil"} {
		ai := NewDefaultApprovalIntegrationWithWebhookConfig(badURL, nil, ApprovalWebhookConfig{RetryBase: time.Millisecond})
		ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
		result, assessment := baseApprovalFixtures()

		// Should not panic; webhook error is logged but CreateApprovalRequest succeeds.
		req, err := ai.CreateApprovalRequest(ctx, result, assessment)
		require.NoError(t, err, "invalid scheme must not propagate to caller (url=%s)", badURL)
		assert.NotNil(t, req)
	}
}

func TestDefaultApprovalIntegration_noWebhook_operationsSucceed(t *testing.T) {
	// Without a webhook configured, all operations complete without error.
	ai := NewDefaultApprovalIntegration(nil)
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
	result, assessment := baseApprovalFixtures()

	req, err := ai.CreateApprovalRequest(ctx, result, assessment)
	require.NoError(t, err)

	err = ai.UpdateApprovalRequest(ctx, req.ID, result)
	require.NoError(t, err)

	err = ai.AddApproval(ctx, req.ID, "approver-1", "approved", "")
	require.NoError(t, err)

	status, err := ai.GetApprovalStatus(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, "approved", status.Status)
}

func TestDefaultApprovalIntegration_webhookPayloadContainsRequiredFields(t *testing.T) {
	srv, payloads := newWebhookTestServer(t)

	ai := NewDefaultApprovalIntegrationWithWebhookConfig(srv.URL, nil, ApprovalWebhookConfig{RetryBase: time.Millisecond})
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "bob@example.com")
	result, assessment := baseApprovalFixtures()

	req, err := ai.CreateApprovalRequest(ctx, result, assessment)
	require.NoError(t, err)

	got := payloads()
	require.Len(t, got, 1)
	p := got[0]

	assert.Equal(t, "approval.requested", p["event"], "event field")
	assert.Equal(t, req.ID, p["diff_id"], "diff_id field")
	assert.Equal(t, "bob@example.com", p["initiator"], "initiator field")
	assert.NotNil(t, p["timestamp"], "timestamp field")
}
