// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package diff

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestNewDefaultApprovalIntegration_nilLogger_usesNoop(t *testing.T) {
	ai := NewDefaultApprovalIntegration(nil)
	require.NotNil(t, ai)
	// Verify no panic on usage
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "test-user")
	result := &ComparisonResult{
		FromRef: ConfigurationReference{Commit: "abc12345"},
		ToRef:   ConfigurationReference{Commit: "def67890"},
		Summary: DiffSummary{TotalChanges: 1},
	}
	assessment := &RiskAssessment{
		OverallRisk: ImpactLevelLow,
	}
	req, err := ai.CreateApprovalRequest(ctx, result, assessment)
	assert.NoError(t, err)
	assert.NotNil(t, req)
}

func TestDefaultApprovalIntegration_logsApproverCount(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	ai := NewDefaultApprovalIntegration(mock)
	require.NotNil(t, ai)

	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "test-user")
	result := &ComparisonResult{
		FromRef: ConfigurationReference{Commit: "abc12345"},
		ToRef:   ConfigurationReference{Commit: "def67890"},
		Summary: DiffSummary{TotalChanges: 2},
	}
	// Use high risk to trigger approvers being added
	assessment := &RiskAssessment{
		OverallRisk: ImpactLevelHigh,
	}

	req, err := ai.CreateApprovalRequest(ctx, result, assessment)
	assert.NoError(t, err)
	assert.NotNil(t, req)

	infoLogs := mock.GetLogs("info")
	require.NotEmpty(t, infoLogs, "expected at least one info log entry")

	// Find the "notifying approvers" entry and verify it has approver_count (integer) not identities
	var found bool
	for _, entry := range infoLogs {
		if entry.Message == "notifying approvers" {
			found = true
			data := entry.Data
			var hasApproverCount bool
			for i := 0; i+1 < len(data); i += 2 {
				key, ok := data[i].(string)
				if !ok {
					continue
				}
				if key == "approver_count" {
					_, isInt := data[i+1].(int)
					assert.True(t, isInt, "approver_count must be an integer, got %T", data[i+1])
					hasApproverCount = true
				}
				// Ensure no approver identity strings are logged
				if key == "approvers" {
					t.Errorf("approver identities (PII) must not be logged, found key %q", key)
				}
			}
			assert.True(t, hasApproverCount, "approver_count key not found in log entry data")
			break
		}
	}
	assert.True(t, found, "expected 'notifying approvers' log entry not found")
}

func TestDefaultApprovalIntegration_logsOnNotifyUpdate(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	ai := NewDefaultApprovalIntegration(mock)

	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "test-user")
	result := &ComparisonResult{
		FromRef: ConfigurationReference{Commit: "abc12345"},
		ToRef:   ConfigurationReference{Commit: "def67890"},
		Summary: DiffSummary{TotalChanges: 1},
	}
	assessment := &RiskAssessment{OverallRisk: ImpactLevelLow}

	req, err := ai.CreateApprovalRequest(ctx, result, assessment)
	require.NoError(t, err)

	mock.Reset()
	err = ai.UpdateApprovalRequest(ctx, req.ID, result)
	assert.NoError(t, err)

	infoLogs := mock.GetLogs("info")
	require.NotEmpty(t, infoLogs)
	assert.Equal(t, "notifying approvers of update", infoLogs[0].Message)
}

func TestDefaultApprovalIntegration_logsOnNotifyCancellation(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	ai := NewDefaultApprovalIntegration(mock)

	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "test-user")
	result := &ComparisonResult{
		FromRef: ConfigurationReference{Commit: "abc12345"},
		ToRef:   ConfigurationReference{Commit: "def67890"},
		Summary: DiffSummary{TotalChanges: 1},
	}
	assessment := &RiskAssessment{OverallRisk: ImpactLevelLow}

	req, err := ai.CreateApprovalRequest(ctx, result, assessment)
	require.NoError(t, err)

	mock.Reset()
	err = ai.CancelApprovalRequest(ctx, req.ID)
	assert.NoError(t, err)

	infoLogs := mock.GetLogs("info")
	require.NotEmpty(t, infoLogs)
	assert.Equal(t, "notifying approvers of cancellation", infoLogs[0].Message)
}

func TestDefaultApprovalIntegration_CreateApprovalRequest_RequesterFromContext(t *testing.T) {
	ai := NewDefaultApprovalIntegration(nil)
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")

	result := &ComparisonResult{
		FromRef: ConfigurationReference{Commit: "abc12345"},
		ToRef:   ConfigurationReference{Commit: "def67890"},
		Summary: DiffSummary{TotalChanges: 1},
	}
	assessment := &RiskAssessment{OverallRisk: ImpactLevelLow}

	req, err := ai.CreateApprovalRequest(ctx, result, assessment)

	require.NoError(t, err)
	require.NotNil(t, req)
	assert.Equal(t, "alice@example.com", req.Requester)
}

func TestDefaultApprovalIntegration_CreateApprovalRequest_ErrorWithoutUserInContext(t *testing.T) {
	ai := NewDefaultApprovalIntegration(nil)
	ctx := context.Background() // No user ID in context

	result := &ComparisonResult{
		FromRef: ConfigurationReference{Commit: "abc12345"},
		ToRef:   ConfigurationReference{Commit: "def67890"},
		Summary: DiffSummary{TotalChanges: 1},
	}
	assessment := &RiskAssessment{OverallRisk: ImpactLevelLow}

	_, err := ai.CreateApprovalRequest(ctx, result, assessment)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthenticated")
}

// Tenant-boundary tests (Issue #4340): an approval decision is refused when the
// approving principal is outside the request's tenant, and a successful
// approval records the approving principal.

func newHighRiskResult() (*ComparisonResult, *RiskAssessment) {
	result := &ComparisonResult{
		FromRef: ConfigurationReference{Commit: "abc12345"},
		ToRef:   ConfigurationReference{Commit: "def67890"},
		Summary: DiffSummary{TotalChanges: 1},
	}
	assessment := &RiskAssessment{OverallRisk: ImpactLevelHigh}
	return result, assessment
}

func TestDefaultApprovalIntegration_AddApproval_DeniedOutsideTenant(t *testing.T) {
	ai := NewDefaultApprovalIntegration(nil)

	createCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
	createCtx = context.WithValue(createCtx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("root/msp-a/client-1"))

	result, assessment := newHighRiskResult()
	req, err := ai.CreateApprovalRequest(createCtx, result, assessment)
	require.NoError(t, err)
	require.Equal(t, "root/msp-a/client-1", req.TenantID)
	require.Contains(t, req.RequiredApprovers, "tech-lead")

	// A principal scoped to a sibling tenant must be refused.
	approveCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "mallory@example.com")
	approveCtx = context.WithValue(approveCtx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("root/msp-a/client-2"))

	err = ai.AddApproval(approveCtx, req.ID, "tech-lead", "approved", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrApprovalOutsideTenant)

	status, err := ai.GetApprovalStatus(context.Background(), req.ID)
	require.NoError(t, err)
	assert.Empty(t, status.Approvals)
}

func TestDefaultApprovalIntegration_AddApproval_RecordsPrincipalWithinTenant(t *testing.T) {
	ai := NewDefaultApprovalIntegration(nil)

	createCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
	createCtx = context.WithValue(createCtx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("root/msp-a/client-1"))

	result, assessment := newHighRiskResult()
	req, err := ai.CreateApprovalRequest(createCtx, result, assessment)
	require.NoError(t, err)

	// A principal within (or equal to) the request's tenant subtree succeeds and
	// is recorded as the approval's Principal, independent of the approver slot.
	approveCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "bob@example.com")
	approveCtx = context.WithValue(approveCtx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("root/msp-a/client-1"))

	require.NoError(t, ai.AddApproval(approveCtx, req.ID, "tech-lead", "approved", "looks good"))

	status, err := ai.GetApprovalStatus(context.Background(), req.ID)
	require.NoError(t, err)
	require.Len(t, status.Approvals, 1)
	assert.Equal(t, "tech-lead", status.Approvals[0].Approver)
	assert.Equal(t, "bob@example.com", status.Approvals[0].Principal)
}

func TestDefaultApprovalIntegration_AddApproval_DeniedWithoutTenantScope(t *testing.T) {
	ai := NewDefaultApprovalIntegration(nil)

	createCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "alice@example.com")
	createCtx = context.WithValue(createCtx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("root/msp-a/client-1"))

	result, assessment := newHighRiskResult()
	req, err := ai.CreateApprovalRequest(createCtx, result, assessment)
	require.NoError(t, err)

	// No tenant scope on the approving context at all — fail closed.
	approveCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "mallory@example.com")

	err = ai.AddApproval(approveCtx, req.ID, "tech-lead", "approved", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrApprovalOutsideTenant)
}
