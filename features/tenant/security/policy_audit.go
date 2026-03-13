// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"context"
	"fmt"
	"time"
)

// LogSecurityPolicyChange logs a security policy creation, update, or deletion event
func (tsal *TenantSecurityAuditLogger) LogSecurityPolicyChange(ctx context.Context, action, tenantID, policyID, policyName string) error {
	entry := TenantSecurityAuditEntry{
		ID:        fmt.Sprintf("policy-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		EventType: TenantSecurityEventSecurityPolicyChange,
		TenantID:  tenantID,
		Action:    action,
		Result:    "success",
		Severity:  AuditSeverityInfo,
		Details: map[string]interface{}{
			"policy_id":   policyID,
			"policy_name": policyName,
		},
	}

	return tsal.addEntry(entry)
}

// LogPolicyEvaluation logs the result of a tenant security policy evaluation
func (tsal *TenantSecurityAuditLogger) LogPolicyEvaluation(ctx context.Context, request *SecurityEvaluationRequest, result *SecurityEvaluationResult) error {
	severity := AuditSeverityInfo
	if !result.Allowed {
		severity = AuditSeverityWarning
	}

	entry := TenantSecurityAuditEntry{
		ID:         fmt.Sprintf("eval-%d", time.Now().UnixNano()),
		Timestamp:  time.Now(),
		EventType:  TenantSecurityEventAccessAttempt,
		TenantID:   request.TenantID,
		SubjectID:  request.SubjectID,
		ResourceID: request.ResourceID,
		Action:     request.Action,
		Result:     result.Decision,
		Severity:   severity,
		Details: map[string]interface{}{
			"allowed":       result.Allowed,
			"violations":    len(result.Violations),
			"applied_rules": result.AppliedRules,
		},
	}

	return tsal.addEntry(entry)
}

// LogZeroTrustOverlayEvaluation logs the result of a coordinated tenant + zero-trust policy evaluation
func (tsal *TenantSecurityAuditLogger) LogZeroTrustOverlayEvaluation(ctx context.Context, request *SecurityEvaluationRequest, result *SecurityEvaluationResult) error {
	severity := AuditSeverityInfo
	if !result.Allowed {
		severity = AuditSeverityWarning
	}

	details := map[string]interface{}{
		"final_allowed":      result.Allowed,
		"final_decision":     result.Decision,
		"violations":         len(result.Violations),
		"applied_rules":      result.AppliedRules,
		"processing_time_ms": result.ProcessingTime.Milliseconds(),
	}

	if result.ZeroTrustOverlay != nil {
		details["overlay_mode"] = result.ZeroTrustOverlay.OverlayMode
		details["tenant_granted"] = result.ZeroTrustOverlay.TenantGranted
		details["zero_trust_granted"] = result.ZeroTrustOverlay.ZeroTrustGranted
		details["conflict_detected"] = result.ZeroTrustOverlay.ConflictDetected
		details["alignment_score"] = result.ZeroTrustOverlay.AlignmentScore
		details["recommended_action"] = result.ZeroTrustOverlay.RecommendedAction
	}

	entry := TenantSecurityAuditEntry{
		ID:         fmt.Sprintf("overlay-eval-%d", time.Now().UnixNano()),
		Timestamp:  time.Now(),
		EventType:  TenantSecurityEventZeroTrustOverlay,
		TenantID:   request.TenantID,
		SubjectID:  request.SubjectID,
		ResourceID: request.ResourceID,
		Action:     request.Action,
		Result:     result.Decision,
		Severity:   severity,
		Details:    details,
	}

	return tsal.addEntry(entry)
}
