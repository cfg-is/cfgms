// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/rbac/zerotrust"
)

// TenantPolicyCoordination manages coordination between tenant security policies and zero-trust policies
type TenantPolicyCoordination struct {
	CoordinationMode   TenantCoordinationMode     `json:"coordination_mode"`
	PolicyPriority     PolicyPriority             `json:"policy_priority"`
	ConflictResolution ConflictResolutionStrategy `json:"conflict_resolution"`
	ValidationRules    []CoordinationRule         `json:"validation_rules"`
	AuditingEnabled    bool                       `json:"auditing_enabled"`
	FailSecure         bool                       `json:"fail_secure"`
}

// TenantCoordinationMode defines how tenant and zero-trust policies coordinate
type TenantCoordinationMode string

const (
	TenantCoordinationModeSequential TenantCoordinationMode = "sequential" // Evaluate tenant policies first, then zero-trust
	TenantCoordinationModeParallel   TenantCoordinationMode = "parallel"   // Evaluate both simultaneously
	TenantCoordinationModeHierarchy  TenantCoordinationMode = "hierarchy"  // Use policy priority to determine order
)

// PolicyPriority defines priority between tenant and zero-trust policies
type PolicyPriority string

const (
	PolicyPriorityTenantFirst      PolicyPriority = "tenant_first"      // Tenant policies take precedence
	PolicyPriorityZeroTrustFirst   PolicyPriority = "zero_trust_first"  // Zero-trust policies take precedence
	PolicyPriorityBothRequired     PolicyPriority = "both_required"     // Both policies must pass
	PolicyPriorityEitherSufficient PolicyPriority = "either_sufficient" // Either policy passing is sufficient
)

// ConflictResolutionStrategy defines how to resolve conflicts between policies
type ConflictResolutionStrategy string

const (
	ConflictResolutionDenyWins       ConflictResolutionStrategy = "deny_wins"       // Any deny decision wins
	ConflictResolutionAllowWins      ConflictResolutionStrategy = "allow_wins"      // Any allow decision wins
	ConflictResolutionHigherSecurity ConflictResolutionStrategy = "higher_security" // More restrictive decision wins
	ConflictResolutionManualReview   ConflictResolutionStrategy = "manual_review"   // Flag for manual review
)

// CoordinationRule defines rules for policy coordination
type CoordinationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Condition   string                 `json:"condition"`
	Action      string                 `json:"action"`
	Priority    int                    `json:"priority"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// ZeroTrustOverlayResult contains the results of zero-trust policy overlay evaluation
type ZeroTrustOverlayResult struct {
	OverlayMode       TenantZeroTrustMode                `json:"overlay_mode"`
	ZeroTrustResponse *zerotrust.ZeroTrustAccessResponse `json:"zero_trust_response"`
	TenantGranted     bool                               `json:"tenant_granted"`
	ZeroTrustGranted  bool                               `json:"zero_trust_granted"`
	ConflictDetected  bool                               `json:"conflict_detected"`
	AlignmentScore    float64                            `json:"alignment_score"`
	RecommendedAction string                             `json:"recommended_action"`
	OverlayReason     string                             `json:"overlay_reason"`
	EvaluationTime    time.Time                          `json:"evaluation_time"`
	ProcessingTime    time.Duration                      `json:"processing_time"`
}

// NewDefaultTenantPolicyCoordination creates default policy coordination configuration
func NewDefaultTenantPolicyCoordination() *TenantPolicyCoordination {
	return &TenantPolicyCoordination{
		CoordinationMode:   TenantCoordinationModeSequential,
		PolicyPriority:     PolicyPriorityBothRequired,
		ConflictResolution: ConflictResolutionDenyWins,
		ValidationRules:    []CoordinationRule{},
		AuditingEnabled:    true,
		FailSecure:         true,
	}
}

// evaluateZeroTrustOverlay evaluates zero-trust policies as an overlay to tenant policies
func (tspe *TenantSecurityPolicyEngine) evaluateZeroTrustOverlay(ctx context.Context, request *SecurityEvaluationRequest, tenantResult *SecurityEvaluationResult) (*ZeroTrustOverlayResult, error) {
	// Convert security evaluation request to zero-trust access request
	zeroTrustRequest := tspe.convertToZeroTrustRequest(request, tenantResult)

	// Evaluate zero-trust policies
	zeroTrustResponse, err := tspe.zeroTrustEngine.EvaluateAccess(ctx, zeroTrustRequest)
	if err != nil {
		return nil, fmt.Errorf("zero-trust policy evaluation failed: %w", err)
	}

	// Create overlay result
	overlayResult := &ZeroTrustOverlayResult{
		OverlayMode:       tspe.zeroTrustMode,
		ZeroTrustResponse: zeroTrustResponse,
		TenantGranted:     tenantResult.Allowed,
		ZeroTrustGranted:  zeroTrustResponse.Granted,
		ConflictDetected:  tenantResult.Allowed != zeroTrustResponse.Granted,
		EvaluationTime:    time.Now(),
		ProcessingTime:    time.Duration(zeroTrustResponse.ProcessingTime.Nanoseconds()),
	}

	// Calculate alignment score between tenant and zero-trust policies
	overlayResult.AlignmentScore = tspe.calculatePolicyAlignment(tenantResult, zeroTrustResponse)

	// Determine recommended action based on overlay mode
	overlayResult.RecommendedAction = tspe.determineOverlayAction(tenantResult.Allowed, zeroTrustResponse.Granted)
	overlayResult.OverlayReason = tspe.buildOverlayReason(tenantResult, zeroTrustResponse, overlayResult.AlignmentScore)

	return overlayResult, nil
}

// coordinatePolicyResults coordinates tenant and zero-trust policy results into a final decision
func (tspe *TenantSecurityPolicyEngine) coordinatePolicyResults(ctx context.Context, tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	var finalResult *SecurityEvaluationResult

	// Apply coordination logic based on mode and priority
	switch tspe.zeroTrustMode {
	case TenantZeroTrustModeOverlay:
		finalResult = tspe.applyOverlayMode(tenantResult, overlayResult)

	case TenantZeroTrustModeEnforced:
		finalResult = tspe.applyEnforcedMode(tenantResult, overlayResult)

	case TenantZeroTrustModeGoverning:
		finalResult = tspe.applyGoverningMode(tenantResult, overlayResult)

	case TenantZeroTrustModeIntegrated:
		finalResult = tspe.applyIntegratedMode(tenantResult, overlayResult)

	default: // TenantZeroTrustModeDisabled
		finalResult = tenantResult
	}

	// Apply conflict resolution if there's a conflict
	if overlayResult.ConflictDetected {
		finalResult = tspe.applyConflictResolution(finalResult, tenantResult, overlayResult)
	}

	// Audit the coordinated evaluation
	_ = tspe.auditLogger.LogZeroTrustOverlayEvaluation(ctx, tenantResult.Request, finalResult)

	return finalResult
}

// convertToZeroTrustRequest converts a security evaluation request to a zero-trust access request
func (tspe *TenantSecurityPolicyEngine) convertToZeroTrustRequest(request *SecurityEvaluationRequest, tenantResult *SecurityEvaluationResult) *zerotrust.ZeroTrustAccessRequest {
	zeroTrustRequest := &zerotrust.ZeroTrustAccessRequest{
		RequestID:     fmt.Sprintf("tenant-zt-%d", time.Now().UnixNano()),
		RequestTime:   time.Now(),
		SubjectType:   zerotrust.SubjectTypeUser,
		ResourceType:  request.ResourceType,
		SourceSystem:  "tenant-security",
		RequestSource: zerotrust.RequestSourceSystem,
		Priority:      zerotrust.RequestPriorityNormal,
	}

	// Set subject attributes with tenant context
	if zeroTrustRequest.SubjectAttributes == nil {
		zeroTrustRequest.SubjectAttributes = make(map[string]interface{})
	}

	zeroTrustRequest.SubjectAttributes["tenant_id"] = request.TenantID
	zeroTrustRequest.SubjectAttributes["subject_id"] = request.SubjectID
	zeroTrustRequest.SubjectAttributes["tenant_granted"] = tenantResult.Allowed
	zeroTrustRequest.SubjectAttributes["tenant_decision"] = tenantResult.Decision
	zeroTrustRequest.SubjectAttributes["tenant_violations"] = len(tenantResult.Violations)
	zeroTrustRequest.SubjectAttributes["permissions"] = request.Permissions

	if request.DataClassification != "" {
		zeroTrustRequest.SubjectAttributes["data_classification"] = request.DataClassification
	}

	// Extract environmental context from request context
	if len(request.Context) > 0 {
		zeroTrustRequest.EnvironmentContext = &zerotrust.EnvironmentContext{}

		if ip, exists := request.Context["source_ip"]; exists {
			zeroTrustRequest.EnvironmentContext.IPAddress = ip
		}

		zeroTrustRequest.SecurityContext = &zerotrust.SecurityContext{
			TrustLevel: zerotrust.TrustLevelMedium, // Default trust level
		}

		if authMethod, exists := request.Context["auth_method"]; exists {
			zeroTrustRequest.SecurityContext.AuthenticationMethod = authMethod
		}

		if mfaVerified := request.Context["mfa_verified"]; mfaVerified == "true" {
			zeroTrustRequest.SecurityContext.MFAVerified = true
		}
	}

	return zeroTrustRequest
}

// calculatePolicyAlignment calculates alignment score between tenant and zero-trust policy decisions
func (tspe *TenantSecurityPolicyEngine) calculatePolicyAlignment(tenantResult *SecurityEvaluationResult, ztResponse *zerotrust.ZeroTrustAccessResponse) float64 {
	// Perfect alignment when both decisions agree
	if tenantResult.Allowed == ztResponse.Granted {
		return 1.0
	}

	// Partial alignment based on violations and policy confidence
	baseAlignment := 0.2 // Base misalignment penalty

	// Factor in tenant policy violations
	if len(tenantResult.Violations) > 0 && !ztResponse.Granted {
		// Zero-trust denying with tenant violations indicates good alignment
		violationAlignment := 0.4
		baseAlignment += violationAlignment
	}

	// Factor in zero-trust policy confidence (based on applied policies)
	policyConfidence := float64(len(ztResponse.AppliedPolicies)) * 0.1
	if policyConfidence > 0.4 {
		policyConfidence = 0.4 // Cap at 0.4
	}
	baseAlignment += policyConfidence

	// Cap final alignment score
	if baseAlignment > 1.0 {
		baseAlignment = 1.0
	}

	return baseAlignment
}

// determineOverlayAction determines the recommended action based on tenant and zero-trust decisions
func (tspe *TenantSecurityPolicyEngine) determineOverlayAction(tenantGranted, zeroTrustGranted bool) string {
	switch tspe.zeroTrustMode {
	case TenantZeroTrustModeOverlay:
		// Overlay mode - both policies must agree for allow
		if tenantGranted && zeroTrustGranted {
			return "allow"
		}
		return "deny"

	case TenantZeroTrustModeEnforced:
		// Enforced mode - zero-trust decision overrides tenant decision
		if zeroTrustGranted {
			return "allow"
		}
		return "deny"

	case TenantZeroTrustModeGoverning:
		// Governing mode - zero-trust first, tenant as fallback
		if zeroTrustGranted {
			return "allow"
		}
		if tenantGranted {
			return "allow_fallback"
		}
		return "deny"

	case TenantZeroTrustModeIntegrated:
		// Integrated mode - use policy priority to determine action
		return tspe.determineIntegratedAction(tenantGranted, zeroTrustGranted)

	default:
		// Default - use tenant decision
		if tenantGranted {
			return "allow"
		}
		return "deny"
	}
}

// determineIntegratedAction determines action for integrated mode based on policy priority
func (tspe *TenantSecurityPolicyEngine) determineIntegratedAction(tenantGranted, zeroTrustGranted bool) string {
	switch tspe.policyCoordination.PolicyPriority {
	case PolicyPriorityTenantFirst:
		if tenantGranted {
			return "allow"
		}
		return "deny"

	case PolicyPriorityZeroTrustFirst:
		if zeroTrustGranted {
			return "allow"
		}
		return "deny"

	case PolicyPriorityBothRequired:
		if tenantGranted && zeroTrustGranted {
			return "allow"
		}
		return "deny"

	case PolicyPriorityEitherSufficient:
		if tenantGranted || zeroTrustGranted {
			return "allow"
		}
		return "deny"

	default:
		// Default to requiring both
		if tenantGranted && zeroTrustGranted {
			return "allow"
		}
		return "deny"
	}
}

// buildOverlayReason creates a descriptive reason for the overlay decision
func (tspe *TenantSecurityPolicyEngine) buildOverlayReason(tenantResult *SecurityEvaluationResult, ztResponse *zerotrust.ZeroTrustAccessResponse, alignmentScore float64) string {
	return fmt.Sprintf("Tenant: %t, ZeroTrust: %t, Alignment: %.2f, Mode: %s",
		tenantResult.Allowed, ztResponse.Granted, alignmentScore, tspe.zeroTrustMode)
}

// applyOverlayMode applies overlay mode coordination logic
func (tspe *TenantSecurityPolicyEngine) applyOverlayMode(tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	finalResult := &SecurityEvaluationResult{
		Request:          tenantResult.Request,
		EvaluationTime:   tenantResult.EvaluationTime,
		Violations:       tenantResult.Violations,
		AppliedRules:     tenantResult.AppliedRules,
		ZeroTrustOverlay: overlayResult,
	}

	// Overlay mode - both policies must pass for allow
	finalResult.Allowed = tenantResult.Allowed && overlayResult.ZeroTrustGranted

	if finalResult.Allowed {
		finalResult.Decision = "allow_overlay"
	} else if !tenantResult.Allowed {
		finalResult.Decision = "deny_tenant_policy"
		finalResult.BlockReason = tenantResult.BlockReason
	} else {
		finalResult.Decision = "deny_zero_trust_overlay"
		finalResult.BlockReason = "Zero-trust overlay denied access"
	}

	return finalResult
}

// applyEnforcedMode applies enforced mode coordination logic
func (tspe *TenantSecurityPolicyEngine) applyEnforcedMode(tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	finalResult := &SecurityEvaluationResult{
		Request:          tenantResult.Request,
		EvaluationTime:   tenantResult.EvaluationTime,
		Violations:       tenantResult.Violations,
		AppliedRules:     tenantResult.AppliedRules,
		ZeroTrustOverlay: overlayResult,
	}

	// Enforced mode - zero-trust decision overrides tenant decision
	finalResult.Allowed = overlayResult.ZeroTrustGranted

	if finalResult.Allowed {
		finalResult.Decision = "allow_zero_trust_enforced"
	} else {
		finalResult.Decision = "deny_zero_trust_enforced"
		finalResult.BlockReason = "Zero-trust enforcement denied access"
	}

	return finalResult
}

// applyGoverningMode applies governing mode coordination logic
func (tspe *TenantSecurityPolicyEngine) applyGoverningMode(tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	finalResult := &SecurityEvaluationResult{
		Request:          tenantResult.Request,
		EvaluationTime:   tenantResult.EvaluationTime,
		Violations:       tenantResult.Violations,
		AppliedRules:     tenantResult.AppliedRules,
		ZeroTrustOverlay: overlayResult,
	}

	// Governing mode - zero-trust first, tenant as fallback
	if overlayResult.ZeroTrustGranted {
		finalResult.Allowed = true
		finalResult.Decision = "allow_zero_trust_governing"
	} else if tenantResult.Allowed {
		finalResult.Allowed = true
		finalResult.Decision = "allow_tenant_fallback"
	} else {
		finalResult.Allowed = false
		finalResult.Decision = "deny_both_governing"
		finalResult.BlockReason = "Both zero-trust and tenant policies denied access"
	}

	return finalResult
}

// applyIntegratedMode applies integrated mode coordination logic
func (tspe *TenantSecurityPolicyEngine) applyIntegratedMode(tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	finalResult := &SecurityEvaluationResult{
		Request:          tenantResult.Request,
		EvaluationTime:   tenantResult.EvaluationTime,
		Violations:       tenantResult.Violations,
		AppliedRules:     tenantResult.AppliedRules,
		ZeroTrustOverlay: overlayResult,
	}

	// Integrated mode - use policy priority and coordination rules
	switch tspe.policyCoordination.PolicyPriority {
	case PolicyPriorityTenantFirst:
		finalResult.Allowed = tenantResult.Allowed
		finalResult.Decision = "integrated_tenant_first"

	case PolicyPriorityZeroTrustFirst:
		finalResult.Allowed = overlayResult.ZeroTrustGranted
		finalResult.Decision = "integrated_zero_trust_first"

	case PolicyPriorityBothRequired:
		finalResult.Allowed = tenantResult.Allowed && overlayResult.ZeroTrustGranted
		finalResult.Decision = "integrated_both_required"

	case PolicyPriorityEitherSufficient:
		finalResult.Allowed = tenantResult.Allowed || overlayResult.ZeroTrustGranted
		finalResult.Decision = "integrated_either_sufficient"

	default:
		// Default to both required
		finalResult.Allowed = tenantResult.Allowed && overlayResult.ZeroTrustGranted
		finalResult.Decision = "integrated_default"
	}

	if !finalResult.Allowed {
		finalResult.BlockReason = "Integrated policy evaluation denied access"
	}

	return finalResult
}

// applyConflictResolution applies conflict resolution strategy
func (tspe *TenantSecurityPolicyEngine) applyConflictResolution(finalResult, tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	switch tspe.policyCoordination.ConflictResolution {
	case ConflictResolutionDenyWins:
		// Any deny decision wins
		if !tenantResult.Allowed || !overlayResult.ZeroTrustGranted {
			finalResult.Allowed = false
			finalResult.Decision = "deny_conflict_resolution"
			finalResult.BlockReason = "Conflict resolution: deny wins"
		}

	case ConflictResolutionAllowWins:
		// Any allow decision wins
		if tenantResult.Allowed || overlayResult.ZeroTrustGranted {
			finalResult.Allowed = true
			finalResult.Decision = "allow_conflict_resolution"
			finalResult.BlockReason = ""
		}

	case ConflictResolutionHigherSecurity:
		// More restrictive decision wins (deny over allow)
		if !tenantResult.Allowed || !overlayResult.ZeroTrustGranted {
			finalResult.Allowed = false
			finalResult.Decision = "deny_higher_security"
			finalResult.BlockReason = "Conflict resolution: higher security wins"
		}

	case ConflictResolutionManualReview:
		// Flag for manual review
		finalResult.Allowed = false
		finalResult.Decision = "pending_manual_review"
		finalResult.BlockReason = "Policy conflict requires manual review"

		// Add manual review flag to violations
		manualReviewViolation := RuleViolation{
			RuleID:      "conflict_resolution",
			RuleName:    "Manual Review Required",
			Severity:    RuleSeverityHigh,
			Description: "Policy conflict detected between tenant and zero-trust policies",
			Details: map[string]interface{}{
				"tenant_decision":    tenantResult.Decision,
				"zero_trust_granted": overlayResult.ZeroTrustGranted,
				"alignment_score":    overlayResult.AlignmentScore,
			},
		}
		finalResult.Violations = append(finalResult.Violations, manualReviewViolation)
	}

	return finalResult
}
