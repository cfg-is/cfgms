// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package risk

import (
	"fmt"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/zerotrust"
)

// RiskPolicyAlignment indicates how well risk assessment aligns with zero-trust policy results
type RiskPolicyAlignment string

const (
	RiskPolicyAlignmentHigh     RiskPolicyAlignment = "high"     // Risk and policy agree
	RiskPolicyAlignmentMedium   RiskPolicyAlignment = "medium"   // Mostly aligned with minor differences
	RiskPolicyAlignmentLow      RiskPolicyAlignment = "low"      // Some conflicting signals
	RiskPolicyAlignmentConflict RiskPolicyAlignment = "conflict" // Direct conflict between risk and policy
)

// RiskFactorsSummary provides a summary of key risk factors
type RiskFactorsSummary struct {
	PrimaryRiskFactors []string  `json:"primary_risk_factors"`
	BehavioralScore    float64   `json:"behavioral_score"`
	EnvironmentalScore float64   `json:"environmental_score"`
	ResourceScore      float64   `json:"resource_score"`
	OverallRiskLevel   RiskLevel `json:"overall_risk_level"`
	ConfidenceLevel    string    `json:"confidence_level"`
	KeyRecommendations []string  `json:"key_recommendations"`
}

// convertToZeroTrustRequest converts a common access request to a zero-trust request with risk context
func (r *RiskBasedAccessIntegration) convertToZeroTrustRequest(request *common.AccessRequest, riskResponse *EnhancedRiskAccessResponse) *zerotrust.ZeroTrustAccessRequest {
	zeroTrustRequest := &zerotrust.ZeroTrustAccessRequest{
		AccessRequest: request,
		RequestID:     fmt.Sprintf("risk-zt-%d", time.Now().UnixNano()),
		RequestTime:   time.Now(),
		SubjectType:   zerotrust.SubjectTypeUser,
		ResourceType:  extractResourceType(request.ResourceId),
		SourceSystem:  "risk-manager",
		RequestSource: zerotrust.RequestSourceSystem,
		Priority:      zerotrust.RequestPriorityNormal,
	}

	// Add risk context as subject attributes
	if zeroTrustRequest.SubjectAttributes == nil {
		zeroTrustRequest.SubjectAttributes = make(map[string]interface{})
	}

	zeroTrustRequest.SubjectAttributes["risk_level"] = riskResponse.RiskLevel
	zeroTrustRequest.SubjectAttributes["risk_score"] = riskResponse.RiskScore
	zeroTrustRequest.SubjectAttributes["risk_factors"] = riskResponse.RiskFactors

	// Extract environmental context from request context
	if request.Context != nil {
		zeroTrustRequest.EnvironmentContext = &zerotrust.EnvironmentContext{
			IPAddress: request.Context["source_ip"],
		}

		zeroTrustRequest.SecurityContext = &zerotrust.SecurityContext{
			AuthenticationMethod: request.Context["auth_method"],
			TrustLevel:           zerotrust.TrustLevelMedium, // Default trust level
		}
	}

	return zeroTrustRequest
}

// calculateRiskPolicyAlignment calculates alignment score between risk assessment and zero-trust policy
func (r *RiskBasedAccessIntegration) calculateRiskPolicyAlignment(riskGranted bool, riskScore float64, policyGranted bool) float64 {
	// Perfect alignment when both agree
	if riskGranted == policyGranted {
		return 1.0
	}

	// Calculate partial alignment based on risk score and decision mismatch
	if riskScore <= 30.0 && policyGranted {
		return 0.8 // High alignment - low risk, policy allows
	}
	if riskScore >= 70.0 && !policyGranted {
		return 0.8 // High alignment - high risk, policy denies
	}
	if riskScore >= 40.0 && riskScore <= 60.0 {
		return 0.6 // Medium alignment - medium risk with conflicting decision
	}

	return 0.2 // Low alignment - significant mismatch
}

// determineRecommendedAction determines the recommended action based on risk and policy decisions
func (r *RiskBasedAccessIntegration) determineRecommendedAction(riskGranted bool, policyGranted bool, alignmentScore float64) string {
	// High alignment cases
	if alignmentScore >= 0.8 {
		if riskGranted && policyGranted {
			return "allow"
		}
		if !riskGranted && !policyGranted {
			return "deny"
		}
	}

	// Conflict resolution based on coordination mode
	switch r.zeroTrustRiskMode {
	case ZeroTrustRiskModeRiskInformed:
		if riskGranted {
			return "allow"
		}
		return "deny"

	case ZeroTrustRiskModePolicyInformed:
		if policyGranted {
			return "allow"
		}
		return "deny"

	case ZeroTrustRiskModeBidirectional, ZeroTrustRiskModeUnified:
		// Conservative approach - require both to agree for allow
		if riskGranted && policyGranted {
			return "allow"
		}
		return "deny"

	default:
		return "deny" // Conservative default
	}
}

// adjustRiskScoreWithPolicyContext adjusts risk score based on zero-trust policy evaluation
func (r *RiskBasedAccessIntegration) adjustRiskScoreWithPolicyContext(originalScore float64, ztResponse *zerotrust.ZeroTrustAccessResponse) float64 {
	// Base adjustment on policy decision
	adjustment := 0.0

	if ztResponse.Granted {
		// Policy allows - slightly reduce risk
		adjustment = -5.0
	} else {
		// Policy denies - increase risk
		adjustment = 10.0
	}

	// Adjust based on policy confidence (if available through applied policies count)
	policyConfidence := float64(len(ztResponse.AppliedPolicies)) * 0.1
	if policyConfidence > 1.0 {
		policyConfidence = 1.0
	}

	adjustedScore := originalScore + (adjustment * policyConfidence)

	// Keep within bounds
	if adjustedScore < 0 {
		adjustedScore = 0
	}
	if adjustedScore > 100 {
		adjustedScore = 100
	}

	return adjustedScore
}

// calculateRiskLevelFromScore calculates risk level from a risk score
func (r *RiskBasedAccessIntegration) calculateRiskLevelFromScore(score float64) string {
	if score >= 90 {
		return "extreme"
	}
	if score >= 75 {
		return "critical"
	}
	if score >= 60 {
		return "high"
	}
	if score >= 40 {
		return "moderate"
	}
	if score >= 20 {
		return "low"
	}
	return "minimal"
}

// boolToAction converts a boolean decision to an action string
func (r *RiskBasedAccessIntegration) boolToAction(decision bool) string {
	if decision {
		return "allow"
	}
	return "deny"
}

// applyCoordinationResult applies zero-trust coordination result to the enhanced response
func (r *RiskBasedAccessIntegration) applyCoordinationResult(response *EnhancedRiskAccessResponse, coordination *ZeroTrustRiskCoordinationResult) {
	// Update access decision based on coordination mode and recommended action
	switch coordination.RecommendedAction {
	case "allow":
		response.AccessResponse.Granted = true
		if coordination.CoordinationReason != "" {
			response.AccessResponse.Reason = fmt.Sprintf("Access allowed by risk-policy coordination: %s", coordination.CoordinationReason)
		}

	case "deny":
		response.AccessResponse.Granted = false
		if coordination.CoordinationReason != "" {
			response.AccessResponse.Reason = fmt.Sprintf("Access denied by risk-policy coordination: %s", coordination.CoordinationReason)
		}
	}

	// Update risk score if adjusted
	if coordination.AdjustedRiskScore != nil {
		response.RiskScore = *coordination.AdjustedRiskScore
	}

	// Update risk level if adjusted
	if coordination.AdjustedRiskLevel != nil {
		response.RiskLevel = *coordination.AdjustedRiskLevel
	}
}

// extractResourceType extracts resource type from resource ID
func extractResourceType(resourceID string) string {
	if resourceID == "" {
		return "unknown"
	}

	// Simple heuristic: take the first part before a delimiter
	for _, sep := range []string{".", "/", ":", "-"} {
		for i, char := range resourceID {
			if string(char) == sep {
				return resourceID[:i]
			}
		}
	}

	return resourceID
}

// extractRiskLevel extracts risk level from access response
func extractRiskLevel(response *common.AccessResponse) string {
	// In a real implementation, this would parse structured response data
	// For now, return a default based on whether access was granted
	if response.Granted {
		return "low"
	}
	return "high"
}

// extractRiskScore extracts risk score from access response
func extractRiskScore(response *common.AccessResponse) float64 {
	// In a real implementation, this would parse structured response data
	// For now, return a default score based on whether access was granted
	if response.Granted {
		return 25.0 // Low risk
	}
	return 75.0 // High risk
}

// extractRiskFactors extracts risk factors from access response
func extractRiskFactors(response *common.AccessResponse) []string {
	// In a real implementation, this would parse structured response data
	// For now, return default factors based on the reason
	factors := []string{}

	if !response.Granted {
		factors = append(factors, "access_denied")
	}

	if response.Reason != "" {
		factors = append(factors, "reason_provided")
	}

	return factors
}

// abs returns the absolute value of a float64
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
