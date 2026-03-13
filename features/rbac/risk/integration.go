// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package risk

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/jit"
	"github.com/cfgis/cfgms/features/rbac/zerotrust"
	"github.com/cfgis/cfgms/features/tenant/security"
)

// RiskBasedAccessIntegration integrates risk assessment with RBAC, JIT access, zero-trust policies, and continuous authorization
type RiskBasedAccessIntegration struct {
	riskEngine            *RiskAssessmentEngine
	adaptiveControls      *AdaptiveControlsEngine
	rbacManager           rbac.RBACManager
	jitIntegrationManager *jit.JITIntegrationManager
	tenantSecurity        *security.TenantSecurityMiddleware
	contextBuilder        *RiskContextBuilder
	decisionEnforcer      *RiskDecisionEnforcer

	// Zero-trust policy integration
	zeroTrustEngine   *zerotrust.ZeroTrustPolicyEngine
	zeroTrustEnabled  bool
	zeroTrustRiskMode ZeroTrustRiskMode
	baseRiskManager   RiskManager // Base risk manager for compatibility
	config            *RiskIntegrationConfig

	// Continuous authorization integration
	continuousRiskMonitor *ContinuousRiskMonitor
	sessionRiskTracker    *SessionRiskTracker
}

// RiskManager interface for base risk assessment
type RiskManager interface {
	AssessRisk(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error)
}

// RiskIntegrationConfig configuration for risk-based access integration
type RiskIntegrationConfig struct {
	FailSecure   bool    `json:"fail_secure"`
	RiskWeight   float64 `json:"risk_weight"`
	PolicyWeight float64 `json:"policy_weight"`
}

// ZeroTrustRiskMode defines how zero-trust policies coordinate with risk-based access decisions
type ZeroTrustRiskMode string

const (
	// ZeroTrustRiskModeDisabled disables zero-trust policy coordination with risk assessment
	ZeroTrustRiskModeDisabled ZeroTrustRiskMode = "disabled"

	// ZeroTrustRiskModeRiskInformed uses risk assessment to inform zero-trust policy evaluation
	ZeroTrustRiskModeRiskInformed ZeroTrustRiskMode = "risk_informed"

	// ZeroTrustRiskModePolicyInformed uses zero-trust policy results to adjust risk assessment
	ZeroTrustRiskModePolicyInformed ZeroTrustRiskMode = "policy_informed"

	// ZeroTrustRiskModeBidirectional enables bidirectional coordination between risk and zero-trust policies
	ZeroTrustRiskModeBidirectional ZeroTrustRiskMode = "bidirectional"

	// ZeroTrustRiskModeUnified creates unified risk-policy decisions with combined scoring
	ZeroTrustRiskModeUnified ZeroTrustRiskMode = "unified"
)

// EnhancedRiskAccessResponse extends JIT access response with risk information and zero-trust policy coordination
type EnhancedRiskAccessResponse struct {
	AccessResponse        *common.AccessResponse           `json:"access_response"`
	RiskLevel             string                           `json:"risk_level"`
	RiskScore             float64                          `json:"risk_score"`
	RiskFactors           []string                         `json:"risk_factors"`
	ZeroTrustCoordination *ZeroTrustRiskCoordinationResult `json:"zero_trust_coordination,omitempty"`
	ProcessingTime        time.Duration                    `json:"processing_time"`
}

// ZeroTrustRiskCoordinationResult contains the results of zero-trust policy coordination with risk assessment
type ZeroTrustRiskCoordinationResult struct {
	CoordinationMode   ZeroTrustRiskMode `json:"coordination_mode"`
	PolicyEvaluated    bool              `json:"policy_evaluated"`
	PolicyGranted      bool              `json:"policy_granted"`
	AlignmentScore     float64           `json:"alignment_score"`
	ConflictDetected   bool              `json:"conflict_detected"`
	RecommendedAction  string            `json:"recommended_action"`
	CoordinationReason string            `json:"coordination_reason"`
	AdjustedRiskScore  *float64          `json:"adjusted_risk_score,omitempty"`
	AdjustedRiskLevel  *string           `json:"adjusted_risk_level,omitempty"`
	UnifiedScore       *float64          `json:"unified_score,omitempty"`
	UnifiedDecision    *bool             `json:"unified_decision,omitempty"`
	ProcessingTime     time.Duration     `json:"processing_time"`
}

// NewRiskBasedAccessIntegration creates a new risk-based access integration
func NewRiskBasedAccessIntegration(
	rbacManager rbac.RBACManager,
	jitIntegrationManager *jit.JITIntegrationManager,
	tenantSecurity *security.TenantSecurityMiddleware,
) *RiskBasedAccessIntegration {
	riskEngine := NewRiskAssessmentEngine()

	return &RiskBasedAccessIntegration{
		riskEngine:            riskEngine,
		adaptiveControls:      NewAdaptiveControlsEngine(),
		rbacManager:           rbacManager,
		jitIntegrationManager: jitIntegrationManager,
		tenantSecurity:        tenantSecurity,
		contextBuilder:        NewRiskContextBuilder(),
		decisionEnforcer:      NewRiskDecisionEnforcer(),

		// Zero-trust defaults
		zeroTrustEngine:   nil,
		zeroTrustEnabled:  false,
		zeroTrustRiskMode: ZeroTrustRiskModeDisabled,

		continuousRiskMonitor: NewContinuousRiskMonitor(riskEngine),
		sessionRiskTracker:    NewSessionRiskTracker(),
	}
}

// EnableZeroTrustPolicyCoordination enables zero-trust policy coordination with risk assessment
func (rrai *RiskBasedAccessIntegration) EnableZeroTrustPolicyCoordination(engine *zerotrust.ZeroTrustPolicyEngine, mode ZeroTrustRiskMode) {
	rrai.zeroTrustEngine = engine
	rrai.zeroTrustRiskMode = mode
	rrai.zeroTrustEnabled = (mode != ZeroTrustRiskModeDisabled && engine != nil)
}

// SetZeroTrustRiskMode updates the zero-trust risk coordination mode
func (rrai *RiskBasedAccessIntegration) SetZeroTrustRiskMode(mode ZeroTrustRiskMode) {
	rrai.zeroTrustRiskMode = mode
	rrai.zeroTrustEnabled = (mode != ZeroTrustRiskModeDisabled && rrai.zeroTrustEngine != nil)
}

// GetZeroTrustRiskMode returns the current zero-trust risk coordination mode
func (rrai *RiskBasedAccessIntegration) GetZeroTrustRiskMode() ZeroTrustRiskMode {
	return rrai.zeroTrustRiskMode
}

// EnhancedRiskAccessCheck performs comprehensive risk assessment with zero-trust policy coordination
func (r *RiskBasedAccessIntegration) EnhancedRiskAccessCheck(ctx context.Context, request *common.AccessRequest) (*EnhancedRiskAccessResponse, error) {
	startTime := time.Now()

	// Step 1: Perform standard risk assessment
	riskResponse, err := r.baseRiskManager.AssessRisk(ctx, request)
	if err != nil {
		return &EnhancedRiskAccessResponse{
			AccessResponse: &common.AccessResponse{
				Granted: false,
				Reason:  fmt.Sprintf("Risk assessment failed: %v", err),
			},
			RiskLevel:      "unknown",
			RiskScore:      -1,
			ProcessingTime: time.Since(startTime),
		}, err
	}

	// Convert risk response to enhanced format
	enhancedResponse := &EnhancedRiskAccessResponse{
		AccessResponse: riskResponse,
		RiskLevel:      extractRiskLevel(riskResponse),
		RiskScore:      extractRiskScore(riskResponse),
		RiskFactors:    extractRiskFactors(riskResponse),
		ProcessingTime: time.Since(startTime),
	}

	// Step 2: Coordinate with zero-trust policies if enabled
	if r.zeroTrustEnabled && r.zeroTrustEngine != nil {
		coordinationResult, err := r.coordinateWithZeroTrust(ctx, request, enhancedResponse)
		if err != nil && r.config.FailSecure {
			enhancedResponse.AccessResponse.Granted = false
			enhancedResponse.AccessResponse.Reason = fmt.Sprintf("Zero-trust coordination failed: %v", err)
		} else if coordinationResult != nil {
			enhancedResponse.ZeroTrustCoordination = coordinationResult
			r.applyCoordinationResult(enhancedResponse, coordinationResult)
		}
	}

	enhancedResponse.ProcessingTime = time.Since(startTime)
	return enhancedResponse, nil
}

// coordinateWithZeroTrust coordinates risk assessment with zero-trust policy evaluation
func (r *RiskBasedAccessIntegration) coordinateWithZeroTrust(ctx context.Context, request *common.AccessRequest, riskResponse *EnhancedRiskAccessResponse) (*ZeroTrustRiskCoordinationResult, error) {
	// Convert to zero-trust request format
	zeroTrustRequest := r.convertToZeroTrustRequest(request, riskResponse)

	var coordinationResult *ZeroTrustRiskCoordinationResult

	switch r.zeroTrustRiskMode {
	case ZeroTrustRiskModeRiskInformed:
		coordinationResult = r.performRiskInformedCoordination(ctx, zeroTrustRequest, riskResponse)

	case ZeroTrustRiskModePolicyInformed:
		coordinationResult = r.performPolicyInformedCoordination(ctx, zeroTrustRequest, riskResponse)

	case ZeroTrustRiskModeBidirectional:
		coordinationResult = r.performBidirectionalCoordination(ctx, zeroTrustRequest, riskResponse)

	case ZeroTrustRiskModeUnified:
		coordinationResult = r.performUnifiedCoordination(ctx, zeroTrustRequest, riskResponse)

	default: // ZeroTrustRiskModeDisabled
		return nil, nil
	}

	return coordinationResult, nil
}

// performRiskInformedCoordination evaluates zero-trust policies with risk context as input
func (r *RiskBasedAccessIntegration) performRiskInformedCoordination(ctx context.Context, request *zerotrust.ZeroTrustAccessRequest, riskResponse *EnhancedRiskAccessResponse) *ZeroTrustRiskCoordinationResult {
	// Add risk context to zero-trust request
	if request.SubjectAttributes == nil {
		request.SubjectAttributes = make(map[string]interface{})
	}
	request.SubjectAttributes["risk_level"] = riskResponse.RiskLevel
	request.SubjectAttributes["risk_score"] = riskResponse.RiskScore
	request.SubjectAttributes["risk_factors"] = riskResponse.RiskFactors

	// Evaluate zero-trust policies with risk context
	ztResponse, err := r.zeroTrustEngine.EvaluateAccess(ctx, request)
	if err != nil {
		return &ZeroTrustRiskCoordinationResult{
			CoordinationMode:   ZeroTrustRiskModeRiskInformed,
			PolicyEvaluated:    false,
			PolicyGranted:      false,
			AlignmentScore:     0.0,
			ConflictDetected:   false,
			RecommendedAction:  "deny",
			CoordinationReason: fmt.Sprintf("Zero-trust evaluation failed: %v", err),
		}
	}

	// Calculate alignment between risk assessment and zero-trust decision
	alignmentScore := r.calculateRiskPolicyAlignment(riskResponse.AccessResponse.Granted, riskResponse.RiskScore, ztResponse.Granted)

	return &ZeroTrustRiskCoordinationResult{
		CoordinationMode:   ZeroTrustRiskModeRiskInformed,
		PolicyEvaluated:    true,
		PolicyGranted:      ztResponse.Granted,
		AlignmentScore:     alignmentScore,
		ConflictDetected:   riskResponse.AccessResponse.Granted != ztResponse.Granted,
		RecommendedAction:  r.determineRecommendedAction(riskResponse.AccessResponse.Granted, ztResponse.Granted, alignmentScore),
		CoordinationReason: fmt.Sprintf("Risk-informed zero-trust evaluation: Risk=%s, ZT=%t, Alignment=%.2f", riskResponse.RiskLevel, ztResponse.Granted, alignmentScore),
	}
}

// performPolicyInformedCoordination evaluates risk with zero-trust policy context as input
func (r *RiskBasedAccessIntegration) performPolicyInformedCoordination(ctx context.Context, request *zerotrust.ZeroTrustAccessRequest, riskResponse *EnhancedRiskAccessResponse) *ZeroTrustRiskCoordinationResult {
	// First evaluate zero-trust policies
	ztResponse, err := r.zeroTrustEngine.EvaluateAccess(ctx, request)
	if err != nil {
		return &ZeroTrustRiskCoordinationResult{
			CoordinationMode:   ZeroTrustRiskModePolicyInformed,
			PolicyEvaluated:    false,
			PolicyGranted:      false,
			AlignmentScore:     0.0,
			ConflictDetected:   false,
			RecommendedAction:  "deny",
			CoordinationReason: fmt.Sprintf("Zero-trust evaluation failed: %v", err),
		}
	}

	// Adjust risk assessment based on zero-trust policy result
	adjustedRiskScore := r.adjustRiskScoreWithPolicyContext(riskResponse.RiskScore, ztResponse)
	adjustedRiskLevel := r.calculateRiskLevelFromScore(adjustedRiskScore)

	// Calculate alignment
	alignmentScore := r.calculateRiskPolicyAlignment(riskResponse.AccessResponse.Granted, adjustedRiskScore, ztResponse.Granted)

	return &ZeroTrustRiskCoordinationResult{
		CoordinationMode:   ZeroTrustRiskModePolicyInformed,
		PolicyEvaluated:    true,
		PolicyGranted:      ztResponse.Granted,
		AlignmentScore:     alignmentScore,
		ConflictDetected:   riskResponse.AccessResponse.Granted != ztResponse.Granted,
		RecommendedAction:  r.determineRecommendedAction(riskResponse.AccessResponse.Granted, ztResponse.Granted, alignmentScore),
		CoordinationReason: fmt.Sprintf("Policy-informed risk evaluation: Original Risk=%.2f, Adjusted Risk=%.2f, ZT=%t", riskResponse.RiskScore, adjustedRiskScore, ztResponse.Granted),
		AdjustedRiskScore:  &adjustedRiskScore,
		AdjustedRiskLevel:  &adjustedRiskLevel,
	}
}

// performBidirectionalCoordination performs iterative coordination between risk and zero-trust evaluations
func (r *RiskBasedAccessIntegration) performBidirectionalCoordination(ctx context.Context, request *zerotrust.ZeroTrustAccessRequest, riskResponse *EnhancedRiskAccessResponse) *ZeroTrustRiskCoordinationResult {
	maxIterations := 3
	convergenceThreshold := 0.1

	currentRiskScore := riskResponse.RiskScore
	var ztResponse *zerotrust.ZeroTrustAccessResponse
	var err error

	for iteration := 0; iteration < maxIterations; iteration++ {
		// Update zero-trust request with current risk context
		if request.SubjectAttributes == nil {
			request.SubjectAttributes = make(map[string]interface{})
		}
		request.SubjectAttributes["risk_score"] = currentRiskScore
		request.SubjectAttributes["risk_level"] = r.calculateRiskLevelFromScore(currentRiskScore)
		request.SubjectAttributes["iteration"] = iteration

		// Evaluate zero-trust policies
		ztResponse, err = r.zeroTrustEngine.EvaluateAccess(ctx, request)
		if err != nil {
			break
		}

		// Adjust risk score based on zero-trust result
		newRiskScore := r.adjustRiskScoreWithPolicyContext(currentRiskScore, ztResponse)

		// Check for convergence
		if abs(newRiskScore-currentRiskScore) < convergenceThreshold {
			break
		}

		currentRiskScore = newRiskScore
	}

	if err != nil {
		return &ZeroTrustRiskCoordinationResult{
			CoordinationMode:   ZeroTrustRiskModeBidirectional,
			PolicyEvaluated:    false,
			PolicyGranted:      false,
			AlignmentScore:     0.0,
			ConflictDetected:   false,
			RecommendedAction:  "deny",
			CoordinationReason: fmt.Sprintf("Bidirectional coordination failed: %v", err),
		}
	}

	alignmentScore := r.calculateRiskPolicyAlignment(riskResponse.AccessResponse.Granted, currentRiskScore, ztResponse.Granted)
	adjustedRiskLevel := r.calculateRiskLevelFromScore(currentRiskScore)

	return &ZeroTrustRiskCoordinationResult{
		CoordinationMode:   ZeroTrustRiskModeBidirectional,
		PolicyEvaluated:    true,
		PolicyGranted:      ztResponse.Granted,
		AlignmentScore:     alignmentScore,
		ConflictDetected:   riskResponse.AccessResponse.Granted != ztResponse.Granted,
		RecommendedAction:  r.determineRecommendedAction(riskResponse.AccessResponse.Granted, ztResponse.Granted, alignmentScore),
		CoordinationReason: fmt.Sprintf("Bidirectional coordination: Final Risk=%.2f, ZT=%t, Alignment=%.2f", currentRiskScore, ztResponse.Granted, alignmentScore),
		AdjustedRiskScore:  &currentRiskScore,
		AdjustedRiskLevel:  &adjustedRiskLevel,
	}
}

// performUnifiedCoordination performs unified evaluation treating risk and zero-trust as equal partners
func (r *RiskBasedAccessIntegration) performUnifiedCoordination(ctx context.Context, request *zerotrust.ZeroTrustAccessRequest, riskResponse *EnhancedRiskAccessResponse) *ZeroTrustRiskCoordinationResult {
	// Evaluate zero-trust policies
	ztResponse, err := r.zeroTrustEngine.EvaluateAccess(ctx, request)
	if err != nil {
		return &ZeroTrustRiskCoordinationResult{
			CoordinationMode:   ZeroTrustRiskModeUnified,
			PolicyEvaluated:    false,
			PolicyGranted:      false,
			AlignmentScore:     0.0,
			ConflictDetected:   false,
			RecommendedAction:  "deny",
			CoordinationReason: fmt.Sprintf("Zero-trust evaluation failed: %v", err),
		}
	}

	// Calculate unified decision using weighted scoring
	riskWeight := r.config.RiskWeight
	policyWeight := r.config.PolicyWeight

	// Normalize risk score to 0-1 range (assuming risk scores are 0-10)
	normalizedRiskScore := riskResponse.RiskScore / 10.0
	if normalizedRiskScore > 1.0 {
		normalizedRiskScore = 1.0
	}

	// Convert zero-trust decision to score (1.0 for granted, 0.0 for denied)
	policyScore := 0.0
	if ztResponse.Granted {
		policyScore = 1.0
	}

	// Calculate unified score
	unifiedScore := (riskWeight*(1.0-normalizedRiskScore) + policyWeight*policyScore) / (riskWeight + policyWeight)

	// Determine unified decision (threshold of 0.5)
	unifiedGranted := unifiedScore >= 0.5

	alignmentScore := r.calculateRiskPolicyAlignment(riskResponse.AccessResponse.Granted, riskResponse.RiskScore, ztResponse.Granted)

	return &ZeroTrustRiskCoordinationResult{
		CoordinationMode:   ZeroTrustRiskModeUnified,
		PolicyEvaluated:    true,
		PolicyGranted:      ztResponse.Granted,
		AlignmentScore:     alignmentScore,
		ConflictDetected:   riskResponse.AccessResponse.Granted != ztResponse.Granted,
		RecommendedAction:  r.boolToAction(unifiedGranted),
		CoordinationReason: fmt.Sprintf("Unified evaluation: Risk=%.2f, ZT=%t, Unified=%.2f->%t", riskResponse.RiskScore, ztResponse.Granted, unifiedScore, unifiedGranted),
		UnifiedScore:       &unifiedScore,
		UnifiedDecision:    &unifiedGranted,
	}
}

// StartSessionRiskMonitoring starts continuous risk monitoring for a session
func (rrai *RiskBasedAccessIntegration) StartSessionRiskMonitoring(ctx context.Context, sessionID, userID, tenantID string, initialRisk *RiskAssessmentResult) error {
	return rrai.continuousRiskMonitor.StartMonitoring(ctx, sessionID, userID, tenantID, initialRisk)
}

// StopSessionRiskMonitoring stops continuous risk monitoring for a session
func (rrai *RiskBasedAccessIntegration) StopSessionRiskMonitoring(ctx context.Context, sessionID string) error {
	return rrai.continuousRiskMonitor.StopMonitoring(ctx, sessionID)
}

// ReassessSessionRisk performs dynamic risk reassessment for an active session
func (rrai *RiskBasedAccessIntegration) ReassessSessionRisk(ctx context.Context, sessionID string, trigger string) (*RiskAssessmentResult, error) {
	return rrai.continuousRiskMonitor.ReassessRisk(ctx, sessionID, trigger)
}

// GetSessionRiskStatus returns current risk status for a session
func (rrai *RiskBasedAccessIntegration) GetSessionRiskStatus(ctx context.Context, sessionID string) (*SessionRiskMonitoring, error) {
	return rrai.continuousRiskMonitor.GetSessionStatus(ctx, sessionID)
}

// RegisterRiskEventCallback registers a callback for risk events
func (rrai *RiskBasedAccessIntegration) RegisterRiskEventCallback(callback RiskEventCallback) {
	rrai.continuousRiskMonitor.RegisterCallback(callback)
}
