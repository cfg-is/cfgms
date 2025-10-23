// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package risk

import (
	"context"
	"fmt"
	"sync"
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

// RiskContextBuilder builds risk assessment contexts from access requests
type RiskContextBuilder struct {
	userDataProvider        *UserDataProvider
	sessionDataProvider     *SessionDataProvider
	resourceDataProvider    *ResourceDataProvider
	environmentDataProvider *EnvironmentDataProvider
	historicalDataProvider  *HistoricalDataProvider
}

// RiskDecisionEnforcer enforces risk-based access decisions
type RiskDecisionEnforcer struct {
	sessionManager      *RiskSessionManager
	controlApplicator   *RiskControlApplicator
	notificationService *RiskNotificationService
	complianceTracker   *RiskComplianceTracker
}

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

// ContinuousRiskMonitor monitors risk levels for active sessions
type ContinuousRiskMonitor struct {
	activeMonitoring   map[string]*SessionRiskMonitoring // sessionID -> monitoring data
	monitoringMutex    sync.RWMutex
	riskEngine         *RiskAssessmentEngine
	riskThresholds     *RiskThresholds
	eventCallbacks     []RiskEventCallback
	monitoringInterval time.Duration
	started            bool
	stopChannel        chan struct{}
}

// SessionRiskMonitoring contains monitoring data for a specific session
type SessionRiskMonitoring struct {
	SessionID         string                    `json:"session_id"`
	UserID            string                    `json:"user_id"`
	TenantID          string                    `json:"tenant_id"`
	CurrentRiskLevel  RiskLevel                 `json:"current_risk_level"`
	RiskScore         float64                   `json:"risk_score"`
	LastAssessment    time.Time                 `json:"last_assessment"`
	RiskTrend         []RiskTrendPoint          `json:"risk_trend"`
	ThresholdBreaches []RiskThresholdBreach     `json:"threshold_breaches"`
	AdaptiveControls  []AdaptiveControlInstance `json:"adaptive_controls"`
	NextReassessment  time.Time                 `json:"next_reassessment"`
	MonitoringStarted time.Time                 `json:"monitoring_started"`
}

// SessionRiskTracker tracks risk changes across sessions
type SessionRiskTracker struct {
	riskHistory     map[string][]RiskAssessmentResult // userID -> historical risk assessments
	historyMutex    sync.RWMutex
	maxHistorySize  int
	patternAnalyzer *RiskPatternAnalyzer
}

// RiskTrendPoint represents a point in the risk trend
type RiskTrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	RiskScore float64   `json:"risk_score"`
	RiskLevel RiskLevel `json:"risk_level"`
	Trigger   string    `json:"trigger"` // What triggered this assessment
}

// RiskThresholdBreach represents a risk threshold breach
type RiskThresholdBreach struct {
	Timestamp     time.Time `json:"timestamp"`
	PreviousLevel RiskLevel `json:"previous_level"`
	NewLevel      RiskLevel `json:"new_level"`
	TriggerEvent  string    `json:"trigger_event"`
	ActionTaken   string    `json:"action_taken"`
	Severity      string    `json:"severity"`
}

// RiskThresholds defines thresholds for risk level changes
type RiskThresholds struct {
	SignificantIncrease float64       `json:"significant_increase"` // % increase to trigger reassessment
	RapidEscalation     float64       `json:"rapid_escalation"`     // % increase in short time to trigger immediate action
	TimeWindow          time.Duration `json:"time_window"`          // Time window for rapid escalation
	CriticalThreshold   float64       `json:"critical_threshold"`   // Absolute score threshold for critical action
}

// RiskEventCallback is called when significant risk events occur
type RiskEventCallback func(sessionID string, event *RiskEvent) error

// RiskEvent represents a significant risk event
type RiskEvent struct {
	EventID       string                 `json:"event_id"`
	SessionID     string                 `json:"session_id"`
	EventType     RiskEventType          `json:"event_type"`
	Timestamp     time.Time              `json:"timestamp"`
	RiskScore     float64                `json:"risk_score"`
	RiskLevel     RiskLevel              `json:"risk_level"`
	PreviousScore float64                `json:"previous_score"`
	PreviousLevel RiskLevel              `json:"previous_level"`
	Trigger       string                 `json:"trigger"`
	Context       map[string]interface{} `json:"context"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// RiskEventType defines types of risk events
type RiskEventType string

const (
	RiskEventTypeThresholdBreach     RiskEventType = "threshold_breach"
	RiskEventTypeRapidEscalation     RiskEventType = "rapid_escalation"
	RiskEventTypePatternAnomaly      RiskEventType = "pattern_anomaly"
	RiskEventTypeContextualChange    RiskEventType = "contextual_change"
	RiskEventTypeBehavioralDeviation RiskEventType = "behavioral_deviation"
	RiskEventTypeEnvironmentalShift  RiskEventType = "environmental_shift"
)

// UserRiskPattern represents a user's risk behavior pattern
type UserRiskPattern struct {
	UserID         string             `json:"user_id"`
	BaselineRisk   float64            `json:"baseline_risk"`
	RecentActivity []RiskEvent        `json:"recent_activity"`
	BehaviorTrends map[string]float64 `json:"behavior_trends"`
	AnomalyScore   float64            `json:"anomaly_score"`
	LastUpdated    time.Time          `json:"last_updated"`
}

// RiskPatternAnalyzer analyzes risk patterns for behavioral insights
type RiskPatternAnalyzer struct {
	patterns       map[string]*UserRiskPattern // userID -> risk pattern
	analysisWindow time.Duration
	confidence     float64
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

// Factory functions for supporting components

func NewRiskContextBuilder() *RiskContextBuilder {
	return &RiskContextBuilder{
		userDataProvider:        &UserDataProvider{},
		sessionDataProvider:     &SessionDataProvider{},
		resourceDataProvider:    &ResourceDataProvider{},
		environmentDataProvider: &EnvironmentDataProvider{},
		historicalDataProvider:  &HistoricalDataProvider{},
	}
}

// BuildRiskContext builds a comprehensive risk assessment context from an access request
func (rcb *RiskContextBuilder) BuildRiskContext(ctx context.Context, request *common.AccessRequest) (*RiskAssessmentRequest, error) {
	riskRequest := &RiskAssessmentRequest{
		AccessRequest: request,
	}

	// Build user context
	userContext, err := rcb.userDataProvider.GetUserContext(ctx, request.SubjectId, request.TenantId)
	if err != nil {
		return nil, fmt.Errorf("failed to get user context: %w", err)
	}
	riskRequest.UserContext = userContext

	// Build session context - this would typically come from the HTTP request context
	sessionContext, err := rcb.sessionDataProvider.GetSessionContext(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to get session context: %w", err)
	}
	riskRequest.SessionContext = sessionContext

	// Build resource context
	resourceContext, err := rcb.resourceDataProvider.GetResourceContext(ctx, request.ResourceId, request.TenantId)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource context: %w", err)
	}
	riskRequest.ResourceContext = resourceContext

	// Build environment context
	environmentContext, err := rcb.environmentDataProvider.GetEnvironmentContext(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to get environment context: %w", err)
	}
	riskRequest.EnvironmentContext = environmentContext

	// Build historical data context
	historicalData, err := rcb.historicalDataProvider.GetHistoricalData(ctx, request.SubjectId, request.ResourceId, request.TenantId)
	if err != nil {
		// Historical data is optional - don't fail if not available
		fmt.Printf("Warning: Could not get historical data: %v", err)
	}
	riskRequest.HistoricalData = historicalData

	// Set default required confidence
	riskRequest.RequiredConfidence = 70.0 // Default 70% confidence requirement

	return riskRequest, nil
}

func NewRiskDecisionEnforcer() *RiskDecisionEnforcer {
	return &RiskDecisionEnforcer{
		sessionManager:      &RiskSessionManager{},
		controlApplicator:   &RiskControlApplicator{},
		notificationService: &RiskNotificationService{},
		complianceTracker:   &RiskComplianceTracker{},
	}
}

// ApplyAdaptiveControls applies the determined adaptive controls
func (rde *RiskDecisionEnforcer) ApplyAdaptiveControls(ctx context.Context, request *common.AccessRequest, controls []AdaptiveControl) error {
	for _, control := range controls {
		err := rde.controlApplicator.ApplyControl(ctx, request, &control)
		if err != nil {
			return fmt.Errorf("failed to apply control %s: %w", control.Type, err)
		}
	}

	// Track compliance with applied controls
	err := rde.complianceTracker.TrackControlApplication(ctx, request, controls)
	if err != nil {
		// Log but don't fail
		fmt.Printf("Warning: Failed to track compliance: %v", err)
	}

	return nil
}

// Supporting types (simplified implementations)
type UserDataProvider struct{}

func (udp *UserDataProvider) GetUserContext(ctx context.Context, userID, tenantID string) (*UserContext, error) {
	// Simplified user context - in practice would query user service
	return &UserContext{
		UserID:            userID,
		MFAEnabled:        true,
		SecurityClearance: "internal",
	}, nil
}

type SessionDataProvider struct{}

func (sdp *SessionDataProvider) GetSessionContext(ctx context.Context, request *common.AccessRequest) (*SessionContext, error) {
	// Simplified session context - in practice would extract from HTTP context
	return &SessionContext{
		SessionID:       fmt.Sprintf("session-%d", time.Now().UnixNano()),
		IPAddress:       "192.168.1.100", // Would extract from request
		LoginTime:       time.Now().Add(-30 * time.Minute),
		LastActivity:    time.Now(),
		SessionDuration: 30 * time.Minute,
	}, nil
}

type ResourceDataProvider struct{}

func (rdp *ResourceDataProvider) GetResourceContext(ctx context.Context, resourceID, tenantID string) (*ResourceContext, error) {
	// Simplified resource context - in practice would query resource service
	return &ResourceContext{
		ResourceID:     resourceID,
		ResourceType:   "database",
		Sensitivity:    ResourceSensitivityConfidential,
		Classification: DataClassificationConfidential,
		Owner:          "data-team",
		LastAccessed:   time.Now().Add(-1 * time.Hour),
	}, nil
}

type EnvironmentDataProvider struct{}

func (edp *EnvironmentDataProvider) GetEnvironmentContext(ctx context.Context, request *common.AccessRequest) (*EnvironmentContext, error) {
	// Simplified environment context - in practice would gather from various sources
	return &EnvironmentContext{
		AccessTime:      time.Now(),
		BusinessHours:   time.Now().Hour() >= 9 && time.Now().Hour() <= 17,
		NetworkType:     "corporate",
		VPNConnected:    false,
		NetworkSecurity: NetworkSecurityLevelHigh,
		GeoLocation: &GeoLocation{
			Country: "US",
			Region:  "California",
			City:    "San Francisco",
		},
	}, nil
}

type HistoricalDataProvider struct{}

func (hdp *HistoricalDataProvider) GetHistoricalData(ctx context.Context, userID, resourceID, tenantID string) (*HistoricalAccessData, error) {
	// Simplified historical data - in practice would query access logs
	return &HistoricalAccessData{
		RecentAccess: []AccessRecord{
			{
				Timestamp:  time.Now().Add(-2 * time.Hour),
				ResourceID: resourceID,
				Action:     "read",
				Result:     "granted",
				IPAddress:  "192.168.1.100",
			},
		},
		AccessPatterns: &AccessPatternAnalysis{
			TypicalHours:      []int{9, 10, 11, 14, 15, 16},
			TypicalDays:       []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday},
			TypicalLocations:  []string{"US:California", "US:New York"},
			TypicalResources:  []string{resourceID, "other-resource"},
			PatternConfidence: 85.0,
			LastUpdated:       time.Now().Add(-24 * time.Hour),
		},
	}, nil
}

type RiskSessionManager struct{}
type RiskControlApplicator struct{}

func (rca *RiskControlApplicator) ApplyControl(ctx context.Context, request *common.AccessRequest, control *AdaptiveControl) error {
	// Simplified control application - in practice would interact with session management, monitoring, etc.
	fmt.Printf("Applied control: %s with parameters: %+v", control.Type, control.Parameters)
	return nil
}

type RiskNotificationService struct{}
type RiskComplianceTracker struct{}

func (rct *RiskComplianceTracker) TrackControlApplication(ctx context.Context, request *common.AccessRequest, controls []AdaptiveControl) error {
	// Simplified compliance tracking
	return nil
}

// Continuous Risk Monitoring Methods

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

// ContinuousRiskMonitor Implementation

// NewContinuousRiskMonitor creates a new continuous risk monitor
func NewContinuousRiskMonitor(riskEngine *RiskAssessmentEngine) *ContinuousRiskMonitor {
	return &ContinuousRiskMonitor{
		activeMonitoring:   make(map[string]*SessionRiskMonitoring),
		riskEngine:         riskEngine,
		riskThresholds:     getDefaultRiskThresholds(),
		eventCallbacks:     make([]RiskEventCallback, 0),
		monitoringInterval: 30 * time.Second,
		stopChannel:        make(chan struct{}),
	}
}

// StartMonitoring starts risk monitoring for a session
func (crm *ContinuousRiskMonitor) StartMonitoring(ctx context.Context, sessionID, userID, tenantID string, initialRisk *RiskAssessmentResult) error {
	crm.monitoringMutex.Lock()
	defer crm.monitoringMutex.Unlock()

	// Create session risk monitoring
	monitoring := &SessionRiskMonitoring{
		SessionID:         sessionID,
		UserID:            userID,
		TenantID:          tenantID,
		CurrentRiskLevel:  initialRisk.RiskLevel,
		RiskScore:         initialRisk.OverallRiskScore,
		LastAssessment:    time.Now(),
		RiskTrend:         make([]RiskTrendPoint, 0),
		ThresholdBreaches: make([]RiskThresholdBreach, 0),
		AdaptiveControls:  make([]AdaptiveControlInstance, 0),
		NextReassessment:  time.Now().Add(crm.monitoringInterval),
		MonitoringStarted: time.Now(),
	}

	// Add initial trend point
	monitoring.RiskTrend = append(monitoring.RiskTrend, RiskTrendPoint{
		Timestamp: time.Now(),
		RiskScore: initialRisk.OverallRiskScore,
		RiskLevel: initialRisk.RiskLevel,
		Trigger:   "session_start",
	})

	crm.activeMonitoring[sessionID] = monitoring

	// Start monitoring loop if not already started
	if !crm.started {
		crm.started = true
		go crm.monitoringLoop(ctx)
	}

	return nil
}

// StopMonitoring stops risk monitoring for a session
func (crm *ContinuousRiskMonitor) StopMonitoring(ctx context.Context, sessionID string) error {
	crm.monitoringMutex.Lock()
	defer crm.monitoringMutex.Unlock()

	delete(crm.activeMonitoring, sessionID)
	return nil
}

// ReassessRisk performs dynamic risk reassessment for a session
func (crm *ContinuousRiskMonitor) ReassessRisk(ctx context.Context, sessionID, trigger string) (*RiskAssessmentResult, error) {
	crm.monitoringMutex.Lock()
	monitoring, exists := crm.activeMonitoring[sessionID]
	crm.monitoringMutex.Unlock()

	if !exists {
		return nil, fmt.Errorf("session %s not under monitoring", sessionID)
	}

	// Create risk assessment request based on current session context
	// In a real implementation, this would gather current context data
	riskRequest := &RiskAssessmentRequest{
		AccessRequest: &common.AccessRequest{
			SubjectId: monitoring.UserID,
			TenantId:  monitoring.TenantID,
		},
		UserContext:        &UserContext{UserID: monitoring.UserID},
		SessionContext:     &SessionContext{SessionID: sessionID},
		RequiredConfidence: 70.0,
	}

	// Perform risk assessment
	riskResult, err := crm.riskEngine.EvaluateRisk(ctx, riskRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to reassess risk for session %s: %w", sessionID, err)
	}

	// Update monitoring data
	crm.monitoringMutex.Lock()
	defer crm.monitoringMutex.Unlock()

	previousScore := monitoring.RiskScore
	previousLevel := monitoring.CurrentRiskLevel

	monitoring.RiskScore = riskResult.OverallRiskScore
	monitoring.CurrentRiskLevel = riskResult.RiskLevel
	monitoring.LastAssessment = time.Now()
	monitoring.NextReassessment = time.Now().Add(crm.monitoringInterval)

	// Add trend point
	monitoring.RiskTrend = append(monitoring.RiskTrend, RiskTrendPoint{
		Timestamp: time.Now(),
		RiskScore: riskResult.OverallRiskScore,
		RiskLevel: riskResult.RiskLevel,
		Trigger:   trigger,
	})

	// Check for threshold breaches
	if crm.hasSignificantRiskChange(previousScore, riskResult.OverallRiskScore, previousLevel, riskResult.RiskLevel) {
		breach := RiskThresholdBreach{
			Timestamp:     time.Now(),
			PreviousLevel: previousLevel,
			NewLevel:      riskResult.RiskLevel,
			TriggerEvent:  trigger,
			Severity:      crm.calculateBreachSeverity(previousLevel, riskResult.RiskLevel),
		}

		monitoring.ThresholdBreaches = append(monitoring.ThresholdBreaches, breach)

		// Create risk event
		event := &RiskEvent{
			EventID:       fmt.Sprintf("risk_event_%d", time.Now().UnixNano()),
			SessionID:     sessionID,
			EventType:     RiskEventTypeThresholdBreach,
			Timestamp:     time.Now(),
			RiskScore:     riskResult.OverallRiskScore,
			RiskLevel:     riskResult.RiskLevel,
			PreviousScore: previousScore,
			PreviousLevel: previousLevel,
			Trigger:       trigger,
			Context: map[string]interface{}{
				"monitoring_duration": time.Since(monitoring.MonitoringStarted).String(),
				"trend_count":         len(monitoring.RiskTrend),
			},
		}

		// Notify callbacks
		crm.notifyRiskEvent(sessionID, event)
	}

	return riskResult, nil
}

// GetSessionStatus returns current risk monitoring status for a session
func (crm *ContinuousRiskMonitor) GetSessionStatus(ctx context.Context, sessionID string) (*SessionRiskMonitoring, error) {
	crm.monitoringMutex.RLock()
	defer crm.monitoringMutex.RUnlock()

	monitoring, exists := crm.activeMonitoring[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not under monitoring", sessionID)
	}

	// Return a copy to prevent external modification
	statusCopy := *monitoring
	return &statusCopy, nil
}

// RegisterCallback registers a risk event callback
func (crm *ContinuousRiskMonitor) RegisterCallback(callback RiskEventCallback) {
	crm.monitoringMutex.Lock()
	defer crm.monitoringMutex.Unlock()
	crm.eventCallbacks = append(crm.eventCallbacks, callback)
}

// monitoringLoop runs continuous risk monitoring
func (crm *ContinuousRiskMonitor) monitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(crm.monitoringInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-crm.stopChannel:
			return
		case <-ticker.C:
			crm.performScheduledAssessments(ctx)
		}
	}
}

// performScheduledAssessments performs scheduled risk assessments
func (crm *ContinuousRiskMonitor) performScheduledAssessments(ctx context.Context) {
	crm.monitoringMutex.RLock()
	sessionsToAssess := make([]string, 0)
	now := time.Now()

	for sessionID, monitoring := range crm.activeMonitoring {
		if now.After(monitoring.NextReassessment) {
			sessionsToAssess = append(sessionsToAssess, sessionID)
		}
	}
	crm.monitoringMutex.RUnlock()

	// Perform reassessments outside the lock
	for _, sessionID := range sessionsToAssess {
		_, err := crm.ReassessRisk(ctx, sessionID, "scheduled_assessment")
		if err != nil {
			// Log error but continue with other sessions
			fmt.Printf("Warning: Failed to reassess risk for session %s: %v", sessionID, err)
		}
	}
}

// Helper methods

// hasSignificantRiskChange determines if there was a significant risk change
func (crm *ContinuousRiskMonitor) hasSignificantRiskChange(previousScore, newScore float64, previousLevel, newLevel RiskLevel) bool {
	// Check for risk level change
	if previousLevel != newLevel {
		return true
	}

	// Check for significant score increase
	if newScore > previousScore {
		increasePercent := (newScore - previousScore) / previousScore * 100
		if increasePercent >= crm.riskThresholds.SignificantIncrease {
			return true
		}
	}

	// Check for critical threshold breach
	if newScore >= crm.riskThresholds.CriticalThreshold {
		return true
	}

	return false
}

// calculateBreachSeverity calculates the severity of a risk threshold breach
func (crm *ContinuousRiskMonitor) calculateBreachSeverity(previousLevel, newLevel RiskLevel) string {
	if newLevel == RiskLevelExtreme {
		return "critical"
	}
	if newLevel == RiskLevelCritical {
		return "high"
	}
	if newLevel == RiskLevelHigh && previousLevel <= RiskLevelModerate {
		return "medium"
	}
	return "low"
}

// notifyRiskEvent notifies all registered callbacks of a risk event
func (crm *ContinuousRiskMonitor) notifyRiskEvent(sessionID string, event *RiskEvent) {
	for _, callback := range crm.eventCallbacks {
		go func(cb RiskEventCallback) {
			if err := cb(sessionID, event); err != nil {
				fmt.Printf("Warning: Risk event callback failed: %v", err)
			}
		}(callback)
	}
}

// SessionRiskTracker Implementation

// NewSessionRiskTracker creates a new session risk tracker
func NewSessionRiskTracker() *SessionRiskTracker {
	return &SessionRiskTracker{
		riskHistory:    make(map[string][]RiskAssessmentResult),
		maxHistorySize: 100, // Keep last 100 assessments per user
		patternAnalyzer: &RiskPatternAnalyzer{
			patterns:       make(map[string]*UserRiskPattern),
			analysisWindow: 24 * time.Hour,
			confidence:     80.0,
		},
	}
}

// TrackRiskAssessment tracks a risk assessment result
func (srt *SessionRiskTracker) TrackRiskAssessment(userID string, result *RiskAssessmentResult) {
	srt.historyMutex.Lock()
	defer srt.historyMutex.Unlock()

	if srt.riskHistory[userID] == nil {
		srt.riskHistory[userID] = make([]RiskAssessmentResult, 0)
	}

	// Add new assessment
	srt.riskHistory[userID] = append(srt.riskHistory[userID], *result)

	// Maintain history size limit
	if len(srt.riskHistory[userID]) > srt.maxHistorySize {
		srt.riskHistory[userID] = srt.riskHistory[userID][1:]
	}
}

// GetRiskHistory returns risk history for a user
func (srt *SessionRiskTracker) GetRiskHistory(userID string) []RiskAssessmentResult {
	srt.historyMutex.RLock()
	defer srt.historyMutex.RUnlock()

	history, exists := srt.riskHistory[userID]
	if !exists {
		return []RiskAssessmentResult{}
	}

	// Return a copy
	historyCopy := make([]RiskAssessmentResult, len(history))
	copy(historyCopy, history)
	return historyCopy
}

// Default configuration

// getDefaultRiskThresholds returns default risk thresholds
func getDefaultRiskThresholds() *RiskThresholds {
	return &RiskThresholds{
		SignificantIncrease: 20.0, // 20% increase
		RapidEscalation:     50.0, // 50% increase in short time
		TimeWindow:          5 * time.Minute,
		CriticalThreshold:   80.0, // Score of 80+ is critical
	}
}

// Zero-trust coordination helper methods

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
