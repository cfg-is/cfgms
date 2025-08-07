package risk

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
)

// RiskAssessmentEngine provides comprehensive risk evaluation for access requests
type RiskAssessmentEngine struct {
	contextualFactors   map[string]ContextualRiskFactor
	behavioralAnalyzer  *BehavioralRiskAnalyzer
	environmentAnalyzer *EnvironmentRiskAnalyzer
	resourceAnalyzer    *ResourceRiskAnalyzer
	policyEngine        *RiskPolicyEngine
	auditLogger         *RiskAuditLogger
	cache               *RiskAssessmentCache
	mutex               sync.RWMutex
}

// NewRiskAssessmentEngine creates a new risk assessment engine
func NewRiskAssessmentEngine() *RiskAssessmentEngine {
	return &RiskAssessmentEngine{
		contextualFactors:   make(map[string]ContextualRiskFactor),
		behavioralAnalyzer:  NewBehavioralRiskAnalyzer(),
		environmentAnalyzer: NewEnvironmentRiskAnalyzer(),
		resourceAnalyzer:    NewResourceRiskAnalyzer(),
		policyEngine:        NewRiskPolicyEngine(),
		auditLogger:         NewRiskAuditLogger(),
		cache:               NewRiskAssessmentCache(),
		mutex:               sync.RWMutex{},
	}
}

// RiskAssessmentRequest contains all information needed for risk evaluation
type RiskAssessmentRequest struct {
	AccessRequest     *common.AccessRequest      `json:"access_request"`
	UserContext       *UserContext               `json:"user_context"`
	SessionContext    *SessionContext            `json:"session_context"`
	ResourceContext   *ResourceContext           `json:"resource_context"`
	EnvironmentContext *EnvironmentContext       `json:"environment_context"`
	HistoricalData    *HistoricalAccessData      `json:"historical_data,omitempty"`
	TenantPolicies    []RiskPolicy               `json:"tenant_policies"`
	RequiredConfidence float64                   `json:"required_confidence"`
}

// RiskAssessmentResult contains the comprehensive risk evaluation
type RiskAssessmentResult struct {
	RequestID              string                    `json:"request_id"`
	OverallRiskScore       float64                   `json:"overall_risk_score"`
	RiskLevel              RiskLevel                 `json:"risk_level"`
	ConfidenceScore        float64                   `json:"confidence_score"`
	RiskFactors            []EvaluatedRiskFactor     `json:"risk_factors"`
	BehavioralRisk         *BehavioralRiskResult     `json:"behavioral_risk"`
	EnvironmentalRisk      *EnvironmentalRiskResult  `json:"environmental_risk"`
	ResourceRisk           *ResourceRiskResult       `json:"resource_risk"`
	RecommendedActions     []RiskMitigationAction    `json:"recommended_actions"`
	AccessDecision         AccessDecision            `json:"access_decision"`
	RequiredControls       []AdaptiveControl         `json:"required_controls"`
	AssessedAt             time.Time                 `json:"assessed_at"`
	ValidityPeriod         time.Duration             `json:"validity_period"`
	NextAssessmentTime     time.Time                 `json:"next_assessment_time"`
	Metadata               map[string]interface{}    `json:"metadata,omitempty"`
}

// RiskLevel defines the overall risk assessment levels
type RiskLevel string

const (
	RiskLevelMinimal    RiskLevel = "minimal"     // 0-25: Very low risk, standard access
	RiskLevelLow        RiskLevel = "low"         // 26-45: Low risk, minimal additional controls
	RiskLevelModerate   RiskLevel = "moderate"    // 46-65: Medium risk, enhanced monitoring
	RiskLevelHigh       RiskLevel = "high"        // 66-80: High risk, strong additional controls
	RiskLevelCritical   RiskLevel = "critical"    // 81-95: Critical risk, maximum controls
	RiskLevelExtreme    RiskLevel = "extreme"     // 96-100: Extreme risk, deny or break-glass only
)

// AccessDecision defines the decision outcomes based on risk assessment
type AccessDecision string

const (
	AccessDecisionAllow          AccessDecision = "allow"              // Normal access granted
	AccessDecisionAllowWithControls AccessDecision = "allow_with_controls" // Access granted with additional controls
	AccessDecisionChallenge      AccessDecision = "challenge"          // Require additional authentication
	AccessDecisionStepUp         AccessDecision = "step_up"            // Require privilege elevation
	AccessDecisionDeny           AccessDecision = "deny"               // Access denied due to high risk
	AccessDecisionBreakGlass     AccessDecision = "break_glass_only"   // Only break-glass access allowed
	AccessDecisionQuarantine     AccessDecision = "quarantine"         // Access requires quarantine controls
)

// EvaluateRisk performs comprehensive risk assessment for an access request
func (rae *RiskAssessmentEngine) EvaluateRisk(ctx context.Context, request *RiskAssessmentRequest) (*RiskAssessmentResult, error) {
	rae.mutex.Lock()
	defer rae.mutex.Unlock()

	startTime := time.Now()
	requestID := fmt.Sprintf("risk-assessment-%d", startTime.UnixNano())

	// Check cache for recent assessment
	if cachedResult := rae.cache.Get(request); cachedResult != nil {
		return cachedResult, nil
	}

	result := &RiskAssessmentResult{
		RequestID:          requestID,
		AssessedAt:         startTime,
		RiskFactors:        make([]EvaluatedRiskFactor, 0),
		RecommendedActions: make([]RiskMitigationAction, 0),
		RequiredControls:   make([]AdaptiveControl, 0),
		Metadata:           make(map[string]interface{}),
	}

	// Evaluate behavioral risk patterns
	behavioralRisk, err := rae.behavioralAnalyzer.EvaluateBehavioralRisk(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("behavioral risk evaluation failed: %w", err)
	}
	result.BehavioralRisk = behavioralRisk

	// Evaluate environmental risk factors
	environmentalRisk, err := rae.environmentAnalyzer.EvaluateEnvironmentalRisk(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("environmental risk evaluation failed: %w", err)
	}
	result.EnvironmentalRisk = environmentalRisk

	// Evaluate resource-specific risk
	resourceRisk, err := rae.resourceAnalyzer.EvaluateResourceRisk(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("resource risk evaluation failed: %w", err)
	}
	result.ResourceRisk = resourceRisk

	// Calculate overall risk score using weighted combination
	overallScore := rae.calculateOverallRiskScore(behavioralRisk, environmentalRisk, resourceRisk)
	result.OverallRiskScore = overallScore
	result.RiskLevel = rae.determineRiskLevel(overallScore)

	// Calculate confidence score based on data quality and completeness
	result.ConfidenceScore = rae.calculateConfidenceScore(request, behavioralRisk, environmentalRisk, resourceRisk)

	// Evaluate against risk policies
	policyResult, err := rae.policyEngine.EvaluatePolicies(ctx, request, result)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	// Determine access decision based on risk level and policies
	result.AccessDecision = rae.determineAccessDecision(result, policyResult)

	// Generate recommended risk mitigation actions
	result.RecommendedActions = rae.generateRecommendedActions(result)

	// Generate required adaptive controls
	result.RequiredControls = rae.generateAdaptiveControls(result)

	// Set validity period based on risk level
	result.ValidityPeriod = rae.calculateValidityPeriod(result.RiskLevel)
	result.NextAssessmentTime = startTime.Add(result.ValidityPeriod)

	// Cache result for future requests
	rae.cache.Store(request, result)

	// Audit the risk assessment
	err = rae.auditLogger.LogRiskAssessment(ctx, request, result)
	if err != nil {
		// Log but don't fail the assessment
		result.Metadata["audit_error"] = err.Error()
	}

	return result, nil
}

// calculateOverallRiskScore combines individual risk scores using weighted formula
func (rae *RiskAssessmentEngine) calculateOverallRiskScore(behavioral *BehavioralRiskResult, environmental *EnvironmentalRiskResult, resource *ResourceRiskResult) float64 {
	// Weighted risk calculation with configurable weights
	behavioralWeight := 0.35  // User behavior patterns
	environmentalWeight := 0.30 // Location, time, device factors
	resourceWeight := 0.35    // Resource sensitivity and classification

	weightedScore := (behavioral.RiskScore * behavioralWeight) +
		(environmental.RiskScore * environmentalWeight) +
		(resource.RiskScore * resourceWeight)

	// Apply amplification factors for high-risk combinations
	amplificationFactor := 1.0
	if behavioral.RiskScore > 70 && environmental.RiskScore > 70 {
		amplificationFactor = 1.15 // 15% increase for dual high-risk
	}
	if resource.RiskScore > 80 {
		amplificationFactor = math.Max(amplificationFactor, 1.10) // 10% minimum for high resource risk
	}

	finalScore := weightedScore * amplificationFactor

	// Ensure score stays within bounds
	if finalScore > 100 {
		finalScore = 100
	}
	if finalScore < 0 {
		finalScore = 0
	}

	return finalScore
}

// determineRiskLevel maps numeric risk score to risk level category
func (rae *RiskAssessmentEngine) determineRiskLevel(score float64) RiskLevel {
	switch {
	case score >= 96:
		return RiskLevelExtreme
	case score >= 81:
		return RiskLevelCritical
	case score >= 66:
		return RiskLevelHigh
	case score >= 46:
		return RiskLevelModerate
	case score >= 26:
		return RiskLevelLow
	default:
		return RiskLevelMinimal
	}
}

// calculateConfidenceScore evaluates the reliability of the risk assessment
func (rae *RiskAssessmentEngine) calculateConfidenceScore(request *RiskAssessmentRequest, behavioral *BehavioralRiskResult, environmental *EnvironmentalRiskResult, resource *ResourceRiskResult) float64 {
	confidenceFactors := []float64{
		behavioral.ConfidenceScore,
		environmental.ConfidenceScore,
		resource.ConfidenceScore,
	}

	// Data completeness factor
	completeness := rae.calculateDataCompleteness(request)
	
	// Calculate weighted average confidence
	totalConfidence := 0.0
	for _, factor := range confidenceFactors {
		totalConfidence += factor
	}
	averageConfidence := totalConfidence / float64(len(confidenceFactors))

	// Apply completeness factor
	finalConfidence := averageConfidence * completeness

	return math.Min(finalConfidence, 100.0)
}

// calculateDataCompleteness evaluates how complete the input data is
func (rae *RiskAssessmentEngine) calculateDataCompleteness(request *RiskAssessmentRequest) float64 {
	completeness := 0.0
	maxScore := 5.0

	// Check presence of different context types
	if request.UserContext != nil && request.UserContext.UserID != "" {
		completeness += 1.0
	}
	if request.SessionContext != nil && request.SessionContext.SessionID != "" {
		completeness += 1.0
	}
	if request.ResourceContext != nil && request.ResourceContext.ResourceID != "" {
		completeness += 1.0
	}
	if request.EnvironmentContext != nil {
		completeness += 1.0
	}
	if request.HistoricalData != nil && len(request.HistoricalData.RecentAccess) > 0 {
		completeness += 1.0
	}

	return completeness / maxScore
}

// determineAccessDecision maps risk level and policy results to access decision
func (rae *RiskAssessmentEngine) determineAccessDecision(result *RiskAssessmentResult, policyResult *PolicyEvaluationResult) AccessDecision {
	// Policy can override risk-based decision
	if policyResult.Decision != "" {
		return AccessDecision(policyResult.Decision)
	}

	// Default risk-based decisions
	switch result.RiskLevel {
	case RiskLevelMinimal, RiskLevelLow:
		return AccessDecisionAllow
	case RiskLevelModerate:
		return AccessDecisionAllowWithControls
	case RiskLevelHigh:
		if result.ConfidenceScore > 80 {
			return AccessDecisionChallenge
		}
		return AccessDecisionStepUp
	case RiskLevelCritical:
		return AccessDecisionBreakGlass
	case RiskLevelExtreme:
		return AccessDecisionDeny
	default:
		return AccessDecisionChallenge
	}
}

// generateRecommendedActions creates risk mitigation recommendations
func (rae *RiskAssessmentEngine) generateRecommendedActions(result *RiskAssessmentResult) []RiskMitigationAction {
	actions := make([]RiskMitigationAction, 0)

	switch result.RiskLevel {
	case RiskLevelHigh, RiskLevelCritical, RiskLevelExtreme:
		actions = append(actions, RiskMitigationAction{
			Type:        "enhanced_monitoring",
			Description: "Enable real-time session monitoring",
			Priority:    "high",
		})
		actions = append(actions, RiskMitigationAction{
			Type:        "session_recording",
			Description: "Record session activity for audit",
			Priority:    "medium",
		})
	case RiskLevelModerate:
		actions = append(actions, RiskMitigationAction{
			Type:        "periodic_validation",
			Description: "Validate session every 15 minutes",
			Priority:    "medium",
		})
	}

	// Add behavioral-specific actions
	if result.BehavioralRisk.RiskScore > 60 {
		actions = append(actions, RiskMitigationAction{
			Type:        "behavioral_analysis",
			Description: "Continuous behavioral pattern monitoring",
			Priority:    "high",
		})
	}

	return actions
}

// generateAdaptiveControls creates specific controls based on risk assessment
func (rae *RiskAssessmentEngine) generateAdaptiveControls(result *RiskAssessmentResult) []AdaptiveControl {
	controls := make([]AdaptiveControl, 0)

	switch result.RiskLevel {
	case RiskLevelModerate:
		controls = append(controls, AdaptiveControl{
			Type:        "session_timeout_reduction",
			Parameters:  map[string]interface{}{"timeout_minutes": 30},
			Description: "Reduce session timeout to 30 minutes",
		})
	case RiskLevelHigh:
		controls = append(controls, AdaptiveControl{
			Type:        "step_up_authentication",
			Parameters:  map[string]interface{}{"method": "mfa"},
			Description: "Require multi-factor authentication",
		})
		controls = append(controls, AdaptiveControl{
			Type:        "restricted_permissions",
			Parameters:  map[string]interface{}{"restriction_level": "high"},
			Description: "Apply permission restrictions",
		})
	case RiskLevelCritical, RiskLevelExtreme:
		controls = append(controls, AdaptiveControl{
			Type:        "quarantine_mode",
			Parameters:  map[string]interface{}{"monitoring_level": "continuous"},
			Description: "Enable quarantine mode with continuous monitoring",
		})
	}

	return controls
}

// calculateValidityPeriod determines how long risk assessment remains valid
func (rae *RiskAssessmentEngine) calculateValidityPeriod(riskLevel RiskLevel) time.Duration {
	switch riskLevel {
	case RiskLevelMinimal:
		return 4 * time.Hour   // Low risk can be cached longer
	case RiskLevelLow:
		return 2 * time.Hour   
	case RiskLevelModerate:
		return 1 * time.Hour   
	case RiskLevelHigh:
		return 30 * time.Minute // High risk needs frequent re-evaluation
	case RiskLevelCritical:
		return 15 * time.Minute
	case RiskLevelExtreme:
		return 5 * time.Minute  // Extreme risk needs constant re-evaluation
	default:
		return 30 * time.Minute
	}
}

// GetRiskFactors returns all available risk factors
func (rae *RiskAssessmentEngine) GetRiskFactors(ctx context.Context) map[string]ContextualRiskFactor {
	rae.mutex.RLock()
	defer rae.mutex.RUnlock()

	factors := make(map[string]ContextualRiskFactor)
	for k, v := range rae.contextualFactors {
		factors[k] = v
	}
	return factors
}

// RegisterRiskFactor adds a new contextual risk factor
func (rae *RiskAssessmentEngine) RegisterRiskFactor(factor ContextualRiskFactor) error {
	rae.mutex.Lock()
	defer rae.mutex.Unlock()

	if factor.ID == "" {
		return fmt.Errorf("risk factor ID cannot be empty")
	}

	rae.contextualFactors[factor.ID] = factor
	return nil
}

// UpdateRiskProfile updates the risk profile for continuous learning
func (rae *RiskAssessmentEngine) UpdateRiskProfile(ctx context.Context, userID string, accessOutcome AccessOutcome) error {
	// Update behavioral patterns based on actual access outcomes
	return rae.behavioralAnalyzer.UpdateBehavioralProfile(ctx, userID, accessOutcome)
}