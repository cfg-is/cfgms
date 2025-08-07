package risk

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/jit"
	"github.com/cfgis/cfgms/features/tenant/security"
)

// RiskBasedAccessIntegration integrates risk assessment with RBAC and JIT access
type RiskBasedAccessIntegration struct {
	riskEngine            *RiskAssessmentEngine
	adaptiveControls      *AdaptiveControlsEngine
	rbacManager           rbac.RBACManager
	jitIntegrationManager *jit.JITIntegrationManager
	tenantSecurity        *security.TenantSecurityMiddleware
	contextBuilder        *RiskContextBuilder
	decisionEnforcer      *RiskDecisionEnforcer
}

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
	sessionManager        *RiskSessionManager
	controlApplicator     *RiskControlApplicator
	notificationService   *RiskNotificationService
	complianceTracker     *RiskComplianceTracker
}

// EnhancedRiskAccessResponse extends JIT access response with risk information
type EnhancedRiskAccessResponse struct {
	StandardResponse    *common.AccessResponse                         `json:"standard_response"`
	TenantSecurity      *security.TenantSecurityValidationResult       `json:"tenant_security"`
	JITAccess           *jit.JITAccessValidationResult                 `json:"jit_access"`
	RiskAssessment      *RiskAssessmentResult                          `json:"risk_assessment"`
	AppliedControls     []AdaptiveControlInstance                      `json:"applied_controls"`
	ValidationLatency   time.Duration                                  `json:"validation_latency"`
	RiskFactorsSummary  *RiskFactorsSummary                            `json:"risk_factors_summary"`
}

// RiskFactorsSummary provides a summary of key risk factors
type RiskFactorsSummary struct {
	PrimaryRiskFactors  []string  `json:"primary_risk_factors"`
	BehavioralScore     float64   `json:"behavioral_score"`
	EnvironmentalScore  float64   `json:"environmental_score"`
	ResourceScore       float64   `json:"resource_score"`
	OverallRiskLevel    RiskLevel `json:"overall_risk_level"`
	ConfidenceLevel     string    `json:"confidence_level"`
	KeyRecommendations  []string  `json:"key_recommendations"`
}

// NewRiskBasedAccessIntegration creates a new risk-based access integration
func NewRiskBasedAccessIntegration(
	rbacManager rbac.RBACManager,
	jitIntegrationManager *jit.JITIntegrationManager,
	tenantSecurity *security.TenantSecurityMiddleware,
) *RiskBasedAccessIntegration {
	return &RiskBasedAccessIntegration{
		riskEngine:            NewRiskAssessmentEngine(),
		adaptiveControls:      NewAdaptiveControlsEngine(),
		rbacManager:           rbacManager,
		jitIntegrationManager: jitIntegrationManager,
		tenantSecurity:        tenantSecurity,
		contextBuilder:        NewRiskContextBuilder(),
		decisionEnforcer:      NewRiskDecisionEnforcer(),
	}
}

// EnhancedRiskAccessCheck performs risk-aware access checks integrating RBAC, JIT, and risk assessment
func (rrai *RiskBasedAccessIntegration) EnhancedRiskAccessCheck(ctx context.Context, request *common.AccessRequest) (*EnhancedRiskAccessResponse, error) {
	startTime := time.Now()
	
	// Step 1: Perform standard RBAC + JIT access check
	jitResponse, err := rrai.jitIntegrationManager.EnhancedAccessCheck(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("JIT access check failed: %w", err)
	}

	// Step 2: Build risk assessment context
	riskRequest, err := rrai.contextBuilder.BuildRiskContext(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to build risk context: %w", err)
	}

	// Step 3: Perform risk assessment
	riskResult, err := rrai.riskEngine.EvaluateRisk(ctx, riskRequest)
	if err != nil {
		return nil, fmt.Errorf("risk assessment failed: %w", err)
	}

	// Step 4: Generate adaptive controls based on risk level
	adaptiveControls, err := rrai.adaptiveControls.GenerateAdaptiveControls(ctx, riskResult, riskRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to generate adaptive controls: %w", err)
	}

	// Step 5: Make final access decision considering risk
	finalDecision, appliedControls, err := rrai.makeRiskAwareAccessDecision(ctx, jitResponse, riskResult, adaptiveControls)
	if err != nil {
		return nil, fmt.Errorf("failed to make risk-aware access decision: %w", err)
	}

	// Step 6: Apply controls if access is granted
	if finalDecision.Granted {
		err = rrai.decisionEnforcer.ApplyAdaptiveControls(ctx, request, appliedControls)
		if err != nil {
			// Log error but don't fail the access - controls are additive security
			fmt.Printf("Warning: Failed to apply some adaptive controls: %v", err)
		}
	}

	// Step 7: Create enhanced response
	response := &EnhancedRiskAccessResponse{
		StandardResponse:   finalDecision,
		TenantSecurity:     jitResponse.TenantSecurity,
		JITAccess:          jitResponse.JITAccess,
		RiskAssessment:     riskResult,
		AppliedControls:    rrai.convertToControlInstances(appliedControls),
		ValidationLatency:  time.Since(startTime),
		RiskFactorsSummary: rrai.buildRiskFactorsSummary(riskResult),
	}

	// Step 8: Log risk-aware access attempt
	err = rrai.logRiskAwareAccess(ctx, request, response)
	if err != nil {
		// Log error but don't fail the access
		fmt.Printf("Warning: Failed to log risk-aware access: %v", err)
	}

	return response, nil
}

// makeRiskAwareAccessDecision makes the final access decision considering all factors
func (rrai *RiskBasedAccessIntegration) makeRiskAwareAccessDecision(
	ctx context.Context,
	jitResponse *jit.EnhancedJITAccessResponse,
	riskResult *RiskAssessmentResult,
	adaptiveControls []AdaptiveControl,
) (*common.AccessResponse, []AdaptiveControl, error) {

	// Start with the JIT access decision
	finalResponse := &common.AccessResponse{
		Granted:             jitResponse.StandardResponse.Granted,
		Reason:              jitResponse.StandardResponse.Reason,
		AppliedPermissions:  jitResponse.StandardResponse.AppliedPermissions,
	}

	appliedControls := make([]AdaptiveControl, 0)

	// Apply risk-based decision logic
	switch riskResult.AccessDecision {
	case AccessDecisionDeny:
		// Risk assessment says deny - override any previous decision
		finalResponse.Granted = false
		finalResponse.Reason = fmt.Sprintf("Access denied due to %s risk level", riskResult.RiskLevel)

	case AccessDecisionBreakGlass:
		// Only allow break-glass access
		finalResponse.Granted = false
		finalResponse.Reason = fmt.Sprintf("Only break-glass access allowed due to %s risk level", riskResult.RiskLevel)

	case AccessDecisionQuarantine:
		// Allow but with quarantine controls
		if finalResponse.Granted {
			finalResponse.Reason = "Access granted with quarantine controls due to risk level"
			quarantineControls := rrai.getQuarantineControls(adaptiveControls)
			appliedControls = append(appliedControls, quarantineControls...)
		}

	case AccessDecisionChallenge:
		// Require additional challenge
		if finalResponse.Granted {
			challengeRequired := rrai.requiresAdditionalChallenge(riskResult, jitResponse)
			if challengeRequired {
				finalResponse.Granted = false
				finalResponse.Reason = "Additional authentication challenge required"
			} else {
				appliedControls = append(appliedControls, adaptiveControls...)
			}
		}

	case AccessDecisionStepUp:
		// Require step-up authentication
		if finalResponse.Granted {
			stepUpRequired := rrai.requiresStepUpAuth(riskResult, jitResponse)
			if stepUpRequired {
				finalResponse.Granted = false
				finalResponse.Reason = "Step-up authentication required"
			} else {
				appliedControls = append(appliedControls, adaptiveControls...)
			}
		}

	case AccessDecisionAllowWithControls:
		// Allow with adaptive controls
		if finalResponse.Granted {
			finalResponse.Reason = "Access granted with adaptive security controls"
			appliedControls = append(appliedControls, adaptiveControls...)
		}

	case AccessDecisionAllow:
		// Standard allow - apply minimal controls
		if finalResponse.Granted {
			minimalControls := rrai.getMinimalControls(adaptiveControls)
			appliedControls = append(appliedControls, minimalControls...)
		}
	}

	// Note: Risk metadata would be logged by audit system since AccessResponse doesn't support metadata
	// Risk assessment metadata: score=%.2f, level=%s, confidence=%.2f, assessed_at=%s
	
	return finalResponse, appliedControls, nil
}

// buildRiskFactorsSummary creates a summary of key risk factors
func (rrai *RiskBasedAccessIntegration) buildRiskFactorsSummary(riskResult *RiskAssessmentResult) *RiskFactorsSummary {
	summary := &RiskFactorsSummary{
		OverallRiskLevel:   riskResult.RiskLevel,
		PrimaryRiskFactors: make([]string, 0),
		KeyRecommendations: make([]string, 0),
	}

	// Extract primary risk factors
	if riskResult.BehavioralRisk != nil {
		summary.BehavioralScore = riskResult.BehavioralRisk.RiskScore
		if riskResult.BehavioralRisk.RiskScore > 60 {
			summary.PrimaryRiskFactors = append(summary.PrimaryRiskFactors, "behavioral_anomaly")
		}
	}

	if riskResult.EnvironmentalRisk != nil {
		summary.EnvironmentalScore = riskResult.EnvironmentalRisk.RiskScore
		if riskResult.EnvironmentalRisk.RiskScore > 60 {
			if !riskResult.EnvironmentalRisk.LocationRisk.IsTypicalLocation {
				summary.PrimaryRiskFactors = append(summary.PrimaryRiskFactors, "unusual_location")
			}
			if !riskResult.EnvironmentalRisk.DeviceRisk.IsKnownDevice {
				summary.PrimaryRiskFactors = append(summary.PrimaryRiskFactors, "unknown_device")
			}
			if !riskResult.EnvironmentalRisk.TimeRisk.IsBusinessHours {
				summary.PrimaryRiskFactors = append(summary.PrimaryRiskFactors, "after_hours_access")
			}
		}
	}

	if riskResult.ResourceRisk != nil {
		summary.ResourceScore = riskResult.ResourceRisk.RiskScore
		if riskResult.ResourceRisk.RiskScore > 60 {
			if riskResult.ResourceRisk.SensitivityRisk.Sensitivity >= ResourceSensitivityConfidential {
				summary.PrimaryRiskFactors = append(summary.PrimaryRiskFactors, "sensitive_resource")
			}
			if len(riskResult.ResourceRisk.ComplianceRisk.Violations) > 0 {
				summary.PrimaryRiskFactors = append(summary.PrimaryRiskFactors, "compliance_violations")
			}
		}
	}

	// Determine confidence level
	if riskResult.ConfidenceScore >= 80 {
		summary.ConfidenceLevel = "high"
	} else if riskResult.ConfidenceScore >= 60 {
		summary.ConfidenceLevel = "medium"
	} else {
		summary.ConfidenceLevel = "low"
	}

	// Generate key recommendations
	for _, action := range riskResult.RecommendedActions {
		if action.Priority == "high" || action.Priority == "critical" {
			summary.KeyRecommendations = append(summary.KeyRecommendations, action.Description)
		}
	}

	return summary
}

// Helper methods for decision making

func (rrai *RiskBasedAccessIntegration) requiresAdditionalChallenge(riskResult *RiskAssessmentResult, jitResponse *jit.EnhancedJITAccessResponse) bool {
	// Check if user has already completed MFA
	if jitResponse.TenantSecurity != nil {
		// If tenant security validation shows MFA was completed, no additional challenge needed
		// This would be implementation-specific based on tenant security context
	}
	
	return riskResult.RiskLevel >= RiskLevelHigh
}

func (rrai *RiskBasedAccessIntegration) requiresStepUpAuth(riskResult *RiskAssessmentResult, jitResponse *jit.EnhancedJITAccessResponse) bool {
	// Similar logic to challenge but for step-up authentication
	return riskResult.RiskLevel >= RiskLevelCritical
}

func (rrai *RiskBasedAccessIntegration) getChallengeType(riskResult *RiskAssessmentResult) string {
	switch riskResult.RiskLevel {
	case RiskLevelHigh:
		return "mfa"
	case RiskLevelCritical:
		return "biometric"
	case RiskLevelExtreme:
		return "hardware_token"
	default:
		return "totp"
	}
}

func (rrai *RiskBasedAccessIntegration) getRequiredAuthLevel(riskResult *RiskAssessmentResult) string {
	switch riskResult.RiskLevel {
	case RiskLevelCritical:
		return "elevated"
	case RiskLevelExtreme:
		return "maximum"
	default:
		return "standard"
	}
}

func (rrai *RiskBasedAccessIntegration) getQuarantineControls(controls []AdaptiveControl) []AdaptiveControl {
	quarantineControls := make([]AdaptiveControl, 0)
	for _, control := range controls {
		if control.Type == "quarantine_mode" || 
		   control.Type == "enhanced_monitoring" ||
		   control.Type == "session_recording" {
			quarantineControls = append(quarantineControls, control)
		}
	}
	return quarantineControls
}

func (rrai *RiskBasedAccessIntegration) getMinimalControls(controls []AdaptiveControl) []AdaptiveControl {
	minimalControls := make([]AdaptiveControl, 0)
	for _, control := range controls {
		if control.Priority == ControlPriorityLow || control.Priority == ControlPriorityMedium {
			minimalControls = append(minimalControls, control)
		}
	}
	return minimalControls
}

func (rrai *RiskBasedAccessIntegration) convertToControlInstances(controls []AdaptiveControl) []AdaptiveControlInstance {
	instances := make([]AdaptiveControlInstance, len(controls))
	for i, control := range controls {
		instances[i] = AdaptiveControlInstance{
			ID:           fmt.Sprintf("ctrl-%d-%d", time.Now().UnixNano(), i),
			DefinitionID: control.Type,
			Status:       ControlStatusActive,
			AppliedAt:    time.Now(),
			Parameters:   control.Parameters,
		}
	}
	return instances
}

func (rrai *RiskBasedAccessIntegration) logRiskAwareAccess(ctx context.Context, request *common.AccessRequest, response *EnhancedRiskAccessResponse) error {
	// Create comprehensive audit log entry
	logEntry := map[string]interface{}{
		"event_type":          "risk_aware_access_check",
		"user_id":             request.SubjectId,
		"tenant_id":           request.TenantId,
		"resource_id":         request.ResourceId,
		"permission_id":       request.PermissionId,
		"access_granted":      response.StandardResponse.Granted,
		"risk_score":          response.RiskAssessment.OverallRiskScore,
		"risk_level":          response.RiskAssessment.RiskLevel,
		"confidence_score":    response.RiskAssessment.ConfidenceScore,
		"access_decision":     response.RiskAssessment.AccessDecision,
		"applied_controls_count": len(response.AppliedControls),
		"validation_latency_ms":  response.ValidationLatency.Milliseconds(),
		"primary_risk_factors":   response.RiskFactorsSummary.PrimaryRiskFactors,
		"jit_access_used":        response.JITAccess.HasJITAccess,
		"timestamp":              time.Now().Unix(),
	}

	// In a real implementation, this would use the configured audit logging system
	fmt.Printf("Risk-aware access log: %+v\n", logEntry)
	
	return nil
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
		SessionID:   fmt.Sprintf("session-%d", time.Now().UnixNano()),
		IPAddress:   "192.168.1.100", // Would extract from request
		LoginTime:   time.Now().Add(-30 * time.Minute),
		LastActivity: time.Now(),
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
			TypicalHours:     []int{9, 10, 11, 14, 15, 16},
			TypicalDays:      []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday},
			TypicalLocations: []string{"US:California", "US:New York"},
			TypicalResources: []string{resourceID, "other-resource"},
			PatternConfidence: 85.0,
			LastUpdated:      time.Now().Add(-24 * time.Hour),
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