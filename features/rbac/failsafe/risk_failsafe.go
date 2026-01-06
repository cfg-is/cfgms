// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package failsafe

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/risk"
)

// FailsafeRiskEngine provides fail-secure behavior for risk assessment operations
// When the underlying risk engine is unavailable, it defaults to enhanced authentication requirements
type FailsafeRiskEngine struct {
	underlying  *risk.RiskAssessmentEngine
	healthCheck *RiskHealthChecker
	failureMode RiskFailureMode
	mutex       sync.RWMutex
	metrics     *RiskFailsafeMetrics
}

// RiskFailureMode defines how the failsafe risk engine behaves during failures
type RiskFailureMode string

const (
	// RiskFailureModeHighRisk treats all requests as high risk during failures
	RiskFailureModeHighRisk RiskFailureMode = "high_risk"
	// RiskFailureModeCriticalRisk treats all requests as critical risk during failures
	RiskFailureModeCriticalRisk RiskFailureMode = "critical_risk"
	// RiskFailureModeEnhancedAuth requires enhanced authentication during failures
	RiskFailureModeEnhancedAuth RiskFailureMode = "enhanced_auth"
)

// RiskHealthChecker monitors the health of the underlying risk engine
type RiskHealthChecker struct {
	riskEngine             *risk.RiskAssessmentEngine
	lastHealthCheck        time.Time
	healthCheckInterval    time.Duration
	consecutiveFailures    int
	maxConsecutiveFailures int
	isHealthy              bool
	mutex                  sync.RWMutex
}

// RiskFailsafeMetrics tracks risk failsafe operation metrics
type RiskFailsafeMetrics struct {
	TotalAssessments    int64
	FailedAssessments   int64
	FailsafeAssessments int64
	HealthCheckFailures int64
	RecoveryEvents      int64
	mutex               sync.RWMutex
}

// NewFailsafeRiskEngine creates a new failsafe risk assessment engine
func NewFailsafeRiskEngine(underlying *risk.RiskAssessmentEngine) *FailsafeRiskEngine {
	healthChecker := &RiskHealthChecker{
		riskEngine:             underlying,
		healthCheckInterval:    45 * time.Second, // Slightly longer than RBAC
		maxConsecutiveFailures: 3,
		isHealthy:              true,
		mutex:                  sync.RWMutex{},
	}

	fre := &FailsafeRiskEngine{
		underlying:  underlying,
		healthCheck: healthChecker,
		failureMode: RiskFailureModeEnhancedAuth, // Default to enhanced auth
		mutex:       sync.RWMutex{},
		metrics: &RiskFailsafeMetrics{
			mutex: sync.RWMutex{},
		},
	}

	// Start health checking in background
	go fre.startHealthChecking()

	return fre
}

// SetFailureMode sets the failure behavior mode
func (fre *FailsafeRiskEngine) SetFailureMode(mode RiskFailureMode) {
	fre.mutex.Lock()
	defer fre.mutex.Unlock()
	fre.failureMode = mode
}

// IsHealthy returns the current health status of the underlying risk engine
func (fre *FailsafeRiskEngine) IsHealthy() bool {
	fre.healthCheck.mutex.RLock()
	defer fre.healthCheck.mutex.RUnlock()
	return fre.healthCheck.isHealthy
}

// GetMetrics returns the current risk failsafe metrics
func (fre *FailsafeRiskEngine) GetMetrics() *RiskFailsafeMetrics {
	fre.metrics.mutex.RLock()
	defer fre.metrics.mutex.RUnlock()
	return &RiskFailsafeMetrics{
		TotalAssessments:    fre.metrics.TotalAssessments,
		FailedAssessments:   fre.metrics.FailedAssessments,
		FailsafeAssessments: fre.metrics.FailsafeAssessments,
		HealthCheckFailures: fre.metrics.HealthCheckFailures,
		RecoveryEvents:      fre.metrics.RecoveryEvents,
	}
}

// EvaluateRisk implements fail-secure risk assessment
func (fre *FailsafeRiskEngine) EvaluateRisk(ctx context.Context, request *risk.RiskAssessmentRequest) (*risk.RiskAssessmentResult, error) {
	fre.metrics.mutex.Lock()
	fre.metrics.TotalAssessments++
	fre.metrics.mutex.Unlock()

	if !fre.IsHealthy() {
		return fre.generateFailsafeRiskAssessment(request)
	}

	result, err := fre.underlying.EvaluateRisk(ctx, request)
	if err != nil {
		fre.metrics.mutex.Lock()
		fre.metrics.FailedAssessments++
		fre.metrics.mutex.Unlock()

		// Mark as unhealthy and return failsafe assessment
		fre.markUnhealthy()
		return fre.generateFailsafeRiskAssessment(request)
	}

	return result, nil
}

// generateFailsafeRiskAssessment creates a high-risk assessment when the risk engine is unavailable
func (fre *FailsafeRiskEngine) generateFailsafeRiskAssessment(request *risk.RiskAssessmentRequest) (*risk.RiskAssessmentResult, error) {
	fre.metrics.mutex.Lock()
	fre.metrics.FailsafeAssessments++
	fre.metrics.mutex.Unlock()

	now := time.Now()
	requestID := fmt.Sprintf("failsafe-risk-assessment-%d", now.UnixNano())

	// Generate conservative (high-risk) assessment based on failure mode
	var riskLevel risk.RiskLevel
	var riskScore float64
	var accessDecision risk.AccessDecision
	var validityPeriod time.Duration

	switch fre.failureMode {
	case RiskFailureModeHighRisk:
		riskLevel = risk.RiskLevelHigh
		riskScore = 75.0
		accessDecision = risk.AccessDecisionStepUp
		validityPeriod = 15 * time.Minute
	case RiskFailureModeCriticalRisk:
		riskLevel = risk.RiskLevelCritical
		riskScore = 85.0
		accessDecision = risk.AccessDecisionBreakGlass
		validityPeriod = 5 * time.Minute
	case RiskFailureModeEnhancedAuth:
		riskLevel = risk.RiskLevelHigh
		riskScore = 70.0
		accessDecision = risk.AccessDecisionChallenge
		validityPeriod = 10 * time.Minute
	default:
		riskLevel = risk.RiskLevelCritical
		riskScore = 90.0
		accessDecision = risk.AccessDecisionDeny
		validityPeriod = 1 * time.Minute
	}

	// Create failsafe risk factors
	riskFactors := []risk.EvaluatedRiskFactor{
		{
			FactorID:      "failsafe-system-unavailable",
			FactorName:    "risk_engine_unavailable",
			Category:      risk.RiskFactorCategoryEnvironmental,
			Score:         100.0,
			Weight:        1.0,
			WeightedScore: 100.0,
			Severity:      risk.RiskFactorSeverityCritical,
			Explanation:   "Risk assessment system is unavailable, applying conservative risk assessment",
			Confidence:    1.0,
		},
	}

	// Generate conservative mitigation actions
	mitigationActions := []risk.RiskMitigationAction{
		{
			Type:        "enhanced_authentication",
			Description: "Require enhanced authentication due to risk engine failure",
			Priority:    "critical",
		},
		{
			Type:        "enhanced_monitoring",
			Description: "Enable enhanced monitoring due to system degradation",
			Priority:    "high",
		},
		{
			Type:        "session_recording",
			Description: "Enable session recording for audit purposes",
			Priority:    "medium",
		},
	}

	// Generate adaptive controls based on failure mode
	adaptiveControls := []risk.AdaptiveControl{
		{
			Type:        "step_up_authentication",
			Parameters:  map[string]interface{}{"method": "mfa", "reason": "risk_engine_failure"},
			Description: "Require multi-factor authentication due to risk engine unavailability",
		},
		{
			Type:        "session_timeout_reduction",
			Parameters:  map[string]interface{}{"timeout_minutes": 10, "reason": "risk_engine_failure"},
			Description: "Reduce session timeout due to system degradation",
		},
		{
			Type:        "restricted_permissions",
			Parameters:  map[string]interface{}{"restriction_level": "high", "reason": "risk_engine_failure"},
			Description: "Apply high-level permission restrictions",
		},
	}

	result := &risk.RiskAssessmentResult{
		RequestID:          requestID,
		OverallRiskScore:   riskScore,
		RiskLevel:          riskLevel,
		ConfidenceScore:    100.0, // High confidence in conservative assessment
		RiskFactors:        riskFactors,
		BehavioralRisk:     fre.generateFailsafeBehavioralRisk(),
		EnvironmentalRisk:  fre.generateFailsafeEnvironmentalRisk(),
		ResourceRisk:       fre.generateFailsafeResourceRisk(),
		RecommendedActions: mitigationActions,
		AccessDecision:     accessDecision,
		RequiredControls:   adaptiveControls,
		AssessedAt:         now,
		ValidityPeriod:     validityPeriod,
		NextAssessmentTime: now.Add(validityPeriod),
		Metadata: map[string]interface{}{
			"failsafe_mode":  true,
			"failure_reason": "risk_engine_unavailable",
			"failure_mode":   string(fre.failureMode),
			"generated_by":   "failsafe_risk_engine",
		},
	}

	return result, nil
}

// generateFailsafeBehavioralRisk creates a conservative behavioral risk assessment
func (fre *FailsafeRiskEngine) generateFailsafeBehavioralRisk() *risk.BehavioralRiskResult {
	return &risk.BehavioralRiskResult{
		RiskScore:       80.0, // High behavioral risk due to uncertainty
		ConfidenceScore: 50.0, // Lower confidence since we can't analyze behavior
		PatternAnomalies: []risk.PatternAnomaly{
			{
				AnomalyType:        "system_unavailable",
				Severity:           0.9,
				Description:        "Unable to analyze behavioral patterns due to system unavailability",
				ExpectedPattern:    nil,
				ActualPattern:      nil,
				DeviationMagnitude: 1.0,
				Confidence:         1.0,
			},
		},
		BehaviorDeviations: []risk.BehaviorDeviation{
			{
				DeviationType:    "system_unavailable",
				Metric:           "pattern_analysis",
				ExpectedValue:    0.0,
				ActualValue:      1.0,
				DeviationPercent: 100.0,
				Significance:     1.0,
			},
		},
		LearningStatus: "baseline_unavailable",
		BaselineAge:    time.Duration(0),
		SamplesCount:   0,
		LastUpdate:     time.Now(),
	}
}

// generateFailsafeEnvironmentalRisk creates a conservative environmental risk assessment
func (fre *FailsafeRiskEngine) generateFailsafeEnvironmentalRisk() *risk.EnvironmentalRiskResult {
	return &risk.EnvironmentalRiskResult{
		RiskScore:       75.0, // High environmental risk due to uncertainty
		ConfidenceScore: 50.0, // Lower confidence since we can't analyze environment
		LocationRisk: risk.LocationRisk{
			RiskScore:           70.0,
			IsTypicalLocation:   false,
			DistanceFromTypical: 0.0,
			CountryRisk:         70.0,
			RegionRisk:          70.0,
			VPNDetected:         false,
			ProxyDetected:       false,
			TorDetected:         false,
		},
		TimeRisk: risk.TimeRisk{
			RiskScore:       60.0,
			IsBusinessHours: false, // Assume worst case
			IsTypicalTime:   false,
			HourDeviation:   1.0,
			DayDeviation:    1.0,
			TimezoneRisk:    0.5,
		},
		NetworkRisk: risk.NetworkRisk{
			RiskScore:        80.0, // High network risk due to uncertainty
			NetworkType:      "unknown",
			IsKnownNetwork:   false,
			SecurityLevel:    "unknown",
			BandwidthAnomaly: false,
			LatencyAnomaly:   false,
		},
		DeviceRisk: risk.DeviceRisk{
			RiskScore:        75.0,
			IsKnownDevice:    false,
			DeviceType:       "unknown",
			OSRisk:           0.5,
			BrowserRisk:      0.5,
			ComplianceStatus: "unknown",
			LastScan:         nil,
		},
		ThreatEnvironment: risk.ThreatEnvironmentRisk{
			RiskScore:        80.0, // Assume elevated threat
			ThreatLevel:      "unknown",
			ReputationScore:  80.0,
			ThreatCategories: []string{},
			ActiveThreats:    0,
			RecentIncidents:  0,
		},
	}
}

// generateFailsafeResourceRisk creates a conservative resource risk assessment
func (fre *FailsafeRiskEngine) generateFailsafeResourceRisk() *risk.ResourceRiskResult {
	return &risk.ResourceRiskResult{
		RiskScore:       85.0, // High resource risk due to uncertainty
		ConfidenceScore: 60.0, // Moderate confidence in conservative assessment
		SensitivityRisk: risk.SensitivityRisk{
			RiskScore:         90.0,
			Sensitivity:       risk.ResourceSensitivityConfidential, // Assume high sensitivity
			Classification:    risk.DataClassificationConfidential,
			RequiredClearance: "",
			HasClearance:      false,
		},
		AccessPatternRisk: risk.AccessPatternRisk{
			RiskScore:         75.0,
			IsTypicalResource: false,
			AccessFrequency:   risk.AccessFrequencyRare,
			LastAccessed:      time.Time{},
			UnusualAccess:     true,
		},
		ComplianceRisk: risk.ComplianceRisk{
			RiskScore:     80.0,
			Requirements:  []string{},
			Violations:    []string{},
			AuditRequired: true,
			DataRetention: true,
		},
		BusinessImpactRisk: risk.BusinessImpactRisk{
			RiskScore:         85.0,
			CriticalityLevel:  risk.ResourceCriticalityHigh,
			BusinessValue:     0.8,
			ServiceDependency: true,
			CustomerImpact:    risk.CustomerImpactHigh,
		},
	}
}

// startHealthChecking runs continuous health checks in background
func (fre *FailsafeRiskEngine) startHealthChecking() {
	ticker := time.NewTicker(fre.healthCheck.healthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		fre.performHealthCheck()
	}
}

// performHealthCheck checks the health of the underlying risk engine
func (fre *FailsafeRiskEngine) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Risk assessment may take longer
	defer cancel()

	// Try a simple risk assessment to verify system health
	testRequest := &risk.RiskAssessmentRequest{
		AccessRequest: &common.AccessRequest{
			SubjectId:    "__health_check__",
			PermissionId: "__health_check__",
			TenantId:     "__health_check__",
			ResourceId:   "__health_check__",
		},
		UserContext: &risk.UserContext{
			UserID: "__health_check__",
		},
		ResourceContext: &risk.ResourceContext{
			ResourceID: "__health_check__",
		},
		RequiredConfidence: 0.5,
	}

	_, err := fre.underlying.EvaluateRisk(ctx, testRequest)

	fre.healthCheck.mutex.Lock()
	defer fre.healthCheck.mutex.Unlock()

	fre.healthCheck.lastHealthCheck = time.Now()

	if err != nil {
		fre.healthCheck.consecutiveFailures++
		fre.metrics.mutex.Lock()
		fre.metrics.HealthCheckFailures++
		fre.metrics.mutex.Unlock()

		if fre.healthCheck.consecutiveFailures >= fre.healthCheck.maxConsecutiveFailures {
			fre.healthCheck.isHealthy = false
			// Risk engine transitioned to unhealthy state (would log in production)
		}
	} else {
		// Health check succeeded
		wasHealthy := fre.healthCheck.isHealthy
		fre.healthCheck.consecutiveFailures = 0
		fre.healthCheck.isHealthy = true

		if !wasHealthy {
			// Risk engine recovered
			fre.metrics.mutex.Lock()
			fre.metrics.RecoveryEvents++
			fre.metrics.mutex.Unlock()
		}
	}
}

// markUnhealthy marks the risk engine as unhealthy due to operational failure
func (fre *FailsafeRiskEngine) markUnhealthy() {
	fre.healthCheck.mutex.Lock()
	defer fre.healthCheck.mutex.Unlock()

	fre.healthCheck.consecutiveFailures++
	if fre.healthCheck.consecutiveFailures >= fre.healthCheck.maxConsecutiveFailures {
		fre.healthCheck.isHealthy = false
	}
}

// Additional risk engine methods can be wrapped similarly if needed

// GetRiskFactors delegates to underlying engine with health check
func (fre *FailsafeRiskEngine) GetRiskFactors(ctx context.Context) map[string]risk.ContextualRiskFactor {
	if !fre.IsHealthy() {
		// Return empty factors when unhealthy
		return make(map[string]risk.ContextualRiskFactor)
	}
	return fre.underlying.GetRiskFactors(ctx)
}

// RegisterRiskFactor delegates to underlying engine with health check
func (fre *FailsafeRiskEngine) RegisterRiskFactor(factor risk.ContextualRiskFactor) error {
	if !fre.IsHealthy() {
		return fmt.Errorf("risk engine is unhealthy, cannot register risk factor")
	}
	return fre.underlying.RegisterRiskFactor(factor)
}

// UpdateRiskProfile delegates to underlying engine with health check
func (fre *FailsafeRiskEngine) UpdateRiskProfile(ctx context.Context, userID string, accessOutcome risk.AccessOutcome) error {
	if !fre.IsHealthy() {
		return fmt.Errorf("risk engine is unhealthy, cannot update risk profile")
	}
	return fre.underlying.UpdateRiskProfile(ctx, userID, accessOutcome)
}
