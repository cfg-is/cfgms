// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package risk

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
)

func TestNewRiskAssessmentEngine(t *testing.T) {
	engine := NewRiskAssessmentEngine()

	assert.NotNil(t, engine)
	assert.NotNil(t, engine.contextualFactors)
	assert.NotNil(t, engine.behavioralAnalyzer)
	assert.NotNil(t, engine.environmentAnalyzer)
	assert.NotNil(t, engine.resourceAnalyzer)
	assert.NotNil(t, engine.policyEngine)
	assert.NotNil(t, engine.auditLogger)
	assert.NotNil(t, engine.cache)
}

func TestRiskAssessmentEngine_EvaluateRisk_MinimalRisk(t *testing.T) {
	engine := NewRiskAssessmentEngine()
	ctx := context.Background()

	request := createMinimalRiskRequest()

	result, err := engine.EvaluateRisk(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.RequestID)
	assert.True(t, result.OverallRiskScore >= 0 && result.OverallRiskScore <= 100)
	assert.NotZero(t, result.AssessedAt)
	assert.Positive(t, result.ValidityPeriod)
	assert.NotZero(t, result.NextAssessmentTime)

	// Minimal risk should result in low risk scores
	assert.True(t, result.OverallRiskScore < 50, "Minimal risk request should have low risk score")
	assert.Contains(t, []RiskLevel{RiskLevelMinimal, RiskLevelLow}, result.RiskLevel)
	assert.Contains(t, []AccessDecision{AccessDecisionAllow, AccessDecisionAllowWithControls}, result.AccessDecision)
}

func TestRiskAssessmentEngine_EvaluateRisk_HighRisk(t *testing.T) {
	engine := NewRiskAssessmentEngine()
	ctx := context.Background()

	request := createHighRiskRequest()

	result, err := engine.EvaluateRisk(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, result)

	// High risk should result in higher risk scores and more restrictive decisions
	assert.True(t, result.OverallRiskScore > 50, "High risk request should have elevated risk score")
	assert.Contains(t, []RiskLevel{RiskLevelModerate, RiskLevelHigh, RiskLevelCritical}, result.RiskLevel)

	// Should have risk factors identified
	assert.NotEmpty(t, result.RiskFactors)

	// Should have recommended mitigation actions
	assert.NotEmpty(t, result.RecommendedActions)

	// May require additional controls
	if result.AccessDecision == AccessDecisionAllowWithControls {
		assert.NotEmpty(t, result.RequiredControls)
	}
}

func TestRiskAssessmentEngine_EvaluateRisk_ExtremeRisk(t *testing.T) {
	engine := NewRiskAssessmentEngine()
	ctx := context.Background()

	request := createExtremeRiskRequest()

	result, err := engine.EvaluateRisk(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, result)

	// Extreme risk should result in very high scores and denial/break-glass decisions
	assert.True(t, result.OverallRiskScore > 70, "Extreme risk request should have very high risk score")
	assert.Contains(t, []RiskLevel{RiskLevelHigh, RiskLevelCritical, RiskLevelExtreme}, result.RiskLevel)

	// Should have restrictive access decision
	assert.Contains(t, []AccessDecision{AccessDecisionDeny, AccessDecisionBreakGlass, AccessDecisionChallenge, AccessDecisionStepUp}, result.AccessDecision)

	// Should have multiple risk factors
	assert.GreaterOrEqual(t, len(result.RiskFactors), 2)

	// Should have mitigation actions
	assert.NotEmpty(t, result.RecommendedActions)
}

func TestRiskAssessmentEngine_EvaluateRisk_WithHistoricalData(t *testing.T) {
	engine := NewRiskAssessmentEngine()
	ctx := context.Background()

	request := createRequestWithHistoricalData()

	result, err := engine.EvaluateRisk(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.BehavioralRisk)

	// Should have behavioral analysis
	if result.BehavioralRisk != nil {
		assert.NotEmpty(t, result.BehavioralRisk.BehaviorDeviations)
		assert.True(t, result.BehavioralRisk.ConfidenceScore >= 0 && result.BehavioralRisk.ConfidenceScore <= 1)
	}
}

func TestRiskAssessmentEngine_EvaluateRisk_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		request *RiskAssessmentRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			request: nil,
			wantErr: true,
		},
		{
			name: "missing access request",
			request: &RiskAssessmentRequest{
				UserContext:     createTestUserContext("user1"),
				SessionContext:  createTestSessionContext("session1"),
				ResourceContext: createTestResourceContext("resource1", ResourceSensitivityInternal),
			},
			wantErr: true,
		},
		{
			name: "missing user context",
			request: &RiskAssessmentRequest{
				AccessRequest:   createTestAccessRequest("user1", "resource1", "read"),
				SessionContext:  createTestSessionContext("session1"),
				ResourceContext: createTestResourceContext("resource1", ResourceSensitivityInternal),
			},
			wantErr: true,
		},
		{
			name: "missing resource context",
			request: &RiskAssessmentRequest{
				AccessRequest:  createTestAccessRequest("user1", "resource1", "read"),
				UserContext:    createTestUserContext("user1"),
				SessionContext: createTestSessionContext("session1"),
			},
			wantErr: true,
		},
	}

	engine := NewRiskAssessmentEngine()
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.EvaluateRisk(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestRiskAssessmentEngine_ResourceSensitivityImpact(t *testing.T) {
	tests := []struct {
		name                  string
		sensitivity           ResourceSensitivity
		expectedMinRiskLevel  RiskLevel
		expectedImpactOnScore bool
	}{
		{
			name:                  "Public sensitivity resource",
			sensitivity:           ResourceSensitivityPublic,
			expectedMinRiskLevel:  RiskLevelMinimal,
			expectedImpactOnScore: false,
		},
		{
			name:                  "Internal sensitivity resource",
			sensitivity:           ResourceSensitivityInternal,
			expectedMinRiskLevel:  RiskLevelLow,
			expectedImpactOnScore: true,
		},
		{
			name:                  "Confidential sensitivity resource",
			sensitivity:           ResourceSensitivityConfidential,
			expectedMinRiskLevel:  RiskLevelModerate,
			expectedImpactOnScore: true,
		},
		{
			name:                  "Secret sensitivity resource",
			sensitivity:           ResourceSensitivitySecret,
			expectedMinRiskLevel:  RiskLevelHigh,
			expectedImpactOnScore: true,
		},
	}

	engine := NewRiskAssessmentEngine()
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := createTestRequest("user1", "resource1", "read", tt.sensitivity)

			result, err := engine.EvaluateRisk(ctx, request)
			require.NoError(t, err)

			// Higher sensitivity should generally result in higher risk scores
			if tt.expectedImpactOnScore {
				assert.True(t, result.OverallRiskScore > 10,
					"Sensitive resources should increase risk score")
			}

			// Resource sensitivity should be reflected in resource risk analysis
			assert.NotNil(t, result.ResourceRisk)
			assert.Equal(t, tt.sensitivity, result.ResourceRisk.SensitivityRisk.Sensitivity)
		})
	}
}

func TestRiskAssessmentEngine_ThreatIntelligenceIntegration(t *testing.T) {
	engine := NewRiskAssessmentEngine()
	ctx := context.Background()

	// Request with threat intelligence indicating high risk IP
	request := createTestRequest("user1", "resource1", "read", ResourceSensitivityInternal)
	request.EnvironmentContext.ThreatIntelligence = &ThreatIntelligenceContext{
		IPReputationScore: 0.9, // High risk IP
		ThreatCategories:  []string{"malware", "phishing"},
		ThreatLevel:       ThreatLevelHigh,
		RecentThreats: []ThreatIndicator{
			{
				Type:        "malware_c2",
				Confidence:  0.85,
				Source:      "threat_intel_feed",
				Timestamp:   time.Now().Add(-1 * time.Hour),
				Description: "Known malware command and control server",
			},
		},
		LastUpdated: time.Now(),
	}

	result, err := engine.EvaluateRisk(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, result)

	// High threat intelligence should significantly increase risk
	assert.True(t, result.OverallRiskScore > 60,
		"High threat intelligence should significantly increase risk score")

	// Should have environmental risk analysis
	assert.NotNil(t, result.EnvironmentalRisk)
	assert.True(t, result.EnvironmentalRisk.ThreatEnvironment.ReputationScore > 0.5)

	// Should recommend additional controls or deny access
	assert.Contains(t, []AccessDecision{
		AccessDecisionDeny,
		AccessDecisionChallenge,
		AccessDecisionStepUp,
		AccessDecisionAllowWithControls,
	}, result.AccessDecision)
}

func TestRiskAssessmentEngine_BehavioralAnomalyDetection(t *testing.T) {
	engine := NewRiskAssessmentEngine()
	ctx := context.Background()

	request := createMinimalRiskRequest()

	// Add anomalous behavioral data
	request.HistoricalData = &HistoricalAccessData{
		AnomalyHistory: []AnomalyRecord{
			{
				Timestamp:     time.Now().Add(-2 * time.Hour),
				AnomalyType:   "unusual_time",
				Severity:      0.8,
				Description:   "Access at unusual hour (3 AM)",
				ExpectedValue: "9AM-5PM",
				ActualValue:   "3AM",
			},
			{
				Timestamp:     time.Now().Add(-1 * time.Hour),
				AnomalyType:   "unusual_location",
				Severity:      0.7,
				Description:   "Access from unusual geographic location",
				ExpectedValue: "New York, US",
				ActualValue:   "Moscow, RU",
			},
		},
		AccessPatterns: &AccessPatternAnalysis{
			TypicalHours:      []int{9, 10, 11, 14, 15, 16},
			TypicalLocations:  []string{"New York", "Boston"},
			PatternConfidence: 0.9,
		},
	}

	result, err := engine.EvaluateRisk(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, result)

	// Behavioral anomalies should increase risk
	assert.True(t, result.OverallRiskScore > 30,
		"Behavioral anomalies should increase risk score")

	// Should have behavioral risk analysis
	assert.NotNil(t, result.BehavioralRisk)
	assert.NotEmpty(t, result.BehavioralRisk.BehaviorDeviations)

	// Should identify anomalies as risk factors
	hasAnomalyFactor := false
	for _, factor := range result.RiskFactors {
		if factor.Category == "behavioral" {
			hasAnomalyFactor = true
			break
		}
	}
	assert.True(t, hasAnomalyFactor, "Should identify behavioral anomalies as risk factors")
}

func TestRiskAssessmentEngine_TimeBasedRiskEvaluation(t *testing.T) {
	tests := []struct {
		name          string
		accessTime    time.Time
		businessHours bool
		expectedRisk  string
	}{
		{
			name:          "Business hours access",
			accessTime:    time.Date(2023, 12, 15, 14, 0, 0, 0, time.UTC), // Friday 2 PM
			businessHours: true,
			expectedRisk:  "lower",
		},
		{
			name:          "After hours access",
			accessTime:    time.Date(2023, 12, 15, 22, 0, 0, 0, time.UTC), // Friday 10 PM
			businessHours: false,
			expectedRisk:  "higher",
		},
		{
			name:          "Weekend access",
			accessTime:    time.Date(2023, 12, 16, 14, 0, 0, 0, time.UTC), // Saturday 2 PM
			businessHours: false,
			expectedRisk:  "higher",
		},
		{
			name:          "Very early morning access",
			accessTime:    time.Date(2023, 12, 15, 3, 0, 0, 0, time.UTC), // Friday 3 AM
			businessHours: false,
			expectedRisk:  "much_higher",
		},
	}

	engine := NewRiskAssessmentEngine()
	ctx := context.Background()

	// Create a baseline request for business hours
	baselineRequest := createMinimalRiskRequest()
	baselineRequest.EnvironmentContext.AccessTime = time.Date(2023, 12, 15, 14, 0, 0, 0, time.UTC)
	baselineRequest.EnvironmentContext.BusinessHours = true

	baselineResult, err := engine.EvaluateRisk(ctx, baselineRequest)
	require.NoError(t, err)
	baselineScore := baselineResult.OverallRiskScore

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := createMinimalRiskRequest()
			request.EnvironmentContext.AccessTime = tt.accessTime
			request.EnvironmentContext.BusinessHours = tt.businessHours

			result, err := engine.EvaluateRisk(ctx, request)
			require.NoError(t, err)

			switch tt.expectedRisk {
			case "lower":
				// Business hours should have similar or lower risk
				assert.LessOrEqual(t, result.OverallRiskScore, baselineScore+5)
			case "higher":
				// After hours should have moderately higher risk
				assert.Greater(t, result.OverallRiskScore, baselineScore+5)
			case "much_higher":
				// Very unusual hours should have significantly higher risk
				assert.Greater(t, result.OverallRiskScore, baselineScore+15)
			}
		})
	}
}

func TestRiskAssessmentEngine_GeographicLocationRisk(t *testing.T) {
	tests := []struct {
		name           string
		country        string
		expectedHigher bool
		description    string
	}{
		{
			name:           "Trusted location",
			country:        "United States",
			expectedHigher: false,
			description:    "Access from trusted country should not increase risk significantly",
		},
		{
			name:           "High-risk location",
			country:        "North Korea",
			expectedHigher: true,
			description:    "Access from high-risk country should increase risk",
		},
		{
			name:           "Sanctioned location",
			country:        "Iran",
			expectedHigher: true,
			description:    "Access from sanctioned country should increase risk",
		},
	}

	engine := NewRiskAssessmentEngine()
	ctx := context.Background()

	// Create baseline request from trusted location
	baselineRequest := createMinimalRiskRequest()
	baselineRequest.EnvironmentContext.GeoLocation = &GeoLocation{
		Country: "United States",
		Region:  "New York",
		City:    "New York",
	}

	baselineResult, err := engine.EvaluateRisk(ctx, baselineRequest)
	require.NoError(t, err)
	baselineScore := baselineResult.OverallRiskScore

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := createMinimalRiskRequest()
			request.EnvironmentContext.GeoLocation = &GeoLocation{
				Country: tt.country,
				Region:  "Unknown",
				City:    "Unknown",
			}

			result, err := engine.EvaluateRisk(ctx, request)
			require.NoError(t, err)

			if tt.expectedHigher {
				assert.Greater(t, result.OverallRiskScore, baselineScore+10, tt.description)
			} else {
				assert.LessOrEqual(t, result.OverallRiskScore, baselineScore+5, tt.description)
			}
		})
	}
}

func TestRiskAssessmentEngine_ConcurrentEvaluations(t *testing.T) {
	engine := NewRiskAssessmentEngine()
	ctx := context.Background()

	const numConcurrent = 10
	results := make(chan *RiskAssessmentResult, numConcurrent)
	errors := make(chan error, numConcurrent)

	// Run multiple concurrent risk evaluations
	for i := 0; i < numConcurrent; i++ {
		go func(requestNum int) {
			request := createMinimalRiskRequest()
			request.AccessRequest.SubjectId = fmt.Sprintf("user%d", requestNum)

			result, err := engine.EvaluateRisk(ctx, request)
			if err != nil {
				errors <- err
			} else {
				results <- result
			}
		}(i)
	}

	// Collect results
	successCount := 0
	errorCount := 0

	for i := 0; i < numConcurrent; i++ {
		select {
		case result := <-results:
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.RequestID)
			successCount++
		case err := <-errors:
			t.Errorf("Unexpected error in concurrent test: %v", err)
			errorCount++
		case <-time.After(5 * time.Second):
			t.Fatal("Test timed out waiting for concurrent evaluations")
		}
	}

	assert.Equal(t, numConcurrent, successCount)
	assert.Equal(t, 0, errorCount)
}

// Helper functions for creating test data

func createMinimalRiskRequest() *RiskAssessmentRequest {
	return &RiskAssessmentRequest{
		AccessRequest:   createTestAccessRequest("user1", "resource1", "read"),
		UserContext:     createTestUserContext("user1"),
		SessionContext:  createTestSessionContext("session1"),
		ResourceContext: createTestResourceContext("resource1", ResourceSensitivityPublic),
		EnvironmentContext: &EnvironmentContext{
			AccessTime:      time.Now(),
			BusinessHours:   true,
			NetworkSecurity: NetworkSecurityLevelHigh,
			VPNConnected:    true,
			GeoLocation: &GeoLocation{
				Country: "United States",
				Region:  "California",
				City:    "San Francisco",
			},
			ThreatIntelligence: &ThreatIntelligenceContext{
				IPReputationScore: 0.1, // Low risk IP
				ThreatLevel:       ThreatLevelLow,
				LastUpdated:       time.Now(),
			},
		},
		RequiredConfidence: 0.8,
	}
}

func createHighRiskRequest() *RiskAssessmentRequest {
	request := createMinimalRiskRequest()

	// Make it high risk
	request.ResourceContext.Sensitivity = ResourceSensitivityConfidential
	request.ResourceContext.Classification = DataClassificationConfidential
	request.EnvironmentContext.BusinessHours = false
	request.EnvironmentContext.AccessTime = time.Date(2023, 12, 15, 2, 0, 0, 0, time.UTC) // 2 AM
	request.EnvironmentContext.VPNConnected = false
	request.EnvironmentContext.NetworkSecurity = NetworkSecurityLevelMedium
	request.EnvironmentContext.ThreatIntelligence.IPReputationScore = 0.6 // Medium risk IP
	request.AccessRequest.PermissionId = "admin"                          // High privilege

	return request
}

func createExtremeRiskRequest() *RiskAssessmentRequest {
	request := createHighRiskRequest()

	// Make it extreme risk
	request.ResourceContext.Sensitivity = ResourceSensitivitySecret
	request.ResourceContext.Classification = DataClassificationRestricted
	request.EnvironmentContext.GeoLocation.Country = "North Korea"
	request.EnvironmentContext.ThreatIntelligence.IPReputationScore = 0.95 // Very high risk IP
	request.EnvironmentContext.ThreatIntelligence.ThreatLevel = ThreatLevelCritical
	request.EnvironmentContext.ThreatIntelligence.ThreatCategories = []string{"malware", "apt", "botnet"}
	request.UserContext.MFAEnabled = false              // No MFA
	request.AccessRequest.PermissionId = "system_admin" // Critical privilege

	return request
}

func createRequestWithHistoricalData() *RiskAssessmentRequest {
	request := createMinimalRiskRequest()

	request.HistoricalData = &HistoricalAccessData{
		RecentAccess: []AccessRecord{
			{
				Timestamp:  time.Now().Add(-1 * time.Hour),
				ResourceID: "resource1",
				Action:     "read",
				Result:     "success",
				IPAddress:  "192.168.1.100",
			},
			{
				Timestamp:  time.Now().Add(-2 * time.Hour),
				ResourceID: "resource2",
				Action:     "write",
				Result:     "success",
				IPAddress:  "192.168.1.100",
			},
		},
		AccessPatterns: &AccessPatternAnalysis{
			TypicalHours:       []int{9, 10, 11, 14, 15, 16},
			TypicalDays:        []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday},
			TypicalLocations:   []string{"San Francisco", "New York"},
			TypicalResources:   []string{"resource1", "resource2"},
			AverageSessionTime: 2 * time.Hour,
			AccessFrequency:    map[string]int{"resource1": 10, "resource2": 5},
			PatternConfidence:  0.85,
			LastUpdated:        time.Now().Add(-24 * time.Hour),
		},
	}

	return request
}

func createTestRequest(userID, resourceID, permission string, sensitivity ResourceSensitivity) *RiskAssessmentRequest {
	return &RiskAssessmentRequest{
		AccessRequest:   createTestAccessRequest(userID, resourceID, permission),
		UserContext:     createTestUserContext(userID),
		SessionContext:  createTestSessionContext("session-" + userID),
		ResourceContext: createTestResourceContext(resourceID, sensitivity),
		EnvironmentContext: &EnvironmentContext{
			AccessTime:      time.Now(),
			BusinessHours:   true,
			NetworkSecurity: NetworkSecurityLevelHigh,
			VPNConnected:    true,
			GeoLocation: &GeoLocation{
				Country: "United States",
				Region:  "California",
				City:    "San Francisco",
			},
			ThreatIntelligence: &ThreatIntelligenceContext{
				IPReputationScore: 0.1,
				ThreatLevel:       ThreatLevelLow,
				LastUpdated:       time.Now(),
			},
		},
		RequiredConfidence: 0.8,
	}
}

func createTestAccessRequest(subjectID, resourceID, permission string) *common.AccessRequest {
	return &common.AccessRequest{
		SubjectId:    subjectID,
		ResourceId:   resourceID,
		PermissionId: permission,
		TenantId:     "tenant1",
		Context: map[string]string{
			"request_type": "direct",
		},
	}
}

func createTestUserContext(userID string) *UserContext {
	return &UserContext{
		UserID:             userID,
		Username:           userID + "@example.com",
		Email:              userID + "@example.com",
		Department:         "Engineering",
		Role:               "Developer",
		SecurityClearance:  "Standard",
		LastPasswordChange: time.Now().Add(-30 * 24 * time.Hour), // 30 days ago
		MFAEnabled:         true,
		MFAMethods:         []string{"totp", "sms"},
	}
}

func createTestSessionContext(sessionID string) *SessionContext {
	return &SessionContext{
		SessionID:       sessionID,
		DeviceID:        "device-123",
		DeviceType:      "laptop",
		IPAddress:       "192.168.1.100",
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		LoginMethod:     "oauth2",
		LoginTime:       time.Now().Add(-1 * time.Hour),
		LastActivity:    time.Now().Add(-5 * time.Minute),
		SessionDuration: time.Hour,
	}
}

func createTestResourceContext(resourceID string, sensitivity ResourceSensitivity) *ResourceContext {
	classification := DataClassificationPublic
	switch sensitivity {
	case ResourceSensitivityInternal:
		classification = DataClassificationInternal
	case ResourceSensitivityConfidential:
		classification = DataClassificationConfidential
	case ResourceSensitivitySecret:
		classification = DataClassificationRestricted
	}

	return &ResourceContext{
		ResourceID:       resourceID,
		ResourceType:     "database",
		ResourceName:     "Test Database",
		Sensitivity:      sensitivity,
		Classification:   classification,
		Owner:            "data-team",
		LastAccessed:     time.Now().Add(-24 * time.Hour),
		AccessFrequency:  50,
		ResourceLocation: "us-west-2",
	}
}
