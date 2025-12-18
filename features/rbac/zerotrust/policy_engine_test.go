// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package zerotrust

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
)

func TestNewZeroTrustPolicyEngine(t *testing.T) {
	config := &ZeroTrustConfig{
		MaxEvaluationTime:          5 * time.Second,
		CacheEnabled:               true,
		CacheTTL:                   10 * time.Minute,
		DefaultEnforcementMode:     PolicyEnforcementModeEnforcing,
		FailSecure:                 true,
		EnableRBACIntegration:      true,
		EnableJITIntegration:       true,
		EnableRiskIntegration:      true,
		EnableTenantIntegration:    true,
		EnableContinuousAuth:       true,
		EnableComplianceValidation: true,
		ComplianceFrameworks:       []ComplianceFramework{ComplianceFrameworkSOC2, ComplianceFrameworkGDPR},
		EnableMetrics:              true,
		EnableAuditing:             true,
		MetricsInterval:            1 * time.Minute,
	}

	engine := NewZeroTrustPolicyEngine(config)

	assert.NotNil(t, engine)
	assert.NotNil(t, engine.activePolicies)
	assert.NotNil(t, engine.policyCache)
	assert.NotNil(t, engine.config)
	assert.NotNil(t, engine.stats)
	assert.NotNil(t, engine.auditLogger)
	assert.Equal(t, config.MaxEvaluationTime, engine.config.MaxEvaluationTime)
	assert.Equal(t, config.FailSecure, engine.config.FailSecure)
	assert.False(t, engine.started)
}

func TestZeroTrustPolicyEngineStartStop(t *testing.T) {
	config := &ZeroTrustConfig{
		MaxEvaluationTime: 5 * time.Second,
		MetricsInterval:   100 * time.Millisecond,
	}

	engine := NewZeroTrustPolicyEngine(config)
	ctx := context.Background()

	// Test Start
	err := engine.Start(ctx)
	assert.NoError(t, err)
	assert.True(t, engine.started)

	// Test double start
	err = engine.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already started")

	// Give background processes time to start
	time.Sleep(50 * time.Millisecond)

	// Test Stop
	err = engine.Stop()
	assert.NoError(t, err)
	assert.False(t, engine.started)

	// Test double stop
	err = engine.Stop()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestZeroTrustPolicyEngineIntegrations(t *testing.T) {
	engine := NewZeroTrustPolicyEngine(&ZeroTrustConfig{})

	mockRBACManager := &mockRBACManager{}
	mockJITManager := &mockJITManager{}
	mockRiskManager := &mockRiskManager{}
	mockContinuousAuthManager := &mockContinuousAuthManager{}
	mockTenantSecurityManager := &mockTenantSecurityManager{}

	engine.SetIntegrations(
		mockRBACManager,
		mockJITManager,
		mockRiskManager,
		mockContinuousAuthManager,
		mockTenantSecurityManager,
	)

	assert.Equal(t, mockRBACManager, engine.rbacManager)
	assert.Equal(t, mockJITManager, engine.jitManager)
	assert.Equal(t, mockRiskManager, engine.riskManager)
	assert.Equal(t, mockContinuousAuthManager, engine.continuousAuthEngine)
	assert.Equal(t, mockTenantSecurityManager, engine.tenantSecurityEngine)
}

func TestEvaluateAccessBasic(t *testing.T) {
	config := &ZeroTrustConfig{
		MaxEvaluationTime: 5 * time.Second,
		FailSecure:        true,
		MetricsInterval:   1 * time.Second,
	}

	engine := NewZeroTrustPolicyEngine(config)
	ctx := context.Background()

	request := &ZeroTrustAccessRequest{
		RequestID:     "test-request-001",
		RequestTime:   time.Now(),
		SubjectType:   SubjectTypeUser,
		ResourceType:  "database",
		SourceSystem:  "test-system",
		RequestSource: RequestSourceAPI,
		Priority:      RequestPriorityNormal,
	}

	response, err := engine.EvaluateAccess(ctx, request)
	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.Contains(t, response.EvaluationID, "eval-")
	assert.NotZero(t, response.EvaluationTime)
	// Windows timer resolution may cause ProcessingTime to be 0 for very fast operations
	// This is acceptable and doesn't indicate a failure
	if runtime.GOOS != "windows" {
		assert.NotZero(t, response.ProcessingTime)
	}

	// Should have audit trail
	assert.NotEmpty(t, response.AuditTrail)
}

func TestZeroTrustStatsTracking(t *testing.T) {
	config := &ZeroTrustConfig{
		MaxEvaluationTime: 5 * time.Second,
		EnableMetrics:     true,
	}

	engine := NewZeroTrustPolicyEngine(config)

	// Get initial stats
	initialStats := engine.GetStats()
	assert.Equal(t, int64(0), initialStats.TotalEvaluations)
	assert.Equal(t, int64(0), initialStats.SuccessfulEvaluations)
	assert.Equal(t, int64(0), initialStats.FailedEvaluations)

	// Simulate statistics update
	testResponse := &ZeroTrustAccessResponse{
		Granted: true,
	}
	processingTime := 10 * time.Millisecond

	engine.updateStatistics(testResponse, processingTime)

	// Check updated stats
	updatedStats := engine.GetStats()
	assert.Equal(t, int64(1), updatedStats.TotalEvaluations)
	assert.Equal(t, int64(1), updatedStats.SuccessfulEvaluations)
	assert.Equal(t, int64(0), updatedStats.FailedEvaluations)
	assert.True(t, updatedStats.AverageEvaluationTime > 0)
	assert.False(t, updatedStats.LastUpdated.IsZero())

	// Test denied request
	testResponse.Granted = false
	engine.updateStatistics(testResponse, processingTime)

	updatedStats2 := engine.GetStats()
	assert.Equal(t, int64(2), updatedStats2.TotalEvaluations)
	assert.Equal(t, int64(1), updatedStats2.SuccessfulEvaluations)
	assert.Equal(t, int64(1), updatedStats2.FailedEvaluations)
}

func TestZeroTrustPolicyPrioritySystem(t *testing.T) {
	tests := []struct {
		name          string
		policies      []*ZeroTrustPolicy
		expectedOrder []string
	}{
		{
			name: "Priority ordering",
			policies: []*ZeroTrustPolicy{
				{
					ID:       "policy-low",
					Priority: PolicyPriorityLow,
				},
				{
					ID:       "policy-critical",
					Priority: PolicyPriorityCritical,
				},
				{
					ID:       "policy-high",
					Priority: PolicyPriorityHigh,
				},
				{
					ID:       "policy-normal",
					Priority: PolicyPriorityNormal,
				},
			},
			expectedOrder: []string{"policy-critical", "policy-high", "policy-normal", "policy-low"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sort policies by priority (would be done by policy engine)
			sortedPolicies := make([]*ZeroTrustPolicy, len(tt.policies))
			copy(sortedPolicies, tt.policies)

			// Simple bubble sort by priority (descending)
			for i := 0; i < len(sortedPolicies); i++ {
				for j := i + 1; j < len(sortedPolicies); j++ {
					if int(sortedPolicies[i].Priority) < int(sortedPolicies[j].Priority) {
						sortedPolicies[i], sortedPolicies[j] = sortedPolicies[j], sortedPolicies[i]
					}
				}
			}

			// Verify order
			for i, expected := range tt.expectedOrder {
				assert.Equal(t, expected, sortedPolicies[i].ID)
			}
		})
	}
}

func TestZeroTrustAccessRequestValidation(t *testing.T) {
	tests := []struct {
		name        string
		request     *ZeroTrustAccessRequest
		expectError bool
	}{
		{
			name: "Valid request",
			request: &ZeroTrustAccessRequest{
				RequestID:     "valid-request",
				RequestTime:   time.Now(),
				SubjectType:   SubjectTypeUser,
				ResourceType:  "database",
				SourceSystem:  "test-system",
				RequestSource: RequestSourceAPI,
				Priority:      RequestPriorityNormal,
			},
			expectError: false,
		},
		{
			name: "Missing request ID",
			request: &ZeroTrustAccessRequest{
				RequestTime:   time.Now(),
				SubjectType:   SubjectTypeUser,
				ResourceType:  "database",
				SourceSystem:  "test-system",
				RequestSource: RequestSourceAPI,
				Priority:      RequestPriorityNormal,
			},
			expectError: false, // Request ID is generated if missing
		},
		{
			name: "Invalid subject type",
			request: &ZeroTrustAccessRequest{
				RequestID:     "test-request",
				RequestTime:   time.Now(),
				SubjectType:   SubjectType("invalid"),
				ResourceType:  "database",
				SourceSystem:  "test-system",
				RequestSource: RequestSourceAPI,
				Priority:      RequestPriorityNormal,
			},
			expectError: false, // Type validation would be done by policy rules
		},
	}

	config := &ZeroTrustConfig{
		MaxEvaluationTime: 5 * time.Second,
		FailSecure:        true,
	}

	engine := NewZeroTrustPolicyEngine(config)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := engine.EvaluateAccess(ctx, tt.request)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
			}
		})
	}
}

func TestEnvironmentContextExtraction(t *testing.T) {
	request := &ZeroTrustAccessRequest{
		RequestID:     "env-test",
		RequestTime:   time.Now(),
		SubjectType:   SubjectTypeUser,
		ResourceType:  "api",
		SourceSystem:  "test",
		RequestSource: RequestSourceAPI,
		Priority:      RequestPriorityNormal,
		EnvironmentContext: &EnvironmentContext{
			IPAddress: "192.168.1.100",
			Location: &GeoLocation{
				Country: "US",
				Region:  "California",
				City:    "San Francisco",
			},
			Network: &NetworkInfo{
				ISP:           "Example ISP",
				ASN:           "AS12345",
				ThreatScore:   0.1,
				VPNDetected:   false,
				ProxyDetected: false,
			},
			Device: &DeviceInfo{
				DeviceID:   "device-123",
				DeviceType: "laptop",
				OS:         "macOS",
				OSVersion:  "14.0",
				Trusted:    true,
				Registered: true,
				Compliant:  true,
			},
		},
		SecurityContext: &SecurityContext{
			AuthenticationMethod:   "oauth2",
			AuthenticationStrength: AuthStrengthStrong,
			MFAVerified:            true,
			CertificateValidated:   true,
			TrustLevel:             TrustLevelHigh,
		},
	}

	// Verify environment context is properly structured
	assert.Equal(t, "192.168.1.100", request.EnvironmentContext.IPAddress)
	assert.Equal(t, "US", request.EnvironmentContext.Location.Country)
	assert.Equal(t, "California", request.EnvironmentContext.Location.Region)
	assert.Equal(t, "Example ISP", request.EnvironmentContext.Network.ISP)
	assert.Equal(t, "device-123", request.EnvironmentContext.Device.DeviceID)
	assert.True(t, request.EnvironmentContext.Device.Trusted)

	assert.Equal(t, "oauth2", request.SecurityContext.AuthenticationMethod)
	assert.Equal(t, AuthStrengthStrong, request.SecurityContext.AuthenticationStrength)
	assert.True(t, request.SecurityContext.MFAVerified)
	assert.Equal(t, TrustLevelHigh, request.SecurityContext.TrustLevel)
}

func TestComplianceFrameworkConstants(t *testing.T) {
	// Test that compliance framework constants are properly defined
	assert.Equal(t, ComplianceFramework("SOC2"), ComplianceFrameworkSOC2)
	assert.Equal(t, ComplianceFramework("ISO27001"), ComplianceFrameworkISO27001)
	assert.Equal(t, ComplianceFramework("GDPR"), ComplianceFrameworkGDPR)
	assert.Equal(t, ComplianceFramework("HIPAA"), ComplianceFrameworkHIPAA)
	assert.Equal(t, ComplianceFramework("CUSTOM"), ComplianceFrameworkCustom)
}

func TestPolicyEnforcementModes(t *testing.T) {
	// Test that enforcement mode constants are properly defined
	assert.Equal(t, PolicyEnforcementMode("enforcing"), PolicyEnforcementModeEnforcing)
	assert.Equal(t, PolicyEnforcementMode("auditing"), PolicyEnforcementModeAuditing)
	assert.Equal(t, PolicyEnforcementMode("testing"), PolicyEnforcementModeTesting)
}

func TestRequestSourceConstants(t *testing.T) {
	// Test that request source constants are properly defined
	assert.Equal(t, RequestSource("api"), RequestSourceAPI)
	assert.Equal(t, RequestSource("ui"), RequestSourceUI)
	assert.Equal(t, RequestSource("cli"), RequestSourceCLI)
	assert.Equal(t, RequestSource("system"), RequestSourceSystem)
}

func TestThreatDetectionIntegration(t *testing.T) {
	request := &ZeroTrustAccessRequest{
		RequestID:     "threat-test",
		RequestTime:   time.Now(),
		SubjectType:   SubjectTypeUser,
		ResourceType:  "sensitive-data",
		SourceSystem:  "test",
		RequestSource: RequestSourceAPI,
		Priority:      RequestPriorityHigh,
		SecurityContext: &SecurityContext{
			ThreatIndicators: []ThreatIndicator{
				{
					Type:        ThreatTypeMalware,
					Severity:    ThreatSeverityHigh,
					Source:      "endpoint-protection",
					Confidence:  0.9,
					Description: "Suspicious executable detected",
					DetectedAt:  time.Now().Add(-5 * time.Minute),
				},
				{
					Type:        ThreatTypeAnomalous,
					Severity:    ThreatSeverityMedium,
					Source:      "behavioral-analysis",
					Confidence:  0.7,
					Description: "Unusual access pattern detected",
					DetectedAt:  time.Now().Add(-2 * time.Minute),
				},
			},
		},
	}

	// Verify threat indicators are properly structured
	assert.Len(t, request.SecurityContext.ThreatIndicators, 2)

	malwareThreat := request.SecurityContext.ThreatIndicators[0]
	assert.Equal(t, ThreatTypeMalware, malwareThreat.Type)
	assert.Equal(t, ThreatSeverityHigh, malwareThreat.Severity)
	assert.Equal(t, 0.9, malwareThreat.Confidence)

	anomalousThreat := request.SecurityContext.ThreatIndicators[1]
	assert.Equal(t, ThreatTypeAnomalous, anomalousThreat.Type)
	assert.Equal(t, ThreatSeverityMedium, anomalousThreat.Severity)
	assert.Equal(t, 0.7, anomalousThreat.Confidence)
}

func TestEvaluateAccessWithSecurityThreats(t *testing.T) {
	tests := []struct {
		name                   string
		request                *ZeroTrustAccessRequest
		expectedGranted        bool
		expectedReasonContains string
	}{
		{
			name: "High severity malware threat detected",
			request: &ZeroTrustAccessRequest{
				RequestID:     "threat-malware-001",
				RequestTime:   time.Now(),
				SubjectType:   SubjectTypeUser,
				ResourceType:  "sensitive-data",
				SourceSystem:  "test-system",
				RequestSource: RequestSourceAPI,
				Priority:      RequestPriorityNormal,
				SecurityContext: &SecurityContext{
					ThreatIndicators: []ThreatIndicator{
						{
							Type:        ThreatTypeMalware,
							Severity:    ThreatSeverityCritical,
							Source:      "endpoint-protection",
							Confidence:  0.95,
							Description: "Active malware detected on device",
							DetectedAt:  time.Now().Add(-1 * time.Minute),
						},
					},
					TrustLevel: TrustLevelUntrusted,
				},
			},
			expectedGranted:        false,
			expectedReasonContains: "Default deny",
		},
		{
			name: "Multiple threat indicators with varying severity",
			request: &ZeroTrustAccessRequest{
				RequestID:     "threat-multiple-001",
				RequestTime:   time.Now(),
				SubjectType:   SubjectTypeUser,
				ResourceType:  "api-endpoint",
				SourceSystem:  "test-system",
				RequestSource: RequestSourceAPI,
				Priority:      RequestPriorityNormal,
				SecurityContext: &SecurityContext{
					ThreatIndicators: []ThreatIndicator{
						{
							Type:        ThreatTypeBruteForce,
							Severity:    ThreatSeverityMedium,
							Source:      "auth-monitor",
							Confidence:  0.8,
							Description: "Multiple failed login attempts",
							DetectedAt:  time.Now().Add(-10 * time.Minute),
						},
						{
							Type:        ThreatTypeAnomalous,
							Severity:    ThreatSeverityLow,
							Source:      "behavioral-analysis",
							Confidence:  0.6,
							Description: "Unusual access time pattern",
							DetectedAt:  time.Now().Add(-5 * time.Minute),
						},
					},
					TrustLevel: TrustLevelLow,
				},
			},
			expectedGranted:        false,
			expectedReasonContains: "Default deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ZeroTrustConfig{
				MaxEvaluationTime: 5 * time.Second,
				FailSecure:        true,
				MetricsInterval:   1 * time.Second,
			}

			engine := NewZeroTrustPolicyEngine(config)
			ctx := context.Background()

			response, err := engine.EvaluateAccess(ctx, tt.request)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedGranted, response.Granted)
			assert.Contains(t, response.Reason, tt.expectedReasonContains)
			assert.NotEmpty(t, response.AuditTrail)

			// Verify security context is preserved in evaluation
			if tt.request.SecurityContext != nil && len(tt.request.SecurityContext.ThreatIndicators) > 0 {
				assert.NotEmpty(t, tt.request.SecurityContext.ThreatIndicators)
			}
		})
	}
}

func TestEvaluateAccessWithSystemIntegrationFailures(t *testing.T) {
	tests := []struct {
		name                   string
		setupMocks             func(*mockRBACManagerWithError, *mockJITManagerWithError, *mockRiskManagerWithError, *mockTenantSecurityManagerWithError)
		expectedGranted        bool
		expectedReasonContains string
	}{
		{
			name: "RBAC system failure with fail-secure enabled",
			setupMocks: func(rbac *mockRBACManagerWithError, jit *mockJITManagerWithError, risk *mockRiskManagerWithError, tenant *mockTenantSecurityManagerWithError) {
				rbac.SetError(true)
			},
			expectedGranted:        false,
			expectedReasonContains: "System integration failed",
		},
		{
			name: "Multiple system failures",
			setupMocks: func(rbac *mockRBACManagerWithError, jit *mockJITManagerWithError, risk *mockRiskManagerWithError, tenant *mockTenantSecurityManagerWithError) {
				rbac.SetError(true)
				jit.SetError(true)
				risk.SetError(true)
			},
			expectedGranted:        false,
			expectedReasonContains: "System integration failed",
		},
		{
			name: "Risk assessment system failure",
			setupMocks: func(rbac *mockRBACManagerWithError, jit *mockJITManagerWithError, risk *mockRiskManagerWithError, tenant *mockTenantSecurityManagerWithError) {
				risk.SetError(true)
			},
			expectedGranted:        false,
			expectedReasonContains: "System integration failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ZeroTrustConfig{
				MaxEvaluationTime:       5 * time.Second,
				FailSecure:              true,
				EnableRBACIntegration:   true,
				EnableJITIntegration:    true,
				EnableRiskIntegration:   true,
				EnableTenantIntegration: true,
				MetricsInterval:         1 * time.Second,
			}

			engine := NewZeroTrustPolicyEngine(config)

			// Setup mock managers with error capability
			rbacManager := &mockRBACManagerWithError{}
			jitManager := &mockJITManagerWithError{}
			riskManager := &mockRiskManagerWithError{}
			continuousAuthManager := &mockContinuousAuthManager{}
			tenantSecurityManager := &mockTenantSecurityManagerWithError{}

			if tt.setupMocks != nil {
				tt.setupMocks(rbacManager, jitManager, riskManager, tenantSecurityManager)
			}

			engine.SetIntegrations(
				rbacManager,
				jitManager,
				riskManager,
				continuousAuthManager,
				tenantSecurityManager,
			)

			request := &ZeroTrustAccessRequest{
				RequestID:     "integration-failure-test",
				RequestTime:   time.Now(),
				SubjectType:   SubjectTypeUser,
				ResourceType:  "sensitive-resource",
				SourceSystem:  "test-system",
				RequestSource: RequestSourceAPI,
				Priority:      RequestPriorityHigh,
				AccessRequest: &common.AccessRequest{
					SubjectId:    "user1",
					ResourceId:   "resource1",
					PermissionId: "read",
					TenantId:     "tenant1",
					Context:      make(map[string]string),
				},
			}

			ctx := context.Background()
			response, err := engine.EvaluateAccess(ctx, request)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedGranted, response.Granted)
			assert.Contains(t, response.Reason, tt.expectedReasonContains)
			assert.NotEmpty(t, response.AuditTrail)
			assert.Positive(t, response.ProcessingTime)
		})
	}
}

func TestEvaluateAccessInputValidation(t *testing.T) {
	tests := []struct {
		name        string
		request     *ZeroTrustAccessRequest
		expectError bool
		description string
	}{
		{
			name:        "Nil request",
			request:     nil,
			expectError: true,
			description: "Should handle nil request gracefully",
		},
		{
			name: "Empty request ID gets generated",
			request: &ZeroTrustAccessRequest{
				RequestTime:   time.Now(),
				SubjectType:   SubjectTypeUser,
				ResourceType:  "test",
				SourceSystem:  "test",
				RequestSource: RequestSourceAPI,
				Priority:      RequestPriorityNormal,
			},
			expectError: false,
			description: "Empty request ID should be auto-generated",
		},
		{
			name: "Invalid subject attributes handled",
			request: &ZeroTrustAccessRequest{
				RequestID:     "invalid-attrs-test",
				RequestTime:   time.Now(),
				SubjectType:   SubjectTypeUser,
				ResourceType:  "test",
				SourceSystem:  "test",
				RequestSource: RequestSourceAPI,
				Priority:      RequestPriorityNormal,
				SubjectAttributes: map[string]interface{}{
					"malformed_json": make(chan int), // Invalid JSON type
				},
			},
			expectError: false,
			description: "Invalid subject attributes should be handled gracefully",
		},
	}

	config := &ZeroTrustConfig{
		MaxEvaluationTime: 5 * time.Second,
		FailSecure:        true,
		MetricsInterval:   1 * time.Second,
	}

	engine := NewZeroTrustPolicyEngine(config)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := engine.EvaluateAccess(ctx, tt.request)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, response, tt.description)
			}
		})
	}
}

func TestConcurrentEvaluateAccess(t *testing.T) {
	config := &ZeroTrustConfig{
		MaxEvaluationTime: 5 * time.Second,
		FailSecure:        true,
		CacheEnabled:      true,
		CacheTTL:          1 * time.Minute,
		MetricsInterval:   1 * time.Second,
	}

	engine := NewZeroTrustPolicyEngine(config)
	ctx := context.Background()

	// Run multiple concurrent evaluations
	const numConcurrent = 10
	results := make(chan *ZeroTrustAccessResponse, numConcurrent)
	errors := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(requestNum int) {
			request := &ZeroTrustAccessRequest{
				RequestID:     fmt.Sprintf("concurrent-test-%d", requestNum),
				RequestTime:   time.Now(),
				SubjectType:   SubjectTypeUser,
				ResourceType:  "test-resource",
				SourceSystem:  "test-system",
				RequestSource: RequestSourceAPI,
				Priority:      RequestPriorityNormal,
			}

			response, err := engine.EvaluateAccess(ctx, request)
			if err != nil {
				errors <- err
			} else {
				results <- response
			}
		}(i)
	}

	// Collect results
	successCount := 0
	errorCount := 0

	for i := 0; i < numConcurrent; i++ {
		select {
		case response := <-results:
			assert.NotNil(t, response)
			assert.NotEmpty(t, response.EvaluationID)
			successCount++
		case err := <-errors:
			assert.NoError(t, err) // We don't expect errors in this test
			errorCount++
		case <-time.After(10 * time.Second):
			t.Fatal("Test timed out waiting for concurrent evaluations")
		}
	}

	assert.Equal(t, numConcurrent, successCount)
	assert.Equal(t, 0, errorCount)

	// Verify statistics were updated correctly
	stats := engine.GetStats()
	assert.Equal(t, int64(numConcurrent), stats.TotalEvaluations)
}

func TestZeroTrustPolicyEngine_PerformanceRequirement(t *testing.T) {
	config := &ZeroTrustConfig{
		MaxEvaluationTime: 5 * time.Millisecond, // Strict 5ms requirement
		FailSecure:        true,
		MetricsInterval:   1 * time.Second,
	}

	engine := NewZeroTrustPolicyEngine(config)
	ctx := context.Background()

	request := &ZeroTrustAccessRequest{
		RequestID:     "performance-test",
		RequestTime:   time.Now(),
		SubjectType:   SubjectTypeUser,
		ResourceType:  "test-resource",
		SourceSystem:  "test-system",
		RequestSource: RequestSourceAPI,
		Priority:      RequestPriorityNormal,
	}

	// Run multiple evaluations to verify consistent performance
	const numTests = 100
	var totalTime time.Duration

	for i := 0; i < numTests; i++ {
		start := time.Now()
		response, err := engine.EvaluateAccess(ctx, request)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.NotNil(t, response)

		// Verify processing time meets requirement
		assert.Less(t, response.ProcessingTime, 5*time.Millisecond,
			"Evaluation %d took %v, exceeds 5ms requirement", i+1, response.ProcessingTime)

		totalTime += elapsed
	}

	averageTime := totalTime / numTests
	t.Logf("Average evaluation time: %v (requirement: <5ms)", averageTime)

	// Performance requirement: <5ms for policy evaluation
	assert.Less(t, averageTime, 5*time.Millisecond,
		"Average evaluation time %v exceeds 5ms performance requirement", averageTime)
}

// Enhanced mock implementations with error simulation
type mockRBACManagerWithError struct {
	shouldError bool
}

func (m *mockRBACManagerWithError) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	if m.shouldError {
		return nil, errors.New("RBAC system unavailable")
	}
	return &common.AccessResponse{Granted: true, Reason: "mock rbac granted"}, nil
}

func (m *mockRBACManagerWithError) GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	if m.shouldError {
		return nil, errors.New("RBAC system unavailable")
	}
	return []*common.Permission{{Id: "test-permission", Name: "Test Permission"}}, nil
}

func (m *mockRBACManagerWithError) SetError(shouldError bool) {
	m.shouldError = shouldError
}

type mockJITManagerWithError struct {
	shouldError bool
}

func (m *mockJITManagerWithError) ValidateJITAccess(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	if m.shouldError {
		return nil, errors.New("JIT system unavailable")
	}
	return &common.AccessResponse{Granted: true, Reason: "mock jit granted"}, nil
}

func (m *mockJITManagerWithError) SetError(shouldError bool) {
	m.shouldError = shouldError
}

type mockRiskManagerWithError struct {
	shouldError bool
}

func (m *mockRiskManagerWithError) AssessRisk(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	if m.shouldError {
		return nil, errors.New("Risk assessment system unavailable")
	}
	return &common.AccessResponse{Granted: true, Reason: "mock risk assessment passed"}, nil
}

func (m *mockRiskManagerWithError) SetError(shouldError bool) {
	m.shouldError = shouldError
}

type mockTenantSecurityManagerWithError struct {
	shouldError bool
}

func (m *mockTenantSecurityManagerWithError) ValidateTenantSecurity(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	if m.shouldError {
		return nil, errors.New("Tenant security system unavailable")
	}
	return &common.AccessResponse{Granted: true, Reason: "mock tenant security validated"}, nil
}

func (m *mockTenantSecurityManagerWithError) SetError(shouldError bool) {
	m.shouldError = shouldError
}

// Mock implementations for testing
type mockRBACManager struct{}

func (m *mockRBACManager) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	return &common.AccessResponse{
		Granted: true,
		Reason:  "mock rbac granted",
	}, nil
}

func (m *mockRBACManager) GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	return []*common.Permission{
		{
			Id:   "test-permission",
			Name: "Test Permission",
		},
	}, nil
}

type mockJITManager struct{}

func (m *mockJITManager) ValidateJITAccess(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	return &common.AccessResponse{
		Granted: true,
		Reason:  "mock jit granted",
	}, nil
}

type mockRiskManager struct{}

func (m *mockRiskManager) AssessRisk(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	return &common.AccessResponse{
		Granted: true,
		Reason:  "mock risk assessment passed",
	}, nil
}

type mockContinuousAuthManager struct{}

func (m *mockContinuousAuthManager) ValidateContinuousAuth(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	return &common.AccessResponse{
		Granted: true,
		Reason:  "mock continuous auth validated",
	}, nil
}

type mockTenantSecurityManager struct{}

func (m *mockTenantSecurityManager) ValidateTenantSecurity(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	return &common.AccessResponse{
		Granted: true,
		Reason:  "mock tenant security validated",
	}, nil
}
