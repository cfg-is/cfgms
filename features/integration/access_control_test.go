package integration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/zerotrust"
)

func TestEnhancedAccessControlManager_ZeroTrustModeConfiguration(t *testing.T) {
	// Create manager without dependencies for configuration testing
	manager := &EnhancedAccessControlManager{
		integrationMode:         IntegrationModeSequential,
		zeroTrustPolicyMode:     ZeroTrustPolicyModeDisabled,
		enableZeroTrustPolicies: false,
	}

	// Test initial state
	assert.Equal(t, ZeroTrustPolicyModeDisabled, manager.GetZeroTrustPolicyMode())
	assert.Equal(t, IntegrationModeSequential, manager.integrationMode)
	assert.False(t, manager.enableZeroTrustPolicies)

	// Test setting zero-trust policy mode to augmented
	manager.SetZeroTrustPolicyMode(ZeroTrustPolicyModeAugmented)
	assert.Equal(t, ZeroTrustPolicyModeAugmented, manager.GetZeroTrustPolicyMode())
	// Should remain false since no engine is set
	assert.False(t, manager.enableZeroTrustPolicies)

	// Test setting mode directly
	manager.SetZeroTrustPolicyMode(ZeroTrustPolicyModeAuditing)
	assert.Equal(t, ZeroTrustPolicyModeAuditing, manager.GetZeroTrustPolicyMode())

	// Test disabling by setting to disabled mode
	manager.SetZeroTrustPolicyMode(ZeroTrustPolicyModeDisabled)
	assert.Equal(t, ZeroTrustPolicyModeDisabled, manager.GetZeroTrustPolicyMode())
	assert.False(t, manager.enableZeroTrustPolicies)
}

func TestEnhancedAccessControlManager_ZeroTrustDecisionCombination(t *testing.T) {
	manager := &EnhancedAccessControlManager{
		zeroTrustPolicyMode: ZeroTrustPolicyModeAugmented,
	}

	testCases := []struct {
		name                   string
		policyMode             ZeroTrustPolicyMode
		traditionalGranted     bool
		zeroTrustGranted       bool
		expectedGranted        bool
		expectedReasonContains string
	}{
		{
			name:                   "Augmented - both grant",
			policyMode:             ZeroTrustPolicyModeAugmented,
			traditionalGranted:     true,
			zeroTrustGranted:       true,
			expectedGranted:        true,
			expectedReasonContains: "Traditional:",
		},
		{
			name:                   "Augmented - traditional denies",
			policyMode:             ZeroTrustPolicyModeAugmented,
			traditionalGranted:     false,
			zeroTrustGranted:       true,
			expectedGranted:        false,
			expectedReasonContains: "Access denied by traditional controls",
		},
		{
			name:                   "Enforced - zero-trust overrides",
			policyMode:             ZeroTrustPolicyModeEnforced,
			traditionalGranted:     false,
			zeroTrustGranted:       true,
			expectedGranted:        true,
			expectedReasonContains: "Zero-trust decision:",
		},
		{
			name:                   "Auditing - traditional wins",
			policyMode:             ZeroTrustPolicyModeAuditing,
			traditionalGranted:     true,
			zeroTrustGranted:       false,
			expectedGranted:        true,
			expectedReasonContains: "(Zero-Trust audit:",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manager.zeroTrustPolicyMode = tc.policyMode

			traditionalResponse := &common.AccessResponse{
				Granted: tc.traditionalGranted,
				Reason:  "Traditional decision",
			}

			zeroTrustResult := &ZeroTrustPolicyValidationResult{
				ZeroTrustGranted: tc.zeroTrustGranted,
				Reason:           "Zero-trust decision",
				TrustScore:       0.7,
			}

			combinedResponse := manager.combineZeroTrustDecision(traditionalResponse, zeroTrustResult)

			assert.Equal(t, tc.expectedGranted, combinedResponse.Granted)
			assert.Contains(t, combinedResponse.Reason, tc.expectedReasonContains)
			assert.Equal(t, tc.expectedGranted, zeroTrustResult.FinalDecision)
		})
	}
}

func TestEnhancedAccessControlManager_AdaptiveMode(t *testing.T) {
	manager := &EnhancedAccessControlManager{}

	// Test different trust scores result in different enforcement modes
	testCases := []struct {
		trustScore   float64
		expectedMode ZeroTrustPolicyMode
		description  string
	}{
		{0.9, ZeroTrustPolicyModeAuditing, "High trust score -> Auditing mode"},
		{0.7, ZeroTrustPolicyModeAugmented, "Medium trust score -> Augmented mode"},
		{0.2, ZeroTrustPolicyModeEnforced, "Low trust score -> Enforced mode"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			// Create a zero-trust result with specific trust score
			ztResult := &ZeroTrustPolicyValidationResult{
				TrustScore: tc.trustScore,
			}

			// Test the adaptive mode determination
			adaptiveMode := manager.determineAdaptiveMode(ztResult)
			assert.Equal(t, tc.expectedMode, adaptiveMode)
		})
	}
}

func TestEnhancedAccessControlManager_HelperFunctions(t *testing.T) {
	// Test extractResourceType
	testCases := []struct {
		resourceID   string
		expectedType string
	}{
		{"steward.register", "steward"},
		{"config/management", "config"},
		{"api:v1:users", "api"},
		{"simple", "simple"},
		{"", "unknown"},
	}

	for _, tc := range testCases {
		result := extractResourceType(tc.resourceID)
		assert.Equal(t, tc.expectedType, result)
	}

	// Test calculateTrustScore
	grantedResponse := &zerotrust.ZeroTrustAccessResponse{Granted: true}
	deniedResponse := &zerotrust.ZeroTrustAccessResponse{Granted: false}

	assert.Equal(t, 0.8, calculateTrustScore(grantedResponse))
	assert.Equal(t, 0.3, calculateTrustScore(deniedResponse))

	// Test generateZeroTrustRecommendations
	slowResponse := &zerotrust.ZeroTrustAccessResponse{
		Granted:        true,
		ProcessingTime: 10 * time.Millisecond,
	}
	recommendations := generateZeroTrustRecommendations(slowResponse)
	assert.Contains(t, recommendations, "Optimize zero-trust policy evaluation performance")

	deniedResponseRecommendation := &zerotrust.ZeroTrustAccessResponse{Granted: false}
	recommendations = generateZeroTrustRecommendations(deniedResponseRecommendation)
	assert.Contains(t, recommendations, "Review zero-trust policy compliance")
}
