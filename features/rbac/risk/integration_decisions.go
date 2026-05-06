// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package risk

import (
	"github.com/cfgis/cfgms/api/proto/common"
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
