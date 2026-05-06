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
	"github.com/cfgis/cfgms/features/rbac/ports"
	"github.com/cfgis/cfgms/features/tenant/security"
)

// DefaultRiskIntegrationConfig returns sensible defaults for risk integration configuration
func DefaultRiskIntegrationConfig() *RiskIntegrationConfig {
	return &RiskIntegrationConfig{
		FailSecure:   true,
		RiskWeight:   0.5,
		PolicyWeight: 0.5,
	}
}

// RiskBasedAccessIntegration integrates risk assessment with RBAC, JIT access, and continuous authorization
type RiskBasedAccessIntegration struct {
	riskEngine            *RiskAssessmentEngine
	adaptiveControls      *AdaptiveControlsEngine
	rbacManager           rbac.RBACManager
	jitIntegrationManager *jit.JITIntegrationManager
	tenantSecurity        *security.TenantSecurityMiddleware
	contextBuilder        *RiskContextBuilder
	decisionEnforcer      *RiskDecisionEnforcer
	baseRiskManager       ports.RiskManager // Base risk manager for compatibility
	config                *RiskIntegrationConfig

	// Continuous authorization integration
	continuousRiskMonitor *ContinuousRiskMonitor
	sessionRiskTracker    *SessionRiskTracker
}

// RiskIntegrationConfig configuration for risk-based access integration
type RiskIntegrationConfig struct {
	FailSecure   bool    `json:"fail_secure"`
	RiskWeight   float64 `json:"risk_weight"`
	PolicyWeight float64 `json:"policy_weight"`
}

// EnhancedRiskAccessResponse extends JIT access response with risk information
type EnhancedRiskAccessResponse struct {
	AccessResponse *common.AccessResponse `json:"access_response"`
	RiskLevel      string                 `json:"risk_level"`
	RiskScore      float64                `json:"risk_score"`
	RiskFactors    []string               `json:"risk_factors"`
	ProcessingTime time.Duration          `json:"processing_time"`
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
		config:                DefaultRiskIntegrationConfig(),
		continuousRiskMonitor: NewContinuousRiskMonitor(riskEngine),
		sessionRiskTracker:    NewSessionRiskTracker(),
	}
}

// EnhancedRiskAccessCheck performs comprehensive risk assessment
func (r *RiskBasedAccessIntegration) EnhancedRiskAccessCheck(ctx context.Context, request *common.AccessRequest) (*EnhancedRiskAccessResponse, error) {
	startTime := time.Now()

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

	enhancedResponse := &EnhancedRiskAccessResponse{
		AccessResponse: riskResponse,
		RiskLevel:      extractRiskLevel(riskResponse),
		RiskScore:      extractRiskScore(riskResponse),
		RiskFactors:    extractRiskFactors(riskResponse),
		ProcessingTime: time.Since(startTime),
	}

	return enhancedResponse, nil
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
