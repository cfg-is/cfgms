// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package risk

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
)

// RiskContextBuilder builds risk assessment contexts from access requests
type RiskContextBuilder struct {
	userDataProvider        *UserDataProvider
	sessionDataProvider     *SessionDataProvider
	resourceDataProvider    *ResourceDataProvider
	environmentDataProvider *EnvironmentDataProvider
	historicalDataProvider  *HistoricalDataProvider
}

// NewRiskContextBuilder creates a new risk context builder
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

// Supporting data provider types

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
