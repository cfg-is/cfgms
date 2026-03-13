// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"context"
	"fmt"
	"time"
)

// ZeroTrustProfile defines zero-trust security profile for a tenant
type ZeroTrustProfile struct {
	TenantID               string                             `json:"tenant_id"`
	TrustLevel             ZeroTrustLevel                     `json:"trust_level"`
	DeviceFingerprints     map[string]*ZeroTrustDeviceProfile `json:"device_fingerprints"`
	BehavioralBaseline     *BehavioralBaseline                `json:"behavioral_baseline"`
	AccessPatterns         []AccessPattern                    `json:"access_patterns"`
	RiskScore              float64                            `json:"risk_score"`
	ContinuousVerification bool                               `json:"continuous_verification"`
	AdaptiveAuthentication *AdaptiveAuthConfig                `json:"adaptive_authentication"`
	ContextualControls     []ContextualControl                `json:"contextual_controls"`
	LastUpdated            time.Time                          `json:"last_updated"`
}

// ZeroTrustLevel defines trust levels in zero-trust model
type ZeroTrustLevel string

const (
	ZeroTrustLevelUntrusted ZeroTrustLevel = "untrusted"
	ZeroTrustLevelLow       ZeroTrustLevel = "low"
	ZeroTrustLevelMedium    ZeroTrustLevel = "medium"
	ZeroTrustLevelHigh      ZeroTrustLevel = "high"
	ZeroTrustLevelVerified  ZeroTrustLevel = "verified"
)

// ZeroTrustDeviceProfile stores device fingerprinting information for zero-trust
type ZeroTrustDeviceProfile struct {
	DeviceID           string                 `json:"device_id"`
	DeviceType         string                 `json:"device_type"`
	OSVersion          string                 `json:"os_version"`
	BrowserFingerprint string                 `json:"browser_fingerprint,omitempty"`
	NetworkFingerprint string                 `json:"network_fingerprint"`
	TrustScore         float64                `json:"trust_score"`
	LastSeen           time.Time              `json:"last_seen"`
	Attributes         map[string]interface{} `json:"attributes"`
	RiskIndicators     []string               `json:"risk_indicators"`
}

// BehavioralBaseline defines normal behavior patterns for a tenant
type BehavioralBaseline struct {
	TypicalAccessHours   []TimeWindow      `json:"typical_access_hours"`
	CommonLocations      []GeographicZone  `json:"common_locations"`
	UsualResources       []string          `json:"usual_resources"`
	AverageSessionLength time.Duration     `json:"average_session_length"`
	NormalDataVolume     DataVolumePattern `json:"normal_data_volume"`
	EstablishedAt        time.Time         `json:"established_at"`
	ConfidenceLevel      float64           `json:"confidence_level"`
}

// TimeWindow defines a time range for access patterns
type TimeWindow struct {
	StartHour int    `json:"start_hour"`
	EndHour   int    `json:"end_hour"`
	DayOfWeek string `json:"day_of_week,omitempty"`
	Timezone  string `json:"timezone"`
}

// GeographicZone defines geographic areas for access patterns
type GeographicZone struct {
	Country string  `json:"country"`
	Region  string  `json:"region,omitempty"`
	City    string  `json:"city,omitempty"`
	Radius  float64 `json:"radius,omitempty"` // km radius for area
}

// DataVolumePattern defines normal data access patterns
type DataVolumePattern struct {
	AverageReadMB  float64 `json:"average_read_mb"`
	AverageWriteMB float64 `json:"average_write_mb"`
	PeakReadMB     float64 `json:"peak_read_mb"`
	PeakWriteMB    float64 `json:"peak_write_mb"`
}

// AccessPattern defines observed access patterns
type AccessPattern struct {
	PatternID  string                 `json:"pattern_id"`
	Type       AccessPatternType      `json:"type"`
	Frequency  int                    `json:"frequency"`
	LastSeen   time.Time              `json:"last_seen"`
	Confidence float64                `json:"confidence"`
	Context    map[string]interface{} `json:"context"`
	RiskLevel  string                 `json:"risk_level"`
}

// AccessPatternType defines types of access patterns
type AccessPatternType string

const (
	AccessPatternTypeNormal     AccessPatternType = "normal"
	AccessPatternTypeSuspicious AccessPatternType = "suspicious"
	AccessPatternTypeAnomaly    AccessPatternType = "anomaly"
	AccessPatternTypeBaseline   AccessPatternType = "baseline"
)

// InitializeZeroTrustProfile initializes a zero-trust profile for a tenant
func (tie *TenantIsolationEngine) InitializeZeroTrustProfile(ctx context.Context, tenantID string) (*ZeroTrustProfile, error) {
	tie.mutex.Lock()
	defer tie.mutex.Unlock()

	// Validate tenant exists
	_, err := tie.tenantManager.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	profile := &ZeroTrustProfile{
		TenantID:               tenantID,
		TrustLevel:             ZeroTrustLevelUntrusted,
		DeviceFingerprints:     make(map[string]*ZeroTrustDeviceProfile),
		BehavioralBaseline:     tie.createDefaultBehavioralBaseline(),
		AccessPatterns:         []AccessPattern{},
		RiskScore:              50.0, // Start with medium risk
		ContinuousVerification: true,
		AdaptiveAuthentication: tie.createDefaultAdaptiveAuthConfig(),
		ContextualControls:     tie.createDefaultContextualControls(),
		LastUpdated:            time.Now(),
	}

	tie.zeroTrustProfiles[tenantID] = profile
	return profile, nil
}

// UpdateTrustLevel updates the trust level for a tenant based on behavior
func (tie *TenantIsolationEngine) UpdateTrustLevel(ctx context.Context, tenantID string, newLevel ZeroTrustLevel, reason string) error {
	tie.mutex.Lock()
	defer tie.mutex.Unlock()

	profile, exists := tie.zeroTrustProfiles[tenantID]
	if !exists {
		return fmt.Errorf("zero-trust profile not found for tenant: %s", tenantID)
	}

	oldLevel := profile.TrustLevel
	profile.TrustLevel = newLevel
	profile.LastUpdated = time.Now()

	// Update risk score based on trust level
	profile.RiskScore = tie.calculateRiskScoreFromTrustLevel(newLevel)

	// Trigger adaptive controls if trust level decreased
	if tie.shouldTriggerAdaptation(oldLevel, newLevel) {
		err := tie.triggerAdaptiveControls(ctx, tenantID, AdaptationTriggerRiskIncrease)
		if err != nil {
			// Log error but don't fail the trust level update
			_ = tie.auditLogger.LogRemediationAction(ctx, fmt.Sprintf("trust-level-%s", tenantID), "adaptation_failed")
		}
	}

	// Audit the trust level change
	return tie.auditLogger.LogVulnerabilityStatusChange(ctx, fmt.Sprintf("trust-level-%s", tenantID), tenantID, string(newLevel))
}

// RecordDeviceFingerprint records device fingerprinting information
func (tie *TenantIsolationEngine) RecordDeviceFingerprint(ctx context.Context, tenantID string, device *ZeroTrustDeviceProfile) error {
	tie.mutex.Lock()
	defer tie.mutex.Unlock()

	profile, exists := tie.zeroTrustProfiles[tenantID]
	if !exists {
		// Initialize profile if it doesn't exist
		var err error
		profile, err = tie.InitializeZeroTrustProfile(ctx, tenantID)
		if err != nil {
			return err
		}
	}

	// Update device profile
	device.LastSeen = time.Now()
	profile.DeviceFingerprints[device.DeviceID] = device
	profile.LastUpdated = time.Now()

	// Calculate device trust score
	device.TrustScore = tie.calculateDeviceTrustScore(device)

	// Update overall risk score based on device risk
	tie.updateRiskScoreFromDevice(profile, device)

	return nil
}

// EstablishBehavioralBaseline establishes behavioral baseline for a tenant
func (tie *TenantIsolationEngine) EstablishBehavioralBaseline(ctx context.Context, tenantID string, accessEvents []ZeroTrustAccessEvent) error {
	tie.mutex.Lock()
	defer tie.mutex.Unlock()

	profile, exists := tie.zeroTrustProfiles[tenantID]
	if !exists {
		return fmt.Errorf("zero-trust profile not found for tenant: %s", tenantID)
	}

	baseline := tie.analyzeBehavioralPatterns(accessEvents)
	baseline.EstablishedAt = time.Now()
	baseline.ConfidenceLevel = tie.calculateBaselineConfidence(accessEvents)

	profile.BehavioralBaseline = baseline
	profile.LastUpdated = time.Now()

	return nil
}

// EvaluateZeroTrustAccess evaluates access request against zero-trust principles
func (tie *TenantIsolationEngine) EvaluateZeroTrustAccess(ctx context.Context, request *ZeroTrustAccessRequest) (*ZeroTrustAccessResponse, error) {
	tie.mutex.RLock()
	defer tie.mutex.RUnlock()

	profile, exists := tie.zeroTrustProfiles[request.TenantID]
	if !exists {
		return &ZeroTrustAccessResponse{
			Granted:      false,
			TrustLevel:   ZeroTrustLevelUntrusted,
			RiskScore:    100.0,
			Reason:       "No zero-trust profile established",
			RequiredAuth: []AuthenticationFactor{AuthFactorPassword, AuthFactorTOTP},
		}, nil
	}

	response := &ZeroTrustAccessResponse{
		TenantID:    request.TenantID,
		RequestID:   request.RequestID,
		EvaluatedAt: time.Now(),
		TrustLevel:  profile.TrustLevel,
		RiskScore:   profile.RiskScore,
	}

	// Evaluate device trust
	deviceTrust := tie.evaluateDeviceTrust(profile, request.DeviceID)

	// Evaluate behavioral patterns
	behaviorTrust := tie.evaluateBehavioralTrust(profile, request)

	// Evaluate contextual factors
	contextTrust := tie.evaluateContextualTrust(profile, request)

	// Calculate overall trust score
	overallTrust := (deviceTrust + behaviorTrust + contextTrust) / 3.0
	response.RiskScore = 100.0 - (overallTrust * 100.0)

	// Determine access decision
	response.Granted = tie.determineZeroTrustAccess(profile, overallTrust, request)

	if response.Granted {
		response.Reason = "Access granted based on zero-trust evaluation"
		response.RequiredAuth = tie.determineRequiredAuthentication(profile, overallTrust)
	} else {
		response.Reason = "Access denied - insufficient trust level"
		response.RequiredAuth = []AuthenticationFactor{AuthFactorPassword, AuthFactorTOTP, AuthFactorBiometric}
	}

	return response, nil
}

func (tie *TenantIsolationEngine) createDefaultBehavioralBaseline() *BehavioralBaseline {
	return &BehavioralBaseline{
		TypicalAccessHours: []TimeWindow{
			{StartHour: 9, EndHour: 17, DayOfWeek: "weekday", Timezone: "UTC"},
		},
		CommonLocations:      []GeographicZone{},
		UsualResources:       []string{},
		AverageSessionLength: time.Hour,
		NormalDataVolume: DataVolumePattern{
			AverageReadMB:  10.0,
			AverageWriteMB: 5.0,
			PeakReadMB:     50.0,
			PeakWriteMB:    25.0,
		},
		EstablishedAt:   time.Now(),
		ConfidenceLevel: 0.0,
	}
}

func (tie *TenantIsolationEngine) createDefaultAdaptiveAuthConfig() *AdaptiveAuthConfig {
	return &AdaptiveAuthConfig{
		MFARequired:       true,
		RiskBasedMFA:      true,
		RiskThreshold:     0.7,
		AdditionalFactors: []AuthenticationFactor{AuthFactorTOTP},
		ContinuousAuth:    false,
		SessionTimeout:    time.Hour * 8,
		ReauthenticationRules: []ReauthenticationRule{
			{Trigger: "high_risk_detected", Condition: "risk_score > 0.8", GracePeriod: time.Minute * 5},
		},
	}
}

func (tie *TenantIsolationEngine) createDefaultContextualControls() []ContextualControl {
	return []ContextualControl{
		{
			ControlID:  "location_control",
			Type:       ContextualControlTypeLocation,
			Condition:  "unknown_location",
			Action:     "require_additional_auth",
			Parameters: map[string]interface{}{"auth_factor": "totp"},
			Enabled:    true,
			Priority:   1,
		},
		{
			ControlID:  "time_control",
			Type:       ContextualControlTypeTime,
			Condition:  "outside_business_hours",
			Action:     "increase_monitoring",
			Parameters: map[string]interface{}{"monitoring_level": "high"},
			Enabled:    true,
			Priority:   2,
		},
	}
}

func (tie *TenantIsolationEngine) calculateRiskScoreFromTrustLevel(level ZeroTrustLevel) float64 {
	switch level {
	case ZeroTrustLevelVerified:
		return 10.0
	case ZeroTrustLevelHigh:
		return 25.0
	case ZeroTrustLevelMedium:
		return 50.0
	case ZeroTrustLevelLow:
		return 75.0
	case ZeroTrustLevelUntrusted:
		return 90.0
	default:
		return 50.0
	}
}

func (tie *TenantIsolationEngine) shouldTriggerAdaptation(oldLevel, newLevel ZeroTrustLevel) bool {
	// Trigger adaptation if trust level decreased
	levels := map[ZeroTrustLevel]int{
		ZeroTrustLevelUntrusted: 0,
		ZeroTrustLevelLow:       1,
		ZeroTrustLevelMedium:    2,
		ZeroTrustLevelHigh:      3,
		ZeroTrustLevelVerified:  4,
	}
	return levels[newLevel] < levels[oldLevel]
}

func (tie *TenantIsolationEngine) calculateDeviceTrustScore(device *ZeroTrustDeviceProfile) float64 {
	score := 1.0

	// Penalize for risk indicators
	score -= float64(len(device.RiskIndicators)) * 0.1
	if score < 0 {
		score = 0
	}

	// Factor in device type (mobile devices might be less trusted)
	if device.DeviceType == "mobile" {
		score *= 0.9
	}

	return score
}

func (tie *TenantIsolationEngine) updateRiskScoreFromDevice(profile *ZeroTrustProfile, device *ZeroTrustDeviceProfile) {
	// Simple risk calculation - in production this would be more sophisticated
	if device.TrustScore < 0.5 {
		profile.RiskScore = profile.RiskScore * 1.2 // Increase risk
		if profile.RiskScore > 100 {
			profile.RiskScore = 100
		}
	}
}

func (tie *TenantIsolationEngine) analyzeBehavioralPatterns(events []ZeroTrustAccessEvent) *BehavioralBaseline {
	// Simplified baseline analysis - in production this would use ML
	baseline := tie.createDefaultBehavioralBaseline()

	if len(events) > 0 {
		// Analyze typical access hours
		hourCounts := make(map[int]int)
		for _, event := range events {
			hour := event.Timestamp.Hour()
			hourCounts[hour]++
		}

		// Find most common hours (simplified)
		maxCount := 0
		var startHour, endHour int
		for hour, count := range hourCounts {
			if count > maxCount {
				maxCount = count
				startHour = hour
				endHour = hour + 8 // Assume 8-hour work day
			}
		}

		baseline.TypicalAccessHours[0].StartHour = startHour
		baseline.TypicalAccessHours[0].EndHour = endHour
	}

	return baseline
}

func (tie *TenantIsolationEngine) calculateBaselineConfidence(events []ZeroTrustAccessEvent) float64 {
	// Simple confidence calculation based on number of events
	if len(events) < 10 {
		return 0.1
	} else if len(events) < 50 {
		return 0.5
	} else if len(events) < 100 {
		return 0.8
	}
	return 0.9
}

func (tie *TenantIsolationEngine) evaluateDeviceTrust(profile *ZeroTrustProfile, deviceID string) float64 {
	device, exists := profile.DeviceFingerprints[deviceID]
	if !exists {
		return 0.1 // Very low trust for unknown devices
	}
	return device.TrustScore
}

func (tie *TenantIsolationEngine) evaluateBehavioralTrust(profile *ZeroTrustProfile, request *ZeroTrustAccessRequest) float64 {
	if profile.BehavioralBaseline == nil {
		return 0.5 // Neutral trust if no baseline
	}

	// Check if access is within typical hours
	currentHour := request.Timestamp.Hour()
	for _, window := range profile.BehavioralBaseline.TypicalAccessHours {
		if currentHour >= window.StartHour && currentHour <= window.EndHour {
			return 0.8 // High trust for typical hours
		}
	}

	return 0.3 // Lower trust for unusual hours
}

func (tie *TenantIsolationEngine) evaluateContextualTrust(profile *ZeroTrustProfile, request *ZeroTrustAccessRequest) float64 {
	trust := 0.5 // Start with neutral trust

	// Evaluate each contextual control
	for _, control := range profile.ContextualControls {
		if control.Enabled {
			switch control.Type {
			case ContextualControlTypeLocation:
				// Check if location is known/trusted
				if request.Location != "" {
					trust += 0.1 // Slight increase for known location
				}
			case ContextualControlTypeRisk:
				// Factor in current risk level
				if profile.RiskScore < 30 {
					trust += 0.2
				} else if profile.RiskScore > 70 {
					trust -= 0.2
				}
			}
		}
	}

	if trust > 1.0 {
		trust = 1.0
	}
	if trust < 0.0 {
		trust = 0.0
	}

	return trust
}

func (tie *TenantIsolationEngine) determineZeroTrustAccess(profile *ZeroTrustProfile, trustScore float64, request *ZeroTrustAccessRequest) bool {
	// Access granted if trust score is above threshold
	threshold := 0.6

	// Adjust threshold based on resource sensitivity
	if request.ResourceType == "sensitive" {
		threshold = 0.8
	}

	return trustScore >= threshold
}

func (tie *TenantIsolationEngine) determineRequiredAuthentication(profile *ZeroTrustProfile, trustScore float64) []AuthenticationFactor {
	if trustScore > 0.8 {
		return []AuthenticationFactor{AuthFactorPassword}
	} else if trustScore > 0.6 {
		return []AuthenticationFactor{AuthFactorPassword, AuthFactorTOTP}
	} else {
		return []AuthenticationFactor{AuthFactorPassword, AuthFactorTOTP, AuthFactorBiometric}
	}
}
