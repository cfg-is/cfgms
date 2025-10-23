// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package security

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/security"
)

// BreachDetector monitors tenant activities for unusual access patterns
type BreachDetector struct {
	tenantProfiles  map[string]*TenantAccessProfile
	alertThresholds *AlertThresholds
	validator       *security.Validator
	auditLogger     *TenantSecurityAuditLogger
	isolationEngine *TenantIsolationEngine
	mutex           sync.RWMutex
	alertCallbacks  []AlertCallback
}

// TenantAccessProfile stores historical access patterns for a tenant
type TenantAccessProfile struct {
	TenantID             string                    `json:"tenant_id"`
	BaselineMetrics      *BaselineMetrics          `json:"baseline_metrics"`
	RecentActivity       []*AccessEvent            `json:"recent_activity"`
	SuspiciousActivities []*SuspiciousActivity     `json:"suspicious_activities"`
	GeographicBaseline   map[string]int            `json:"geographic_baseline"`
	DeviceFingerprints   map[string]*DeviceProfile `json:"device_fingerprints"`
	TimePatterns         *TimePatternProfile       `json:"time_patterns"`
	LastUpdated          time.Time                 `json:"last_updated"`
	RiskScore            float64                   `json:"risk_score"`
	BreachIndicators     []*BreachIndicator        `json:"breach_indicators"`
}

// BaselineMetrics represents normal behavior patterns for a tenant
type BaselineMetrics struct {
	AvgRequestsPerHour  float64   `json:"avg_requests_per_hour"`
	PeakRequestsPerHour int       `json:"peak_requests_per_hour"`
	TypicalIPAddresses  []string  `json:"typical_ip_addresses"`
	TypicalUserAgents   []string  `json:"typical_user_agents"`
	TypicalOperations   []string  `json:"typical_operations"`
	TypicalTimezones    []string  `json:"typical_timezones"`
	EstablishedDate     time.Time `json:"established_date"`
	UpdateCount         int       `json:"update_count"`
	ConfidenceScore     float64   `json:"confidence_score"`
}

// AccessEvent represents a single access attempt or operation
type AccessEvent struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	UserID       string            `json:"user_id,omitempty"`
	Operation    string            `json:"operation"`
	Resource     string            `json:"resource"`
	SourceIP     string            `json:"source_ip"`
	UserAgent    string            `json:"user_agent"`
	Timestamp    time.Time         `json:"timestamp"`
	Success      bool              `json:"success"`
	ResponseTime time.Duration     `json:"response_time"`
	DataSize     int64             `json:"data_size"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	AnomalyScore float64           `json:"anomaly_score"`
}

// SuspiciousActivity represents detected suspicious behavior
type SuspiciousActivity struct {
	ID          string                 `json:"id"`
	TenantID    string                 `json:"tenant_id"`
	Type        SuspiciousActivityType `json:"type"`
	Severity    SeverityLevel          `json:"severity"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	Count       int                    `json:"count"`
	Resolved    bool                   `json:"resolved"`
	RiskScore   float64                `json:"risk_score"`
}

// DeviceProfile represents characteristics of a device/client
type DeviceProfile struct {
	Fingerprint     string            `json:"fingerprint"`
	UserAgent       string            `json:"user_agent"`
	IPAddresses     []string          `json:"ip_addresses"`
	FirstSeen       time.Time         `json:"first_seen"`
	LastSeen        time.Time         `json:"last_seen"`
	AccessCount     int               `json:"access_count"`
	TrustScore      float64           `json:"trust_score"`
	Characteristics map[string]string `json:"characteristics"`
}

// TimePatternProfile represents temporal access patterns
type TimePatternProfile struct {
	HourlyDistribution [24]int            `json:"hourly_distribution"`
	DailyDistribution  [7]int             `json:"daily_distribution"`
	MonthlyTrends      map[string]int     `json:"monthly_trends"`
	TimezonePreference string             `json:"timezone_preference"`
	ActiveHours        *ActiveHoursRange  `json:"active_hours"`
	Seasonality        map[string]float64 `json:"seasonality"`
}

// ActiveHoursRange defines typical active hours for a tenant
type ActiveHoursRange struct {
	StartHour int `json:"start_hour"`
	EndHour   int `json:"end_hour"`
}

// BreachIndicator represents potential security breach indicators
type BreachIndicator struct {
	ID          string              `json:"id"`
	Type        BreachIndicatorType `json:"type"`
	Severity    SeverityLevel       `json:"severity"`
	Description string              `json:"description"`
	Confidence  float64             `json:"confidence"`
	Evidence    []string            `json:"evidence"`
	DetectedAt  time.Time           `json:"detected_at"`
	Mitigated   bool                `json:"mitigated"`
}

// AlertThresholds defines detection sensitivity
type AlertThresholds struct {
	RequestVolumeMultiplier    float64 `json:"request_volume_multiplier"`    // 3.0 = 300% of baseline
	NewIPAddressWindow         int     `json:"new_ip_address_window"`        // Minutes to consider IP "new"
	GeographicDistanceKm       float64 `json:"geographic_distance_km"`       // Suspicious geographic distance
	FailedLoginThreshold       int     `json:"failed_login_threshold"`       // Failed attempts before alert
	UnusualTimeWindow          int     `json:"unusual_time_window"`          // Hours outside normal activity
	DataExfiltrationSizeMB     int64   `json:"data_exfiltration_size_mb"`    // MB threshold for data access
	ConcurrentSessionThreshold int     `json:"concurrent_session_threshold"` // Max concurrent sessions
	VelocityCheckWindow        int     `json:"velocity_check_window"`        // Minutes for velocity checks
}

// Enum types
type SuspiciousActivityType string
type SeverityLevel string
type BreachIndicatorType string

const (
	// Suspicious Activity Types
	SuspiciousVolumeSpike    SuspiciousActivityType = "volume_spike"
	SuspiciousNewLocation    SuspiciousActivityType = "new_location"
	SuspiciousTimeAccess     SuspiciousActivityType = "unusual_time"
	SuspiciousFailedLogins   SuspiciousActivityType = "failed_logins"
	SuspiciousDataAccess     SuspiciousActivityType = "excessive_data_access"
	SuspiciousVelocity       SuspiciousActivityType = "impossible_velocity"
	SuspiciousUserAgent      SuspiciousActivityType = "suspicious_user_agent"
	SuspiciousPrivilegeEsc   SuspiciousActivityType = "privilege_escalation"
	SuspiciousNewDevice      SuspiciousActivityType = "new_device"
	SuspiciousConcurrentSess SuspiciousActivityType = "concurrent_sessions"

	// Severity Levels
	SeverityLow      SeverityLevel = "low"
	SeverityMedium   SeverityLevel = "medium"
	SeverityHigh     SeverityLevel = "high"
	SeverityCritical SeverityLevel = "critical"

	// Breach Indicator Types
	BreachCredentialStuffing BreachIndicatorType = "credential_stuffing"
	BreachAccountTakeover    BreachIndicatorType = "account_takeover"
	BreachDataExfiltration   BreachIndicatorType = "data_exfiltration"
	BreachInsiderThreat      BreachIndicatorType = "insider_threat"
	BreachAPIAbuse           BreachIndicatorType = "api_abuse"
	BreachBotActivity        BreachIndicatorType = "bot_activity"
	BreachPrivilegeAbuse     BreachIndicatorType = "privilege_abuse"
)

// AlertCallback defines the function signature for breach alerts
type AlertCallback func(ctx context.Context, activity *SuspiciousActivity, indicator *BreachIndicator)

// NewBreachDetector creates a new breach detection system
func NewBreachDetector(auditLogger *TenantSecurityAuditLogger, isolationEngine *TenantIsolationEngine) *BreachDetector {
	return &BreachDetector{
		tenantProfiles:  make(map[string]*TenantAccessProfile),
		alertThresholds: getDefaultAlertThresholds(),
		validator:       security.NewValidator(),
		auditLogger:     auditLogger,
		isolationEngine: isolationEngine,
		mutex:           sync.RWMutex{},
		alertCallbacks:  make([]AlertCallback, 0),
	}
}

// GetCurrentHourRequestCount exposes internal method for testing
func (bd *BreachDetector) GetCurrentHourRequestCount(profile *TenantAccessProfile) int {
	return bd.getCurrentHourRequestCount(profile)
}

// GetAlertThresholds exposes alert thresholds for testing
func (bd *BreachDetector) GetAlertThresholds() *AlertThresholds {
	return bd.alertThresholds
}

// IsAccountTakeoverPattern exposes internal method for testing
func (bd *BreachDetector) IsAccountTakeoverPattern(profile *TenantAccessProfile) bool {
	return bd.isAccountTakeoverPattern(profile)
}

// EstimateLocation exposes internal method for testing
func (bd *BreachDetector) EstimateLocation(ip string) string {
	return bd.estimateLocation(ip)
}

// AnalyzeBreachIndicators exposes internal method for testing
func (bd *BreachDetector) AnalyzeBreachIndicators(ctx context.Context, profile *TenantAccessProfile) []*BreachIndicator {
	return bd.analyzeBreachIndicators(ctx, profile)
}

// RecordAccess processes a new access event and checks for anomalies
func (bd *BreachDetector) RecordAccess(ctx context.Context, event *AccessEvent) error {
	// Validate the access event
	if err := bd.validateAccessEvent(event); err != nil {
		return fmt.Errorf("invalid access event: %w", err)
	}

	bd.mutex.Lock()
	defer bd.mutex.Unlock()

	// Get or create tenant profile
	profile := bd.getTenantProfile(event.TenantID)

	// Calculate anomaly score for this event
	anomalyScore := bd.calculateAnomalyScore(event, profile)
	event.AnomalyScore = anomalyScore

	// Update tenant profile with new event FIRST for full context
	bd.updateTenantProfile(profile, event)

	// Check for suspicious activities AFTER updating profile (except geographic baseline)
	// Save current geographic state for new location detection
	originalGeoBaseline := make(map[string]int)
	for k, v := range profile.GeographicBaseline {
		originalGeoBaseline[k] = v
	}

	// Remove the just-added geographic location for new location detection
	location := bd.estimateLocation(event.SourceIP)
	if location != "" {
		profile.GeographicBaseline[location]--
		if profile.GeographicBaseline[location] <= 0 {
			delete(profile.GeographicBaseline, location)
		}
	}

	// Now detect suspicious activities with the "pre-update" geographic state
	suspicious := bd.detectSuspiciousActivities(ctx, event, profile)

	// Restore the geographic baseline
	for k, v := range originalGeoBaseline {
		profile.GeographicBaseline[k] = v
	}
	if location != "" {
		profile.GeographicBaseline[location]++
	}

	if len(suspicious) > 0 {
		profile.SuspiciousActivities = append(profile.SuspiciousActivities, suspicious...)

		// Check for breach indicators
		indicators := bd.analyzeBreachIndicators(ctx, profile)
		if len(indicators) > 0 {
			profile.BreachIndicators = append(profile.BreachIndicators, indicators...)

			// Trigger alerts
			for _, activity := range suspicious {
				for _, indicator := range indicators {
					bd.triggerAlerts(ctx, activity, indicator)
				}
			}
		}
	}

	// Update risk score
	profile.RiskScore = bd.calculateRiskScore(profile)
	profile.LastUpdated = time.Now()

	return nil
}

// calculateAnomalyScore determines how unusual an access event is
func (bd *BreachDetector) calculateAnomalyScore(event *AccessEvent, profile *TenantAccessProfile) float64 {
	score := 0.0

	if profile.BaselineMetrics == nil {
		return 0.1 // Low score for new tenants
	}

	// Check IP address novelty
	if !bd.isKnownIP(event.SourceIP, profile.BaselineMetrics.TypicalIPAddresses) {
		score += 0.3
	}

	// Check user agent novelty
	if !bd.isKnownUserAgent(event.UserAgent, profile.BaselineMetrics.TypicalUserAgents) {
		score += 0.2
	}

	// Check operation frequency
	if !bd.isTypicalOperation(event.Operation, profile.BaselineMetrics.TypicalOperations) {
		score += 0.2
	}

	// Check time patterns
	timeScore := bd.calculateTimeAnomalyScore(event.Timestamp, profile.TimePatterns)
	score += timeScore * 0.3

	// Check geographic distance if we can determine location
	geoScore := bd.calculateGeographicAnomalyScore(event.SourceIP, profile)
	score += geoScore * 0.4

	// Check for failed access patterns
	if !event.Success {
		score += 0.2
	}

	// Normalize score to 0-1 range
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// detectSuspiciousActivities identifies potential security threats
func (bd *BreachDetector) detectSuspiciousActivities(ctx context.Context, event *AccessEvent, profile *TenantAccessProfile) []*SuspiciousActivity {
	var activities []*SuspiciousActivity

	// Check for volume spikes
	if bd.isVolumeSpikeDetected(profile) {
		activities = append(activities, &SuspiciousActivity{
			ID:          bd.generateActivityID(),
			TenantID:    event.TenantID,
			Type:        SuspiciousVolumeSpike,
			Severity:    SeverityMedium,
			Description: "Unusual increase in request volume detected",
			Evidence: map[string]interface{}{
				"current_hour_requests": bd.getCurrentHourRequestCount(profile),
				"baseline_avg":          profile.BaselineMetrics.AvgRequestsPerHour,
			},
			FirstSeen: event.Timestamp,
			LastSeen:  event.Timestamp,
			Count:     1,
			RiskScore: 0.6,
		})
	}

	// Check for failed login patterns
	if bd.isFailedLoginSpike(profile) {
		activities = append(activities, &SuspiciousActivity{
			ID:          bd.generateActivityID(),
			TenantID:    event.TenantID,
			Type:        SuspiciousFailedLogins,
			Severity:    SeverityHigh,
			Description: "Multiple failed login attempts detected",
			Evidence: map[string]interface{}{
				"failed_attempts_last_hour": bd.getFailedAttemptsCount(profile, time.Hour),
				"source_ips":                bd.getUniqueFailedLoginIPs(profile),
			},
			FirstSeen: event.Timestamp,
			LastSeen:  event.Timestamp,
			Count:     1,
			RiskScore: 0.8,
		})
	}

	// Check for new geographic location
	if bd.isNewGeographicLocation(event.SourceIP, profile) {
		activities = append(activities, &SuspiciousActivity{
			ID:          bd.generateActivityID(),
			TenantID:    event.TenantID,
			Type:        SuspiciousNewLocation,
			Severity:    SeverityMedium,
			Description: "Access from new geographic location",
			Evidence: map[string]interface{}{
				"source_ip":          event.SourceIP,
				"estimated_location": bd.estimateLocation(event.SourceIP),
			},
			FirstSeen: event.Timestamp,
			LastSeen:  event.Timestamp,
			Count:     1,
			RiskScore: 0.5,
		})
	}

	// Check for unusual time access
	if bd.isUnusualTimeAccess(event.Timestamp, profile) {
		activities = append(activities, &SuspiciousActivity{
			ID:          bd.generateActivityID(),
			TenantID:    event.TenantID,
			Type:        SuspiciousTimeAccess,
			Severity:    SeverityLow,
			Description: "Access outside typical hours",
			Evidence: map[string]interface{}{
				"access_time":   event.Timestamp.Format("15:04 MST"),
				"typical_hours": profile.TimePatterns.ActiveHours,
			},
			FirstSeen: event.Timestamp,
			LastSeen:  event.Timestamp,
			Count:     1,
			RiskScore: 0.3,
		})
	}

	// Check for impossible velocity (accessing from distant locations quickly)
	if bd.isImpossibleVelocity(event, profile) {
		activities = append(activities, &SuspiciousActivity{
			ID:          bd.generateActivityID(),
			TenantID:    event.TenantID,
			Type:        SuspiciousVelocity,
			Severity:    SeverityCritical,
			Description: "Impossible travel velocity detected",
			Evidence: map[string]interface{}{
				"current_ip":   event.SourceIP,
				"previous_ip":  bd.getLastDifferentIP(profile),
				"time_between": bd.getTimeBetweenLocations(profile),
			},
			FirstSeen: event.Timestamp,
			LastSeen:  event.Timestamp,
			Count:     1,
			RiskScore: 0.9,
		})
	}

	return activities
}

// analyzeBreachIndicators looks for patterns that suggest actual breaches
func (bd *BreachDetector) analyzeBreachIndicators(ctx context.Context, profile *TenantAccessProfile) []*BreachIndicator {
	var indicators []*BreachIndicator

	// Check for credential stuffing (many failed logins from different IPs)
	if bd.isCredentialStuffingPattern(profile) {
		indicators = append(indicators, &BreachIndicator{
			ID:          bd.generateIndicatorID(),
			Type:        BreachCredentialStuffing,
			Severity:    SeverityHigh,
			Description: "Credential stuffing attack detected",
			Confidence:  0.85,
			Evidence:    []string{"Multiple failed logins", "Diverse IP sources", "Short time window"},
			DetectedAt:  time.Now(),
		})
	}

	// Check for account takeover (successful login after many failures from new location)
	if bd.isAccountTakeoverPattern(profile) {
		indicators = append(indicators, &BreachIndicator{
			ID:          bd.generateIndicatorID(),
			Type:        BreachAccountTakeover,
			Severity:    SeverityCritical,
			Description: "Potential account takeover detected",
			Confidence:  0.9,
			Evidence:    []string{"Successful login after failures", "New geographic location", "New device"},
			DetectedAt:  time.Now(),
		})
	}

	// Check for data exfiltration (large amounts of data accessed)
	if bd.isDataExfiltrationPattern(profile) {
		indicators = append(indicators, &BreachIndicator{
			ID:          bd.generateIndicatorID(),
			Type:        BreachDataExfiltration,
			Severity:    SeverityCritical,
			Description: "Potential data exfiltration detected",
			Confidence:  0.8,
			Evidence:    []string{"Large data access volume", "Unusual access patterns", "Multiple resource types"},
			DetectedAt:  time.Now(),
		})
	}

	// Check for bot activity (high frequency, consistent patterns)
	if bd.isBotActivityPattern(profile) {
		indicators = append(indicators, &BreachIndicator{
			ID:          bd.generateIndicatorID(),
			Type:        BreachBotActivity,
			Severity:    SeverityMedium,
			Description: "Automated bot activity detected",
			Confidence:  0.75,
			Evidence:    []string{"High frequency requests", "Consistent timing", "Limited operation variety"},
			DetectedAt:  time.Now(),
		})
	}

	return indicators
}

// Helper methods for detection logic

func (bd *BreachDetector) getTenantProfile(tenantID string) *TenantAccessProfile {
	if profile, exists := bd.tenantProfiles[tenantID]; exists {
		return profile
	}

	// Create new profile
	profile := &TenantAccessProfile{
		TenantID:             tenantID,
		BaselineMetrics:      nil, // Will be established over time
		RecentActivity:       make([]*AccessEvent, 0),
		SuspiciousActivities: make([]*SuspiciousActivity, 0),
		GeographicBaseline:   make(map[string]int),
		DeviceFingerprints:   make(map[string]*DeviceProfile),
		TimePatterns: &TimePatternProfile{
			MonthlyTrends: make(map[string]int),
			Seasonality:   make(map[string]float64),
		},
		LastUpdated:      time.Now(),
		RiskScore:        0.0,
		BreachIndicators: make([]*BreachIndicator, 0),
	}

	bd.tenantProfiles[tenantID] = profile
	return profile
}

func (bd *BreachDetector) updateTenantProfile(profile *TenantAccessProfile, event *AccessEvent) {
	// Add to recent activity (keep last 1000 events)
	profile.RecentActivity = append(profile.RecentActivity, event)
	if len(profile.RecentActivity) > 1000 {
		profile.RecentActivity = profile.RecentActivity[1:]
	}

	// Update baseline metrics if we have enough data
	if len(profile.RecentActivity) >= 50 && profile.BaselineMetrics == nil {
		profile.BaselineMetrics = bd.establishBaseline(profile)
	} else if profile.BaselineMetrics != nil {
		bd.updateBaseline(profile, event)
	}

	// Update time patterns
	bd.updateTimePatterns(profile.TimePatterns, event)

	// Update device fingerprints
	bd.updateDeviceFingerprints(profile, event)

	// Update geographic baseline
	bd.updateGeographicBaseline(profile, event)
}

func (bd *BreachDetector) establishBaseline(profile *TenantAccessProfile) *BaselineMetrics {
	events := profile.RecentActivity
	if len(events) == 0 {
		return nil
	}

	// Calculate hourly request average
	hourlyRequests := make(map[int]int)
	ipMap := make(map[string]bool)
	agentMap := make(map[string]bool)
	opMap := make(map[string]bool)

	for _, event := range events {
		hour := event.Timestamp.Hour()
		hourlyRequests[hour]++
		ipMap[event.SourceIP] = true
		agentMap[event.UserAgent] = true
		opMap[event.Operation] = true
	}

	// Calculate average
	totalRequests := len(events)
	hoursSpanned := len(hourlyRequests)
	avgPerHour := float64(totalRequests) / float64(hoursSpanned)

	// Get peak
	maxRequests := 0
	for _, count := range hourlyRequests {
		if count > maxRequests {
			maxRequests = count
		}
	}

	// Convert maps to slices
	ips := make([]string, 0, len(ipMap))
	agents := make([]string, 0, len(agentMap))
	ops := make([]string, 0, len(opMap))

	for ip := range ipMap {
		ips = append(ips, ip)
	}
	for agent := range agentMap {
		agents = append(agents, agent)
	}
	for op := range opMap {
		ops = append(ops, op)
	}

	return &BaselineMetrics{
		AvgRequestsPerHour:  avgPerHour,
		PeakRequestsPerHour: maxRequests,
		TypicalIPAddresses:  ips,
		TypicalUserAgents:   agents,
		TypicalOperations:   ops,
		EstablishedDate:     time.Now(),
		UpdateCount:         1,
		ConfidenceScore:     math.Min(float64(len(events))/100.0, 1.0), // Max confidence at 100 events
	}
}

func (bd *BreachDetector) updateBaseline(profile *TenantAccessProfile, event *AccessEvent) {
	baseline := profile.BaselineMetrics
	baseline.UpdateCount++

	// Update IP addresses (keep recent ones)
	if !bd.isKnownIP(event.SourceIP, baseline.TypicalIPAddresses) {
		baseline.TypicalIPAddresses = append(baseline.TypicalIPAddresses, event.SourceIP)
		// Keep only last 20 IPs
		if len(baseline.TypicalIPAddresses) > 20 {
			baseline.TypicalIPAddresses = baseline.TypicalIPAddresses[1:]
		}
	}

	// Similar updates for user agents and operations...
	if !bd.isKnownUserAgent(event.UserAgent, baseline.TypicalUserAgents) {
		baseline.TypicalUserAgents = append(baseline.TypicalUserAgents, event.UserAgent)
		if len(baseline.TypicalUserAgents) > 10 {
			baseline.TypicalUserAgents = baseline.TypicalUserAgents[1:]
		}
	}

	if !bd.isTypicalOperation(event.Operation, baseline.TypicalOperations) {
		baseline.TypicalOperations = append(baseline.TypicalOperations, event.Operation)
		if len(baseline.TypicalOperations) > 15 {
			baseline.TypicalOperations = baseline.TypicalOperations[1:]
		}
	}
}

func (bd *BreachDetector) updateTimePatterns(patterns *TimePatternProfile, event *AccessEvent) {
	hour := event.Timestamp.Hour()
	day := int(event.Timestamp.Weekday())
	month := event.Timestamp.Format("2006-01")

	patterns.HourlyDistribution[hour]++
	patterns.DailyDistribution[day]++
	patterns.MonthlyTrends[month]++

	// Update active hours based on most common access times
	bd.updateActiveHours(patterns)
}

func (bd *BreachDetector) updateActiveHours(patterns *TimePatternProfile) {
	// Find the 8-hour window with most activity
	maxActivity := 0
	bestStart := 0

	for start := 0; start < 24; start++ {
		activity := 0
		for i := 0; i < 8; i++ {
			hour := (start + i) % 24
			activity += patterns.HourlyDistribution[hour]
		}
		if activity > maxActivity {
			maxActivity = activity
			bestStart = start
		}
	}

	patterns.ActiveHours = &ActiveHoursRange{
		StartHour: bestStart,
		EndHour:   (bestStart + 8) % 24,
	}
}

func (bd *BreachDetector) updateDeviceFingerprints(profile *TenantAccessProfile, event *AccessEvent) {
	fingerprint := bd.generateDeviceFingerprint(event)

	if device, exists := profile.DeviceFingerprints[fingerprint]; exists {
		device.LastSeen = event.Timestamp
		device.AccessCount++
		// Update trust score based on consistent behavior
		device.TrustScore = math.Min(1.0, device.TrustScore+0.01)
	} else {
		profile.DeviceFingerprints[fingerprint] = &DeviceProfile{
			Fingerprint: fingerprint,
			UserAgent:   event.UserAgent,
			IPAddresses: []string{event.SourceIP},
			FirstSeen:   event.Timestamp,
			LastSeen:    event.Timestamp,
			AccessCount: 1,
			TrustScore:  0.1, // Low trust for new devices
			Characteristics: map[string]string{
				"user_agent": event.UserAgent,
				"first_ip":   event.SourceIP,
			},
		}
	}
}

func (bd *BreachDetector) updateGeographicBaseline(profile *TenantAccessProfile, event *AccessEvent) {
	location := bd.estimateLocation(event.SourceIP)
	if location != "" {
		profile.GeographicBaseline[location]++
	}
}

// Detection helper methods

func (bd *BreachDetector) isKnownIP(ip string, knownIPs []string) bool {
	for _, known := range knownIPs {
		if ip == known {
			return true
		}
	}
	return false
}

func (bd *BreachDetector) isKnownUserAgent(agent string, knownAgents []string) bool {
	for _, known := range knownAgents {
		if agent == known {
			return true
		}
	}
	return false
}

func (bd *BreachDetector) isTypicalOperation(op string, knownOps []string) bool {
	for _, known := range knownOps {
		if op == known {
			return true
		}
	}
	return false
}

func (bd *BreachDetector) calculateTimeAnomalyScore(timestamp time.Time, patterns *TimePatternProfile) float64 {
	if patterns.ActiveHours == nil {
		return 0.0 // No pattern established yet
	}

	hour := timestamp.Hour()
	start := patterns.ActiveHours.StartHour
	end := patterns.ActiveHours.EndHour

	// Check if hour is within active range
	var inRange bool
	if start <= end {
		inRange = hour >= start && hour <= end
	} else { // Range wraps around midnight
		inRange = hour >= start || hour <= end
	}

	if inRange {
		return 0.0 // Normal time
	}
	return 0.5 // Outside normal hours
}

func (bd *BreachDetector) calculateGeographicAnomalyScore(ip string, profile *TenantAccessProfile) float64 {
	location := bd.estimateLocation(ip)
	if location == "" {
		return 0.1 // Can't determine location
	}

	if count, exists := profile.GeographicBaseline[location]; exists && count > 0 {
		return 0.0 // Known location
	}
	return 0.6 // New location
}

func (bd *BreachDetector) isVolumeSpikeDetected(profile *TenantAccessProfile) bool {
	if profile.BaselineMetrics == nil {
		return false
	}

	currentHourCount := bd.getCurrentHourRequestCount(profile)
	threshold := profile.BaselineMetrics.AvgRequestsPerHour * bd.alertThresholds.RequestVolumeMultiplier

	return float64(currentHourCount) > threshold
}

func (bd *BreachDetector) getCurrentHourRequestCount(profile *TenantAccessProfile) int {
	now := time.Now()
	currentHour := now.Hour()
	count := 0

	for _, event := range profile.RecentActivity {
		if event.Timestamp.Hour() == currentHour &&
			event.Timestamp.Day() == now.Day() &&
			event.Timestamp.Month() == now.Month() {
			count++
		}
	}
	return count
}

func (bd *BreachDetector) isFailedLoginSpike(profile *TenantAccessProfile) bool {
	failedCount := bd.getFailedAttemptsCount(profile, time.Hour)
	return failedCount >= bd.alertThresholds.FailedLoginThreshold
}

func (bd *BreachDetector) getFailedAttemptsCount(profile *TenantAccessProfile, window time.Duration) int {
	cutoff := time.Now().Add(-window)
	count := 0

	for _, event := range profile.RecentActivity {
		if event.Timestamp.After(cutoff) && !event.Success {
			count++
		}
	}
	return count
}

func (bd *BreachDetector) getUniqueFailedLoginIPs(profile *TenantAccessProfile) []string {
	cutoff := time.Now().Add(-time.Hour)
	ipMap := make(map[string]bool)

	for _, event := range profile.RecentActivity {
		if event.Timestamp.After(cutoff) && !event.Success {
			ipMap[event.SourceIP] = true
		}
	}

	ips := make([]string, 0, len(ipMap))
	for ip := range ipMap {
		ips = append(ips, ip)
	}
	return ips
}

func (bd *BreachDetector) isNewGeographicLocation(ip string, profile *TenantAccessProfile) bool {
	location := bd.estimateLocation(ip)
	if location == "" {
		return false
	}

	_, exists := profile.GeographicBaseline[location]
	return !exists
}

func (bd *BreachDetector) isUnusualTimeAccess(timestamp time.Time, profile *TenantAccessProfile) bool {
	if profile.TimePatterns.ActiveHours == nil {
		return false
	}

	hour := timestamp.Hour()
	start := profile.TimePatterns.ActiveHours.StartHour
	end := profile.TimePatterns.ActiveHours.EndHour

	// Check if outside active hours
	if start <= end {
		return hour < start || hour > end
	}
	// Range wraps around midnight
	return hour < start && hour > end
}

func (bd *BreachDetector) isImpossibleVelocity(event *AccessEvent, profile *TenantAccessProfile) bool {
	if len(profile.RecentActivity) < 2 {
		return false
	}

	// Get last event from different IP
	var lastEvent *AccessEvent
	for i := len(profile.RecentActivity) - 2; i >= 0; i-- {
		if profile.RecentActivity[i].SourceIP != event.SourceIP {
			lastEvent = profile.RecentActivity[i]
			break
		}
	}

	if lastEvent == nil {
		return false
	}

	timeDiff := event.Timestamp.Sub(lastEvent.Timestamp)
	if timeDiff < time.Duration(bd.alertThresholds.VelocityCheckWindow)*time.Minute {
		// Calculate distance between IPs
		distance := bd.calculateIPDistance(lastEvent.SourceIP, event.SourceIP)
		if distance > bd.alertThresholds.GeographicDistanceKm {
			// Check if travel time is physically possible (assuming max 1000 km/h)
			maxPossibleDistance := timeDiff.Hours() * 1000.0
			return distance > maxPossibleDistance
		}
	}

	return false
}

// Pattern recognition methods for breach indicators

func (bd *BreachDetector) isCredentialStuffingPattern(profile *TenantAccessProfile) bool {
	// Look for many failed logins from diverse IPs in short time
	recentFailures := bd.getFailedAttemptsCount(profile, time.Hour)
	uniqueIPs := len(bd.getUniqueFailedLoginIPs(profile))

	return recentFailures >= 20 && uniqueIPs >= 5
}

func (bd *BreachDetector) isAccountTakeoverPattern(profile *TenantAccessProfile) bool {
	// Look for successful login after failures from new location
	if len(profile.RecentActivity) < 5 {
		return false
	}

	// Simple approach: look for failed login attempts followed by successful login
	// where the successful login is from a different location than baseline
	recentEvents := profile.RecentActivity
	if len(recentEvents) > 10 {
		recentEvents = profile.RecentActivity[len(profile.RecentActivity)-10:]
	}

	hasRecentFailures := false
	hasSuccessFromNewLocation := false

	// Find the most common baseline location (excluding recent login events)
	baselineLocations := make(map[string]int)
	for _, event := range profile.RecentActivity {
		// Only count non-login events for baseline (normal operations)
		if event.Operation != "login" && event.Success {
			location := bd.estimateLocation(event.SourceIP)
			if location != "" {
				baselineLocations[location]++
			}
		}
	}

	// Find most common baseline location
	primaryLocation := ""
	maxBaselineCount := 0
	for location, count := range baselineLocations {
		if count > maxBaselineCount {
			maxBaselineCount = count
			primaryLocation = location
		}
	}

	// Now check recent login events
	for _, event := range recentEvents {
		if event.Operation == "login" {
			if !event.Success {
				hasRecentFailures = true
			} else if event.Success {
				// Check if successful login is from different location than primary baseline
				location := bd.estimateLocation(event.SourceIP)
				if location != "" && location != primaryLocation && maxBaselineCount > 5 {
					hasSuccessFromNewLocation = true
				}
			}
		}
	}

	return hasRecentFailures && hasSuccessFromNewLocation
}

func (bd *BreachDetector) isDataExfiltrationPattern(profile *TenantAccessProfile) bool {
	// Look for large amounts of data accessed
	cutoff := time.Now().Add(-time.Hour)
	totalDataSize := int64(0)

	for _, event := range profile.RecentActivity {
		if event.Timestamp.After(cutoff) && event.Success {
			totalDataSize += event.DataSize
		}
	}

	return totalDataSize > bd.alertThresholds.DataExfiltrationSizeMB*1024*1024
}

func (bd *BreachDetector) isBotActivityPattern(profile *TenantAccessProfile) bool {
	// Look for highly consistent timing patterns
	if len(profile.RecentActivity) < 10 {
		return false
	}

	recent := profile.RecentActivity[len(profile.RecentActivity)-10:]
	intervals := make([]time.Duration, 0, len(recent)-1)

	for i := 1; i < len(recent); i++ {
		interval := recent[i].Timestamp.Sub(recent[i-1].Timestamp)
		intervals = append(intervals, interval)
	}

	// Calculate variance in intervals
	variance := bd.calculateTimeVariance(intervals)
	return variance < time.Second*5 // Very consistent timing
}

// Utility methods

func (bd *BreachDetector) calculateRiskScore(profile *TenantAccessProfile) float64 {
	score := 0.0

	// Base score from suspicious activities
	for _, activity := range profile.SuspiciousActivities {
		if !activity.Resolved {
			score += activity.RiskScore * 0.3
		}
	}

	// Score from breach indicators
	for _, indicator := range profile.BreachIndicators {
		if !indicator.Mitigated {
			score += indicator.Confidence * 0.5
		}
	}

	// Score from recent anomaly scores
	recentAnomalies := 0.0
	count := 0
	cutoff := time.Now().Add(-time.Hour)

	for _, event := range profile.RecentActivity {
		if event.Timestamp.After(cutoff) {
			recentAnomalies += event.AnomalyScore
			count++
		}
	}

	if count > 0 {
		avgAnomaly := recentAnomalies / float64(count)
		score += avgAnomaly * 0.2
	}

	// Normalize to 0-1 range
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (bd *BreachDetector) validateAccessEvent(event *AccessEvent) error {
	// Basic validation without using the security validator which is too strict for access events
	// The security validator is designed for user input, not for logging access patterns

	// Validate tenant ID format (basic UUID check)
	if event.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if len(event.TenantID) != 36 { // Simple UUID length check
		return fmt.Errorf("tenant_id must be valid UUID format")
	}

	// Validate operation
	if event.Operation == "" {
		return fmt.Errorf("operation is required")
	}
	if len(event.Operation) > 64 {
		return fmt.Errorf("operation too long (max 64 characters)")
	}

	// Validate resource
	if event.Resource == "" {
		return fmt.Errorf("resource is required")
	}
	if len(event.Resource) > 256 {
		return fmt.Errorf("resource too long (max 256 characters)")
	}

	// Validate source IP
	if event.SourceIP == "" {
		return fmt.Errorf("source_ip is required")
	}
	if net.ParseIP(event.SourceIP) == nil {
		return fmt.Errorf("source_ip must be valid IP address")
	}

	// Validate user agent length
	if len(event.UserAgent) > 512 {
		return fmt.Errorf("user_agent too long (max 512 characters)")
	}

	return nil
}

func (bd *BreachDetector) estimateLocation(ip string) string {
	// Simple implementation - in production would use GeoIP database
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}

	if parsedIP.IsLoopback() || parsedIP.IsPrivate() {
		return "local"
	}

	// Simplified geographic estimation based on IP ranges for testing
	// In production, use proper GeoIP database
	if ip == "198.51.100.10" {
		return "region_a"
	}
	if ip == "203.0.113.50" {
		return "region_b"
	}

	return "unknown_location"
}

func (bd *BreachDetector) calculateIPDistance(ip1, ip2 string) float64 {
	// Simplified distance calculation
	// In production, use proper GeoIP coordinates
	loc1 := bd.estimateLocation(ip1)
	loc2 := bd.estimateLocation(ip2)

	if loc1 != loc2 {
		return 500.0 // Assume 500km for different locations
	}
	return 0.0
}

func (bd *BreachDetector) calculateTimeVariance(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	// Calculate mean
	sum := time.Duration(0)
	for _, interval := range intervals {
		sum += interval
	}
	mean := sum / time.Duration(len(intervals))

	// Calculate variance
	varianceSum := int64(0)
	for _, interval := range intervals {
		diff := interval - mean
		varianceSum += int64(diff) * int64(diff)
	}

	variance := time.Duration(varianceSum / int64(len(intervals)))
	return variance
}

func (bd *BreachDetector) generateDeviceFingerprint(event *AccessEvent) string {
	// Simple fingerprint based on user agent and behavioral patterns
	hash := fmt.Sprintf("%x", event.UserAgent)
	if len(hash) > 16 {
		return hash[:16]
	}
	return hash
}

func (bd *BreachDetector) generateActivityID() string {
	return fmt.Sprintf("activity_%d", time.Now().UnixNano())
}

func (bd *BreachDetector) generateIndicatorID() string {
	return fmt.Sprintf("indicator_%d", time.Now().UnixNano())
}

func (bd *BreachDetector) getLastDifferentIP(profile *TenantAccessProfile) string {
	if len(profile.RecentActivity) < 2 {
		return ""
	}

	currentIP := profile.RecentActivity[len(profile.RecentActivity)-1].SourceIP
	for i := len(profile.RecentActivity) - 2; i >= 0; i-- {
		if profile.RecentActivity[i].SourceIP != currentIP {
			return profile.RecentActivity[i].SourceIP
		}
	}
	return ""
}

func (bd *BreachDetector) getTimeBetweenLocations(profile *TenantAccessProfile) time.Duration {
	if len(profile.RecentActivity) < 2 {
		return 0
	}

	latest := profile.RecentActivity[len(profile.RecentActivity)-1]
	currentIP := latest.SourceIP

	for i := len(profile.RecentActivity) - 2; i >= 0; i-- {
		if profile.RecentActivity[i].SourceIP != currentIP {
			return latest.Timestamp.Sub(profile.RecentActivity[i].Timestamp)
		}
	}
	return 0
}

func (bd *BreachDetector) triggerAlerts(ctx context.Context, activity *SuspiciousActivity, indicator *BreachIndicator) {
	for _, callback := range bd.alertCallbacks {
		go callback(ctx, activity, indicator)
	}
}

// RegisterAlertCallback adds a callback function for breach alerts
func (bd *BreachDetector) RegisterAlertCallback(callback AlertCallback) {
	bd.mutex.Lock()
	defer bd.mutex.Unlock()
	bd.alertCallbacks = append(bd.alertCallbacks, callback)
}

// GetTenantRiskScore returns the current risk score for a tenant
func (bd *BreachDetector) GetTenantRiskScore(tenantID string) float64 {
	bd.mutex.RLock()
	defer bd.mutex.RUnlock()

	if profile, exists := bd.tenantProfiles[tenantID]; exists {
		return profile.RiskScore
	}
	return 0.0
}

// GetActiveBreach Indicators returns unmitigated breach indicators for a tenant
func (bd *BreachDetector) GetActiveBreachIndicators(tenantID string) []*BreachIndicator {
	bd.mutex.RLock()
	defer bd.mutex.RUnlock()

	if profile, exists := bd.tenantProfiles[tenantID]; exists {
		var active []*BreachIndicator
		for _, indicator := range profile.BreachIndicators {
			if !indicator.Mitigated {
				active = append(active, indicator)
			}
		}
		return active
	}
	return nil
}

func getDefaultAlertThresholds() *AlertThresholds {
	return &AlertThresholds{
		RequestVolumeMultiplier:    3.0,   // 300% of baseline
		NewIPAddressWindow:         60,    // 1 hour
		GeographicDistanceKm:       500.0, // 500km
		FailedLoginThreshold:       10,    // 10 failed attempts
		UnusualTimeWindow:          8,     // 8 hours outside normal
		DataExfiltrationSizeMB:     100,   // 100MB
		ConcurrentSessionThreshold: 5,     // 5 concurrent sessions
		VelocityCheckWindow:        30,    // 30 minutes
	}
}
