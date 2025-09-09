package risk

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
)

// EnvironmentRiskAnalyzer analyzes environmental risk factors for access requests
type EnvironmentRiskAnalyzer struct {
	geoRiskAssessor     *GeoRiskAssessor
	timeRiskAssessor    *TimeRiskAssessor
	networkRiskAssessor *NetworkRiskAssessor
	deviceRiskAssessor  *DeviceRiskAssessor
	threatIntelService  *ThreatIntelligenceService
}

// GeoRiskAssessor assesses geographic and location-based risks
type GeoRiskAssessor struct {
	countryRiskScores   map[string]float64
	regionRiskScores    map[string]float64
	vpnDetector         *VPNDetector
	proxyDetector       *ProxyDetector
	torDetector         *TorDetector
}

// TimeRiskAssessor assesses time-based risks
type TimeRiskAssessor struct {
	businessHours       BusinessHoursConfig
	timezoneValidator   *TimezoneValidator
	holidayCalendar     *HolidayCalendar
}

// NetworkRiskAssessor assesses network-based risks
type NetworkRiskAssessor struct {
	knownNetworks       map[string]NetworkInfo
	securityScanner     *NetworkSecurityScanner
	bandwidthAnalyzer   *BandwidthAnalyzer
	latencyAnalyzer     *LatencyAnalyzer
}

// DeviceRiskAssessor assesses device-based risks
type DeviceRiskAssessor struct {
	knownDevices        map[string]DeviceInfo
	complianceChecker   *DeviceComplianceChecker
	fingerprintAnalyzer *DeviceFingerprintAnalyzer
}

// ThreatIntelligenceService provides threat intelligence data
type ThreatIntelligenceService struct {
	ipReputationDB      *IPReputationDatabase
	threatFeedService   *ThreatFeedService
	malwareDetector     *MalwareDetector
}

// Supporting configuration and data types

// BusinessHoursConfig defines business hours configuration
type BusinessHoursConfig struct {
	Monday    TimeRange `json:"monday"`
	Tuesday   TimeRange `json:"tuesday"`
	Wednesday TimeRange `json:"wednesday"`
	Thursday  TimeRange `json:"thursday"`
	Friday    TimeRange `json:"friday"`
	Saturday  TimeRange `json:"saturday"`
	Sunday    TimeRange `json:"sunday"`
	Timezone  string    `json:"timezone"`
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// NetworkInfo contains information about known networks
type NetworkInfo struct {
	NetworkID     string                 `json:"network_id"`
	CIDR          string                 `json:"cidr"`
	Organization  string                 `json:"organization"`
	SecurityLevel NetworkSecurityLevel   `json:"security_level"`
	TrustScore    float64                `json:"trust_score"`
	LastUpdated   time.Time              `json:"last_updated"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// DeviceInfo contains information about known devices
type DeviceInfo struct {
	DeviceID          string                 `json:"device_id"`
	DeviceType        string                 `json:"device_type"`
	OS                string                 `json:"os"`
	OSVersion         string                 `json:"os_version"`
	Browser           string                 `json:"browser"`
	BrowserVersion    string                 `json:"browser_version"`
	ComplianceStatus  DeviceComplianceStatus `json:"compliance_status"`
	TrustScore        float64                `json:"trust_score"`
	LastSeen          time.Time              `json:"last_seen"`
	RiskFactors       []string               `json:"risk_factors"`
}

// NewEnvironmentRiskAnalyzer creates a new environment risk analyzer
func NewEnvironmentRiskAnalyzer() *EnvironmentRiskAnalyzer {
	return &EnvironmentRiskAnalyzer{
		geoRiskAssessor:     NewGeoRiskAssessor(),
		timeRiskAssessor:    NewTimeRiskAssessor(),
		networkRiskAssessor: NewNetworkRiskAssessor(),
		deviceRiskAssessor:  NewDeviceRiskAssessor(),
		threatIntelService:  NewThreatIntelligenceService(),
	}
}

// EvaluateEnvironmentalRisk evaluates environmental risk for an access request
func (era *EnvironmentRiskAnalyzer) EvaluateEnvironmentalRisk(ctx context.Context, request *RiskAssessmentRequest) (*EnvironmentalRiskResult, error) {
	result := &EnvironmentalRiskResult{}

	// Assess location risk
	locationRisk, err := era.assessLocationRisk(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("location risk assessment failed: %w", err)
	}
	result.LocationRisk = *locationRisk

	// Assess time-based risk
	timeRisk, err := era.assessTimeRisk(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("time risk assessment failed: %w", err)
	}
	result.TimeRisk = *timeRisk

	// Assess network risk
	networkRisk, err := era.assessNetworkRisk(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("network risk assessment failed: %w", err)
	}
	result.NetworkRisk = *networkRisk

	// Assess device risk
	deviceRisk, err := era.assessDeviceRisk(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("device risk assessment failed: %w", err)
	}
	result.DeviceRisk = *deviceRisk

	// Assess threat environment
	threatRisk, err := era.assessThreatEnvironment(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("threat environment assessment failed: %w", err)
	}
	result.ThreatEnvironment = *threatRisk

	// Calculate overall environmental risk score with dynamic weighting
	locationWeight := 0.25
	timeWeight := 0.15
	networkWeight := 0.25
	deviceWeight := 0.20
	threatWeight := 0.15
	
	// For high threat intelligence, increase threat weight significantly
	if threatRisk.RiskScore > 70.0 {
		threatWeight = 0.55      // 55% weight for high threat scenarios
		locationWeight = 0.15    // 15% weight
		timeWeight = 0.10        // 10% weight
		networkWeight = 0.10     // 10% weight
		deviceWeight = 0.10      // 10% weight
	} else if timeRisk.RiskScore > 40.0 {
		// For high time risk (after hours, unusual times), increase time weight
		timeWeight = 0.35        // 35% weight for time-based risk
		locationWeight = 0.20    // 20% weight
		threatWeight = 0.20      // 20% weight
		networkWeight = 0.15     // 15% weight
		deviceWeight = 0.10      // 10% weight
	}
	
	riskComponents := []float64{
		locationRisk.RiskScore * locationWeight,
		timeRisk.RiskScore * timeWeight,
		networkRisk.RiskScore * networkWeight,
		deviceRisk.RiskScore * deviceWeight,
		threatRisk.RiskScore * threatWeight,
	}

	combinedRisk := 0.0
	for _, score := range riskComponents {
		combinedRisk += score
	}

	// Apply amplification for high-risk combinations
	amplificationFactor := era.calculateEnvironmentalAmplification(locationRisk, timeRisk, networkRisk, deviceRisk, threatRisk)
	result.RiskScore = math.Min(combinedRisk*amplificationFactor, 100.0)

	// Calculate confidence score based on data availability and quality
	result.ConfidenceScore = era.calculateEnvironmentalConfidence(request, locationRisk, timeRisk, networkRisk, deviceRisk, threatRisk)

	return result, nil
}

// assessLocationRisk assesses location-based risks
func (era *EnvironmentRiskAnalyzer) assessLocationRisk(ctx context.Context, request *RiskAssessmentRequest) (*LocationRisk, error) {
	locationRisk := &LocationRisk{}

	if request.EnvironmentContext == nil || request.EnvironmentContext.GeoLocation == nil {
		locationRisk.RiskScore = 50.0 // Default medium risk for unknown location
		return locationRisk, nil
	}

	geoLocation := request.EnvironmentContext.GeoLocation
	
	// Assess country risk
	countryRisk := era.geoRiskAssessor.getCountryRisk(geoLocation.Country)
	locationRisk.CountryRisk = countryRisk
	
	// Assess region risk
	regionKey := fmt.Sprintf("%s:%s", geoLocation.Country, geoLocation.Region)
	regionRisk := era.geoRiskAssessor.getRegionRisk(regionKey)
	locationRisk.RegionRisk = regionRisk

	// Check for VPN/Proxy/Tor usage
	ipAddress := ""
	if request.SessionContext != nil {
		ipAddress = request.SessionContext.IPAddress
	}

	if ipAddress != "" {
		locationRisk.VPNDetected = era.geoRiskAssessor.vpnDetector.IsVPN(ipAddress)
		locationRisk.ProxyDetected = era.geoRiskAssessor.proxyDetector.IsProxy(ipAddress)
		locationRisk.TorDetected = era.geoRiskAssessor.torDetector.IsTor(ipAddress)
	}

	// Check if location is typical for user
	if request.HistoricalData != nil && request.HistoricalData.AccessPatterns != nil {
		locationRisk.IsTypicalLocation = era.isTypicalLocation(geoLocation, request.HistoricalData.AccessPatterns.TypicalLocations)
		if !locationRisk.IsTypicalLocation {
			locationRisk.DistanceFromTypical = era.calculateLocationDistance(geoLocation, request.HistoricalData.AccessPatterns.TypicalLocations)
		}
	} else {
		locationRisk.IsTypicalLocation = false
		locationRisk.DistanceFromTypical = 1000.0 // Assume far from typical if no data
	}

	// Calculate location risk score
	locationRisk.RiskScore = era.calculateLocationRiskScore(locationRisk)

	return locationRisk, nil
}

// assessTimeRisk assesses time-based risks
func (era *EnvironmentRiskAnalyzer) assessTimeRisk(ctx context.Context, request *RiskAssessmentRequest) (*TimeRisk, error) {
	timeRisk := &TimeRisk{}

	if request.EnvironmentContext == nil {
		timeRisk.RiskScore = 25.0 // Default low-medium risk
		return timeRisk, nil
	}

	accessTime := request.EnvironmentContext.AccessTime
	timezone := request.EnvironmentContext.Timezone

	// Check if access is during business hours - use provided context value
	timeRisk.IsBusinessHours = request.EnvironmentContext.BusinessHours

	// Check if time is typical for user
	if request.HistoricalData != nil && request.HistoricalData.AccessPatterns != nil {
		timeRisk.IsTypicalTime = era.isTypicalTime(accessTime, request.HistoricalData.AccessPatterns.TypicalHours)
		if !timeRisk.IsTypicalTime {
			timeRisk.HourDeviation = era.calculateHourDeviation(accessTime.Hour(), request.HistoricalData.AccessPatterns.TypicalHours)
			timeRisk.DayDeviation = era.calculateDayDeviation(accessTime.Weekday(), request.HistoricalData.AccessPatterns.TypicalDays)
		}
	} else {
		timeRisk.IsTypicalTime = timeRisk.IsBusinessHours // Default to business hours if no historical data
	}

	// Assess timezone risk
	timeRisk.TimezoneRisk = era.assessTimezoneRisk(timezone, request.EnvironmentContext.GeoLocation)

	// Calculate time risk score with access time context
	timeRisk.RiskScore = era.calculateTimeRiskScore(timeRisk, accessTime)

	return timeRisk, nil
}

// assessNetworkRisk assesses network-based risks
func (era *EnvironmentRiskAnalyzer) assessNetworkRisk(ctx context.Context, request *RiskAssessmentRequest) (*NetworkRisk, error) {
	networkRisk := &NetworkRisk{}

	if request.SessionContext == nil || request.SessionContext.IPAddress == "" {
		networkRisk.RiskScore = 40.0 // Medium risk for unknown network
		return networkRisk, nil
	}

	ipAddress := request.SessionContext.IPAddress

	// Determine network type
	networkRisk.NetworkType = era.networkRiskAssessor.determineNetworkType(ipAddress)

	// Check if network is known
	networkInfo, isKnown := era.networkRiskAssessor.getNetworkInfo(ipAddress)
	networkRisk.IsKnownNetwork = isKnown
	if isKnown {
		networkRisk.SecurityLevel = networkInfo.SecurityLevel
	} else {
		networkRisk.SecurityLevel = NetworkSecurityLevelLow // Default for unknown networks
	}

	// Check for bandwidth and latency anomalies
	networkRisk.BandwidthAnomaly = era.networkRiskAssessor.bandwidthAnalyzer.detectAnomaly(ipAddress)
	networkRisk.LatencyAnomaly = era.networkRiskAssessor.latencyAnalyzer.detectAnomaly(ipAddress)

	// Calculate network risk score
	networkRisk.RiskScore = era.calculateNetworkRiskScore(networkRisk)

	return networkRisk, nil
}

// assessDeviceRisk assesses device-based risks
func (era *EnvironmentRiskAnalyzer) assessDeviceRisk(ctx context.Context, request *RiskAssessmentRequest) (*DeviceRisk, error) {
	deviceRisk := &DeviceRisk{}

	if request.SessionContext == nil {
		deviceRisk.RiskScore = 35.0 // Default medium-low risk
		return deviceRisk, nil
	}

	deviceID := request.SessionContext.DeviceID
	deviceType := request.SessionContext.DeviceType
	userAgent := request.SessionContext.UserAgent

	// Check if device is known
	if deviceID != "" {
		deviceInfo, isKnown := era.deviceRiskAssessor.getDeviceInfo(deviceID)
		deviceRisk.IsKnownDevice = isKnown
		if isKnown {
			deviceRisk.DeviceType = deviceInfo.DeviceType
			deviceRisk.ComplianceStatus = deviceInfo.ComplianceStatus
			deviceRisk.LastScan = &deviceInfo.LastSeen
		}
	} else {
		deviceRisk.IsKnownDevice = false
	}

	deviceRisk.DeviceType = deviceType

	// Analyze User Agent for OS and browser risk
	if userAgent != "" {
		osRisk, browserRisk := era.deviceRiskAssessor.analyzeUserAgent(userAgent)
		deviceRisk.OSRisk = osRisk
		deviceRisk.BrowserRisk = browserRisk
	}

	// Set default compliance status if not known
	if deviceRisk.ComplianceStatus == "" {
		deviceRisk.ComplianceStatus = DeviceComplianceStatusUnknown
	}

	// Calculate device risk score
	deviceRisk.RiskScore = era.calculateDeviceRiskScore(deviceRisk)

	return deviceRisk, nil
}

// assessThreatEnvironment assesses threat intelligence and environmental threats
func (era *EnvironmentRiskAnalyzer) assessThreatEnvironment(ctx context.Context, request *RiskAssessmentRequest) (*ThreatEnvironmentRisk, error) {
	threatRisk := &ThreatEnvironmentRisk{}

	if request.SessionContext == nil || request.SessionContext.IPAddress == "" {
		threatRisk.RiskScore = 20.0 // Default low risk
		return threatRisk, nil
	}

	ipAddress := request.SessionContext.IPAddress

	// Use threat intelligence from request context if available, otherwise query service
	if request.EnvironmentContext != nil && request.EnvironmentContext.ThreatIntelligence != nil {
		threatIntel := request.EnvironmentContext.ThreatIntelligence
		
		// Use provided threat intelligence data
		threatRisk.ReputationScore = threatIntel.IPReputationScore * 100.0 // Convert from 0-1 scale to 0-100 scale
		threatRisk.ThreatCategories = threatIntel.ThreatCategories
		threatRisk.ThreatLevel = threatIntel.ThreatLevel
		
		// Count recent threats as active threats
		threatRisk.ActiveThreats = len(threatIntel.RecentThreats)
		
		// Recent incidents based on recent threats
		threatRisk.RecentIncidents = len(threatIntel.RecentThreats)
	} else {
		// Fallback to querying threat intelligence service
		reputationScore := era.threatIntelService.getIPReputation(ipAddress)
		threatRisk.ReputationScore = reputationScore

		threatCategories := era.threatIntelService.getThreatCategories(ipAddress)
		threatRisk.ThreatCategories = threatCategories

		activeThreats := era.threatIntelService.getActiveThreats(ipAddress)
		threatRisk.ActiveThreats = len(activeThreats)

		recentIncidents := era.threatIntelService.getRecentIncidents(ipAddress, 24*time.Hour)
		threatRisk.RecentIncidents = len(recentIncidents)

		// Determine threat level
		threatRisk.ThreatLevel = era.determineThreatLevel(reputationScore, len(threatCategories), threatRisk.ActiveThreats, threatRisk.RecentIncidents)
	}

	// Calculate threat environment risk score
	threatRisk.RiskScore = era.calculateThreatRiskScore(threatRisk)

	return threatRisk, nil
}

// Risk calculation methods

func (era *EnvironmentRiskAnalyzer) calculateLocationRiskScore(locationRisk *LocationRisk) float64 {
	score := 0.0

	// Country risk contribution (0-25 points)
	score += locationRisk.CountryRisk * 25.0

	// Region risk contribution (0-15 points)  
	score += locationRisk.RegionRisk * 15.0

	// Unusual location penalty (0-30 points)
	if !locationRisk.IsTypicalLocation {
		distanceRisk := math.Min(locationRisk.DistanceFromTypical/5000.0, 1.0) // Normalize by 5000km
		score += distanceRisk * 30.0
	}

	// VPN/Proxy/Tor penalties
	if locationRisk.VPNDetected {
		score += 15.0
	}
	if locationRisk.ProxyDetected {
		score += 20.0
	}
	if locationRisk.TorDetected {
		score += 25.0
	}

	return math.Min(score, 100.0)
}

func (era *EnvironmentRiskAnalyzer) calculateTimeRiskScore(timeRisk *TimeRisk, accessTime time.Time) float64 {
	score := 0.0

	// Business hours factor
	if !timeRisk.IsBusinessHours {
		score += 20.0 // Base penalty for non-business hours
	}

	// Typical time factor
	if !timeRisk.IsTypicalTime {
		score += timeRisk.HourDeviation * 25.0    // Increased from 20 to 25 points
		score += timeRisk.DayDeviation * 15.0     // Increased from 10 to 15 points
	}

	// Extreme hour penalty for very late/early access (midnight to 6 AM)
	hour := accessTime.Hour()
	if hour >= 0 && hour <= 6 {
		extremeRisk := 0.0
		switch hour {
		case 0, 1, 2, 3:
			extremeRisk = 36.0 // Very extreme hours (midnight to 3 AM)
		case 4, 5, 6:
			extremeRisk = 12.0 // Somewhat extreme hours (4 AM to 6 AM)
		}
		score += extremeRisk
	}

	// Timezone risk
	score += timeRisk.TimezoneRisk * 15.0        // 0-15 points

	return math.Min(score, 100.0)
}

func (era *EnvironmentRiskAnalyzer) calculateNetworkRiskScore(networkRisk *NetworkRisk) float64 {
	score := 0.0

	// Unknown network penalty
	if !networkRisk.IsKnownNetwork {
		score += 25.0
	}

	// Security level factor
	switch networkRisk.SecurityLevel {
	case NetworkSecurityLevelLow:
		score += 30.0
	case NetworkSecurityLevelMedium:
		score += 15.0
	case NetworkSecurityLevelHigh:
		score += 5.0
	case NetworkSecurityLevelCritical:
		score += 0.0
	}

	// Network type factor
	switch networkRisk.NetworkType {
	case "public":
		score += 20.0
	case "mobile":
		score += 10.0
	}

	// Anomaly penalties
	if networkRisk.BandwidthAnomaly {
		score += 10.0
	}
	if networkRisk.LatencyAnomaly {
		score += 10.0
	}

	return math.Min(score, 100.0)
}

func (era *EnvironmentRiskAnalyzer) calculateDeviceRiskScore(deviceRisk *DeviceRisk) float64 {
	score := 0.0

	// Unknown device penalty
	if !deviceRisk.IsKnownDevice {
		score += 20.0
	}

	// Compliance status factor
	switch deviceRisk.ComplianceStatus {
	case DeviceComplianceStatusNonCompliant:
		score += 40.0
	case DeviceComplianceStatusUnknown:
		score += 25.0
	case DeviceComplianceStatusCompliant:
		score += 0.0
	}

	// OS and browser risk
	score += deviceRisk.OSRisk * 20.0      // 0-20 points
	score += deviceRisk.BrowserRisk * 15.0 // 0-15 points

	return math.Min(score, 100.0)
}

func (era *EnvironmentRiskAnalyzer) calculateThreatRiskScore(threatRisk *ThreatEnvironmentRisk) float64 {
	score := 0.0

	// Reputation score factor (direct - higher reputation score = higher risk)
	reputationRisk := threatRisk.ReputationScore / 100.0
	score += reputationRisk * 40.0

	// Threat categories penalty
	score += float64(len(threatRisk.ThreatCategories)) * 10.0

	// Active threats penalty
	score += float64(threatRisk.ActiveThreats) * 15.0

	// Recent incidents penalty
	score += float64(threatRisk.RecentIncidents) * 5.0

	return math.Min(score, 100.0)
}

func (era *EnvironmentRiskAnalyzer) calculateEnvironmentalAmplification(locationRisk *LocationRisk, timeRisk *TimeRisk, networkRisk *NetworkRisk, deviceRisk *DeviceRisk, threatRisk *ThreatEnvironmentRisk) float64 {
	amplification := 1.0
	highRiskCount := 0

	risks := []float64{
		locationRisk.RiskScore,
		timeRisk.RiskScore,
		networkRisk.RiskScore,
		deviceRisk.RiskScore,
		threatRisk.RiskScore,
	}

	for _, risk := range risks {
		if risk > 60.0 {
			highRiskCount++
		}
	}

	// Special amplification for high threat scenarios
	if threatRisk.RiskScore > 70.0 {
		amplification = math.Max(amplification, 1.25) // 25% amplification for high threat
	}
	
	// Amplify risk for high-risk combinations
	switch highRiskCount {
	case 2:
		amplification = math.Max(amplification, 1.10)
	case 3:
		amplification = math.Max(amplification, 1.20)
	case 4, 5:
		amplification = math.Max(amplification, 1.35)
	}

	return amplification
}

func (era *EnvironmentRiskAnalyzer) calculateEnvironmentalConfidence(request *RiskAssessmentRequest, locationRisk *LocationRisk, timeRisk *TimeRisk, networkRisk *NetworkRisk, deviceRisk *DeviceRisk, threatRisk *ThreatEnvironmentRisk) float64 {
	confidence := 0.0
	factors := 0

	// Location data confidence
	if request.EnvironmentContext != nil && request.EnvironmentContext.GeoLocation != nil {
		confidence += 20.0
	}
	factors++

	// Session data confidence
	if request.SessionContext != nil && request.SessionContext.IPAddress != "" {
		confidence += 20.0
	}
	factors++

	// Historical data confidence
	if request.HistoricalData != nil {
		confidence += 20.0
	}
	factors++

	// Network information confidence
	if networkRisk.IsKnownNetwork {
		confidence += 20.0
	}
	factors++

	// Device information confidence
	if deviceRisk.IsKnownDevice {
		confidence += 20.0
	}
	factors++

	if factors > 0 {
		return confidence / float64(factors) * float64(factors) / 5.0 * 100.0
	}

	return 50.0 // Default moderate confidence
}

// Helper methods

func (era *EnvironmentRiskAnalyzer) isTypicalLocation(geoLocation *GeoLocation, typicalLocations []string) bool {
	currentLocation := fmt.Sprintf("%s:%s", geoLocation.Country, geoLocation.City)
	for _, location := range typicalLocations {
		if location == currentLocation {
			return true
		}
	}
	return false
}

func (era *EnvironmentRiskAnalyzer) calculateLocationDistance(geoLocation *GeoLocation, typicalLocations []string) float64 {
	// Simplified distance calculation - in practice would use haversine formula
	if len(typicalLocations) == 0 {
		return 1000.0
	}
	
	// For simplicity, return a moderate distance
	// Real implementation would calculate geographic distance
	return 500.0
}

func (era *EnvironmentRiskAnalyzer) isTypicalTime(accessTime time.Time, typicalHours []int) bool {
	currentHour := accessTime.Hour()
	for _, hour := range typicalHours {
		if hour == currentHour {
			return true
		}
	}
	return false
}

func (era *EnvironmentRiskAnalyzer) calculateHourDeviation(currentHour int, typicalHours []int) float64 {
	if len(typicalHours) == 0 {
		return 1.0
	}

	minDistance := 24
	for _, hour := range typicalHours {
		distance := int(math.Abs(float64(currentHour - hour)))
		if distance > 12 {
			distance = 24 - distance
		}
		if distance < minDistance {
			minDistance = distance
		}
	}

	return float64(minDistance) / 12.0
}

func (era *EnvironmentRiskAnalyzer) calculateDayDeviation(currentDay time.Weekday, typicalDays []time.Weekday) float64 {
	for _, day := range typicalDays {
		if currentDay == day {
			return 0.0
		}
	}
	return 0.5 // Moderate deviation for different day
}

func (era *EnvironmentRiskAnalyzer) assessTimezoneRisk(timezone string, geoLocation *GeoLocation) float64 {
	// Simplified timezone risk assessment
	// Real implementation would validate timezone against location
	if timezone == "" {
		return 0.3 // Some risk for missing timezone
	}
	return 0.1 // Low risk for present timezone
}

func (era *EnvironmentRiskAnalyzer) determineThreatLevel(reputationScore float64, threatCategoryCount, activeThreats, recentIncidents int) ThreatLevel {
	if reputationScore < 20.0 || activeThreats > 5 || recentIncidents > 10 {
		return ThreatLevelCritical
	} else if reputationScore < 40.0 || activeThreats > 2 || recentIncidents > 5 {
		return ThreatLevelHigh
	} else if reputationScore < 70.0 || activeThreats > 0 || recentIncidents > 2 {
		return ThreatLevelMedium
	}
	return ThreatLevelLow
}

// Factory functions for supporting components

func NewGeoRiskAssessor() *GeoRiskAssessor {
	return &GeoRiskAssessor{
		countryRiskScores: map[string]float64{
			// Sample country risk scores (0.0 = lowest risk, 1.0 = highest risk)
			"United States": 0.1, "US": 0.1, "CA": 0.1, "Canada": 0.1, 
			"GB": 0.1, "United Kingdom": 0.1, "DE": 0.1, "Germany": 0.1, 
			"FR": 0.1, "France": 0.1, "AU": 0.1, "Australia": 0.1,
			"CN": 0.6, "China": 0.6, "RU": 0.7, "Russia": 0.7, 
			"KP": 0.9, "North Korea": 0.9, "IR": 0.8, "Iran": 0.8, 
			"SY": 0.9, "Syria": 0.9, "AF": 0.8, "Afghanistan": 0.8,
		},
		regionRiskScores: make(map[string]float64),
		vpnDetector:      &VPNDetector{},
		proxyDetector:    &ProxyDetector{},
		torDetector:      &TorDetector{},
	}
}

func (gra *GeoRiskAssessor) getCountryRisk(country string) float64 {
	if risk, exists := gra.countryRiskScores[country]; exists {
		return risk
	}
	return 0.3 // Default moderate risk for unknown countries
}

func (gra *GeoRiskAssessor) getRegionRisk(regionKey string) float64 {
	if risk, exists := gra.regionRiskScores[regionKey]; exists {
		return risk
	}
	return 0.2 // Default low-moderate risk for unknown regions
}

func NewTimeRiskAssessor() *TimeRiskAssessor {
	return &TimeRiskAssessor{
		businessHours: BusinessHoursConfig{
			Monday:    TimeRange{Start: parseTime("09:00"), End: parseTime("17:00")},
			Tuesday:   TimeRange{Start: parseTime("09:00"), End: parseTime("17:00")},
			Wednesday: TimeRange{Start: parseTime("09:00"), End: parseTime("17:00")},
			Thursday:  TimeRange{Start: parseTime("09:00"), End: parseTime("17:00")},
			Friday:    TimeRange{Start: parseTime("09:00"), End: parseTime("17:00")},
			Timezone:  "UTC",
		},
		timezoneValidator: &TimezoneValidator{},
		holidayCalendar:   &HolidayCalendar{},
	}
}

func NewNetworkRiskAssessor() *NetworkRiskAssessor {
	return &NetworkRiskAssessor{
		knownNetworks:     make(map[string]NetworkInfo),
		securityScanner:   &NetworkSecurityScanner{},
		bandwidthAnalyzer: &BandwidthAnalyzer{},
		latencyAnalyzer:   &LatencyAnalyzer{},
	}
}

func (nra *NetworkRiskAssessor) determineNetworkType(ipAddress string) string {
	// Simplified network type determination
	if strings.HasPrefix(ipAddress, "10.") || strings.HasPrefix(ipAddress, "192.168.") || strings.HasPrefix(ipAddress, "172.") {
		return "private"
	}
	return "public"
}

func (nra *NetworkRiskAssessor) getNetworkInfo(ipAddress string) (NetworkInfo, bool) {
	// Simplified network info lookup
	if info, exists := nra.knownNetworks[ipAddress]; exists {
		return info, true
	}
	return NetworkInfo{}, false
}

func NewDeviceRiskAssessor() *DeviceRiskAssessor {
	return &DeviceRiskAssessor{
		knownDevices:        make(map[string]DeviceInfo),
		complianceChecker:   &DeviceComplianceChecker{},
		fingerprintAnalyzer: &DeviceFingerprintAnalyzer{},
	}
}

func (dra *DeviceRiskAssessor) getDeviceInfo(deviceID string) (DeviceInfo, bool) {
	if info, exists := dra.knownDevices[deviceID]; exists {
		return info, true
	}
	return DeviceInfo{}, false
}

func (dra *DeviceRiskAssessor) analyzeUserAgent(userAgent string) (float64, float64) {
	// Simplified user agent analysis
	osRisk := 0.2   // Default low OS risk
	browserRisk := 0.2 // Default low browser risk

	userAgent = strings.ToLower(userAgent)
	
	// Check for outdated OS indicators
	if strings.Contains(userAgent, "windows xp") || strings.Contains(userAgent, "windows vista") {
		osRisk = 0.9
	} else if strings.Contains(userAgent, "windows 7") {
		osRisk = 0.6
	}
	
	// Check for outdated browser indicators  
	if strings.Contains(userAgent, "msie") || strings.Contains(userAgent, "internet explorer") {
		browserRisk = 0.8
	}
	
	return osRisk, browserRisk
}

func NewThreatIntelligenceService() *ThreatIntelligenceService {
	return &ThreatIntelligenceService{
		ipReputationDB:    &IPReputationDatabase{},
		threatFeedService: &ThreatFeedService{},
		malwareDetector:   &MalwareDetector{},
	}
}

func (tis *ThreatIntelligenceService) getIPReputation(ipAddress string) float64 {
	// Simplified IP reputation lookup
	// Real implementation would query threat intelligence databases
	return 85.0 // Default good reputation
}

func (tis *ThreatIntelligenceService) getThreatCategories(ipAddress string) []string {
	// Simplified threat category lookup
	return []string{} // Default no threats
}

func (tis *ThreatIntelligenceService) getActiveThreats(ipAddress string) []ThreatIndicator {
	return []ThreatIndicator{} // Default no active threats
}

func (tis *ThreatIntelligenceService) getRecentIncidents(ipAddress string, window time.Duration) []ThreatIndicator {
	return []ThreatIndicator{} // Default no recent incidents
}

// Helper function to parse time strings
func parseTime(timeStr string) time.Time {
	t, _ := time.Parse("15:04", timeStr)
	return t
}

// Supporting types (simplified implementations)
type VPNDetector struct{}
func (vd *VPNDetector) IsVPN(ipAddress string) bool { return false }

type ProxyDetector struct{}
func (pd *ProxyDetector) IsProxy(ipAddress string) bool { return false }

type TorDetector struct{}
func (td *TorDetector) IsTor(ipAddress string) bool { return false }

type TimezoneValidator struct{}
type HolidayCalendar struct{}
type NetworkSecurityScanner struct{}
type BandwidthAnalyzer struct{}
func (ba *BandwidthAnalyzer) detectAnomaly(ipAddress string) bool { return false }

type LatencyAnalyzer struct{}
func (la *LatencyAnalyzer) detectAnomaly(ipAddress string) bool { return false }

type DeviceComplianceChecker struct{}
type DeviceFingerprintAnalyzer struct{}
type IPReputationDatabase struct{}
type ThreatFeedService struct{}
type MalwareDetector struct{}