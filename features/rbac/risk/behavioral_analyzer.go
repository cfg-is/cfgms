package risk

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// BehavioralRiskAnalyzer analyzes user behavioral patterns for risk assessment
type BehavioralRiskAnalyzer struct {
	userProfiles     map[string]*UserBehaviorProfile
	patternDetector  *PatternDetector
	anomalyDetector  *AnomalyDetector
	learningEngine   *BehavioralLearningEngine
	confidenceEngine *ConfidenceEngine
	mutex            sync.RWMutex
}

// UserBehaviorProfile represents a user's behavioral baseline
type UserBehaviorProfile struct {
	UserID              string                    `json:"user_id"`
	TenantID            string                    `json:"tenant_id"`
	BaselineEstablished bool                      `json:"baseline_established"`
	ProfileCreated      time.Time                 `json:"profile_created"`
	LastUpdated         time.Time                 `json:"last_updated"`
	SampleCount         int                       `json:"sample_count"`
	TypicalAccessHours  []int                     `json:"typical_access_hours"`
	TypicalAccessDays   []time.Weekday            `json:"typical_access_days"`
	TypicalLocations    map[string]float64        `json:"typical_locations"`
	TypicalResources    map[string]float64        `json:"typical_resources"`
	AverageSessionTime  time.Duration             `json:"average_session_time"`
	AccessVelocity      AccessVelocityProfile     `json:"access_velocity"`
	DevicePatterns      map[string]DevicePattern  `json:"device_patterns"`
	NetworkPatterns     map[string]NetworkPattern `json:"network_patterns"`
	BehaviorMeans       map[string]float64        `json:"behavior_means"`
	BehaviorStdDevs     map[string]float64        `json:"behavior_std_devs"`
	AnomalyHistory      []AnomalyRecord           `json:"anomaly_history"`
}

// AccessVelocityProfile tracks access velocity patterns
type AccessVelocityProfile struct {
	RequestsPerHour           float64        `json:"requests_per_hour"`
	RequestsPerDay            float64        `json:"requests_per_day"`
	PeakHourlyRate            float64        `json:"peak_hourly_rate"`
	AverageGapBetweenRequests time.Duration  `json:"average_gap_between_requests"`
	BurstPatterns             []BurstPattern `json:"burst_patterns"`
}

// BurstPattern represents patterns of burst activity
type BurstPattern struct {
	StartHour   int            `json:"start_hour"`
	Duration    time.Duration  `json:"duration"`
	Intensity   float64        `json:"intensity"`
	Frequency   float64        `json:"frequency"`
	TypicalDays []time.Weekday `json:"typical_days"`
}

// DevicePattern tracks device usage patterns
type DevicePattern struct {
	DeviceID       string    `json:"device_id"`
	DeviceType     string    `json:"device_type"`
	UsageFrequency float64   `json:"usage_frequency"`
	TypicalHours   []int     `json:"typical_hours"`
	LastUsed       time.Time `json:"last_used"`
	TrustScore     float64   `json:"trust_score"`
}

// NetworkPattern tracks network usage patterns
type NetworkPattern struct {
	NetworkID       string               `json:"network_id"`
	UsageFrequency  float64              `json:"usage_frequency"`
	LocationContext string               `json:"location_context"`
	SecurityLevel   NetworkSecurityLevel `json:"security_level"`
	LastUsed        time.Time            `json:"last_used"`
	TrustScore      float64              `json:"trust_score"`
}

// PatternDetector detects behavioral patterns
type PatternDetector struct {
}

// AnomalyDetector detects behavioral anomalies
type AnomalyDetector struct {
}

// BehavioralLearningEngine handles continuous learning
type BehavioralLearningEngine struct {
}

// ConfidenceEngine calculates confidence scores
type ConfidenceEngine struct {
	dataQualityAssessor *DataQualityAssessor
	sampleSizeAnalyzer  *SampleSizeAnalyzer
	temporalAnalyzer    *TemporalConfidenceAnalyzer
}

// NewBehavioralRiskAnalyzer creates a new behavioral risk analyzer
func NewBehavioralRiskAnalyzer() *BehavioralRiskAnalyzer {
	return &BehavioralRiskAnalyzer{
		userProfiles:     make(map[string]*UserBehaviorProfile),
		patternDetector:  NewPatternDetector(),
		anomalyDetector:  NewAnomalyDetector(),
		learningEngine:   NewBehavioralLearningEngine(),
		confidenceEngine: NewConfidenceEngine(),
		mutex:            sync.RWMutex{},
	}
}

// EvaluateBehavioralRisk evaluates behavioral risk for an access request
func (bra *BehavioralRiskAnalyzer) EvaluateBehavioralRisk(ctx context.Context, request *RiskAssessmentRequest) (*BehavioralRiskResult, error) {
	bra.mutex.Lock()
	defer bra.mutex.Unlock()

	startTime := time.Now()
	userID := request.UserContext.UserID
	tenantID := request.AccessRequest.TenantId

	// Get or create user behavior profile
	profile, err := bra.getUserBehaviorProfile(userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user behavior profile: %w", err)
	}

	// If historical data is available, use it to establish baseline
	if request.HistoricalData != nil && !profile.BaselineEstablished {
		bra.establishBaselineFromHistoricalData(profile, request.HistoricalData)
	}

	result := &BehavioralRiskResult{
		LastUpdate:         startTime,
		PatternAnomalies:   make([]PatternAnomaly, 0),
		BehaviorDeviations: make([]BehaviorDeviation, 0),
		LearningStatus:     profile.getLearningStatus(),
		BaselineAge:        time.Since(profile.ProfileCreated),
		SamplesCount:       profile.SampleCount,
	}

	// For new users without baseline, perform contextual risk analysis
	if !profile.BaselineEstablished {
		result.ConfidenceScore = 25.0 // Low confidence without baseline
		result.LearningStatus = LearningStatusInitializing

		// Perform contextual behavioral risk analysis
		contextualRisk, patterns := bra.performContextualAnalysis(ctx, request)
		result.RiskScore = contextualRisk
		result.PatternAnomalies = patterns

		// Generate behavioral deviations for new user analysis
		deviations := bra.generateNewUserDeviations(ctx, request)
		result.BehaviorDeviations = deviations

		return result, nil
	}

	// Analyze temporal patterns
	temporalRisk, err := bra.analyzeTemporalPatterns(ctx, request, profile)
	if err != nil {
		return nil, fmt.Errorf("temporal pattern analysis failed: %w", err)
	}

	// Analyze spatial patterns (location/network)
	spatialRisk, err := bra.analyzeSpatialPatterns(ctx, request, profile)
	if err != nil {
		return nil, fmt.Errorf("spatial pattern analysis failed: %w", err)
	}

	// Analyze access patterns (resources, actions)
	accessRisk, err := bra.analyzeAccessPatterns(ctx, request, profile)
	if err != nil {
		return nil, fmt.Errorf("access pattern analysis failed: %w", err)
	}

	// Analyze access velocity
	velocityRisk, err := bra.analyzeAccessVelocity(ctx, request, profile)
	if err != nil {
		return nil, fmt.Errorf("velocity analysis failed: %w", err)
	}

	// Analyze device patterns
	deviceRisk, err := bra.analyzeDevicePatterns(ctx, request, profile)
	if err != nil {
		return nil, fmt.Errorf("device pattern analysis failed: %w", err)
	}

	// Process historical anomalies if present (regardless of baseline status)
	anomalyRisk := 0.0
	if request.HistoricalData != nil && len(request.HistoricalData.AnomalyHistory) > 0 {
		for _, anomaly := range request.HistoricalData.AnomalyHistory {
			// Add risk based on historical anomaly severity
			anomalyRisk += anomaly.Severity * 15.0 // Up to 15 points per anomaly

			// Create pattern anomaly from historical data
			result.PatternAnomalies = append(result.PatternAnomalies, PatternAnomaly{
				AnomalyType: anomaly.AnomalyType,
				Severity:    anomaly.Severity,
				Description: fmt.Sprintf("Historical anomaly: %s", anomaly.Description),
				Confidence:  0.8, // Good confidence for historical data
			})

			// Create behavior deviation from historical anomaly
			result.BehaviorDeviations = append(result.BehaviorDeviations, BehaviorDeviation{
				DeviationType:    "historical_anomaly",
				Metric:           anomaly.AnomalyType,
				ExpectedValue:    0.0, // No anomaly expected
				ActualValue:      anomaly.Severity,
				DeviationPercent: anomaly.Severity * 100.0,
				Significance:     anomaly.Severity,
			})
		}
	}

	// Combine risk scores using weighted approach
	riskComponents := map[string]float64{
		"temporal": temporalRisk.RiskScore * 0.20, // 20% weight
		"spatial":  spatialRisk.RiskScore * 0.25,  // 25% weight
		"access":   accessRisk.RiskScore * 0.25,   // 25% weight
		"velocity": velocityRisk.RiskScore * 0.15, // 15% weight
		"device":   deviceRisk.RiskScore * 0.15,   // 15% weight
	}

	// Add anomaly risk to the combined score (not as a weighted component)
	combinedAnomalyRisk := anomalyRisk

	combinedRisk := 0.0
	for _, score := range riskComponents {
		combinedRisk += score
	}

	// Add anomaly risk to the base combined risk
	combinedRisk += combinedAnomalyRisk

	// Apply amplification factors for high-risk combinations
	amplificationFactor := bra.calculateAmplificationFactor(riskComponents)

	// Additional amplification for multiple anomalies (applies to historical anomaly cases)
	totalAnomalies := len(temporalRisk.Anomalies) + len(spatialRisk.Anomalies) +
		len(accessRisk.Anomalies) + len(velocityRisk.Anomalies) + len(deviceRisk.Anomalies)
	if totalAnomalies > 3 {
		amplificationFactor = math.Max(amplificationFactor, 1.50) // 50% minimum amplification for multiple anomalies
	}

	result.RiskScore = math.Min(combinedRisk*amplificationFactor, 100.0)

	// Calculate confidence score
	result.ConfidenceScore = bra.confidenceEngine.calculateBehavioralConfidence(
		profile, request, []RiskComponent{
			*temporalRisk, *spatialRisk, *accessRisk, *velocityRisk, *deviceRisk,
		})

	// Aggregate anomalies and deviations
	result.PatternAnomalies = append(result.PatternAnomalies, temporalRisk.Anomalies...)
	result.PatternAnomalies = append(result.PatternAnomalies, spatialRisk.Anomalies...)
	result.PatternAnomalies = append(result.PatternAnomalies, accessRisk.Anomalies...)
	result.PatternAnomalies = append(result.PatternAnomalies, velocityRisk.Anomalies...)
	result.PatternAnomalies = append(result.PatternAnomalies, deviceRisk.Anomalies...)

	result.BehaviorDeviations = append(result.BehaviorDeviations, temporalRisk.Deviations...)
	result.BehaviorDeviations = append(result.BehaviorDeviations, spatialRisk.Deviations...)
	result.BehaviorDeviations = append(result.BehaviorDeviations, accessRisk.Deviations...)
	result.BehaviorDeviations = append(result.BehaviorDeviations, velocityRisk.Deviations...)
	result.BehaviorDeviations = append(result.BehaviorDeviations, deviceRisk.Deviations...)

	return result, nil
}

// getUserBehaviorProfile gets or creates a user behavior profile
func (bra *BehavioralRiskAnalyzer) getUserBehaviorProfile(userID, tenantID string) (*UserBehaviorProfile, error) {
	profileKey := fmt.Sprintf("%s:%s", tenantID, userID)

	profile, exists := bra.userProfiles[profileKey]
	if !exists {
		profile = &UserBehaviorProfile{
			UserID:              userID,
			TenantID:            tenantID,
			BaselineEstablished: false,
			ProfileCreated:      time.Now(),
			LastUpdated:         time.Now(),
			SampleCount:         0,
			TypicalAccessHours:  make([]int, 0),
			TypicalAccessDays:   make([]time.Weekday, 0),
			TypicalLocations:    make(map[string]float64),
			TypicalResources:    make(map[string]float64),
			DevicePatterns:      make(map[string]DevicePattern),
			NetworkPatterns:     make(map[string]NetworkPattern),
			BehaviorMeans:       make(map[string]float64),
			BehaviorStdDevs:     make(map[string]float64),
			AnomalyHistory:      make([]AnomalyRecord, 0),
		}
		bra.userProfiles[profileKey] = profile
	}

	return profile, nil
}

// analyzeTemporalPatterns analyzes time-based behavioral patterns
func (bra *BehavioralRiskAnalyzer) analyzeTemporalPatterns(ctx context.Context, request *RiskAssessmentRequest, profile *UserBehaviorProfile) (*RiskComponent, error) {
	accessTime := request.EnvironmentContext.AccessTime
	risk := &RiskComponent{
		ComponentType: "temporal",
		Anomalies:     make([]PatternAnomaly, 0),
		Deviations:    make([]BehaviorDeviation, 0),
	}

	// Analyze hour of day pattern
	currentHour := accessTime.Hour()
	isTypicalHour := bra.isTypicalHour(currentHour, profile.TypicalAccessHours)
	if !isTypicalHour {
		hourDeviation := bra.calculateHourDeviation(currentHour, profile.TypicalAccessHours)
		risk.RiskScore += hourDeviation * 15.0 // Up to 15 points for hour deviation

		risk.Anomalies = append(risk.Anomalies, PatternAnomaly{
			AnomalyType:        "unusual_hour",
			Severity:           hourDeviation,
			Description:        fmt.Sprintf("Access at unusual hour: %d", currentHour),
			ExpectedPattern:    profile.TypicalAccessHours,
			ActualPattern:      currentHour,
			DeviationMagnitude: hourDeviation,
			Confidence:         0.8,
		})

		// Generate behavior deviation for unusual hour
		risk.Deviations = append(risk.Deviations, BehaviorDeviation{
			DeviationType:    "unusual_hour",
			Metric:           "access_hour",
			ExpectedValue:    float64(bra.getMostCommonHour(profile.TypicalAccessHours)),
			ActualValue:      float64(currentHour),
			DeviationPercent: hourDeviation * 100,
			Significance:     hourDeviation,
		})
	}

	// Analyze day of week pattern
	currentDay := accessTime.Weekday()
	isTypicalDay := bra.isTypicalDay(currentDay, profile.TypicalAccessDays)
	if !isTypicalDay {
		dayDeviation := bra.calculateDayDeviation(currentDay, profile.TypicalAccessDays)
		risk.RiskScore += dayDeviation * 10.0 // Up to 10 points for day deviation

		risk.Deviations = append(risk.Deviations, BehaviorDeviation{
			DeviationType:    "unusual_day",
			Metric:           "day_of_week",
			ExpectedValue:    float64(bra.getMostCommonDay(profile.TypicalAccessDays)),
			ActualValue:      float64(currentDay),
			DeviationPercent: dayDeviation * 100,
			Significance:     0.7,
		})
	}

	// Ensure risk score doesn't exceed 100
	risk.RiskScore = math.Min(risk.RiskScore, 100.0)

	return risk, nil
}

// analyzeSpatialPatterns analyzes location and network behavioral patterns
func (bra *BehavioralRiskAnalyzer) analyzeSpatialPatterns(ctx context.Context, request *RiskAssessmentRequest, profile *UserBehaviorProfile) (*RiskComponent, error) {
	risk := &RiskComponent{
		ComponentType: "spatial",
		Anomalies:     make([]PatternAnomaly, 0),
		Deviations:    make([]BehaviorDeviation, 0),
	}

	// Analyze location patterns
	if request.EnvironmentContext.GeoLocation != nil {
		locationKey := fmt.Sprintf("%s:%s", request.EnvironmentContext.GeoLocation.Country, request.EnvironmentContext.GeoLocation.City)
		locationFrequency, exists := profile.TypicalLocations[locationKey]

		if !exists || locationFrequency < 0.1 { // Less than 10% of typical access
			risk.RiskScore += 25.0 // High risk for new/unusual locations

			risk.Anomalies = append(risk.Anomalies, PatternAnomaly{
				AnomalyType:        "unusual_location",
				Severity:           0.8,
				Description:        fmt.Sprintf("Access from unusual location: %s", locationKey),
				ExpectedPattern:    bra.getTopLocations(profile.TypicalLocations, 3),
				ActualPattern:      locationKey,
				DeviationMagnitude: 1.0 - locationFrequency,
				Confidence:         0.9,
			})

			// Generate behavior deviation for unusual location
			risk.Deviations = append(risk.Deviations, BehaviorDeviation{
				DeviationType:    "unusual_location",
				Metric:           "access_location",
				ExpectedValue:    bra.getMostCommonLocationFrequency(profile.TypicalLocations),
				ActualValue:      locationFrequency,
				DeviationPercent: (1.0 - locationFrequency) * 100,
				Significance:     0.8,
			})
		}
	}

	// Analyze network patterns
	if request.SessionContext.IPAddress != "" {
		// Get network pattern based on IP address (simplified)
		networkKey := bra.getNetworkKey(request.SessionContext.IPAddress)
		networkPattern, exists := profile.NetworkPatterns[networkKey]

		if !exists || networkPattern.UsageFrequency < 0.1 {
			risk.RiskScore += 20.0 // Medium-high risk for new networks

			risk.Deviations = append(risk.Deviations, BehaviorDeviation{
				DeviationType:    "unusual_network",
				Metric:           "network_usage",
				ExpectedValue:    0.5, // Expected typical usage
				ActualValue:      networkPattern.UsageFrequency,
				DeviationPercent: (0.5 - networkPattern.UsageFrequency) * 100,
				Significance:     0.8,
			})
		}
	}

	risk.RiskScore = math.Min(risk.RiskScore, 100.0)
	return risk, nil
}

// analyzeAccessPatterns analyzes resource access behavioral patterns
func (bra *BehavioralRiskAnalyzer) analyzeAccessPatterns(ctx context.Context, request *RiskAssessmentRequest, profile *UserBehaviorProfile) (*RiskComponent, error) {
	risk := &RiskComponent{
		ComponentType: "access",
		Anomalies:     make([]PatternAnomaly, 0),
		Deviations:    make([]BehaviorDeviation, 0),
	}

	// Analyze resource access patterns
	resourceID := request.AccessRequest.ResourceId
	resourceFrequency, exists := profile.TypicalResources[resourceID]

	if !exists || resourceFrequency < 0.05 { // Less than 5% of typical access
		risk.RiskScore += 30.0 // High risk for unusual resources

		risk.Anomalies = append(risk.Anomalies, PatternAnomaly{
			AnomalyType:        "unusual_resource",
			Severity:           0.7,
			Description:        fmt.Sprintf("Access to unusual resource: %s", resourceID),
			ExpectedPattern:    bra.getTopResources(profile.TypicalResources, 5),
			ActualPattern:      resourceID,
			DeviationMagnitude: 1.0 - resourceFrequency,
			Confidence:         0.85,
		})
	}

	risk.RiskScore = math.Min(risk.RiskScore, 100.0)
	return risk, nil
}

// analyzeAccessVelocity analyzes access velocity patterns
func (bra *BehavioralRiskAnalyzer) analyzeAccessVelocity(ctx context.Context, request *RiskAssessmentRequest, profile *UserBehaviorProfile) (*RiskComponent, error) {
	risk := &RiskComponent{
		ComponentType: "velocity",
		Anomalies:     make([]PatternAnomaly, 0),
		Deviations:    make([]BehaviorDeviation, 0),
	}

	// Analyze historical data if available
	if request.HistoricalData != nil && len(request.HistoricalData.RecentAccess) > 0 {
		recentCount := len(request.HistoricalData.RecentAccess)
		recentTimeSpan := time.Since(request.HistoricalData.RecentAccess[recentCount-1].Timestamp)
		currentRate := float64(recentCount) / recentTimeSpan.Hours()

		// Compare with typical velocity
		if currentRate > profile.AccessVelocity.RequestsPerHour*2.0 { // More than 2x typical rate
			velocityIncrease := (currentRate - profile.AccessVelocity.RequestsPerHour) / profile.AccessVelocity.RequestsPerHour
			risk.RiskScore += velocityIncrease * 20.0 // Up to 20 points for velocity anomalies

			risk.Deviations = append(risk.Deviations, BehaviorDeviation{
				DeviationType:    "high_velocity",
				Metric:           "requests_per_hour",
				ExpectedValue:    profile.AccessVelocity.RequestsPerHour,
				ActualValue:      currentRate,
				DeviationPercent: velocityIncrease * 100,
				Significance:     0.9,
			})
		}
	}

	risk.RiskScore = math.Min(risk.RiskScore, 100.0)
	return risk, nil
}

// analyzeDevicePatterns analyzes device usage patterns
func (bra *BehavioralRiskAnalyzer) analyzeDevicePatterns(ctx context.Context, request *RiskAssessmentRequest, profile *UserBehaviorProfile) (*RiskComponent, error) {
	risk := &RiskComponent{
		ComponentType: "device",
		Anomalies:     make([]PatternAnomaly, 0),
		Deviations:    make([]BehaviorDeviation, 0),
	}

	// Analyze device patterns if device information is available
	if request.SessionContext.DeviceID != "" {
		devicePattern, exists := profile.DevicePatterns[request.SessionContext.DeviceID]

		if !exists || devicePattern.UsageFrequency < 0.1 {
			risk.RiskScore += 15.0 // Medium risk for new/unusual devices

			risk.Anomalies = append(risk.Anomalies, PatternAnomaly{
				AnomalyType:        "unusual_device",
				Severity:           0.6,
				Description:        fmt.Sprintf("Access from unusual device: %s", request.SessionContext.DeviceID),
				ExpectedPattern:    bra.getTopDevices(profile.DevicePatterns, 3),
				ActualPattern:      request.SessionContext.DeviceID,
				DeviationMagnitude: 1.0 - devicePattern.UsageFrequency,
				Confidence:         0.8,
			})
		}
	}

	risk.RiskScore = math.Min(risk.RiskScore, 100.0)
	return risk, nil
}

// calculateAmplificationFactor calculates risk amplification for high-risk combinations
func (bra *BehavioralRiskAnalyzer) calculateAmplificationFactor(riskComponents map[string]float64) float64 {
	amplification := 1.0
	highRiskCount := 0

	for _, score := range riskComponents {
		if score > 60.0 {
			highRiskCount++
		}
	}

	// Amplify risk when multiple components show high risk
	switch highRiskCount {
	case 2:
		amplification = 1.15 // 15% increase
	case 3:
		amplification = 1.25 // 25% increase
	case 4, 5:
		amplification = 1.40 // 40% increase
	}

	return amplification
}

// UpdateBehavioralProfile updates a user's behavioral profile with new access data
func (bra *BehavioralRiskAnalyzer) UpdateBehavioralProfile(ctx context.Context, userID string, accessOutcome AccessOutcome) error {
	bra.mutex.Lock()
	defer bra.mutex.Unlock()

	profileKey := fmt.Sprintf("%s:%s", accessOutcome.TenantID, userID)
	profile, exists := bra.userProfiles[profileKey]
	if !exists {
		return fmt.Errorf("user profile not found: %s", userID)
	}

	// Update profile based on access outcome
	profile.SampleCount++
	profile.LastUpdated = time.Now()

	// Update temporal patterns
	hour := accessOutcome.Timestamp.Hour()
	if !bra.containsInt(profile.TypicalAccessHours, hour) {
		profile.TypicalAccessHours = append(profile.TypicalAccessHours, hour)
	}

	day := accessOutcome.Timestamp.Weekday()
	if !bra.containsWeekday(profile.TypicalAccessDays, day) {
		profile.TypicalAccessDays = append(profile.TypicalAccessDays, day)
	}

	// Update resource patterns
	if accessOutcome.ResourceID != "" {
		if _, exists := profile.TypicalResources[accessOutcome.ResourceID]; !exists {
			profile.TypicalResources[accessOutcome.ResourceID] = 0
		}
		profile.TypicalResources[accessOutcome.ResourceID] += 1.0 / float64(profile.SampleCount)
	}

	// Establish baseline after sufficient samples
	if profile.SampleCount >= 10 && !profile.BaselineEstablished {
		profile.BaselineEstablished = true
	}

	return nil
}

// Helper methods for pattern analysis

func (bra *BehavioralRiskAnalyzer) isTypicalHour(hour int, typicalHours []int) bool {
	return bra.containsInt(typicalHours, hour)
}

func (bra *BehavioralRiskAnalyzer) isTypicalDay(day time.Weekday, typicalDays []time.Weekday) bool {
	return bra.containsWeekday(typicalDays, day)
}

func (bra *BehavioralRiskAnalyzer) calculateHourDeviation(hour int, typicalHours []int) float64 {
	if len(typicalHours) == 0 {
		return 1.0 // Maximum deviation if no baseline
	}

	// Calculate minimum distance to any typical hour
	minDistance := 24
	for _, typicalHour := range typicalHours {
		distance := int(math.Abs(float64(hour - typicalHour)))
		if distance > 12 {
			distance = 24 - distance // Wrap around for circular hour calculation
		}
		if distance < minDistance {
			minDistance = distance
		}
	}

	return float64(minDistance) / 12.0 // Normalize to 0-1 range
}

func (bra *BehavioralRiskAnalyzer) calculateDayDeviation(day time.Weekday, typicalDays []time.Weekday) float64 {
	if len(typicalDays) == 0 {
		return 1.0
	}

	for _, typicalDay := range typicalDays {
		if day == typicalDay {
			return 0.0
		}
	}

	return 0.7 // Moderate deviation for different day
}

func (bra *BehavioralRiskAnalyzer) getMostCommonDay(typicalDays []time.Weekday) time.Weekday {
	if len(typicalDays) == 0 {
		return time.Monday
	}
	return typicalDays[0] // Simplified - should track frequency
}

func (bra *BehavioralRiskAnalyzer) getTopLocations(locations map[string]float64, count int) []string {
	// Simplified implementation - should sort by frequency
	result := make([]string, 0, count)
	for location := range locations {
		if len(result) < count {
			result = append(result, location)
		}
	}
	return result
}

func (bra *BehavioralRiskAnalyzer) getTopResources(resources map[string]float64, count int) []string {
	// Simplified implementation - should sort by frequency
	result := make([]string, 0, count)
	for resource := range resources {
		if len(result) < count {
			result = append(result, resource)
		}
	}
	return result
}

func (bra *BehavioralRiskAnalyzer) getTopDevices(devices map[string]DevicePattern, count int) []string {
	result := make([]string, 0, count)
	for deviceID := range devices {
		if len(result) < count {
			result = append(result, deviceID)
		}
	}
	return result
}

func (bra *BehavioralRiskAnalyzer) getNetworkKey(ipAddress string) string {
	// Simplified network key generation - in practice would use CIDR blocks
	return ipAddress[:len(ipAddress)-2] + "xx" // Mask last 2 characters
}

func (bra *BehavioralRiskAnalyzer) containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (bra *BehavioralRiskAnalyzer) containsWeekday(slice []time.Weekday, item time.Weekday) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// getLearningStatus returns the learning status of the profile
func (ubp *UserBehaviorProfile) getLearningStatus() LearningStatus {
	if ubp.SampleCount < 5 {
		return LearningStatusInitializing
	} else if ubp.SampleCount < 10 {
		return LearningStatusLearning
	} else if ubp.BaselineEstablished {
		return LearningStatusTrained
	} else {
		return LearningStatusUpdating
	}
}

// RiskComponent represents a component of behavioral risk analysis
type RiskComponent struct {
	ComponentType string              `json:"component_type"`
	RiskScore     float64             `json:"risk_score"`
	Anomalies     []PatternAnomaly    `json:"anomalies"`
	Deviations    []BehaviorDeviation `json:"deviations"`
}

// Component factories - simplified implementations for supporting components

func NewPatternDetector() *PatternDetector {
	return &PatternDetector{}
}

func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{}
}

func NewBehavioralLearningEngine() *BehavioralLearningEngine {
	return &BehavioralLearningEngine{}
}

func NewConfidenceEngine() *ConfidenceEngine {
	return &ConfidenceEngine{
		dataQualityAssessor: &DataQualityAssessor{},
		sampleSizeAnalyzer:  &SampleSizeAnalyzer{},
		temporalAnalyzer:    &TemporalConfidenceAnalyzer{},
	}
}

// calculateBehavioralConfidence calculates confidence score for behavioral analysis
func (ce *ConfidenceEngine) calculateBehavioralConfidence(profile *UserBehaviorProfile, request *RiskAssessmentRequest, components []RiskComponent) float64 {
	// Base confidence on sample size (0.0 to 1.0)
	sampleConfidence := math.Min(float64(profile.SampleCount)/20.0, 1.0)

	// Adjust for profile age - newer profiles are less reliable (0.0 to 1.0)
	ageConfidence := math.Min(time.Since(profile.ProfileCreated).Hours()/168.0, 1.0) // 1 week to full confidence

	// Combine confidence factors (result: 0.0 to 1.0)
	return (sampleConfidence*0.6 + ageConfidence*0.4)
}

// Supporting types for confidence engine
type DataQualityAssessor struct{}
type SampleSizeAnalyzer struct{}
type TemporalConfidenceAnalyzer struct{}

// performContextualAnalysis performs risk analysis for users without established baselines
func (bra *BehavioralRiskAnalyzer) performContextualAnalysis(ctx context.Context, request *RiskAssessmentRequest) (float64, []PatternAnomaly) {
	riskScore := 30.0 // Start with low-moderate risk
	patterns := make([]PatternAnomaly, 0)

	// Analyze access time patterns
	if request.EnvironmentContext != nil {
		accessTime := request.EnvironmentContext.AccessTime
		hour := accessTime.Hour()

		// After hours access increases risk
		if !request.EnvironmentContext.BusinessHours {
			riskScore += 15.0
			patterns = append(patterns, PatternAnomaly{
				AnomalyType: "temporal_deviation",
				Severity:    0.6,
				Description: "Access outside business hours",
				Confidence:  0.8,
			})
		}

		// Very early morning access (2-6 AM) increases risk significantly
		if hour >= 2 && hour <= 6 {
			riskScore += 20.0
			patterns = append(patterns, PatternAnomaly{
				AnomalyType: "suspicious_timing",
				Severity:    0.8,
				Description: "Access during unusual hours (2-6 AM)",
				Confidence:  0.9,
			})
		}

		// Weekend access increases risk
		weekday := accessTime.Weekday()
		if weekday == time.Saturday || weekday == time.Sunday {
			riskScore += 10.0
			patterns = append(patterns, PatternAnomaly{
				AnomalyType: "temporal_deviation",
				Severity:    0.4,
				Description: "Weekend access",
				Confidence:  0.7,
			})
		}

		// Geographic location risk
		if request.EnvironmentContext.GeoLocation != nil {
			country := request.EnvironmentContext.GeoLocation.Country

			// High-risk countries significantly increase risk
			highRiskCountries := []string{"North Korea", "Iran", "Russia", "China"}
			for _, riskCountry := range highRiskCountries {
				if country == riskCountry {
					riskScore += 30.0
					patterns = append(patterns, PatternAnomaly{
						AnomalyType: "geographic_anomaly",
						Severity:    0.9,
						Description: fmt.Sprintf("Access from high-risk location: %s", country),
						Confidence:  0.95,
					})
					break
				}
			}
		}

		// Network security factors
		if !request.EnvironmentContext.VPNConnected {
			riskScore += 8.0
			patterns = append(patterns, PatternAnomaly{
				AnomalyType: "network_security",
				Severity:    0.6,
				Description: "Direct internet access without VPN",
				Confidence:  0.7,
			})
		}

		// Threat intelligence factors
		if request.EnvironmentContext.ThreatIntelligence != nil {
			ipRep := request.EnvironmentContext.ThreatIntelligence.IPReputationScore
			if ipRep > 0.5 {
				riskIncrease := ipRep * 25.0 // Up to 25 point increase
				riskScore += riskIncrease
				patterns = append(patterns, PatternAnomaly{
					AnomalyType: "threat_intelligence",
					Severity:    0.8,
					Description: fmt.Sprintf("High IP reputation risk score: %.2f", ipRep),
					Confidence:  0.85,
				})
			}
		}
	}

	// Analyze user context factors
	if request.UserContext != nil {
		// No MFA significantly increases risk
		if !request.UserContext.MFAEnabled {
			riskScore += 15.0
			patterns = append(patterns, PatternAnomaly{
				AnomalyType: "authentication_weakness",
				Severity:    0.8,
				Description: "Multi-factor authentication not enabled",
				Confidence:  0.9,
			})
		}

		// Privileged account access increases risk
		if request.AccessRequest != nil {
			permission := request.AccessRequest.PermissionId
			highPrivilegePerms := []string{"admin", "system_admin", "root", "administrator"}
			for _, privPerm := range highPrivilegePerms {
				if permission == privPerm {
					riskScore += 20.0
					patterns = append(patterns, PatternAnomaly{
						AnomalyType: "privilege_escalation",
						Severity:    0.9,
						Description: fmt.Sprintf("High privilege access request: %s", permission),
						Confidence:  0.9,
					})
					break
				}
			}
		}
	}

	// Factor in historical anomaly data if available
	if request.HistoricalData != nil && len(request.HistoricalData.AnomalyHistory) > 0 {
		for _, anomaly := range request.HistoricalData.AnomalyHistory {
			// Add risk based on historical anomaly severity
			anomalyRisk := anomaly.Severity * 15.0 // Up to 15 points per anomaly
			riskScore += anomalyRisk

			// Create pattern anomaly from historical data
			patterns = append(patterns, PatternAnomaly{
				AnomalyType: anomaly.AnomalyType,
				Severity:    anomaly.Severity,
				Description: fmt.Sprintf("Historical anomaly: %s", anomaly.Description),
				Confidence:  0.8, // Good confidence for historical data
			})
		}
	}

	// Cap risk score at 100
	if riskScore > 100.0 {
		riskScore = 100.0
	}

	return riskScore, patterns
}

// generateNewUserDeviations generates behavioral deviations for new users
func (bra *BehavioralRiskAnalyzer) generateNewUserDeviations(ctx context.Context, request *RiskAssessmentRequest) []BehaviorDeviation {
	deviations := make([]BehaviorDeviation, 0)

	if request.EnvironmentContext != nil {
		// Time-based deviation
		if !request.EnvironmentContext.BusinessHours {
			deviations = append(deviations, BehaviorDeviation{
				DeviationType:    "temporal_pattern",
				Metric:           "access_time",
				ExpectedValue:    1.0,  // Business hours expected
				ActualValue:      0.0,  // Non-business hours
				DeviationPercent: 70.0, // 70% deviation
				Significance:     0.7,
			})
		}

		// Location-based deviation for high-risk locations
		if request.EnvironmentContext.GeoLocation != nil {
			country := request.EnvironmentContext.GeoLocation.Country
			highRiskCountries := []string{"North Korea", "Iran", "Russia", "China"}
			for _, riskCountry := range highRiskCountries {
				if country == riskCountry {
					deviations = append(deviations, BehaviorDeviation{
						DeviationType:    "geographic_pattern",
						Metric:           "access_location",
						ExpectedValue:    0.1,  // Low-risk location expected
						ActualValue:      0.9,  // High-risk location
						DeviationPercent: 95.0, // 95% deviation
						Significance:     0.95,
					})
					break
				}
			}
		}
	}

	return deviations
}

// getMostCommonHour returns the most common hour from typical access hours
func (bra *BehavioralRiskAnalyzer) getMostCommonHour(hours []int) int {
	if len(hours) == 0 {
		return 12 // Default to noon
	}
	// For simplicity, return the first hour (could be enhanced with frequency analysis)
	return hours[0]
}

// getMostCommonLocationFrequency returns the highest frequency from typical locations
func (bra *BehavioralRiskAnalyzer) getMostCommonLocationFrequency(locations map[string]float64) float64 {
	if len(locations) == 0 {
		return 0.0
	}

	maxFreq := 0.0
	for _, freq := range locations {
		if freq > maxFreq {
			maxFreq = freq
		}
	}
	return maxFreq
}

// establishBaselineFromHistoricalData uses historical data to establish user baseline
func (bra *BehavioralRiskAnalyzer) establishBaselineFromHistoricalData(profile *UserBehaviorProfile, historicalData *HistoricalAccessData) {
	if historicalData.AccessPatterns == nil {
		return
	}

	patterns := historicalData.AccessPatterns

	// Set baseline from historical patterns
	profile.TypicalAccessHours = patterns.TypicalHours
	profile.TypicalAccessDays = patterns.TypicalDays
	profile.AverageSessionTime = patterns.AverageSessionTime

	// Convert locations to map format
	profile.TypicalLocations = make(map[string]float64)
	for _, location := range patterns.TypicalLocations {
		// Store location in the format used by spatial analysis: "Country:City"
		// For historical data, we assume US locations if no country specified
		if !strings.Contains(location, ":") {
			location = "United States:" + location
		}
		profile.TypicalLocations[location] = 0.9 // High confidence for typical locations
	}

	// Convert resources to map format
	profile.TypicalResources = make(map[string]float64)
	for _, resource := range patterns.TypicalResources {
		profile.TypicalResources[resource] = 0.8 // Good confidence for typical resources
	}

	// Mark baseline as established
	profile.BaselineEstablished = true
	profile.SampleCount = len(historicalData.RecentAccess)
	profile.LastUpdated = time.Now()
}

// Supporting types for pattern detection
type TemporalPatternAnalyzer struct{}
type SpatialPatternAnalyzer struct{}
type AccessPatternAnalyzer struct{}
type VelocityPatternAnalyzer struct{}

// Supporting types for anomaly detection
type StatisticalAnomalyDetector struct{}
type MLAnomalyDetector struct{}
type RuleBasedAnomalyDetector struct{}

// Supporting types for learning engine
type ProfileUpdater struct{}
type FeedbackProcessor struct{}
type AdaptiveThresholdManager struct{}
