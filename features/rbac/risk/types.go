package risk

import (
	"time"
)

// Context types for risk assessment

// UserContext contains user-specific information for risk assessment
type UserContext struct {
	UserID             string                     `json:"user_id"`
	Username           string                     `json:"username,omitempty"`
	Email              string                     `json:"email,omitempty"`
	Department         string                     `json:"department,omitempty"`
	Role               string                     `json:"role,omitempty"`
	SecurityClearance  string                     `json:"security_clearance,omitempty"`
	LastPasswordChange time.Time                  `json:"last_password_change,omitempty"`
	MFAEnabled         bool                       `json:"mfa_enabled"`
	MFAMethods         []string                   `json:"mfa_methods,omitempty"`
	UserAttributes     map[string]interface{}     `json:"user_attributes,omitempty"`
}

// SessionContext contains session-specific information
type SessionContext struct {
	SessionID          string                     `json:"session_id"`
	DeviceID           string                     `json:"device_id,omitempty"`
	DeviceType         string                     `json:"device_type,omitempty"`
	DeviceFingerprint  string                     `json:"device_fingerprint,omitempty"`
	IPAddress          string                     `json:"ip_address"`
	UserAgent          string                     `json:"user_agent,omitempty"`
	LoginMethod        string                     `json:"login_method,omitempty"`
	LoginTime          time.Time                  `json:"login_time"`
	LastActivity       time.Time                  `json:"last_activity"`
	SessionDuration    time.Duration              `json:"session_duration"`
	PreviousIPAddress  string                     `json:"previous_ip_address,omitempty"`
	SSLCertificate     string                     `json:"ssl_certificate,omitempty"`
	SessionAttributes  map[string]interface{}     `json:"session_attributes,omitempty"`
}

// ResourceContext contains resource-specific information
type ResourceContext struct {
	ResourceID         string                     `json:"resource_id"`
	ResourceType       string                     `json:"resource_type"`
	ResourceName       string                     `json:"resource_name,omitempty"`
	Sensitivity        ResourceSensitivity        `json:"sensitivity"`
	Classification     DataClassification         `json:"classification"`
	Owner              string                     `json:"owner,omitempty"`
	LastAccessed       time.Time                  `json:"last_accessed,omitempty"`
	AccessFrequency    int                        `json:"access_frequency,omitempty"`
	ResourceLocation   string                     `json:"resource_location,omitempty"`
	ComplianceFlags    []string                   `json:"compliance_flags,omitempty"`
	ResourceAttributes map[string]interface{}     `json:"resource_attributes,omitempty"`
}

// EnvironmentContext contains environmental factors
type EnvironmentContext struct {
	AccessTime         time.Time                  `json:"access_time"`
	Timezone           string                     `json:"timezone,omitempty"`
	GeoLocation        *GeoLocation               `json:"geo_location,omitempty"`
	NetworkType        string                     `json:"network_type,omitempty"`
	VPNConnected       bool                       `json:"vpn_connected"`
	NetworkSecurity    NetworkSecurityLevel       `json:"network_security"`
	ThreatIntelligence *ThreatIntelligenceContext `json:"threat_intelligence,omitempty"`
	WeatherConditions  string                     `json:"weather_conditions,omitempty"`
	BusinessHours      bool                       `json:"business_hours"`
	EnvironmentFlags   map[string]interface{}     `json:"environment_flags,omitempty"`
}

// HistoricalAccessData contains historical access patterns
type HistoricalAccessData struct {
	RecentAccess       []AccessRecord             `json:"recent_access"`
	AccessPatterns     *AccessPatternAnalysis     `json:"access_patterns,omitempty"`
	AnomalyHistory     []AnomalyRecord            `json:"anomaly_history,omitempty"`
	ViolationHistory   []ViolationRecord          `json:"violation_history,omitempty"`
	TrendAnalysis      *AccessTrendAnalysis       `json:"trend_analysis,omitempty"`
}

// GeoLocation represents geographical location information
type GeoLocation struct {
	Country      string  `json:"country"`
	Region       string  `json:"region,omitempty"`
	City         string  `json:"city,omitempty"`
	Latitude     float64 `json:"latitude,omitempty"`
	Longitude    float64 `json:"longitude,omitempty"`
	Accuracy     float64 `json:"accuracy,omitempty"`
	ISP          string  `json:"isp,omitempty"`
	Organization string  `json:"organization,omitempty"`
}

// ThreatIntelligenceContext contains threat intelligence information
type ThreatIntelligenceContext struct {
	IPReputationScore  float64                    `json:"ip_reputation_score"`
	ThreatCategories   []string                   `json:"threat_categories,omitempty"`
	RecentThreats      []ThreatIndicator          `json:"recent_threats,omitempty"`
	RiskSources        []string                   `json:"risk_sources,omitempty"`
	ThreatLevel        ThreatLevel                `json:"threat_level"`
	LastUpdated        time.Time                  `json:"last_updated"`
}

// ThreatIndicator represents a specific threat indicator
type ThreatIndicator struct {
	Type        string                     `json:"type"`
	Value       string                     `json:"value"`
	Confidence  float64                    `json:"confidence"`
	Source      string                     `json:"source"`
	Timestamp   time.Time                  `json:"timestamp"`
	Description string                     `json:"description,omitempty"`
}

// AccessRecord represents a historical access record
type AccessRecord struct {
	Timestamp     time.Time                  `json:"timestamp"`
	ResourceID    string                     `json:"resource_id"`
	Action        string                     `json:"action"`
	Result        string                     `json:"result"`
	IPAddress     string                     `json:"ip_address,omitempty"`
	Location      *GeoLocation               `json:"location,omitempty"`
	Duration      time.Duration              `json:"duration,omitempty"`
	BytesAccessed int64                      `json:"bytes_accessed,omitempty"`
}

// AccessPatternAnalysis contains analysis of user access patterns
type AccessPatternAnalysis struct {
	TypicalHours       []int                      `json:"typical_hours"`
	TypicalDays        []time.Weekday             `json:"typical_days"`
	TypicalLocations   []string                   `json:"typical_locations"`
	TypicalResources   []string                   `json:"typical_resources"`
	AverageSessionTime time.Duration              `json:"average_session_time"`
	AccessFrequency    map[string]int             `json:"access_frequency"`
	PatternConfidence  float64                    `json:"pattern_confidence"`
	LastUpdated        time.Time                  `json:"last_updated"`
}

// AnomalyRecord represents a detected access anomaly
type AnomalyRecord struct {
	Timestamp     time.Time                  `json:"timestamp"`
	AnomalyType   string                     `json:"anomaly_type"`
	Severity      float64                    `json:"severity"`
	Description   string                     `json:"description"`
	ExpectedValue interface{}                `json:"expected_value,omitempty"`
	ActualValue   interface{}                `json:"actual_value,omitempty"`
	Context       map[string]interface{}     `json:"context,omitempty"`
}

// ViolationRecord represents a security policy violation
type ViolationRecord struct {
	Timestamp     time.Time                  `json:"timestamp"`
	ViolationType string                     `json:"violation_type"`
	PolicyID      string                     `json:"policy_id"`
	Severity      string                     `json:"severity"`
	Description   string                     `json:"description"`
	Action        string                     `json:"action"`
	Resolved      bool                       `json:"resolved"`
	ResolvedAt    *time.Time                 `json:"resolved_at,omitempty"`
}

// AccessTrendAnalysis contains trend analysis data
type AccessTrendAnalysis struct {
	TrendDirection     TrendDirection             `json:"trend_direction"`
	VelocityChange     float64                    `json:"velocity_change"`
	VolumeTrend        VolumeTrend                `json:"volume_trend"`
	PeakUsageHours     []int                      `json:"peak_usage_hours"`
	AccessDiversity    float64                    `json:"access_diversity"`
	RiskTrendScore     float64                    `json:"risk_trend_score"`
	LastAnalyzed       time.Time                  `json:"last_analyzed"`
}

// Contextual risk factors

// ContextualRiskFactor represents a configurable risk factor
type ContextualRiskFactor struct {
	ID             string                     `json:"id"`
	Name           string                     `json:"name"`
	Description    string                     `json:"description"`
	Category       RiskFactorCategory         `json:"category"`
	Weight         float64                    `json:"weight"`
	Threshold      float64                    `json:"threshold"`
	Severity       RiskFactorSeverity         `json:"severity"`
	Evaluator      RiskFactorEvaluator        `json:"evaluator"`
	Parameters     map[string]interface{}     `json:"parameters,omitempty"`
	Enabled        bool                       `json:"enabled"`
	CreatedAt      time.Time                  `json:"created_at"`
	UpdatedAt      time.Time                  `json:"updated_at"`
}

// RiskFactorEvaluator defines how a risk factor is evaluated
type RiskFactorEvaluator struct {
	Type       EvaluatorType              `json:"type"`
	Expression string                     `json:"expression,omitempty"`
	Rules      []EvaluationRule           `json:"rules,omitempty"`
	Function   string                     `json:"function,omitempty"`
}

// EvaluationRule defines a single evaluation rule
type EvaluationRule struct {
	Condition  string                     `json:"condition"`
	Score      float64                    `json:"score"`
	Weight     float64                    `json:"weight,omitempty"`
	Message    string                     `json:"message,omitempty"`
}

// RuleCondition defines a condition in a rule
type RuleCondition struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// EvaluatedRiskFactor represents a risk factor that has been evaluated
type EvaluatedRiskFactor struct {
	FactorID      string                     `json:"factor_id"`
	FactorName    string                     `json:"factor_name"`
	Category      RiskFactorCategory         `json:"category"`
	Score         float64                    `json:"score"`
	Weight        float64                    `json:"weight"`
	WeightedScore float64                    `json:"weighted_score"`
	Severity      RiskFactorSeverity         `json:"severity"`
	Explanation   string                     `json:"explanation"`
	Evidence      map[string]interface{}     `json:"evidence,omitempty"`
	Confidence    float64                    `json:"confidence"`
}

// Risk assessment results by category

// BehavioralRiskResult contains behavioral risk assessment results
type BehavioralRiskResult struct {
	RiskScore           float64                    `json:"risk_score"`
	ConfidenceScore     float64                    `json:"confidence_score"`
	PatternAnomalies    []PatternAnomaly           `json:"pattern_anomalies"`
	BehaviorDeviations  []BehaviorDeviation        `json:"behavior_deviations"`
	LearningStatus      LearningStatus             `json:"learning_status"`
	BaselineAge         time.Duration              `json:"baseline_age"`
	SamplesCount        int                        `json:"samples_count"`
	LastUpdate          time.Time                  `json:"last_update"`
}

// PatternAnomaly represents an anomaly in user behavior patterns
type PatternAnomaly struct {
	AnomalyType       string                     `json:"anomaly_type"`
	Severity          float64                    `json:"severity"`
	Description       string                     `json:"description"`
	ExpectedPattern   interface{}                `json:"expected_pattern"`
	ActualPattern     interface{}                `json:"actual_pattern"`
	DeviationMagnitude float64                   `json:"deviation_magnitude"`
	Confidence        float64                    `json:"confidence"`
}

// BehaviorDeviation represents a deviation from normal behavior
type BehaviorDeviation struct {
	DeviationType     string                     `json:"deviation_type"`
	Metric            string                     `json:"metric"`
	ExpectedValue     float64                    `json:"expected_value"`
	ActualValue       float64                    `json:"actual_value"`
	DeviationPercent  float64                    `json:"deviation_percent"`
	Significance      float64                    `json:"significance"`
}

// EnvironmentalRiskResult contains environmental risk assessment results
type EnvironmentalRiskResult struct {
	RiskScore         float64                    `json:"risk_score"`
	ConfidenceScore   float64                    `json:"confidence_score"`
	LocationRisk      LocationRisk               `json:"location_risk"`
	TimeRisk          TimeRisk                   `json:"time_risk"`
	NetworkRisk       NetworkRisk                `json:"network_risk"`
	DeviceRisk        DeviceRisk                 `json:"device_risk"`
	ThreatEnvironment ThreatEnvironmentRisk      `json:"threat_environment"`
}

// LocationRisk contains location-based risk information
type LocationRisk struct {
	RiskScore         float64                    `json:"risk_score"`
	IsTypicalLocation bool                       `json:"is_typical_location"`
	DistanceFromTypical float64                  `json:"distance_from_typical"`
	CountryRisk       float64                    `json:"country_risk"`
	RegionRisk        float64                    `json:"region_risk"`
	VPNDetected       bool                       `json:"vpn_detected"`
	ProxyDetected     bool                       `json:"proxy_detected"`
	TorDetected       bool                       `json:"tor_detected"`
}

// TimeRisk contains time-based risk information
type TimeRisk struct {
	RiskScore         float64                    `json:"risk_score"`
	IsBusinessHours   bool                       `json:"is_business_hours"`
	IsTypicalTime     bool                       `json:"is_typical_time"`
	HourDeviation     float64                    `json:"hour_deviation"`
	DayDeviation      float64                    `json:"day_deviation"`
	TimezoneRisk      float64                    `json:"timezone_risk"`
}

// NetworkRisk contains network-based risk information
type NetworkRisk struct {
	RiskScore         float64                    `json:"risk_score"`
	NetworkType       string                     `json:"network_type"`
	IsKnownNetwork    bool                       `json:"is_known_network"`
	SecurityLevel     NetworkSecurityLevel       `json:"security_level"`
	BandwidthAnomaly  bool                       `json:"bandwidth_anomaly"`
	LatencyAnomaly    bool                       `json:"latency_anomaly"`
}

// DeviceRisk contains device-based risk information
type DeviceRisk struct {
	RiskScore         float64                    `json:"risk_score"`
	IsKnownDevice     bool                       `json:"is_known_device"`
	DeviceType        string                     `json:"device_type"`
	OSRisk            float64                    `json:"os_risk"`
	BrowserRisk       float64                    `json:"browser_risk"`
	ComplianceStatus  DeviceComplianceStatus     `json:"compliance_status"`
	LastScan          *time.Time                 `json:"last_scan,omitempty"`
}

// ThreatEnvironmentRisk contains threat environment risk information
type ThreatEnvironmentRisk struct {
	RiskScore         float64                    `json:"risk_score"`
	ThreatLevel       ThreatLevel                `json:"threat_level"`
	ReputationScore   float64                    `json:"reputation_score"`
	ThreatCategories  []string                   `json:"threat_categories"`
	ActiveThreats     int                        `json:"active_threats"`
	RecentIncidents   int                        `json:"recent_incidents"`
}

// ResourceRiskResult contains resource-based risk assessment results
type ResourceRiskResult struct {
	RiskScore         float64                    `json:"risk_score"`
	ConfidenceScore   float64                    `json:"confidence_score"`
	SensitivityRisk   SensitivityRisk            `json:"sensitivity_risk"`
	AccessPatternRisk AccessPatternRisk          `json:"access_pattern_risk"`
	ComplianceRisk    ComplianceRisk             `json:"compliance_risk"`
	BusinessImpactRisk BusinessImpactRisk        `json:"business_impact_risk"`
}

// SensitivityRisk contains resource sensitivity risk information
type SensitivityRisk struct {
	RiskScore         float64                    `json:"risk_score"`
	Sensitivity       ResourceSensitivity        `json:"sensitivity"`
	Classification    DataClassification         `json:"classification"`
	RequiredClearance string                     `json:"required_clearance,omitempty"`
	HasClearance      bool                       `json:"has_clearance"`
}

// AccessPatternRisk contains access pattern risk information
type AccessPatternRisk struct {
	RiskScore         float64                    `json:"risk_score"`
	IsTypicalResource bool                       `json:"is_typical_resource"`
	AccessFrequency   AccessFrequency            `json:"access_frequency"`
	LastAccessed      time.Time                  `json:"last_accessed"`
	UnusualAccess     bool                       `json:"unusual_access"`
}

// ComplianceRisk contains compliance-related risk information
type ComplianceRisk struct {
	RiskScore         float64                    `json:"risk_score"`
	Requirements      []string                   `json:"requirements"`
	Violations        []string                   `json:"violations"`
	AuditRequired     bool                       `json:"audit_required"`
	DataRetention     bool                       `json:"data_retention"`
}

// BusinessImpactRisk contains business impact risk information
type BusinessImpactRisk struct {
	RiskScore         float64                    `json:"risk_score"`
	CriticalityLevel  ResourceCriticality        `json:"criticality_level"`
	BusinessValue     float64                    `json:"business_value"`
	ServiceDependency bool                       `json:"service_dependency"`
	CustomerImpact    CustomerImpact             `json:"customer_impact"`
}

// Risk mitigation and adaptive controls

// RiskMitigationAction represents an action to mitigate risk
type RiskMitigationAction struct {
	Type        string                     `json:"type"`
	Description string                     `json:"description"`
	Priority    string                     `json:"priority"`
	Parameters  map[string]interface{}     `json:"parameters,omitempty"`
	Timeout     time.Duration              `json:"timeout,omitempty"`
}

// AdaptiveControl represents an adaptive security control
type AdaptiveControl struct {
	Type        string                     `json:"type"`
	Parameters  map[string]interface{}     `json:"parameters"`
	Description string                     `json:"description"`
	Priority    ControlPriority            `json:"priority,omitempty"`
	Duration    time.Duration              `json:"duration,omitempty"`
}

// Access outcomes for learning

// AccessOutcome represents the outcome of an access attempt
type AccessOutcome struct {
	AccessRequestID   string                     `json:"access_request_id"`
	UserID            string                     `json:"user_id"`
	TenantID          string                     `json:"tenant_id"`
	ResourceID        string                     `json:"resource_id"`
	Timestamp         time.Time                  `json:"timestamp"`
	Granted           bool                       `json:"granted"`
	RiskScore         float64                    `json:"risk_score,omitempty"`
	ActualBehavior    *ActualBehaviorData        `json:"actual_behavior,omitempty"`
	SecurityIncident  bool                       `json:"security_incident,omitempty"`
	ViolationDetected bool                       `json:"violation_detected,omitempty"`
	SessionDuration   time.Duration              `json:"session_duration,omitempty"`
	DataAccessed      int64                      `json:"data_accessed,omitempty"`
}

// ActualBehaviorData contains data about actual user behavior during access
type ActualBehaviorData struct {
	SessionDuration   time.Duration              `json:"session_duration"`
	ResourcesAccessed []string                   `json:"resources_accessed"`
	ActionsPerformed  []string                   `json:"actions_performed"`
	DataVolume        int64                      `json:"data_volume"`
	LocationChanges   int                        `json:"location_changes"`
	DeviceChanges     int                        `json:"device_changes"`
	SuspiciousActivity bool                      `json:"suspicious_activity"`
}

// Policy evaluation results

// PolicyEvaluationResult contains the result of policy evaluation
type PolicyEvaluationResult struct {
	PolicyID        string                     `json:"policy_id,omitempty"`
	Decision        string                     `json:"decision,omitempty"`
	AppliedRules    []string                   `json:"applied_rules"`
	Violations      []string                   `json:"violations,omitempty"`
	Recommendations []string                   `json:"recommendations,omitempty"`
	Metadata        map[string]interface{}     `json:"metadata,omitempty"`
}

// Risk policy types

// RiskPolicy defines a policy for risk-based access control
type RiskPolicy struct {
	ID              string                     `json:"id"`
	Name            string                     `json:"name"`
	Description     string                     `json:"description"`
	TenantID        string                     `json:"tenant_id,omitempty"`
	Rules           []RiskPolicyRule           `json:"rules"`
	Priority        int                        `json:"priority"`
	Enabled         bool                       `json:"enabled"`
	CreatedAt       time.Time                  `json:"created_at"`
	UpdatedAt       time.Time                  `json:"updated_at"`
}

// RiskPolicyRule defines a rule within a risk policy
type RiskPolicyRule struct {
	ID          string                     `json:"id"`
	Condition   string                     `json:"condition"`
	Action      PolicyAction               `json:"action"`
	Parameters  map[string]interface{}     `json:"parameters,omitempty"`
	Priority    int                        `json:"priority"`
	Enabled     bool                       `json:"enabled"`
}

// Enumeration types

// ResourceSensitivity defines the sensitivity level of a resource
type ResourceSensitivity string

const (
	ResourceSensitivityPublic       ResourceSensitivity = "public"
	ResourceSensitivityInternal     ResourceSensitivity = "internal"
	ResourceSensitivityConfidential ResourceSensitivity = "confidential"
	ResourceSensitivitySecret       ResourceSensitivity = "secret"
	ResourceSensitivityTopSecret    ResourceSensitivity = "top_secret"
)

// DataClassification defines data classification levels
type DataClassification string

const (
	DataClassificationPublic       DataClassification = "public"
	DataClassificationInternal     DataClassification = "internal"
	DataClassificationConfidential DataClassification = "confidential"
	DataClassificationRestricted   DataClassification = "restricted"
)

// NetworkSecurityLevel defines network security levels
type NetworkSecurityLevel string

const (
	NetworkSecurityLevelLow      NetworkSecurityLevel = "low"
	NetworkSecurityLevelMedium   NetworkSecurityLevel = "medium"
	NetworkSecurityLevelHigh     NetworkSecurityLevel = "high"
	NetworkSecurityLevelCritical NetworkSecurityLevel = "critical"
)

// ThreatLevel defines threat levels
type ThreatLevel string

const (
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
)

// RiskFactorCategory defines categories of risk factors
type RiskFactorCategory string

const (
	RiskFactorCategoryBehavioral    RiskFactorCategory = "behavioral"
	RiskFactorCategoryEnvironmental RiskFactorCategory = "environmental"
	RiskFactorCategoryResource      RiskFactorCategory = "resource"
	RiskFactorCategoryTemporal      RiskFactorCategory = "temporal"
	RiskFactorCategoryGeographic    RiskFactorCategory = "geographic"
)

// RiskFactorSeverity defines severity levels for risk factors
type RiskFactorSeverity string

const (
	RiskFactorSeverityLow      RiskFactorSeverity = "low"
	RiskFactorSeverityMedium   RiskFactorSeverity = "medium"
	RiskFactorSeverityHigh     RiskFactorSeverity = "high"
	RiskFactorSeverityCritical RiskFactorSeverity = "critical"
)

// EvaluatorType defines types of risk factor evaluators
type EvaluatorType string

const (
	EvaluatorTypeRule       EvaluatorType = "rule"
	EvaluatorTypeExpression EvaluatorType = "expression"
	EvaluatorTypeFunction   EvaluatorType = "function"
	EvaluatorTypeML         EvaluatorType = "ml"
)

// LearningStatus defines the status of behavioral learning
type LearningStatus string

const (
	LearningStatusInitializing LearningStatus = "initializing"
	LearningStatusLearning     LearningStatus = "learning"
	LearningStatusTrained      LearningStatus = "trained"
	LearningStatusUpdating     LearningStatus = "updating"
)

// TrendDirection defines trend directions
type TrendDirection string

const (
	TrendDirectionIncreasing TrendDirection = "increasing"
	TrendDirectionDecreasing TrendDirection = "decreasing"
	TrendDirectionStable     TrendDirection = "stable"
	TrendDirectionVolatile   TrendDirection = "volatile"
)

// VolumeTrend defines volume trend patterns
type VolumeTrend string

const (
	VolumeTrendLow      VolumeTrend = "low"
	VolumeTrendNormal   VolumeTrend = "normal"
	VolumeTrendHigh     VolumeTrend = "high"
	VolumeTrendSpike    VolumeTrend = "spike"
)

// DeviceComplianceStatus defines device compliance status
type DeviceComplianceStatus string

const (
	DeviceComplianceStatusCompliant    DeviceComplianceStatus = "compliant"
	DeviceComplianceStatusNonCompliant DeviceComplianceStatus = "non_compliant"
	DeviceComplianceStatusUnknown      DeviceComplianceStatus = "unknown"
)

// AccessFrequency defines access frequency levels
type AccessFrequency string

const (
	AccessFrequencyRare      AccessFrequency = "rare"
	AccessFrequencyOccasional AccessFrequency = "occasional"
	AccessFrequencyRegular   AccessFrequency = "regular"
	AccessFrequencyFrequent  AccessFrequency = "frequent"
)

// ResourceCriticality defines resource criticality levels
type ResourceCriticality string

const (
	ResourceCriticalityLow      ResourceCriticality = "low"
	ResourceCriticalityMedium   ResourceCriticality = "medium"
	ResourceCriticalityHigh     ResourceCriticality = "high"
	ResourceCriticalityCritical ResourceCriticality = "critical"
)

// CustomerImpact defines customer impact levels
type CustomerImpact string

const (
	CustomerImpactNone     CustomerImpact = "none"
	CustomerImpactLow      CustomerImpact = "low"
	CustomerImpactMedium   CustomerImpact = "medium"
	CustomerImpactHigh     CustomerImpact = "high"
	CustomerImpactCritical CustomerImpact = "critical"
)

// ControlPriority defines priority levels for adaptive controls
type ControlPriority string

const (
	ControlPriorityLow      ControlPriority = "low"
	ControlPriorityMedium   ControlPriority = "medium"
	ControlPriorityHigh     ControlPriority = "high"
	ControlPriorityCritical ControlPriority = "critical"
)

// PolicyAction defines actions that policies can take
type PolicyAction string

const (
	PolicyActionAllow            PolicyAction = "allow"
	PolicyActionDeny             PolicyAction = "deny"
	PolicyActionChallenge        PolicyAction = "challenge"
	PolicyActionStepUp           PolicyAction = "step_up"
	PolicyActionMonitor          PolicyAction = "monitor"
	PolicyActionQuarantine       PolicyAction = "quarantine"
	PolicyActionRequireApproval  PolicyAction = "require_approval"
)