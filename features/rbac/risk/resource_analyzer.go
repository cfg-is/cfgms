package risk

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
)

// ResourceRiskAnalyzer analyzes resource-specific risk factors for access requests
type ResourceRiskAnalyzer struct {
	sensitivityClassifier     *ResourceSensitivityClassifier
	accessPatternAnalyzer     *ResourceAccessPatternAnalyzer
	complianceValidator       *ResourceComplianceValidator
	businessImpactAssessor    *BusinessImpactAssessor
	dataClassificationEngine  *DataClassificationEngine
}

// ResourceSensitivityClassifier classifies resource sensitivity levels
type ResourceSensitivityClassifier struct {
	classificationRules       map[string]SensitivityRule
	dataTypeClassifications   map[string]ResourceSensitivity
	resourceCatalogue        map[string]ResourceMetadata
}

// ResourceAccessPatternAnalyzer analyzes resource access patterns
type ResourceAccessPatternAnalyzer struct {
	accessHistoryDB          *AccessHistoryDatabase
	patternLearner           *ResourcePatternLearner
	anomalyDetector          *ResourceAnomalyDetector
}

// ResourceComplianceValidator validates compliance requirements
type ResourceComplianceValidator struct {
	complianceFrameworks     map[string]ComplianceFramework
	requirementEngine        *ComplianceRequirementEngine
	violationDetector        *ComplianceViolationDetector
}

// BusinessImpactAssessor assesses business impact of resource access
type BusinessImpactAssessor struct {
	businessValueCalculator  *BusinessValueCalculator
	criticalityAnalyzer      *ResourceCriticalityAnalyzer
	dependencyMapper         *ServiceDependencyMapper
	customerImpactAnalyzer   *CustomerImpactAnalyzer
}

// DataClassificationEngine handles data classification
type DataClassificationEngine struct {
	classificationPolicies   map[string]ClassificationPolicy
	dataDiscoveryEngine      *DataDiscoveryEngine
	labelingService          *DataLabelingService
}

// Supporting data structures

// ResourceMetadata contains metadata about resources
type ResourceMetadata struct {
	ResourceID        string                     `json:"resource_id"`
	ResourceType      string                     `json:"resource_type"`
	Name              string                     `json:"name"`
	Description       string                     `json:"description"`
	Owner             string                     `json:"owner"`
	Sensitivity       ResourceSensitivity        `json:"sensitivity"`
	Classification    DataClassification         `json:"classification"`
	BusinessValue     float64                    `json:"business_value"`
	Criticality       ResourceCriticality        `json:"criticality"`
	ComplianceFlags   []string                   `json:"compliance_flags"`
	DataTypes         []string                   `json:"data_types"`
	CreatedAt         time.Time                  `json:"created_at"`
	LastUpdated       time.Time                  `json:"last_updated"`
	Tags              map[string]string          `json:"tags"`
	Attributes        map[string]interface{}     `json:"attributes"`
}

// SensitivityRule defines rules for classifying resource sensitivity
type SensitivityRule struct {
	RuleID       string                     `json:"rule_id"`
	Name         string                     `json:"name"`
	Conditions   []RuleCondition            `json:"conditions"`
	Sensitivity  ResourceSensitivity        `json:"sensitivity"`
	Priority     int                        `json:"priority"`
	Enabled      bool                       `json:"enabled"`
}

// ComplianceFramework defines compliance framework requirements
type ComplianceFramework struct {
	FrameworkID     string                     `json:"framework_id"`
	Name            string                     `json:"name"`
	Version         string                     `json:"version"`
	Requirements    []ComplianceRequirement    `json:"requirements"`
	DataTypes       []string                   `json:"data_types"`
	Regions         []string                   `json:"regions"`
	Industries      []string                   `json:"industries"`
}

// ComplianceRequirement defines a specific compliance requirement
type ComplianceRequirement struct {
	RequirementID   string                     `json:"requirement_id"`
	Name            string                     `json:"name"`
	Description     string                     `json:"description"`
	Severity        string                     `json:"severity"`
	Controls        []string                   `json:"controls"`
	DataTypes       []string                   `json:"data_types"`
	Actions         []string                   `json:"actions"`
	Conditions      []RuleCondition            `json:"conditions"`
}

// ClassificationPolicy defines data classification policies
type ClassificationPolicy struct {
	PolicyID        string                     `json:"policy_id"`
	Name            string                     `json:"name"`
	DataTypes       []string                   `json:"data_types"`
	Classification  DataClassification         `json:"classification"`
	Rules           []ClassificationRule       `json:"rules"`
	AutoApply       bool                       `json:"auto_apply"`
	Priority        int                        `json:"priority"`
}

// ClassificationRule defines rules for data classification
type ClassificationRule struct {
	RuleID      string                     `json:"rule_id"`
	Pattern     string                     `json:"pattern"`
	Confidence  float64                    `json:"confidence"`
	Context     string                     `json:"context"`
	Action      string                     `json:"action"`
}

// ResourceAccessHistory represents historical access data for a resource
type ResourceAccessHistory struct {
	ResourceID           string                     `json:"resource_id"`
	AccessCount          int                        `json:"access_count"`
	UniqueUsers          int                        `json:"unique_users"`
	LastAccessed         time.Time                  `json:"last_accessed"`
	AverageAccessTime    time.Duration              `json:"average_access_time"`
	PeakAccessHours      []int                      `json:"peak_access_hours"`
	TypicalUsers         map[string]float64         `json:"typical_users"`
	AccessTrends         AccessTrendData            `json:"access_trends"`
	AnomalyHistory       []ResourceAnomalyRecord    `json:"anomaly_history"`
	ComplianceEvents     []ComplianceEvent          `json:"compliance_events"`
}

// AccessTrendData contains access trend information
type AccessTrendData struct {
	TrendDirection       TrendDirection             `json:"trend_direction"`
	VolumeChange         float64                    `json:"volume_change"`
	UserDiversityChange  float64                    `json:"user_diversity_change"`
	PatternStability     float64                    `json:"pattern_stability"`
	LastAnalyzed         time.Time                  `json:"last_analyzed"`
}

// ResourceAnomalyRecord represents a resource access anomaly
type ResourceAnomalyRecord struct {
	AnomalyID       string                     `json:"anomaly_id"`
	Timestamp       time.Time                  `json:"timestamp"`
	AnomalyType     string                     `json:"anomaly_type"`
	Severity        float64                    `json:"severity"`
	Description     string                     `json:"description"`
	UserID          string                     `json:"user_id,omitempty"`
	Details         map[string]interface{}     `json:"details"`
	Resolved        bool                       `json:"resolved"`
	ResolvedAt      *time.Time                 `json:"resolved_at,omitempty"`
}

// ComplianceEvent represents a compliance-related event
type ComplianceEvent struct {
	EventID         string                     `json:"event_id"`
	Timestamp       time.Time                  `json:"timestamp"`
	EventType       string                     `json:"event_type"`
	Framework       string                     `json:"framework"`
	Requirement     string                     `json:"requirement"`
	Severity        string                     `json:"severity"`
	Status          string                     `json:"status"`
	Description     string                     `json:"description"`
	UserID          string                     `json:"user_id,omitempty"`
	Remediation     string                     `json:"remediation,omitempty"`
}

// NewResourceRiskAnalyzer creates a new resource risk analyzer
func NewResourceRiskAnalyzer() *ResourceRiskAnalyzer {
	return &ResourceRiskAnalyzer{
		sensitivityClassifier:    NewResourceSensitivityClassifier(),
		accessPatternAnalyzer:    NewResourceAccessPatternAnalyzer(),
		complianceValidator:      NewResourceComplianceValidator(),
		businessImpactAssessor:   NewBusinessImpactAssessor(),
		dataClassificationEngine: NewDataClassificationEngine(),
	}
}

// EvaluateResourceRisk evaluates resource-specific risk for an access request
func (rra *ResourceRiskAnalyzer) EvaluateResourceRisk(ctx context.Context, request *RiskAssessmentRequest) (*ResourceRiskResult, error) {
	result := &ResourceRiskResult{}

	// Assess resource sensitivity risk
	sensitivityRisk, err := rra.assessSensitivityRisk(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("sensitivity risk assessment failed: %w", err)
	}
	result.SensitivityRisk = *sensitivityRisk

	// Assess access pattern risk
	accessPatternRisk, err := rra.assessAccessPatternRisk(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("access pattern risk assessment failed: %w", err)
	}
	result.AccessPatternRisk = *accessPatternRisk

	// Assess compliance risk
	complianceRisk, err := rra.assessComplianceRisk(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("compliance risk assessment failed: %w", err)
	}
	result.ComplianceRisk = *complianceRisk

	// Assess business impact risk
	businessImpactRisk, err := rra.assessBusinessImpactRisk(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("business impact risk assessment failed: %w", err)
	}
	result.BusinessImpactRisk = *businessImpactRisk

	// Calculate overall resource risk score with dynamic weighting
	// For high-sensitivity resources, increase sensitivity weight
	sensitivityWeight := 0.30
	accessPatternWeight := 0.25
	complianceWeight := 0.25
	businessImpactWeight := 0.20
	
	if sensitivityRisk.Sensitivity == ResourceSensitivitySecret || sensitivityRisk.Sensitivity == ResourceSensitivityTopSecret {
		// For extreme sensitivity, increase sensitivity weight significantly
		sensitivityWeight = 0.60        // 60% weight for secret/top-secret
		accessPatternWeight = 0.15      // 15% weight
		complianceWeight = 0.15         // 15% weight
		businessImpactWeight = 0.10     // 10% weight
	} else if sensitivityRisk.Sensitivity == ResourceSensitivityConfidential {
		// For high sensitivity, moderately increase sensitivity weight
		sensitivityWeight = 0.45        // 45% weight for confidential
		accessPatternWeight = 0.20      // 20% weight
		complianceWeight = 0.20         // 20% weight
		businessImpactWeight = 0.15     // 15% weight
	}
	
	riskComponents := []float64{
		sensitivityRisk.RiskScore * sensitivityWeight,
		accessPatternRisk.RiskScore * accessPatternWeight,
		complianceRisk.RiskScore * complianceWeight,
		businessImpactRisk.RiskScore * businessImpactWeight,
	}

	combinedRisk := 0.0
	for _, score := range riskComponents {
		combinedRisk += score
	}

	// Apply amplification for critical resource combinations
	amplificationFactor := rra.calculateResourceAmplification(sensitivityRisk, accessPatternRisk, complianceRisk, businessImpactRisk)
	result.RiskScore = math.Min(combinedRisk*amplificationFactor, 100.0)

	// Calculate confidence score
	result.ConfidenceScore = rra.calculateResourceConfidence(request, sensitivityRisk, accessPatternRisk, complianceRisk, businessImpactRisk)

	return result, nil
}

// assessSensitivityRisk assesses resource sensitivity-based risk
func (rra *ResourceRiskAnalyzer) assessSensitivityRisk(ctx context.Context, request *RiskAssessmentRequest) (*SensitivityRisk, error) {
	sensitivityRisk := &SensitivityRisk{}

	if request.ResourceContext == nil {
		sensitivityRisk.RiskScore = 40.0 // Default medium risk for unknown resource
		return sensitivityRisk, nil
	}

	resourceContext := request.ResourceContext

	// Get or classify resource sensitivity
	sensitivity := resourceContext.Sensitivity
	if sensitivity == "" {
		classifiedSensitivity, err := rra.sensitivityClassifier.ClassifyResource(ctx, resourceContext)
		if err != nil {
			return nil, fmt.Errorf("failed to classify resource sensitivity: %w", err)
		}
		sensitivity = classifiedSensitivity
	}
	sensitivityRisk.Sensitivity = sensitivity

	// Get or classify data classification
	classification := resourceContext.Classification
	if classification == "" {
		classifiedData, err := rra.dataClassificationEngine.ClassifyData(ctx, resourceContext)
		if err != nil {
			return nil, fmt.Errorf("failed to classify data: %w", err)
		}
		classification = classifiedData
	}
	sensitivityRisk.Classification = classification

	// Check security clearance requirements
	requiredClearance := rra.getRequiredClearance(sensitivity, classification)
	sensitivityRisk.RequiredClearance = requiredClearance

	// Verify user has required clearance
	userClearance := ""
	if request.UserContext != nil {
		userClearance = request.UserContext.SecurityClearance
	}
	sensitivityRisk.HasClearance = rra.validateClearance(userClearance, requiredClearance)

	// Calculate sensitivity risk score
	sensitivityRisk.RiskScore = rra.calculateSensitivityRiskScore(sensitivityRisk)

	return sensitivityRisk, nil
}

// assessAccessPatternRisk assesses access pattern-based risk
func (rra *ResourceRiskAnalyzer) assessAccessPatternRisk(ctx context.Context, request *RiskAssessmentRequest) (*AccessPatternRisk, error) {
	accessPatternRisk := &AccessPatternRisk{}

	if request.ResourceContext == nil {
		accessPatternRisk.RiskScore = 30.0 // Default low-medium risk
		return accessPatternRisk, nil
	}

	resourceID := request.ResourceContext.ResourceID
	userID := ""
	if request.UserContext != nil {
		userID = request.UserContext.UserID
	}

	// Get resource access history
	accessHistory, err := rra.accessPatternAnalyzer.GetAccessHistory(ctx, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get access history: %w", err)
	}

	// Check if resource is typically accessed by this user
	accessPatternRisk.IsTypicalResource = rra.isTypicalResourceForUser(userID, accessHistory)

	// Determine access frequency
	accessPatternRisk.AccessFrequency = rra.determineAccessFrequency(accessHistory)

	// Set last accessed time
	accessPatternRisk.LastAccessed = accessHistory.LastAccessed

	// Detect unusual access patterns
	accessPatternRisk.UnusualAccess = rra.detectUnusualAccess(ctx, request, accessHistory)

	// Calculate access pattern risk score
	accessPatternRisk.RiskScore = rra.calculateAccessPatternRiskScore(accessPatternRisk)

	return accessPatternRisk, nil
}

// assessComplianceRisk assesses compliance-related risk
func (rra *ResourceRiskAnalyzer) assessComplianceRisk(ctx context.Context, request *RiskAssessmentRequest) (*ComplianceRisk, error) {
	complianceRisk := &ComplianceRisk{}

	if request.ResourceContext == nil {
		complianceRisk.RiskScore = 20.0 // Default low risk
		return complianceRisk, nil
	}

	resourceContext := request.ResourceContext

	// Get applicable compliance requirements
	requirements, err := rra.complianceValidator.GetApplicableRequirements(ctx, resourceContext)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance requirements: %w", err)
	}
	complianceRisk.Requirements = rra.extractRequirementNames(requirements)

	// Validate access against compliance requirements
	violations, err := rra.complianceValidator.ValidateAccess(ctx, request, requirements)
	if err != nil {
		return nil, fmt.Errorf("failed to validate compliance: %w", err)
	}
	complianceRisk.Violations = violations

	// Check if audit is required
	complianceRisk.AuditRequired = rra.isAuditRequired(requirements, request)

	// Check data retention requirements
	complianceRisk.DataRetention = rra.hasDataRetentionRequirements(requirements)

	// Calculate compliance risk score
	complianceRisk.RiskScore = rra.calculateComplianceRiskScore(complianceRisk)

	return complianceRisk, nil
}

// assessBusinessImpactRisk assesses business impact-related risk
func (rra *ResourceRiskAnalyzer) assessBusinessImpactRisk(ctx context.Context, request *RiskAssessmentRequest) (*BusinessImpactRisk, error) {
	businessImpactRisk := &BusinessImpactRisk{}

	if request.ResourceContext == nil {
		businessImpactRisk.RiskScore = 25.0 // Default low-medium risk
		return businessImpactRisk, nil
	}

	resourceContext := request.ResourceContext

	// Assess resource criticality
	criticality, err := rra.businessImpactAssessor.AssessResourceCriticality(ctx, resourceContext)
	if err != nil {
		return nil, fmt.Errorf("failed to assess resource criticality: %w", err)
	}
	businessImpactRisk.CriticalityLevel = criticality

	// Calculate business value
	businessValue, err := rra.businessImpactAssessor.CalculateBusinessValue(ctx, resourceContext)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate business value: %w", err)
	}
	businessImpactRisk.BusinessValue = businessValue

	// Check service dependencies
	serviceDependency, err := rra.businessImpactAssessor.HasServiceDependency(ctx, resourceContext)
	if err != nil {
		return nil, fmt.Errorf("failed to check service dependency: %w", err)
	}
	businessImpactRisk.ServiceDependency = serviceDependency

	// Assess customer impact
	customerImpact, err := rra.businessImpactAssessor.AssessCustomerImpact(ctx, resourceContext)
	if err != nil {
		return nil, fmt.Errorf("failed to assess customer impact: %w", err)
	}
	businessImpactRisk.CustomerImpact = customerImpact

	// Calculate business impact risk score
	businessImpactRisk.RiskScore = rra.calculateBusinessImpactRiskScore(businessImpactRisk)

	return businessImpactRisk, nil
}

// Risk calculation methods

func (rra *ResourceRiskAnalyzer) calculateSensitivityRiskScore(sensitivityRisk *SensitivityRisk) float64 {
	score := 0.0

	// Sensitivity level contribution
	switch sensitivityRisk.Sensitivity {
	case ResourceSensitivityPublic:
		score += 0.0
	case ResourceSensitivityInternal:
		score += 20.0
	case ResourceSensitivityConfidential:
		score += 40.0
	case ResourceSensitivitySecret:
		score += 70.0
	case ResourceSensitivityTopSecret:
		score += 90.0
	}

	// Data classification contribution
	switch sensitivityRisk.Classification {
	case DataClassificationPublic:
		score += 0.0
	case DataClassificationInternal:
		score += 10.0
	case DataClassificationConfidential:
		score += 25.0
	case DataClassificationRestricted:
		score += 40.0
	}

	// Clearance requirement penalty
	if sensitivityRisk.RequiredClearance != "" && !sensitivityRisk.HasClearance {
		score += 50.0 // High penalty for missing required clearance
	}

	return math.Min(score, 100.0)
}

func (rra *ResourceRiskAnalyzer) calculateAccessPatternRiskScore(accessPatternRisk *AccessPatternRisk) float64 {
	score := 0.0

	// Unusual resource penalty
	if !accessPatternRisk.IsTypicalResource {
		score += 30.0
	}

	// Access frequency factor
	switch accessPatternRisk.AccessFrequency {
	case AccessFrequencyRare:
		score += 20.0
	case AccessFrequencyOccasional:
		score += 10.0
	case AccessFrequencyRegular:
		score += 0.0
	case AccessFrequencyFrequent:
		score += 5.0 // Slight penalty for very frequent access
	}

	// Unusual access pattern penalty
	if accessPatternRisk.UnusualAccess {
		score += 25.0
	}

	// Time since last access factor
	if !accessPatternRisk.LastAccessed.IsZero() {
		daysSinceAccess := time.Since(accessPatternRisk.LastAccessed).Hours() / 24
		if daysSinceAccess > 90 { // More than 3 months
			score += 15.0
		} else if daysSinceAccess > 30 { // More than 1 month
			score += 10.0
		}
	}

	return math.Min(score, 100.0)
}

func (rra *ResourceRiskAnalyzer) calculateComplianceRiskScore(complianceRisk *ComplianceRisk) float64 {
	score := 0.0

	// Violations penalty
	violationCount := len(complianceRisk.Violations)
	score += float64(violationCount) * 25.0 // 25 points per violation

	// Audit requirement factor
	if complianceRisk.AuditRequired {
		score += 15.0
	}

	// Data retention requirement factor
	if complianceRisk.DataRetention {
		score += 10.0
	}

	return math.Min(score, 100.0)
}

func (rra *ResourceRiskAnalyzer) calculateBusinessImpactRiskScore(businessImpactRisk *BusinessImpactRisk) float64 {
	score := 0.0

	// Criticality level contribution
	switch businessImpactRisk.CriticalityLevel {
	case ResourceCriticalityLow:
		score += 0.0
	case ResourceCriticalityMedium:
		score += 15.0
	case ResourceCriticalityHigh:
		score += 35.0
	case ResourceCriticalityCritical:
		score += 60.0
	}

	// Business value factor (normalized to 0-25 points)
	businessValueRisk := businessImpactRisk.BusinessValue / 1000000.0 // Assuming values up to 1M
	score += math.Min(businessValueRisk*25.0, 25.0)

	// Service dependency penalty
	if businessImpactRisk.ServiceDependency {
		score += 15.0
	}

	// Customer impact factor
	switch businessImpactRisk.CustomerImpact {
	case CustomerImpactNone:
		score += 0.0
	case CustomerImpactLow:
		score += 5.0
	case CustomerImpactMedium:
		score += 15.0
	case CustomerImpactHigh:
		score += 30.0
	case CustomerImpactCritical:
		score += 50.0
	}

	return math.Min(score, 100.0)
}

func (rra *ResourceRiskAnalyzer) calculateResourceAmplification(sensitivityRisk *SensitivityRisk, accessPatternRisk *AccessPatternRisk, complianceRisk *ComplianceRisk, businessImpactRisk *BusinessImpactRisk) float64 {
	amplification := 1.0
	highRiskCount := 0

	risks := []float64{
		sensitivityRisk.RiskScore,
		accessPatternRisk.RiskScore,
		complianceRisk.RiskScore,
		businessImpactRisk.RiskScore,
	}

	for _, risk := range risks {
		if risk > 70.0 {
			highRiskCount++
		}
	}

	// Special amplification for critical combinations
	if sensitivityRisk.Sensitivity == ResourceSensitivitySecret || sensitivityRisk.Sensitivity == ResourceSensitivityTopSecret {
		if len(complianceRisk.Violations) > 0 {
			amplification = math.Max(amplification, 1.25) // 25% amplification
		}
	}

	if businessImpactRisk.CriticalityLevel == ResourceCriticalityCritical && !accessPatternRisk.IsTypicalResource {
		amplification = math.Max(amplification, 1.20) // 20% amplification
	}

	// General high-risk combination amplification
	switch highRiskCount {
	case 2:
		amplification = math.Max(amplification, 1.15)
	case 3:
		amplification = math.Max(amplification, 1.30)
	case 4:
		amplification = math.Max(amplification, 1.50)
	}

	return amplification
}

func (rra *ResourceRiskAnalyzer) calculateResourceConfidence(request *RiskAssessmentRequest, sensitivityRisk *SensitivityRisk, accessPatternRisk *AccessPatternRisk, complianceRisk *ComplianceRisk, businessImpactRisk *BusinessImpactRisk) float64 {
	confidence := 0.0
	factors := 0

	// Resource metadata confidence
	if request.ResourceContext != nil {
		confidence += 25.0
	}
	factors++

	// Access history confidence
	if !accessPatternRisk.LastAccessed.IsZero() {
		confidence += 25.0
	}
	factors++

	// Compliance data confidence
	if len(complianceRisk.Requirements) > 0 {
		confidence += 25.0
	}
	factors++

	// Business data confidence
	if businessImpactRisk.BusinessValue > 0 {
		confidence += 25.0
	}
	factors++

	if factors > 0 {
		return confidence / float64(factors) * float64(factors) / 4.0 * 100.0
	}

	return 60.0 // Default moderate confidence for resources
}

// Helper methods

func (rra *ResourceRiskAnalyzer) getRequiredClearance(sensitivity ResourceSensitivity, classification DataClassification) string {
	// Simplified clearance requirement mapping
	switch sensitivity {
	case ResourceSensitivitySecret:
		return "secret"
	case ResourceSensitivityTopSecret:
		return "top_secret"
	case ResourceSensitivityConfidential:
		return "confidential"
	default:
		return ""
	}
}

func (rra *ResourceRiskAnalyzer) validateClearance(userClearance, requiredClearance string) bool {
	if requiredClearance == "" {
		return true
	}
	if userClearance == "" {
		return false
	}

	// Simplified clearance hierarchy
	clearanceHierarchy := map[string]int{
		"public":       0,
		"internal":     1,
		"confidential": 2,
		"secret":       3,
		"top_secret":   4,
	}

	userLevel := clearanceHierarchy[strings.ToLower(userClearance)]
	requiredLevel := clearanceHierarchy[strings.ToLower(requiredClearance)]

	return userLevel >= requiredLevel
}

func (rra *ResourceRiskAnalyzer) isTypicalResourceForUser(userID string, accessHistory *ResourceAccessHistory) bool {
	if userID == "" || accessHistory == nil {
		return false
	}

	frequency, exists := accessHistory.TypicalUsers[userID]
	return exists && frequency > 0.1 // User accesses resource more than 10% of the time
}

func (rra *ResourceRiskAnalyzer) determineAccessFrequency(accessHistory *ResourceAccessHistory) AccessFrequency {
	if accessHistory == nil {
		return AccessFrequencyRare
	}

	// Simplified frequency determination based on access count
	switch {
	case accessHistory.AccessCount > 1000:
		return AccessFrequencyFrequent
	case accessHistory.AccessCount > 100:
		return AccessFrequencyRegular
	case accessHistory.AccessCount > 10:
		return AccessFrequencyOccasional
	default:
		return AccessFrequencyRare
	}
}

func (rra *ResourceRiskAnalyzer) detectUnusualAccess(ctx context.Context, request *RiskAssessmentRequest, accessHistory *ResourceAccessHistory) bool {
	if accessHistory == nil || len(accessHistory.AnomalyHistory) == 0 {
		return false
	}

	// Check for recent anomalies
	recentThreshold := time.Now().Add(-24 * time.Hour)
	for _, anomaly := range accessHistory.AnomalyHistory {
		if anomaly.Timestamp.After(recentThreshold) && !anomaly.Resolved {
			return true
		}
	}

	return false
}

func (rra *ResourceRiskAnalyzer) extractRequirementNames(requirements []ComplianceRequirement) []string {
	names := make([]string, len(requirements))
	for i, req := range requirements {
		names[i] = req.Name
	}
	return names
}

func (rra *ResourceRiskAnalyzer) isAuditRequired(requirements []ComplianceRequirement, request *RiskAssessmentRequest) bool {
	for _, req := range requirements {
		if strings.Contains(strings.ToLower(req.Description), "audit") {
			return true
		}
	}
	return false
}

func (rra *ResourceRiskAnalyzer) hasDataRetentionRequirements(requirements []ComplianceRequirement) bool {
	for _, req := range requirements {
		if strings.Contains(strings.ToLower(req.Description), "retention") {
			return true
		}
	}
	return false
}

// Factory functions for supporting components

func NewResourceSensitivityClassifier() *ResourceSensitivityClassifier {
	return &ResourceSensitivityClassifier{
		classificationRules:     make(map[string]SensitivityRule),
		dataTypeClassifications: map[string]ResourceSensitivity{
			"pii":       ResourceSensitivityConfidential,
			"phi":       ResourceSensitivitySecret,
			"financial": ResourceSensitivityConfidential,
			"public":    ResourceSensitivityPublic,
		},
		resourceCatalogue: make(map[string]ResourceMetadata),
	}
}

func (rsc *ResourceSensitivityClassifier) ClassifyResource(ctx context.Context, resourceContext *ResourceContext) (ResourceSensitivity, error) {
	// Simplified resource classification
	resourceType := strings.ToLower(resourceContext.ResourceType)
	
	switch {
	case strings.Contains(resourceType, "database") || strings.Contains(resourceType, "db"):
		return ResourceSensitivityConfidential, nil
	case strings.Contains(resourceType, "backup") || strings.Contains(resourceType, "archive"):
		return ResourceSensitivityInternal, nil
	case strings.Contains(resourceType, "public") || strings.Contains(resourceType, "web"):
		return ResourceSensitivityPublic, nil
	default:
		return ResourceSensitivityInternal, nil
	}
}

func NewResourceAccessPatternAnalyzer() *ResourceAccessPatternAnalyzer {
	return &ResourceAccessPatternAnalyzer{
		accessHistoryDB: &AccessHistoryDatabase{},
		patternLearner:  &ResourcePatternLearner{},
		anomalyDetector: &ResourceAnomalyDetector{},
	}
}

func (rapa *ResourceAccessPatternAnalyzer) GetAccessHistory(ctx context.Context, resourceID string) (*ResourceAccessHistory, error) {
	// Simplified access history retrieval
	return &ResourceAccessHistory{
		ResourceID:       resourceID,
		AccessCount:      100, // Default values
		UniqueUsers:      10,
		LastAccessed:     time.Now().Add(-24 * time.Hour),
		TypicalUsers:     make(map[string]float64),
		AnomalyHistory:   make([]ResourceAnomalyRecord, 0),
		ComplianceEvents: make([]ComplianceEvent, 0),
	}, nil
}

func NewResourceComplianceValidator() *ResourceComplianceValidator {
	return &ResourceComplianceValidator{
		complianceFrameworks: make(map[string]ComplianceFramework),
		requirementEngine:    &ComplianceRequirementEngine{},
		violationDetector:    &ComplianceViolationDetector{},
	}
}

func (rcv *ResourceComplianceValidator) GetApplicableRequirements(ctx context.Context, resourceContext *ResourceContext) ([]ComplianceRequirement, error) {
	// Simplified requirement retrieval
	requirements := []ComplianceRequirement{}

	// Check compliance flags
	for _, flag := range resourceContext.ComplianceFlags {
		switch strings.ToLower(flag) {
		case "gdpr":
			requirements = append(requirements, ComplianceRequirement{
				RequirementID: "gdpr-001",
				Name:          "GDPR Data Protection",
				Description:   "Ensure proper data protection measures",
				Severity:      "high",
			})
		case "hipaa":
			requirements = append(requirements, ComplianceRequirement{
				RequirementID: "hipaa-001",
				Name:          "HIPAA Privacy Rule",
				Description:   "Protect health information privacy",
				Severity:      "critical",
			})
		}
	}

	return requirements, nil
}

func (rcv *ResourceComplianceValidator) ValidateAccess(ctx context.Context, request *RiskAssessmentRequest, requirements []ComplianceRequirement) ([]string, error) {
	violations := []string{}

	// Simplified compliance validation
	for _, req := range requirements {
		if req.Severity == "critical" && request.UserContext != nil && request.UserContext.SecurityClearance == "" {
			violations = append(violations, fmt.Sprintf("Missing required clearance for %s", req.Name))
		}
	}

	return violations, nil
}

func NewBusinessImpactAssessor() *BusinessImpactAssessor {
	return &BusinessImpactAssessor{
		businessValueCalculator: &BusinessValueCalculator{},
		criticalityAnalyzer:     &ResourceCriticalityAnalyzer{},
		dependencyMapper:        &ServiceDependencyMapper{},
		customerImpactAnalyzer:  &CustomerImpactAnalyzer{},
	}
}

func (bia *BusinessImpactAssessor) AssessResourceCriticality(ctx context.Context, resourceContext *ResourceContext) (ResourceCriticality, error) {
	// Simplified criticality assessment
	resourceType := strings.ToLower(resourceContext.ResourceType)
	
	switch {
	case strings.Contains(resourceType, "production") || strings.Contains(resourceType, "critical"):
		return ResourceCriticalityCritical, nil
	case strings.Contains(resourceType, "database") || strings.Contains(resourceType, "service"):
		return ResourceCriticalityHigh, nil
	case strings.Contains(resourceType, "test") || strings.Contains(resourceType, "dev"):
		return ResourceCriticalityLow, nil
	default:
		return ResourceCriticalityMedium, nil
	}
}

func (bia *BusinessImpactAssessor) CalculateBusinessValue(ctx context.Context, resourceContext *ResourceContext) (float64, error) {
	// Simplified business value calculation
	return 50000.0, nil // Default moderate business value
}

func (bia *BusinessImpactAssessor) HasServiceDependency(ctx context.Context, resourceContext *ResourceContext) (bool, error) {
	// Simplified service dependency check
	return strings.Contains(strings.ToLower(resourceContext.ResourceType), "service"), nil
}

func (bia *BusinessImpactAssessor) AssessCustomerImpact(ctx context.Context, resourceContext *ResourceContext) (CustomerImpact, error) {
	// Simplified customer impact assessment
	resourceType := strings.ToLower(resourceContext.ResourceType)
	
	switch {
	case strings.Contains(resourceType, "customer") || strings.Contains(resourceType, "frontend"):
		return CustomerImpactHigh, nil
	case strings.Contains(resourceType, "api") || strings.Contains(resourceType, "service"):
		return CustomerImpactMedium, nil
	case strings.Contains(resourceType, "internal") || strings.Contains(resourceType, "admin"):
		return CustomerImpactLow, nil
	default:
		return CustomerImpactLow, nil
	}
}

func NewDataClassificationEngine() *DataClassificationEngine {
	return &DataClassificationEngine{
		classificationPolicies: make(map[string]ClassificationPolicy),
		dataDiscoveryEngine:    &DataDiscoveryEngine{},
		labelingService:        &DataLabelingService{},
	}
}

func (dce *DataClassificationEngine) ClassifyData(ctx context.Context, resourceContext *ResourceContext) (DataClassification, error) {
	// Simplified data classification
	resourceName := strings.ToLower(resourceContext.ResourceName)
	
	switch {
	case strings.Contains(resourceName, "public") || strings.Contains(resourceName, "open"):
		return DataClassificationPublic, nil
	case strings.Contains(resourceName, "confidential") || strings.Contains(resourceName, "private"):
		return DataClassificationConfidential, nil
	case strings.Contains(resourceName, "restricted") || strings.Contains(resourceName, "sensitive"):
		return DataClassificationRestricted, nil
	default:
		return DataClassificationInternal, nil
	}
}

// Supporting types (simplified implementations)
type AccessHistoryDatabase struct{}
type ResourcePatternLearner struct{}
type ResourceAnomalyDetector struct{}
type ComplianceRequirementEngine struct{}
type ComplianceViolationDetector struct{}
type BusinessValueCalculator struct{}
type ResourceCriticalityAnalyzer struct{}
type ServiceDependencyMapper struct{}
type CustomerImpactAnalyzer struct{}
type DataDiscoveryEngine struct{}
type DataLabelingService struct{}