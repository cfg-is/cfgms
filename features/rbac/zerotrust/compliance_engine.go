package zerotrust

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ComplianceFrameworkEngine provides compliance validation against major frameworks
type ComplianceFrameworkEngine struct {
	// Framework templates and validators
	frameworks        map[ComplianceFramework]*FrameworkTemplate
	validators        map[ComplianceFramework]ComplianceValidator
	
	// Compliance cache for performance
	complianceCache   *ComplianceCache
	
	// Configuration
	enabledFrameworks []ComplianceFramework
	strictMode        bool
	cacheEnabled      bool
	
	// Statistics and monitoring
	stats            *ComplianceStats
}

// FrameworkTemplate defines the structure and requirements for a compliance framework
type FrameworkTemplate struct {
	Name              string                    `json:"name"`
	Version           string                    `json:"version"`
	Description       string                    `json:"description"`
	Controls          map[string]*ControlTemplate `json:"controls"`
	Categories        []string                  `json:"categories"`
	RequirementLevels []RequirementLevel        `json:"requirement_levels"`
	
	// Framework metadata
	LastUpdated       time.Time                 `json:"last_updated"`
	Authority         string                    `json:"authority"`
	ApplicableRegions []string                  `json:"applicable_regions"`
}

// ControlTemplate defines a specific control within a compliance framework
type ControlTemplate struct {
	ID                string                    `json:"id"`
	Name              string                    `json:"name"`
	Description       string                    `json:"description"`
	Category          string                    `json:"category"`
	RequirementLevel  RequirementLevel          `json:"requirement_level"`
	
	// Control requirements
	Requirements      []ControlRequirement      `json:"requirements"`
	ValidationRules   []ValidationRule          `json:"validation_rules"`
	EvidenceTypes     []EvidenceType            `json:"evidence_types"`
	
	// Implementation guidance
	ImplementationGuidance string               `json:"implementation_guidance"`
	TestProcedures        []TestProcedure       `json:"test_procedures"`
	CommonPitfalls        []string              `json:"common_pitfalls"`
	
	// Relationships
	RelatedControls   []string                  `json:"related_controls"`
	Prerequisites     []string                  `json:"prerequisites"`
}

// ControlRequirement defines specific requirements for a control
type ControlRequirement struct {
	ID                string                    `json:"id"`
	Description       string                    `json:"description"`
	Type              RequirementType           `json:"type"`
	ValidationLogic   string                    `json:"validation_logic"`
	RequiredEvidence  []string                  `json:"required_evidence"`
	Frequency         string                    `json:"frequency"`
	Automated         bool                      `json:"automated"`
}

// ValidationRule defines how to validate a control requirement
type ValidationRule struct {
	ID                string                    `json:"id"`
	Name              string                    `json:"name"`
	Logic             string                    `json:"logic"`
	Parameters        map[string]interface{}    `json:"parameters"`
	ErrorMessage      string                    `json:"error_message"`
	Severity          ValidationSeverity        `json:"severity"`
}

// EvidenceType defines types of evidence that can satisfy control requirements
type EvidenceType struct {
	Type              string                    `json:"type"`
	Description       string                    `json:"description"`
	CollectionMethod  string                    `json:"collection_method"`
	RetentionPeriod   time.Duration             `json:"retention_period"`
	EncryptionRequired bool                     `json:"encryption_required"`
}

// TestProcedure defines how to test a control
type TestProcedure struct {
	ID                string                    `json:"id"`
	Name              string                    `json:"name"`
	Description       string                    `json:"description"`
	Steps             []string                  `json:"steps"`
	ExpectedOutcome   string                    `json:"expected_outcome"`
	Frequency         string                    `json:"frequency"`
	Automated         bool                      `json:"automated"`
}

// ComplianceValidator validates requests against specific compliance frameworks
type ComplianceValidator interface {
	ValidateCompliance(ctx context.Context, request *ZeroTrustAccessRequest, framework ComplianceFramework) (*ComplianceValidationResult, error)
	GetFramework() ComplianceFramework
	GetSupportedControls() []string
}

// ComplianceCache provides high-performance caching for compliance validation results
type ComplianceCache struct {
	entries           map[string]*ComplianceCacheEntry
	mutex            sync.RWMutex
	maxSize          int
	ttl              time.Duration
}

// ComplianceCacheEntry represents a cached compliance validation result
type ComplianceCacheEntry struct {
	Key               string                      `json:"key"`
	Result            *ComplianceValidationResult `json:"result"`
	CreatedAt         time.Time                   `json:"created_at"`
	ExpiresAt         time.Time                   `json:"expires_at"`
	AccessCount       int64                       `json:"access_count"`
	LastAccessed      time.Time                   `json:"last_accessed"`
}

// ComplianceStats tracks compliance engine statistics
type ComplianceStats struct {
	TotalValidations      int64                                     `json:"total_validations"`
	ValidationsByFramework map[ComplianceFramework]int64            `json:"validations_by_framework"`
	PassedValidations     int64                                     `json:"passed_validations"`
	FailedValidations     int64                                     `json:"failed_validations"`
	CachedValidations     int64                                     `json:"cached_validations"`
	
	AverageValidationTime time.Duration                             `json:"average_validation_time"`
	ValidationTimeByFramework map[ComplianceFramework]time.Duration `json:"validation_time_by_framework"`
	
	ControlViolationsCount map[string]int64                        `json:"control_violations_count"`
	MostViolatedControls   []string                                 `json:"most_violated_controls"`
	
	CacheHitRate          float64                                   `json:"cache_hit_rate"`
	LastValidation        time.Time                                 `json:"last_validation"`
	
	mutex                sync.RWMutex
}

// Supporting types

type ValidationSeverity string

const (
	ValidationSeverityInfo     ValidationSeverity = "info"
	ValidationSeverityWarning  ValidationSeverity = "warning"
	ValidationSeverityError    ValidationSeverity = "error"
	ValidationSeverityCritical ValidationSeverity = "critical"
)

// NewComplianceFrameworkEngine creates a new compliance framework engine
func NewComplianceFrameworkEngine(enabledFrameworks []ComplianceFramework) *ComplianceFrameworkEngine {
	engine := &ComplianceFrameworkEngine{
		frameworks:        make(map[ComplianceFramework]*FrameworkTemplate),
		validators:        make(map[ComplianceFramework]ComplianceValidator),
		complianceCache:   NewComplianceCache(1000, 10*time.Minute),
		enabledFrameworks: enabledFrameworks,
		strictMode:        true,
		cacheEnabled:      true,
		stats:            NewComplianceStats(),
	}
	
	// Initialize framework templates
	engine.initializeFrameworkTemplates()
	
	// Register framework validators
	engine.registerFrameworkValidators()
	
	return engine
}

// ValidateCompliance validates a request against all enabled compliance frameworks
func (c *ComplianceFrameworkEngine) ValidateCompliance(ctx context.Context, request *ZeroTrustAccessRequest, policyResults []*PolicyEvaluationResult) (*ComplianceValidationResults, error) {
	startTime := time.Now()
	
	results := &ComplianceValidationResults{
		OverallCompliance:   true,
		FrameworkResults:    make([]*ComplianceValidationResult, 0),
		ViolationsDetected:  make([]*ComplianceViolation, 0),
		RemediationRequired: make([]*RemediationAction, 0),
	}
	
	// Validate against each enabled framework
	for _, framework := range c.enabledFrameworks {
		frameworkResult, err := c.validateFrameworkCompliance(ctx, request, framework, policyResults)
		if err != nil {
			if c.strictMode {
				return nil, fmt.Errorf("compliance validation failed for %s: %w", framework, err)
			}
			// In non-strict mode, log error and continue
			frameworkResult = &ComplianceValidationResult{
				Framework:         framework,
				ControlsEvaluated: []string{},
				ControlsCompliant: []string{},
				ControlsViolated:  []string{"validation_error"},
				ComplianceRate:    0.0,
				ProcessingTime:    time.Since(startTime),
			}
		}
		
		results.FrameworkResults = append(results.FrameworkResults, frameworkResult)
		
		// Check overall compliance
		if frameworkResult.ComplianceRate < 1.0 {
			results.OverallCompliance = false
		}
	}
	
	// Update statistics
	processingTime := time.Since(startTime)
	c.updateStats(len(c.enabledFrameworks), results.OverallCompliance, processingTime)
	
	return results, nil
}

// validateFrameworkCompliance validates against a specific framework
func (c *ComplianceFrameworkEngine) validateFrameworkCompliance(ctx context.Context, request *ZeroTrustAccessRequest, framework ComplianceFramework, policyResults []*PolicyEvaluationResult) (*ComplianceValidationResult, error) {
	startTime := time.Now()
	
	// Check cache first
	if c.cacheEnabled {
		cacheKey := c.generateComplianceCacheKey(request, framework)
		if cachedResult := c.complianceCache.Get(cacheKey); cachedResult != nil {
			c.stats.mutex.Lock()
			c.stats.CachedValidations++
			c.stats.mutex.Unlock()
			return cachedResult, nil
		}
	}
	
	// Get framework validator
	validator, exists := c.validators[framework]
	if !exists {
		return nil, fmt.Errorf("no validator found for framework: %s", framework)
	}
	
	// Perform validation
	result, err := validator.ValidateCompliance(ctx, request, framework)
	if err != nil {
		return nil, fmt.Errorf("framework validation failed: %w", err)
	}
	
	result.ProcessingTime = time.Since(startTime)
	
	// Cache the result
	if c.cacheEnabled {
		cacheKey := c.generateComplianceCacheKey(request, framework)
		c.complianceCache.Put(cacheKey, result)
	}
	
	return result, nil
}

// Framework template initialization

func (c *ComplianceFrameworkEngine) initializeFrameworkTemplates() {
	c.frameworks[ComplianceFrameworkSOC2] = c.createSOC2Template()
	c.frameworks[ComplianceFrameworkISO27001] = c.createISO27001Template()
	c.frameworks[ComplianceFrameworkGDPR] = c.createGDPRTemplate()
	c.frameworks[ComplianceFrameworkHIPAA] = c.createHIPAATemplate()
}

func (c *ComplianceFrameworkEngine) createSOC2Template() *FrameworkTemplate {
	return &FrameworkTemplate{
		Name:              "SOC 2 Type II",
		Version:           "2017",
		Description:       "Service Organization Control 2 Type II compliance framework",
		Authority:         "American Institute of CPAs (AICPA)",
		ApplicableRegions: []string{"US", "Global"},
		LastUpdated:       time.Now(),
		Categories:        []string{"Security", "Availability", "Processing Integrity", "Confidentiality", "Privacy"},
		Controls: map[string]*ControlTemplate{
			"CC6.1": {
				ID:               "CC6.1",
				Name:             "Logical and Physical Access Controls",
				Description:      "The entity implements logical access security software and policies",
				Category:         "Security",
				RequirementLevel: RequirementLevelMust,
				Requirements: []ControlRequirement{
					{
						ID:               "CC6.1-1",
						Description:      "Implement logical access controls for information systems",
						Type:             RequirementTypeAuthentication,
						ValidationLogic:  "access_control.logical_controls_implemented",
						RequiredEvidence: []string{"access_control_policy", "user_access_reviews", "authentication_logs"},
						Frequency:        "continuous",
						Automated:        true,
					},
					{
						ID:               "CC6.1-2",
						Description:      "Multi-factor authentication for privileged access",
						Type:             RequirementTypeMFA,
						ValidationLogic:  "access_control.mfa_enabled_for_privileged",
						RequiredEvidence: []string{"mfa_configuration", "privileged_access_logs"},
						Frequency:        "continuous",
						Automated:        true,
					},
				},
				ValidationRules: []ValidationRule{
					{
						ID:           "SOC2-CC6.1-AUTH",
						Name:         "Authentication Required",
						Logic:        "request.security_context.authentication_method != 'none'",
						Parameters:   map[string]interface{}{"required": true},
						ErrorMessage: "Authentication is required for all access requests",
						Severity:     ValidationSeverityCritical,
					},
					{
						ID:           "SOC2-CC6.1-MFA",
						Name:         "MFA for Privileged Access",
						Logic:        "request.subject_type == 'user' AND request.privilege_level == 'high' IMPLIES request.security_context.mfa_verified == true",
						Parameters:   map[string]interface{}{"privilege_threshold": "high"},
						ErrorMessage: "Multi-factor authentication required for privileged access",
						Severity:     ValidationSeverityCritical,
					},
				},
				EvidenceTypes: []EvidenceType{
					{
						Type:               "authentication_log",
						Description:        "Log of authentication attempts and results",
						CollectionMethod:   "automated",
						RetentionPeriod:    365 * 24 * time.Hour, // 1 year
						EncryptionRequired: true,
					},
				},
				TestProcedures: []TestProcedure{
					{
						ID:              "SOC2-CC6.1-TEST-1",
						Name:            "Authentication Controls Test",
						Description:     "Verify that authentication controls are properly implemented",
						Steps:           []string{"Review access control policies", "Test authentication mechanisms", "Verify MFA implementation"},
						ExpectedOutcome: "All access requests require proper authentication",
						Frequency:       "quarterly",
						Automated:       false,
					},
				},
			},
			"CC6.2": {
				ID:               "CC6.2",
				Name:             "Authorization Controls",
				Description:      "Prior to issuing system credentials and granting access, the entity registers and authorizes new users",
				Category:         "Security",
				RequirementLevel: RequirementLevelMust,
				Requirements: []ControlRequirement{
					{
						ID:               "CC6.2-1",
						Description:      "Implement role-based access control",
						Type:             RequirementTypeAuthorization,
						ValidationLogic:  "access_control.rbac_implemented",
						RequiredEvidence: []string{"rbac_policy", "role_definitions", "access_reviews"},
						Frequency:        "continuous",
						Automated:        true,
					},
				},
				ValidationRules: []ValidationRule{
					{
						ID:           "SOC2-CC6.2-AUTHZ",
						Name:         "Authorization Required",
						Logic:        "rbac_validation.granted == true",
						Parameters:   map[string]interface{}{"require_explicit_grant": true},
						ErrorMessage: "Explicit authorization required for access",
						Severity:     ValidationSeverityCritical,
					},
				},
			},
			"CC6.7": {
				ID:               "CC6.7",
				Name:             "Data Transmission Controls",
				Description:      "The entity restricts the transmission of system data to authorized users",
				Category:         "Security",
				RequirementLevel: RequirementLevelMust,
				Requirements: []ControlRequirement{
					{
						ID:               "CC6.7-1",
						Description:      "Encrypt data in transit",
						Type:             RequirementTypeEncryption,
						ValidationLogic:  "network_security.encryption_in_transit",
						RequiredEvidence: []string{"tls_configuration", "encryption_policies"},
						Frequency:        "continuous",
						Automated:        true,
					},
				},
				ValidationRules: []ValidationRule{
					{
						ID:           "SOC2-CC6.7-TLS",
						Name:         "TLS Required",
						Logic:        "request.environment_context.network.tls_enabled == true",
						Parameters:   map[string]interface{}{"min_tls_version": "1.2"},
						ErrorMessage: "TLS encryption required for data transmission",
						Severity:     ValidationSeverityCritical,
					},
				},
			},
		},
	}
}

func (c *ComplianceFrameworkEngine) createISO27001Template() *FrameworkTemplate {
	return &FrameworkTemplate{
		Name:              "ISO/IEC 27001:2013",
		Version:           "2013",
		Description:       "Information Security Management System requirements",
		Authority:         "International Organization for Standardization (ISO)",
		ApplicableRegions: []string{"Global"},
		LastUpdated:       time.Now(),
		Categories:        []string{"Information Security", "Access Control", "Cryptography", "Operations Security"},
		Controls: map[string]*ControlTemplate{
			"A.9.1": {
				ID:               "A.9.1",
				Name:             "Access Control Policy",
				Description:      "Business requirements of access control",
				Category:         "Access Control",
				RequirementLevel: RequirementLevelMust,
				Requirements: []ControlRequirement{
					{
						ID:               "A.9.1.1",
						Description:      "Establish and maintain access control policy",
						Type:             RequirementTypePolicy,
						ValidationLogic:  "policies.access_control_policy_exists",
						RequiredEvidence: []string{"access_control_policy", "policy_review_records"},
						Frequency:        "annual",
						Automated:        false,
					},
				},
				ValidationRules: []ValidationRule{
					{
						ID:           "ISO27001-A.9.1-POLICY",
						Name:         "Access Control Policy Compliance",
						Logic:        "access_control_policy.documented == true AND access_control_policy.approved == true",
						ErrorMessage: "Access control policy must be documented and approved",
						Severity:     ValidationSeverityError,
					},
				},
			},
			"A.9.2": {
				ID:               "A.9.2",
				Name:             "User Access Management",
				Description:      "User access provisioning process",
				Category:         "Access Control",
				RequirementLevel: RequirementLevelMust,
				Requirements: []ControlRequirement{
					{
						ID:               "A.9.2.1",
						Description:      "Implement user registration and de-registration process",
						Type:             RequirementTypeProcess,
						ValidationLogic:  "user_management.registration_process_implemented",
						RequiredEvidence: []string{"user_registration_procedures", "access_reviews"},
						Frequency:        "continuous",
						Automated:        true,
					},
				},
			},
		},
	}
}

func (c *ComplianceFrameworkEngine) createGDPRTemplate() *FrameworkTemplate {
	return &FrameworkTemplate{
		Name:              "General Data Protection Regulation",
		Version:           "2016/679",
		Description:       "EU data protection regulation",
		Authority:         "European Union",
		ApplicableRegions: []string{"EU", "EEA"},
		LastUpdated:       time.Now(),
		Categories:        []string{"Data Protection", "Privacy", "Consent", "Data Subject Rights"},
		Controls: map[string]*ControlTemplate{
			"Art.25": {
				ID:               "Art.25",
				Name:             "Data Protection by Design and by Default",
				Description:      "Privacy by design and default requirements",
				Category:         "Data Protection",
				RequirementLevel: RequirementLevelMust,
				Requirements: []ControlRequirement{
					{
						ID:               "Art.25-1",
						Description:      "Implement appropriate technical and organizational measures",
						Type:             RequirementTypePrivacy,
						ValidationLogic:  "privacy.technical_measures_implemented",
						RequiredEvidence: []string{"privacy_impact_assessment", "technical_measures_documentation"},
						Frequency:        "continuous",
						Automated:        true,
					},
				},
				ValidationRules: []ValidationRule{
					{
						ID:           "GDPR-Art.25-DESIGN",
						Name:         "Privacy by Design",
						Logic:        "data_processing.privacy_by_design == true",
						ErrorMessage: "Privacy by design principles must be implemented",
						Severity:     ValidationSeverityCritical,
					},
				},
			},
			"Art.32": {
				ID:               "Art.32",
				Name:             "Security of Processing",
				Description:      "Security requirements for personal data processing",
				Category:         "Data Protection",
				RequirementLevel: RequirementLevelMust,
				Requirements: []ControlRequirement{
					{
						ID:               "Art.32-1",
						Description:      "Implement appropriate security measures",
						Type:             RequirementTypeSecurity,
						ValidationLogic:  "security.appropriate_measures_implemented",
						RequiredEvidence: []string{"security_measures_documentation", "risk_assessment"},
						Frequency:        "continuous",
						Automated:        true,
					},
				},
				ValidationRules: []ValidationRule{
					{
						ID:           "GDPR-Art.32-SECURITY",
						Name:         "Security Measures",
						Logic:        "request.data_classification == 'personal' IMPLIES security_measures.implemented == true",
						ErrorMessage: "Appropriate security measures required for personal data",
						Severity:     ValidationSeverityCritical,
					},
				},
			},
		},
	}
}

func (c *ComplianceFrameworkEngine) createHIPAATemplate() *FrameworkTemplate {
	return &FrameworkTemplate{
		Name:              "Health Insurance Portability and Accountability Act",
		Version:           "1996",
		Description:       "US healthcare data protection regulation",
		Authority:         "US Department of Health and Human Services",
		ApplicableRegions: []string{"US"},
		LastUpdated:       time.Now(),
		Categories:        []string{"Administrative Safeguards", "Physical Safeguards", "Technical Safeguards"},
		Controls: map[string]*ControlTemplate{
			"164.312(a)(1)": {
				ID:               "164.312(a)(1)",
				Name:             "Access Control",
				Description:      "Assign unique user identification and automatic logoff",
				Category:         "Technical Safeguards",
				RequirementLevel: RequirementLevelMust,
				Requirements: []ControlRequirement{
					{
						ID:               "164.312(a)(1)-1",
						Description:      "Unique user identification",
						Type:             RequirementTypeIdentification,
						ValidationLogic:  "access_control.unique_user_identification",
						RequiredEvidence: []string{"user_identification_policy", "user_accounts_review"},
						Frequency:        "continuous",
						Automated:        true,
					},
				},
				ValidationRules: []ValidationRule{
					{
						ID:           "HIPAA-164.312(a)(1)-UID",
						Name:         "Unique User Identification",
						Logic:        "request.access_request.subject_id != '' AND request.access_request.subject_id != 'anonymous'",
						ErrorMessage: "Unique user identification required for PHI access",
						Severity:     ValidationSeverityCritical,
					},
				},
			},
		},
	}
}

// Framework validator registration

func (c *ComplianceFrameworkEngine) registerFrameworkValidators() {
	c.validators[ComplianceFrameworkSOC2] = &SOC2Validator{engine: c}
	c.validators[ComplianceFrameworkISO27001] = &ISO27001Validator{engine: c}
	c.validators[ComplianceFrameworkGDPR] = &GDPRValidator{engine: c}
	c.validators[ComplianceFrameworkHIPAA] = &HIPAAValidator{engine: c}
}

// Utility methods

func (c *ComplianceFrameworkEngine) generateComplianceCacheKey(request *ZeroTrustAccessRequest, framework ComplianceFramework) string {
	return fmt.Sprintf("compliance:%s:%s:%s:%s", 
		framework, 
		request.AccessRequest.SubjectId, 
		request.AccessRequest.TenantId, 
		request.RequestID)
}

func (c *ComplianceFrameworkEngine) updateStats(frameworkCount int, passed bool, processingTime time.Duration) {
	c.stats.mutex.Lock()
	defer c.stats.mutex.Unlock()
	
	c.stats.TotalValidations++
	if passed {
		c.stats.PassedValidations++
	} else {
		c.stats.FailedValidations++
	}
	
	// Update average processing time
	alpha := 0.1
	if c.stats.AverageValidationTime == 0 {
		c.stats.AverageValidationTime = processingTime
	} else {
		avgNanos := float64(c.stats.AverageValidationTime.Nanoseconds())
		newNanos := float64(processingTime.Nanoseconds())
		c.stats.AverageValidationTime = time.Duration(int64((1-alpha)*avgNanos + alpha*newNanos))
	}
	
	c.stats.LastValidation = time.Now()
}

// GetStats returns current compliance engine statistics
func (c *ComplianceFrameworkEngine) GetStats() *ComplianceStats {
	c.stats.mutex.RLock()
	defer c.stats.mutex.RUnlock()
	
	// Return a copy to prevent external modification (without copying mutex)
	validationsByFramework := make(map[ComplianceFramework]int64)
	for k, v := range c.stats.ValidationsByFramework {
		validationsByFramework[k] = v
	}
	
	validationTimeByFramework := make(map[ComplianceFramework]time.Duration)
	for k, v := range c.stats.ValidationTimeByFramework {
		validationTimeByFramework[k] = v
	}
	
	controlViolationsCount := make(map[string]int64)
	for k, v := range c.stats.ControlViolationsCount {
		controlViolationsCount[k] = v
	}
	
	return &ComplianceStats{
		TotalValidations:          c.stats.TotalValidations,
		PassedValidations:         c.stats.PassedValidations,
		FailedValidations:        c.stats.FailedValidations,
		CachedValidations:        c.stats.CachedValidations,
		ValidationsByFramework:   validationsByFramework,
		ValidationTimeByFramework: validationTimeByFramework,
		ControlViolationsCount:   controlViolationsCount,
		MostViolatedControls:     append([]string(nil), c.stats.MostViolatedControls...),
		CacheHitRate:             c.stats.CacheHitRate,
		AverageValidationTime:    c.stats.AverageValidationTime,
		LastValidation:           c.stats.LastValidation,
	}
}

// Factory functions

func NewComplianceStats() *ComplianceStats {
	return &ComplianceStats{
		ValidationsByFramework:    make(map[ComplianceFramework]int64),
		ValidationTimeByFramework: make(map[ComplianceFramework]time.Duration),
		ControlViolationsCount:    make(map[string]int64),
		MostViolatedControls:      make([]string, 0),
		LastValidation:           time.Now(),
	}
}

func NewComplianceCache(maxSize int, ttl time.Duration) *ComplianceCache {
	cache := &ComplianceCache{
		entries:  make(map[string]*ComplianceCacheEntry),
		maxSize:  maxSize,
		ttl:      ttl,
	}
	
	// Start cleanup goroutine
	go cache.cleanupLoop()
	
	return cache
}

// ComplianceCache methods

func (cc *ComplianceCache) Get(key string) *ComplianceValidationResult {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	
	entry, exists := cc.entries[key]
	if !exists {
		return nil
	}
	
	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		delete(cc.entries, key)
		return nil
	}
	
	// Update access information
	entry.AccessCount++
	entry.LastAccessed = time.Now()
	
	return entry.Result
}

func (cc *ComplianceCache) Put(key string, result *ComplianceValidationResult) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	
	// Check if we need to evict entries
	if len(cc.entries) >= cc.maxSize {
		cc.evictLRU()
	}
	
	now := time.Now()
	cc.entries[key] = &ComplianceCacheEntry{
		Key:          key,
		Result:       result,
		CreatedAt:    now,
		ExpiresAt:    now.Add(cc.ttl),
		AccessCount:  1,
		LastAccessed: now,
	}
}

func (cc *ComplianceCache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time
	
	for key, entry := range cc.entries {
		if oldestTime.IsZero() || entry.LastAccessed.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.LastAccessed
		}
	}
	
	if oldestKey != "" {
		delete(cc.entries, oldestKey)
	}
}

func (cc *ComplianceCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		cc.cleanup()
	}
}

func (cc *ComplianceCache) cleanup() {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	
	now := time.Now()
	var expiredKeys []string
	
	for key, entry := range cc.entries {
		if now.After(entry.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	for _, key := range expiredKeys {
		delete(cc.entries, key)
	}
}