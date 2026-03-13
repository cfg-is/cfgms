// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/rbac/zerotrust"
	"github.com/cfgis/cfgms/features/tenant"
)

// TenantSecurityPolicyEngine manages and enforces tenant-specific security policies with zero-trust overlay
type TenantSecurityPolicyEngine struct {
	tenantManager   *tenant.Manager
	policies        map[string]*TenantSecurityPolicy
	policyRules     map[string][]SecurityRule
	auditLogger     *TenantSecurityAuditLogger
	isolationEngine *TenantIsolationEngine
	mutex           sync.RWMutex

	// Zero-trust policy overlay integration
	zeroTrustEngine    *zerotrust.ZeroTrustPolicyEngine
	zeroTrustEnabled   bool
	zeroTrustMode      TenantZeroTrustMode
	policyCoordination *TenantPolicyCoordination
}

// TenantSecurityPolicy defines comprehensive security policies for a tenant
type TenantSecurityPolicy struct {
	ID                    string                 `json:"id"`
	TenantID              string                 `json:"tenant_id"`
	Name                  string                 `json:"name"`
	Description           string                 `json:"description"`
	Version               string                 `json:"version"`
	DataSecurityRules     []DataSecurityRule     `json:"data_security_rules"`
	AccessControlRules    []AccessControlRule    `json:"access_control_rules"`
	NetworkSecurityRules  []NetworkSecurityRule  `json:"network_security_rules"`
	ComplianceRules       []ComplianceRule       `json:"compliance_rules"`
	IncidentResponseRules []IncidentResponseRule `json:"incident_response_rules"`
	MonitoringRules       []MonitoringRule       `json:"monitoring_rules"`
	Status                PolicyStatus           `json:"status"`
	EnforcementMode       PolicyEnforcementMode  `json:"enforcement_mode"`
	CreatedBy             string                 `json:"created_by"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
	EffectiveFrom         time.Time              `json:"effective_from"`
	ExpiresAt             *time.Time             `json:"expires_at,omitempty"`
}

// SecurityRule is the base interface for all security rules
type SecurityRule interface {
	GetID() string
	GetName() string
	GetDescription() string
	GetSeverity() RuleSeverity
	Evaluate(ctx context.Context, request *SecurityEvaluationRequest) (*RuleEvaluationResult, error)
}

// DataSecurityRule defines rules for data protection and classification
type DataSecurityRule struct {
	ID                 string             `json:"id"`
	Name               string             `json:"name"`
	Description        string             `json:"description"`
	Severity           RuleSeverity       `json:"severity"`
	DataTypes          []string           `json:"data_types"` // "pii", "phi", "financial", etc.
	Classification     DataClassification `json:"classification"`
	EncryptionRequired bool               `json:"encryption_required"`
	EncryptionLevel    string             `json:"encryption_level"` // "aes128", "aes256", "fips"
	AccessRestrictions []string           `json:"access_restrictions"`
	RetentionPeriod    int                `json:"retention_period"` // Days
	Conditions         []RuleCondition    `json:"conditions"`
}

// AccessControlRule defines rules for access control and authorization
type AccessControlRule struct {
	ID                    string           `json:"id"`
	Name                  string           `json:"name"`
	Description           string           `json:"description"`
	Severity              RuleSeverity     `json:"severity"`
	ResourceTypes         []string         `json:"resource_types"`
	RequiredPermissions   []string         `json:"required_permissions"`
	ForbiddenActions      []string         `json:"forbidden_actions"`
	MaxConcurrentSessions int              `json:"max_concurrent_sessions"`
	SessionTimeout        time.Duration    `json:"session_timeout"`
	MFARequired           bool             `json:"mfa_required"`
	IPWhitelist           []string         `json:"ip_whitelist"`
	IPBlacklist           []string         `json:"ip_blacklist"`
	TimeRestrictions      *TimeRestriction `json:"time_restrictions,omitempty"`
	Conditions            []RuleCondition  `json:"conditions"`
}

// NetworkSecurityRule defines rules for network-level security
type NetworkSecurityRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Description      string           `json:"description"`
	Severity         RuleSeverity     `json:"severity"`
	RequireTLS       bool             `json:"require_tls"`
	MinTLSVersion    string           `json:"min_tls_version"`
	RequireMutualTLS bool             `json:"require_mutual_tls"`
	AllowedProtocols []string         `json:"allowed_protocols"`
	BlockedProtocols []string         `json:"blocked_protocols"`
	AllowedPorts     []int            `json:"allowed_ports"`
	BlockedPorts     []int            `json:"blocked_ports"`
	RateLimits       []RateLimit      `json:"rate_limits"`
	RequireVPNAccess bool             `json:"require_vpn_access"`
	GeoRestrictions  []GeoRestriction `json:"geo_restrictions"`
	Conditions       []RuleCondition  `json:"conditions"`
}

// ComplianceRule defines rules for regulatory compliance
type ComplianceRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	Description          string          `json:"description"`
	Severity             RuleSeverity    `json:"severity"`
	Framework            string          `json:"framework"`   // "hipaa", "gdpr", "sox", etc.
	Requirement          string          `json:"requirement"` // Specific requirement ID
	Controls             []string        `json:"controls"`    // Control IDs
	EvidenceRequired     bool            `json:"evidence_required"`
	AuditFrequency       time.Duration   `json:"audit_frequency"`
	AutoRemediation      bool            `json:"auto_remediation"`
	RemediationActions   []string        `json:"remediation_actions"`
	NotificationRequired bool            `json:"notification_required"`
	Conditions           []RuleCondition `json:"conditions"`
}

// IncidentResponseRule defines rules for incident response and remediation
type IncidentResponseRule struct {
	ID                    string             `json:"id"`
	Name                  string             `json:"name"`
	Description           string             `json:"description"`
	Severity              RuleSeverity       `json:"severity"`
	TriggerEvents         []string           `json:"trigger_events"`
	ResponseActions       []ResponseAction   `json:"response_actions"`
	EscalationRules       []EscalationRule   `json:"escalation_rules"`
	NotificationRules     []NotificationRule `json:"notification_rules"`
	AutoRemediation       bool               `json:"auto_remediation"`
	MaxResponseTime       time.Duration      `json:"max_response_time"`
	RequireManualApproval bool               `json:"require_manual_approval"`
	Conditions            []RuleCondition    `json:"conditions"`
}

// MonitoringRule defines rules for security monitoring and alerting
type MonitoringRule struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Severity        RuleSeverity    `json:"severity"`
	MonitoredEvents []string        `json:"monitored_events"`
	Thresholds      []Threshold     `json:"thresholds"`
	AlertRules      []AlertRule     `json:"alert_rules"`
	SamplingRate    float64         `json:"sampling_rate"`
	RetentionPeriod time.Duration   `json:"retention_period"`
	Conditions      []RuleCondition `json:"conditions"`
}

// TenantZeroTrustMode defines how zero-trust policies overlay tenant security policies
type TenantZeroTrustMode string

const (
	// TenantZeroTrustModeDisabled disables zero-trust policy overlay for tenant security
	TenantZeroTrustModeDisabled TenantZeroTrustMode = "disabled"

	// TenantZeroTrustModeOverlay applies zero-trust policies as an additional security layer
	TenantZeroTrustModeOverlay TenantZeroTrustMode = "overlay"

	// TenantZeroTrustModeEnforced uses zero-trust policies to override tenant security decisions
	TenantZeroTrustModeEnforced TenantZeroTrustMode = "enforced"

	// TenantZeroTrustModeGoverning makes zero-trust policies the primary security control with tenant policies as fallback
	TenantZeroTrustModeGoverning TenantZeroTrustMode = "governing"

	// TenantZeroTrustModeIntegrated deeply integrates zero-trust and tenant policies into unified decisions
	TenantZeroTrustModeIntegrated TenantZeroTrustMode = "integrated"
)

// Supporting types
type PolicyStatus string

const (
	PolicyStatusDraft     PolicyStatus = "draft"
	PolicyStatusActive    PolicyStatus = "active"
	PolicyStatusSuspended PolicyStatus = "suspended"
	PolicyStatusArchived  PolicyStatus = "archived"
)

type PolicyEnforcementMode string

const (
	PolicyEnforcementModeMonitor PolicyEnforcementMode = "monitor" // Log only
	PolicyEnforcementModeWarn    PolicyEnforcementMode = "warn"    // Warn but allow
	PolicyEnforcementModeBlock   PolicyEnforcementMode = "block"   // Block action
)


type RuleSeverity string

const (
	RuleSeverityLow      RuleSeverity = "low"
	RuleSeverityMedium   RuleSeverity = "medium"
	RuleSeverityHigh     RuleSeverity = "high"
	RuleSeverityCritical RuleSeverity = "critical"
)

type DataClassification string

const (
	DataClassificationPublic       DataClassification = "public"
	DataClassificationInternal     DataClassification = "internal"
	DataClassificationConfidential DataClassification = "confidential"
	DataClassificationRestricted   DataClassification = "restricted"
)

type RuleCondition struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type RateLimit struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	WindowSize        time.Duration `json:"window_size"`
}

type GeoRestriction struct {
	Type      string   `json:"type"` // "allow" or "block"
	Countries []string `json:"countries"`
	Regions   []string `json:"regions"`
}

type ResponseAction struct {
	Type       string            `json:"type"`
	Parameters map[string]string `json:"parameters"`
	Priority   int               `json:"priority"`
	Timeout    time.Duration     `json:"timeout"`
}

type EscalationRule struct {
	Condition  string        `json:"condition"`
	Delay      time.Duration `json:"delay"`
	Recipients []string      `json:"recipients"`
}

type Threshold struct {
	Metric     string        `json:"metric"`
	Operator   string        `json:"operator"`
	Value      interface{}   `json:"value"`
	TimeWindow time.Duration `json:"time_window"`
}

type AlertRule struct {
	Condition  string   `json:"condition"`
	Recipients []string `json:"recipients"`
	Channels   []string `json:"channels"`
	Template   string   `json:"template"`
}

// NewTenantSecurityPolicyEngine creates a new tenant security policy engine
func NewTenantSecurityPolicyEngine(tenantManager *tenant.Manager, auditLogger *TenantSecurityAuditLogger, isolationEngine *TenantIsolationEngine) *TenantSecurityPolicyEngine {
	return &TenantSecurityPolicyEngine{
		tenantManager:   tenantManager,
		policies:        make(map[string]*TenantSecurityPolicy),
		policyRules:     make(map[string][]SecurityRule),
		auditLogger:     auditLogger,
		isolationEngine: isolationEngine,
		mutex:           sync.RWMutex{},

		// Zero-trust defaults
		zeroTrustEngine:    nil,
		zeroTrustEnabled:   false,
		zeroTrustMode:      TenantZeroTrustModeDisabled,
		policyCoordination: NewDefaultTenantPolicyCoordination(),
	}
}

// EnableZeroTrustOverlay enables zero-trust policy overlay integration
func (tspe *TenantSecurityPolicyEngine) EnableZeroTrustOverlay(engine *zerotrust.ZeroTrustPolicyEngine, mode TenantZeroTrustMode, coordination *TenantPolicyCoordination) {
	tspe.mutex.Lock()
	defer tspe.mutex.Unlock()

	tspe.zeroTrustEngine = engine
	tspe.zeroTrustMode = mode
	tspe.zeroTrustEnabled = (mode != TenantZeroTrustModeDisabled && engine != nil)

	if coordination != nil {
		tspe.policyCoordination = coordination
	}
}

// SetZeroTrustMode updates the zero-trust overlay mode
func (tspe *TenantSecurityPolicyEngine) SetZeroTrustMode(mode TenantZeroTrustMode) {
	tspe.mutex.Lock()
	defer tspe.mutex.Unlock()

	tspe.zeroTrustMode = mode
	tspe.zeroTrustEnabled = (mode != TenantZeroTrustModeDisabled && tspe.zeroTrustEngine != nil)
}

// GetZeroTrustMode returns the current zero-trust overlay mode
func (tspe *TenantSecurityPolicyEngine) GetZeroTrustMode() TenantZeroTrustMode {
	tspe.mutex.RLock()
	defer tspe.mutex.RUnlock()
	return tspe.zeroTrustMode
}

// CreateSecurityPolicy creates a new tenant security policy
func (tspe *TenantSecurityPolicyEngine) CreateSecurityPolicy(ctx context.Context, policy *TenantSecurityPolicy) error {
	tspe.mutex.Lock()
	defer tspe.mutex.Unlock()

	// Validate the policy
	if err := tspe.validateSecurityPolicy(ctx, policy); err != nil {
		return fmt.Errorf("invalid security policy: %w", err)
	}

	// Generate ID if not provided
	if policy.ID == "" {
		policy.ID = fmt.Sprintf("policy-%s-%d", policy.TenantID, time.Now().Unix())
	}

	// Set timestamps
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now

	if policy.EffectiveFrom.IsZero() {
		policy.EffectiveFrom = now
	}

	// Store the policy
	tspe.policies[policy.ID] = policy

	// Compile and store security rules
	rules, err := tspe.compileSecurityRules(policy)
	if err != nil {
		delete(tspe.policies, policy.ID)
		return fmt.Errorf("failed to compile security rules: %w", err)
	}
	tspe.policyRules[policy.ID] = rules

	// Audit policy creation
	_ = tspe.auditLogger.LogSecurityPolicyChange(ctx, "create", policy.TenantID, policy.ID, policy.Name)

	return nil
}

// EvaluateSecurityPolicy evaluates a security request against tenant policies with zero-trust overlay
func (tspe *TenantSecurityPolicyEngine) EvaluateSecurityPolicy(ctx context.Context, request *SecurityEvaluationRequest) (*SecurityEvaluationResult, error) {
	startTime := time.Now()

	// Step 1: Evaluate standard tenant security policy
	tenantResult, err := tspe.evaluateTenantSecurityPolicy(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate tenant security policy: %w", err)
	}

	// Step 2: Apply zero-trust policy overlay if enabled
	if tspe.zeroTrustEnabled && tspe.zeroTrustEngine != nil {
		overlayResult, err := tspe.evaluateZeroTrustOverlay(ctx, request, tenantResult)
		if err != nil {
			if tspe.policyCoordination.FailSecure {
				tenantResult.Allowed = false
				tenantResult.Decision = "deny_on_zero_trust_error"
				tenantResult.BlockReason = fmt.Sprintf("Zero-trust overlay evaluation failed: %v", err)
			}
			// Log error but continue with tenant policy result if not fail-secure
		} else {
			// Coordinate tenant and zero-trust policy results
			finalResult := tspe.coordinatePolicyResults(ctx, tenantResult, overlayResult)
			finalResult.ProcessingTime = time.Since(startTime)
			return finalResult, nil
		}
	}

	tenantResult.ProcessingTime = time.Since(startTime)
	return tenantResult, nil
}

// evaluateTenantSecurityPolicy performs standard tenant security policy evaluation
func (tspe *TenantSecurityPolicyEngine) evaluateTenantSecurityPolicy(ctx context.Context, request *SecurityEvaluationRequest) (*SecurityEvaluationResult, error) {
	tspe.mutex.RLock()
	defer tspe.mutex.RUnlock()

	result := &SecurityEvaluationResult{
		Request:        request,
		EvaluationTime: time.Now(),
		Allowed:        true,
		Violations:     []RuleViolation{},
		AppliedRules:   []string{},
	}

	// Get tenant policy
	var tenantPolicy *TenantSecurityPolicy
	for _, policy := range tspe.policies {
		if policy.TenantID == request.TenantID && policy.Status == PolicyStatusActive {
			tenantPolicy = policy
			break
		}
	}

	if tenantPolicy == nil {
		// Apply default security policy if no custom policy exists
		return tspe.evaluateDefaultPolicy(ctx, request)
	}

	// Get compiled rules for the policy
	rules, exists := tspe.policyRules[tenantPolicy.ID]
	if !exists {
		return nil, fmt.Errorf("compiled rules not found for policy %s", tenantPolicy.ID)
	}

	// Evaluate each rule
	var criticalViolations, highViolations int
	for _, rule := range rules {
		ruleResult, err := rule.Evaluate(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate rule %s: %w", rule.GetID(), err)
		}

		result.AppliedRules = append(result.AppliedRules, rule.GetID())

		if !ruleResult.Passed {
			violation := RuleViolation{
				RuleID:      rule.GetID(),
				RuleName:    rule.GetName(),
				Severity:    rule.GetSeverity(),
				Description: ruleResult.Description,
				Details:     ruleResult.Details,
			}
			result.Violations = append(result.Violations, violation)

			// Count violations by severity
			switch rule.GetSeverity() {
			case RuleSeverityCritical:
				criticalViolations++
			case RuleSeverityHigh:
				highViolations++
			}
		}
	}

	// Determine final decision based on enforcement mode and violations
	switch tenantPolicy.EnforcementMode {
	case PolicyEnforcementModeMonitor:
		// Allow but log violations
		result.Allowed = true
		result.Decision = "allow_with_monitoring"
	case PolicyEnforcementModeWarn:
		// Allow but warn about violations
		result.Allowed = true
		result.Decision = "allow_with_warning"
		if len(result.Violations) > 0 {
			result.WarningMessage = fmt.Sprintf("Security policy violations detected but action allowed: %d violations", len(result.Violations))
		}
	case PolicyEnforcementModeBlock:
		// Block on any critical or high severity violations
		if criticalViolations > 0 || (highViolations > 0 && tenantPolicy.TenantID != "default") {
			result.Allowed = false
			result.Decision = "block_on_violation"
			result.BlockReason = fmt.Sprintf("Policy violations: %d critical, %d high", criticalViolations, highViolations)
		} else {
			result.Decision = "allow"
		}
	}

	// Audit the tenant policy evaluation
	_ = tspe.auditLogger.LogPolicyEvaluation(ctx, request, result)

	return result, nil
}

// compileSecurityRules compiles policy rules into executable security rules
func (tspe *TenantSecurityPolicyEngine) compileSecurityRules(policy *TenantSecurityPolicy) ([]SecurityRule, error) {
	var rules []SecurityRule

	// Compile data security rules
	for _, dataRule := range policy.DataSecurityRules {
		rule := &CompiledDataSecurityRule{
			BaseRule: BaseRule{
				ID:          dataRule.ID,
				Name:        dataRule.Name,
				Description: dataRule.Description,
				Severity:    dataRule.Severity,
			},
			DataRule: dataRule,
		}
		rules = append(rules, rule)
	}

	// Compile access control rules
	for _, accessRule := range policy.AccessControlRules {
		rule := &CompiledAccessControlRule{
			BaseRule: BaseRule{
				ID:          accessRule.ID,
				Name:        accessRule.Name,
				Description: accessRule.Description,
				Severity:    accessRule.Severity,
			},
			AccessRule: accessRule,
		}
		rules = append(rules, rule)
	}

	// Additional rule types would be compiled similarly...

	return rules, nil
}

// evaluateDefaultPolicy applies default security policies when no custom policy exists
func (tspe *TenantSecurityPolicyEngine) evaluateDefaultPolicy(ctx context.Context, request *SecurityEvaluationRequest) (*SecurityEvaluationResult, error) {
	result := &SecurityEvaluationResult{
		Request:        request,
		EvaluationTime: time.Now(),
		Allowed:        true,
		Decision:       "allow_default",
		AppliedRules:   []string{"default_policy"},
		Violations:     []RuleViolation{},
	}

	// Apply basic default security checks
	if request.ResourceType == "sensitive_data" && !request.HasPermission("data_access") {
		result.Allowed = false
		result.Decision = "block_default"
		result.BlockReason = "Insufficient permissions for sensitive data access"
		result.Violations = append(result.Violations, RuleViolation{
			RuleID:      "default_data_access",
			RuleName:    "Default Data Access Control",
			Severity:    RuleSeverityHigh,
			Description: "Access to sensitive data requires explicit permission",
		})
	}

	return result, nil
}

// validateSecurityPolicy validates a security policy for correctness
func (tspe *TenantSecurityPolicyEngine) validateSecurityPolicy(ctx context.Context, policy *TenantSecurityPolicy) error {
	if policy.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}

	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	if policy.CreatedBy == "" {
		return fmt.Errorf("created by is required")
	}

	// Validate tenant exists
	if tspe.tenantManager != nil {
		if _, err := tspe.tenantManager.GetTenant(ctx, policy.TenantID); err != nil {
			return fmt.Errorf("tenant not found: %w", err)
		}
	}

	return nil
}

// Supporting evaluation types

// SecurityEvaluationRequest represents a request to evaluate security policies
type SecurityEvaluationRequest struct {
	TenantID           string            `json:"tenant_id"`
	SubjectID          string            `json:"subject_id"`
	Action             string            `json:"action"`
	ResourceType       string            `json:"resource_type"`
	ResourceID         string            `json:"resource_id"`
	Context            map[string]string `json:"context"`
	Permissions        []string          `json:"permissions"`
	DataClassification string            `json:"data_classification,omitempty"`
}

// HasPermission checks if the request has a specific permission
func (ser *SecurityEvaluationRequest) HasPermission(permission string) bool {
	for _, p := range ser.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// SecurityEvaluationResult contains the results of a security policy evaluation
type SecurityEvaluationResult struct {
	Request          *SecurityEvaluationRequest `json:"request"`
	EvaluationTime   time.Time                  `json:"evaluation_time"`
	Allowed          bool                       `json:"allowed"`
	Decision         string                     `json:"decision"`
	BlockReason      string                     `json:"block_reason,omitempty"`
	WarningMessage   string                     `json:"warning_message,omitempty"`
	AppliedRules     []string                   `json:"applied_rules"`
	Violations       []RuleViolation            `json:"violations"`
	ZeroTrustOverlay *ZeroTrustOverlayResult    `json:"zero_trust_overlay,omitempty"`
	ProcessingTime   time.Duration              `json:"processing_time"`
}

// RuleViolation represents a security rule violation
type RuleViolation struct {
	RuleID      string                 `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	Severity    RuleSeverity           `json:"severity"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// RuleEvaluationResult contains the result of evaluating a single rule
type RuleEvaluationResult struct {
	Passed      bool                   `json:"passed"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// BaseRule provides common fields for all compiled rule types
type BaseRule struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Severity    RuleSeverity `json:"severity"`
}

func (br *BaseRule) GetID() string             { return br.ID }
func (br *BaseRule) GetName() string           { return br.Name }
func (br *BaseRule) GetDescription() string    { return br.Description }
func (br *BaseRule) GetSeverity() RuleSeverity { return br.Severity }

// CompiledDataSecurityRule is a compiled, evaluatable data security rule
type CompiledDataSecurityRule struct {
	BaseRule
	DataRule DataSecurityRule
}

func (cdsr *CompiledDataSecurityRule) Evaluate(ctx context.Context, request *SecurityEvaluationRequest) (*RuleEvaluationResult, error) {
	result := &RuleEvaluationResult{
		Passed: true,
	}

	// Evaluate data security conditions
	if cdsr.DataRule.EncryptionRequired && request.Context["encrypted"] != "true" {
		result.Passed = false
		result.Description = "Data encryption is required but not present"
		result.Details = map[string]interface{}{
			"required_encryption": true,
			"current_encryption":  request.Context["encrypted"],
		}
	}

	return result, nil
}

// CompiledAccessControlRule is a compiled, evaluatable access control rule
type CompiledAccessControlRule struct {
	BaseRule
	AccessRule AccessControlRule
}

func (cacr *CompiledAccessControlRule) Evaluate(ctx context.Context, request *SecurityEvaluationRequest) (*RuleEvaluationResult, error) {
	result := &RuleEvaluationResult{
		Passed: true,
	}

	// Evaluate access control conditions
	if cacr.AccessRule.MFARequired && request.Context["mfa_verified"] != "true" {
		result.Passed = false
		result.Description = "Multi-factor authentication is required"
		result.Details = map[string]interface{}{
			"mfa_required": true,
			"mfa_verified": request.Context["mfa_verified"],
		}
	}

	return result, nil
}
