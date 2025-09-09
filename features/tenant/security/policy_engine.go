package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/features/rbac/zerotrust"
)

// TenantSecurityPolicyEngine manages and enforces tenant-specific security policies with zero-trust overlay
type TenantSecurityPolicyEngine struct {
	tenantManager    *tenant.Manager
	policies         map[string]*TenantSecurityPolicy
	policyRules      map[string][]SecurityRule
	auditLogger      *TenantSecurityAuditLogger
	isolationEngine  *TenantIsolationEngine
	mutex            sync.RWMutex
	
	// Zero-trust policy overlay integration
	zeroTrustEngine     *zerotrust.ZeroTrustPolicyEngine
	zeroTrustEnabled    bool
	zeroTrustMode       TenantZeroTrustMode
	policyCoordination  *TenantPolicyCoordination
}

// TenantSecurityPolicy defines comprehensive security policies for a tenant
type TenantSecurityPolicy struct {
	ID                    string                     `json:"id"`
	TenantID              string                     `json:"tenant_id"`
	Name                  string                     `json:"name"`
	Description           string                     `json:"description"`
	Version               string                     `json:"version"`
	DataSecurityRules     []DataSecurityRule         `json:"data_security_rules"`
	AccessControlRules    []AccessControlRule        `json:"access_control_rules"`
	NetworkSecurityRules  []NetworkSecurityRule      `json:"network_security_rules"`
	ComplianceRules       []ComplianceRule           `json:"compliance_rules"`
	IncidentResponseRules []IncidentResponseRule     `json:"incident_response_rules"`
	MonitoringRules       []MonitoringRule           `json:"monitoring_rules"`
	Status                PolicyStatus               `json:"status"`
	EnforcementMode       PolicyEnforcementMode      `json:"enforcement_mode"`
	CreatedBy             string                     `json:"created_by"`
	CreatedAt             time.Time                  `json:"created_at"`
	UpdatedAt             time.Time                  `json:"updated_at"`
	EffectiveFrom         time.Time                  `json:"effective_from"`
	ExpiresAt             *time.Time                 `json:"expires_at,omitempty"`
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
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	Severity          RuleSeverity      `json:"severity"`
	DataTypes         []string          `json:"data_types"`         // "pii", "phi", "financial", etc.
	Classification    DataClassification `json:"classification"`
	EncryptionRequired bool             `json:"encryption_required"`
	EncryptionLevel   string            `json:"encryption_level"`   // "aes128", "aes256", "fips"
	AccessRestrictions []string         `json:"access_restrictions"`
	RetentionPeriod   int               `json:"retention_period"`   // Days
	Conditions        []RuleCondition   `json:"conditions"`
}

// AccessControlRule defines rules for access control and authorization
type AccessControlRule struct {
	ID                    string          `json:"id"`
	Name                  string          `json:"name"`
	Description           string          `json:"description"`
	Severity              RuleSeverity    `json:"severity"`
	ResourceTypes         []string        `json:"resource_types"`
	RequiredPermissions   []string        `json:"required_permissions"`
	ForbiddenActions      []string        `json:"forbidden_actions"`
	MaxConcurrentSessions int             `json:"max_concurrent_sessions"`
	SessionTimeout        time.Duration   `json:"session_timeout"`
	MFARequired           bool            `json:"mfa_required"`
	IPWhitelist           []string        `json:"ip_whitelist"`
	IPBlacklist           []string        `json:"ip_blacklist"`
	TimeRestrictions      *TimeRestriction `json:"time_restrictions,omitempty"`
	Conditions            []RuleCondition `json:"conditions"`
}

// NetworkSecurityRule defines rules for network-level security
type NetworkSecurityRule struct {
	ID                     string          `json:"id"`
	Name                   string          `json:"name"`
	Description            string          `json:"description"`
	Severity               RuleSeverity    `json:"severity"`
	RequireTLS             bool            `json:"require_tls"`
	MinTLSVersion          string          `json:"min_tls_version"`
	RequireMutualTLS       bool            `json:"require_mutual_tls"`
	AllowedProtocols       []string        `json:"allowed_protocols"`
	BlockedProtocols       []string        `json:"blocked_protocols"`
	AllowedPorts           []int           `json:"allowed_ports"`
	BlockedPorts           []int           `json:"blocked_ports"`
	RateLimits             []RateLimit     `json:"rate_limits"`
	RequireVPNAccess       bool            `json:"require_vpn_access"`
	GeoRestrictions        []GeoRestriction `json:"geo_restrictions"`
	Conditions             []RuleCondition `json:"conditions"`
}

// ComplianceRule defines rules for regulatory compliance
type ComplianceRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	Description          string          `json:"description"`
	Severity             RuleSeverity    `json:"severity"`
	Framework            string          `json:"framework"`        // "hipaa", "gdpr", "sox", etc.
	Requirement          string          `json:"requirement"`      // Specific requirement ID
	Controls             []string        `json:"controls"`         // Control IDs
	EvidenceRequired     bool            `json:"evidence_required"`
	AuditFrequency       time.Duration   `json:"audit_frequency"`
	AutoRemediation      bool            `json:"auto_remediation"`
	RemediationActions   []string        `json:"remediation_actions"`
	NotificationRequired bool            `json:"notification_required"`
	Conditions           []RuleCondition `json:"conditions"`
}

// IncidentResponseRule defines rules for incident response and remediation
type IncidentResponseRule struct {
	ID                  string              `json:"id"`
	Name                string              `json:"name"`
	Description         string              `json:"description"`
	Severity            RuleSeverity        `json:"severity"`
	TriggerEvents       []string            `json:"trigger_events"`
	ResponseActions     []ResponseAction    `json:"response_actions"`
	EscalationRules     []EscalationRule    `json:"escalation_rules"`
	NotificationRules   []NotificationRule  `json:"notification_rules"`
	AutoRemediation     bool                `json:"auto_remediation"`
	MaxResponseTime     time.Duration       `json:"max_response_time"`
	RequireManualApproval bool              `json:"require_manual_approval"`
	Conditions          []RuleCondition     `json:"conditions"`
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

// Supporting types
type PolicyStatus string
const (
	PolicyStatusDraft    PolicyStatus = "draft"
	PolicyStatusActive   PolicyStatus = "active"
	PolicyStatusSuspended PolicyStatus = "suspended"
	PolicyStatusArchived PolicyStatus = "archived"
)

type PolicyEnforcementMode string
const (
	PolicyEnforcementModeMonitor PolicyEnforcementMode = "monitor"  // Log only
	PolicyEnforcementModeWarn   PolicyEnforcementMode = "warn"     // Warn but allow
	PolicyEnforcementModeBlock  PolicyEnforcementMode = "block"    // Block action
)

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

// TenantPolicyCoordination manages coordination between tenant security policies and zero-trust policies
type TenantPolicyCoordination struct {
	CoordinationMode      TenantCoordinationMode     `json:"coordination_mode"`
	PolicyPriority        PolicyPriority             `json:"policy_priority"`
	ConflictResolution    ConflictResolutionStrategy `json:"conflict_resolution"`
	ValidationRules       []CoordinationRule         `json:"validation_rules"`
	AuditingEnabled       bool                       `json:"auditing_enabled"`
	FailSecure           bool                       `json:"fail_secure"`
}

// TenantCoordinationMode defines how tenant and zero-trust policies coordinate
type TenantCoordinationMode string

const (
	TenantCoordinationModeSequential TenantCoordinationMode = "sequential" // Evaluate tenant policies first, then zero-trust
	TenantCoordinationModeParallel   TenantCoordinationMode = "parallel"   // Evaluate both simultaneously
	TenantCoordinationModeHierarchy  TenantCoordinationMode = "hierarchy"  // Use policy priority to determine order
)

// PolicyPriority defines priority between tenant and zero-trust policies
type PolicyPriority string

const (
	PolicyPriorityTenantFirst     PolicyPriority = "tenant_first"     // Tenant policies take precedence
	PolicyPriorityZeroTrustFirst  PolicyPriority = "zero_trust_first" // Zero-trust policies take precedence
	PolicyPriorityBothRequired    PolicyPriority = "both_required"    // Both policies must pass
	PolicyPriorityEitherSufficient PolicyPriority = "either_sufficient" // Either policy passing is sufficient
)

// ConflictResolutionStrategy defines how to resolve conflicts between policies
type ConflictResolutionStrategy string

const (
	ConflictResolutionDenyWins       ConflictResolutionStrategy = "deny_wins"       // Any deny decision wins
	ConflictResolutionAllowWins      ConflictResolutionStrategy = "allow_wins"      // Any allow decision wins
	ConflictResolutionHigherSecurity ConflictResolutionStrategy = "higher_security" // More restrictive decision wins
	ConflictResolutionManualReview   ConflictResolutionStrategy = "manual_review"   // Flag for manual review
)

// CoordinationRule defines rules for policy coordination
type CoordinationRule struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Condition    string          `json:"condition"`
	Action       string          `json:"action"`
	Priority     int             `json:"priority"`
	Parameters   map[string]interface{} `json:"parameters"`
}

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
	Type      string   `json:"type"`      // "allow" or "block"
	Countries []string `json:"countries"`
	Regions   []string `json:"regions"`
}

type ResponseAction struct {
	Type        string            `json:"type"`
	Parameters  map[string]string `json:"parameters"`
	Priority    int               `json:"priority"`
	Timeout     time.Duration     `json:"timeout"`
}

type EscalationRule struct {
	Condition  string        `json:"condition"`
	Delay      time.Duration `json:"delay"`
	Recipients []string      `json:"recipients"`
}

type Threshold struct {
	Metric    string      `json:"metric"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	TimeWindow time.Duration `json:"time_window"`
}

type AlertRule struct {
	Condition   string   `json:"condition"`
	Recipients  []string `json:"recipients"`
	Channels    []string `json:"channels"`
	Template    string   `json:"template"`
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

// evaluateZeroTrustOverlay evaluates zero-trust policies as an overlay to tenant policies
func (tspe *TenantSecurityPolicyEngine) evaluateZeroTrustOverlay(ctx context.Context, request *SecurityEvaluationRequest, tenantResult *SecurityEvaluationResult) (*ZeroTrustOverlayResult, error) {
	// Convert security evaluation request to zero-trust access request
	zeroTrustRequest := tspe.convertToZeroTrustRequest(request, tenantResult)
	
	// Evaluate zero-trust policies
	zeroTrustResponse, err := tspe.zeroTrustEngine.EvaluateAccess(ctx, zeroTrustRequest)
	if err != nil {
		return nil, fmt.Errorf("zero-trust policy evaluation failed: %w", err)
	}
	
	// Create overlay result
	overlayResult := &ZeroTrustOverlayResult{
		OverlayMode:         tspe.zeroTrustMode,
		ZeroTrustResponse:   zeroTrustResponse,
		TenantGranted:       tenantResult.Allowed,
		ZeroTrustGranted:    zeroTrustResponse.Granted,
		ConflictDetected:    tenantResult.Allowed != zeroTrustResponse.Granted,
		EvaluationTime:      time.Now(),
		ProcessingTime:      time.Duration(zeroTrustResponse.ProcessingTime.Nanoseconds()),
	}
	
	// Calculate alignment score between tenant and zero-trust policies
	overlayResult.AlignmentScore = tspe.calculatePolicyAlignment(tenantResult, zeroTrustResponse)
	
	// Determine recommended action based on overlay mode
	overlayResult.RecommendedAction = tspe.determineOverlayAction(tenantResult.Allowed, zeroTrustResponse.Granted)
	overlayResult.OverlayReason = tspe.buildOverlayReason(tenantResult, zeroTrustResponse, overlayResult.AlignmentScore)
	
	return overlayResult, nil
}

// coordinatePolicyResults coordinates tenant and zero-trust policy results into a final decision
func (tspe *TenantSecurityPolicyEngine) coordinatePolicyResults(ctx context.Context, tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	var finalResult *SecurityEvaluationResult
	
	// Apply coordination logic based on mode and priority
	switch tspe.zeroTrustMode {
	case TenantZeroTrustModeOverlay:
		finalResult = tspe.applyOverlayMode(tenantResult, overlayResult)
		
	case TenantZeroTrustModeEnforced:
		finalResult = tspe.applyEnforcedMode(tenantResult, overlayResult)
		
	case TenantZeroTrustModeGoverning:
		finalResult = tspe.applyGoverningMode(tenantResult, overlayResult)
		
	case TenantZeroTrustModeIntegrated:
		finalResult = tspe.applyIntegratedMode(tenantResult, overlayResult)
		
	default: // TenantZeroTrustModeDisabled
		finalResult = tenantResult
	}
	
	// Apply conflict resolution if there's a conflict
	if overlayResult.ConflictDetected {
		finalResult = tspe.applyConflictResolution(finalResult, tenantResult, overlayResult)
	}
	
	// Audit the coordinated evaluation
	_ = tspe.auditLogger.LogZeroTrustOverlayEvaluation(ctx, tenantResult.Request, finalResult)
	
	return finalResult
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
type SecurityEvaluationRequest struct {
	TenantID        string            `json:"tenant_id"`
	SubjectID       string            `json:"subject_id"`
	Action          string            `json:"action"`
	ResourceType    string            `json:"resource_type"`
	ResourceID      string            `json:"resource_id"`
	Context         map[string]string `json:"context"`
	Permissions     []string          `json:"permissions"`
	DataClassification string         `json:"data_classification,omitempty"`
}

// ZeroTrustOverlayResult contains the results of zero-trust policy overlay evaluation
type ZeroTrustOverlayResult struct {
	OverlayMode         TenantZeroTrustMode                `json:"overlay_mode"`
	ZeroTrustResponse   *zerotrust.ZeroTrustAccessResponse `json:"zero_trust_response"`
	TenantGranted       bool                               `json:"tenant_granted"`
	ZeroTrustGranted    bool                               `json:"zero_trust_granted"`
	ConflictDetected    bool                               `json:"conflict_detected"`
	AlignmentScore      float64                            `json:"alignment_score"`
	RecommendedAction   string                             `json:"recommended_action"`
	OverlayReason       string                             `json:"overlay_reason"`
	EvaluationTime      time.Time                          `json:"evaluation_time"`
	ProcessingTime      time.Duration                      `json:"processing_time"`
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

type SecurityEvaluationResult struct {
	Request        *SecurityEvaluationRequest `json:"request"`
	EvaluationTime time.Time                  `json:"evaluation_time"`
	Allowed        bool                       `json:"allowed"`
	Decision       string                     `json:"decision"`
	BlockReason    string                     `json:"block_reason,omitempty"`
	WarningMessage string                     `json:"warning_message,omitempty"`
	AppliedRules   []string                   `json:"applied_rules"`
	Violations     []RuleViolation            `json:"violations"`
	ZeroTrustOverlay *ZeroTrustOverlayResult  `json:"zero_trust_overlay,omitempty"`
	ProcessingTime time.Duration              `json:"processing_time"`
}

type RuleViolation struct {
	RuleID      string                 `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	Severity    RuleSeverity           `json:"severity"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

type RuleEvaluationResult struct {
	Passed      bool                   `json:"passed"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// Base rule implementation
type BaseRule struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Severity    RuleSeverity `json:"severity"`
}

func (br *BaseRule) GetID() string          { return br.ID }
func (br *BaseRule) GetName() string        { return br.Name }
func (br *BaseRule) GetDescription() string { return br.Description }
func (br *BaseRule) GetSeverity() RuleSeverity { return br.Severity }

// Compiled rule implementations
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
			"mfa_required":  true,
			"mfa_verified": request.Context["mfa_verified"],
		}
	}

	return result, nil
}

// Additional audit logger method
func (tsal *TenantSecurityAuditLogger) LogSecurityPolicyChange(ctx context.Context, action, tenantID, policyID, policyName string) error {
	entry := TenantSecurityAuditEntry{
		ID:        fmt.Sprintf("policy-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		EventType: TenantSecurityEventSecurityPolicyChange,
		TenantID:  tenantID,
		Action:    action,
		Result:    "success",
		Severity:  AuditSeverityInfo,
		Details: map[string]interface{}{
			"policy_id":   policyID,
			"policy_name": policyName,
		},
	}

	return tsal.addEntry(entry)
}

func (tsal *TenantSecurityAuditLogger) LogPolicyEvaluation(ctx context.Context, request *SecurityEvaluationRequest, result *SecurityEvaluationResult) error {
	severity := AuditSeverityInfo
	if !result.Allowed {
		severity = AuditSeverityWarning
	}

	entry := TenantSecurityAuditEntry{
		ID:        fmt.Sprintf("eval-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		EventType: TenantSecurityEventAccessAttempt,
		TenantID:  request.TenantID,
		SubjectID: request.SubjectID,
		ResourceID: request.ResourceID,
		Action:    request.Action,
		Result:    result.Decision,
		Severity:  severity,
		Details: map[string]interface{}{
			"allowed":       result.Allowed,
			"violations":    len(result.Violations),
			"applied_rules": result.AppliedRules,
		},
	}

	return tsal.addEntry(entry)
}

func (tsal *TenantSecurityAuditLogger) LogZeroTrustOverlayEvaluation(ctx context.Context, request *SecurityEvaluationRequest, result *SecurityEvaluationResult) error {
	severity := AuditSeverityInfo
	if !result.Allowed {
		severity = AuditSeverityWarning
	}
	
	details := map[string]interface{}{
		"final_allowed":     result.Allowed,
		"final_decision":    result.Decision,
		"violations":        len(result.Violations),
		"applied_rules":     result.AppliedRules,
		"processing_time_ms": result.ProcessingTime.Milliseconds(),
	}
	
	if result.ZeroTrustOverlay != nil {
		details["overlay_mode"] = result.ZeroTrustOverlay.OverlayMode
		details["tenant_granted"] = result.ZeroTrustOverlay.TenantGranted
		details["zero_trust_granted"] = result.ZeroTrustOverlay.ZeroTrustGranted
		details["conflict_detected"] = result.ZeroTrustOverlay.ConflictDetected
		details["alignment_score"] = result.ZeroTrustOverlay.AlignmentScore
		details["recommended_action"] = result.ZeroTrustOverlay.RecommendedAction
	}

	entry := TenantSecurityAuditEntry{
		ID:         fmt.Sprintf("overlay-eval-%d", time.Now().UnixNano()),
		Timestamp:  time.Now(),
		EventType:  TenantSecurityEventZeroTrustOverlay,
		TenantID:   request.TenantID,
		SubjectID:  request.SubjectID,
		ResourceID: request.ResourceID,
		Action:     request.Action,
		Result:     result.Decision,
		Severity:   severity,
		Details:    details,
	}

	return tsal.addEntry(entry)
}

// Zero-trust overlay helper methods

// NewDefaultTenantPolicyCoordination creates default policy coordination configuration
func NewDefaultTenantPolicyCoordination() *TenantPolicyCoordination {
	return &TenantPolicyCoordination{
		CoordinationMode:   TenantCoordinationModeSequential,
		PolicyPriority:     PolicyPriorityBothRequired,
		ConflictResolution: ConflictResolutionDenyWins,
		ValidationRules:    []CoordinationRule{},
		AuditingEnabled:    true,
		FailSecure:         true,
	}
}

// convertToZeroTrustRequest converts a security evaluation request to a zero-trust access request
func (tspe *TenantSecurityPolicyEngine) convertToZeroTrustRequest(request *SecurityEvaluationRequest, tenantResult *SecurityEvaluationResult) *zerotrust.ZeroTrustAccessRequest {
	zeroTrustRequest := &zerotrust.ZeroTrustAccessRequest{
		RequestID:     fmt.Sprintf("tenant-zt-%d", time.Now().UnixNano()),
		RequestTime:   time.Now(),
		SubjectType:   zerotrust.SubjectTypeUser,
		ResourceType:  request.ResourceType,
		SourceSystem:  "tenant-security",
		RequestSource: zerotrust.RequestSourceSystem,
		Priority:      zerotrust.RequestPriorityNormal,
	}

	// Set subject attributes with tenant context
	if zeroTrustRequest.SubjectAttributes == nil {
		zeroTrustRequest.SubjectAttributes = make(map[string]interface{})
	}
	
	zeroTrustRequest.SubjectAttributes["tenant_id"] = request.TenantID
	zeroTrustRequest.SubjectAttributes["subject_id"] = request.SubjectID
	zeroTrustRequest.SubjectAttributes["tenant_granted"] = tenantResult.Allowed
	zeroTrustRequest.SubjectAttributes["tenant_decision"] = tenantResult.Decision
	zeroTrustRequest.SubjectAttributes["tenant_violations"] = len(tenantResult.Violations)
	zeroTrustRequest.SubjectAttributes["permissions"] = request.Permissions
	
	if request.DataClassification != "" {
		zeroTrustRequest.SubjectAttributes["data_classification"] = request.DataClassification
	}

	// Extract environmental context from request context
	if len(request.Context) > 0 {
		zeroTrustRequest.EnvironmentContext = &zerotrust.EnvironmentContext{}
		
		if ip, exists := request.Context["source_ip"]; exists {
			zeroTrustRequest.EnvironmentContext.IPAddress = ip
		}
		
		zeroTrustRequest.SecurityContext = &zerotrust.SecurityContext{
			TrustLevel: zerotrust.TrustLevelMedium, // Default trust level
		}
		
		if authMethod, exists := request.Context["auth_method"]; exists {
			zeroTrustRequest.SecurityContext.AuthenticationMethod = authMethod
		}
		
		if mfaVerified := request.Context["mfa_verified"]; mfaVerified == "true" {
			zeroTrustRequest.SecurityContext.MFAVerified = true
		}
	}

	return zeroTrustRequest
}

// calculatePolicyAlignment calculates alignment score between tenant and zero-trust policy decisions
func (tspe *TenantSecurityPolicyEngine) calculatePolicyAlignment(tenantResult *SecurityEvaluationResult, ztResponse *zerotrust.ZeroTrustAccessResponse) float64 {
	// Perfect alignment when both decisions agree
	if tenantResult.Allowed == ztResponse.Granted {
		return 1.0
	}
	
	// Partial alignment based on violations and policy confidence
	baseAlignment := 0.2 // Base misalignment penalty
	
	// Factor in tenant policy violations
	if len(tenantResult.Violations) > 0 && !ztResponse.Granted {
		// Zero-trust denying with tenant violations indicates good alignment
		violationAlignment := 0.4
		baseAlignment += violationAlignment
	}
	
	// Factor in zero-trust policy confidence (based on applied policies)
	policyConfidence := float64(len(ztResponse.AppliedPolicies)) * 0.1
	if policyConfidence > 0.4 {
		policyConfidence = 0.4 // Cap at 0.4
	}
	baseAlignment += policyConfidence
	
	// Cap final alignment score
	if baseAlignment > 1.0 {
		baseAlignment = 1.0
	}
	
	return baseAlignment
}

// determineOverlayAction determines the recommended action based on tenant and zero-trust decisions
func (tspe *TenantSecurityPolicyEngine) determineOverlayAction(tenantGranted, zeroTrustGranted bool) string {
	switch tspe.zeroTrustMode {
	case TenantZeroTrustModeOverlay:
		// Overlay mode - both policies must agree for allow
		if tenantGranted && zeroTrustGranted {
			return "allow"
		}
		return "deny"
		
	case TenantZeroTrustModeEnforced:
		// Enforced mode - zero-trust decision overrides tenant decision
		if zeroTrustGranted {
			return "allow"
		}
		return "deny"
		
	case TenantZeroTrustModeGoverning:
		// Governing mode - zero-trust first, tenant as fallback
		if zeroTrustGranted {
			return "allow"
		}
		if tenantGranted {
			return "allow_fallback"
		}
		return "deny"
		
	case TenantZeroTrustModeIntegrated:
		// Integrated mode - use policy priority to determine action
		return tspe.determineIntegratedAction(tenantGranted, zeroTrustGranted)
		
	default:
		// Default - use tenant decision
		if tenantGranted {
			return "allow"
		}
		return "deny"
	}
}

// determineIntegratedAction determines action for integrated mode based on policy priority
func (tspe *TenantSecurityPolicyEngine) determineIntegratedAction(tenantGranted, zeroTrustGranted bool) string {
	switch tspe.policyCoordination.PolicyPriority {
	case PolicyPriorityTenantFirst:
		if tenantGranted {
			return "allow"
		}
		return "deny"
		
	case PolicyPriorityZeroTrustFirst:
		if zeroTrustGranted {
			return "allow"
		}
		return "deny"
		
	case PolicyPriorityBothRequired:
		if tenantGranted && zeroTrustGranted {
			return "allow"
		}
		return "deny"
		
	case PolicyPriorityEitherSufficient:
		if tenantGranted || zeroTrustGranted {
			return "allow"
		}
		return "deny"
		
	default:
		// Default to requiring both
		if tenantGranted && zeroTrustGranted {
			return "allow"
		}
		return "deny"
	}
}

// buildOverlayReason creates a descriptive reason for the overlay decision
func (tspe *TenantSecurityPolicyEngine) buildOverlayReason(tenantResult *SecurityEvaluationResult, ztResponse *zerotrust.ZeroTrustAccessResponse, alignmentScore float64) string {
	return fmt.Sprintf("Tenant: %t, ZeroTrust: %t, Alignment: %.2f, Mode: %s", 
		tenantResult.Allowed, ztResponse.Granted, alignmentScore, tspe.zeroTrustMode)
}

// Overlay mode application methods

// applyOverlayMode applies overlay mode coordination logic
func (tspe *TenantSecurityPolicyEngine) applyOverlayMode(tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	finalResult := &SecurityEvaluationResult{
		Request:          tenantResult.Request,
		EvaluationTime:   tenantResult.EvaluationTime,
		Violations:       tenantResult.Violations,
		AppliedRules:     tenantResult.AppliedRules,
		ZeroTrustOverlay: overlayResult,
	}
	
	// Overlay mode - both policies must pass for allow
	finalResult.Allowed = tenantResult.Allowed && overlayResult.ZeroTrustGranted
	
	if finalResult.Allowed {
		finalResult.Decision = "allow_overlay"
	} else if !tenantResult.Allowed {
		finalResult.Decision = "deny_tenant_policy" 
		finalResult.BlockReason = tenantResult.BlockReason
	} else {
		finalResult.Decision = "deny_zero_trust_overlay"
		finalResult.BlockReason = "Zero-trust overlay denied access"
	}
	
	return finalResult
}

// applyEnforcedMode applies enforced mode coordination logic
func (tspe *TenantSecurityPolicyEngine) applyEnforcedMode(tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	finalResult := &SecurityEvaluationResult{
		Request:          tenantResult.Request,
		EvaluationTime:   tenantResult.EvaluationTime,
		Violations:       tenantResult.Violations,
		AppliedRules:     tenantResult.AppliedRules,
		ZeroTrustOverlay: overlayResult,
	}
	
	// Enforced mode - zero-trust decision overrides tenant decision
	finalResult.Allowed = overlayResult.ZeroTrustGranted
	
	if finalResult.Allowed {
		finalResult.Decision = "allow_zero_trust_enforced"
	} else {
		finalResult.Decision = "deny_zero_trust_enforced"
		finalResult.BlockReason = "Zero-trust enforcement denied access"
	}
	
	return finalResult
}

// applyGoverningMode applies governing mode coordination logic
func (tspe *TenantSecurityPolicyEngine) applyGoverningMode(tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	finalResult := &SecurityEvaluationResult{
		Request:          tenantResult.Request,
		EvaluationTime:   tenantResult.EvaluationTime,
		Violations:       tenantResult.Violations,
		AppliedRules:     tenantResult.AppliedRules,
		ZeroTrustOverlay: overlayResult,
	}
	
	// Governing mode - zero-trust first, tenant as fallback
	if overlayResult.ZeroTrustGranted {
		finalResult.Allowed = true
		finalResult.Decision = "allow_zero_trust_governing"
	} else if tenantResult.Allowed {
		finalResult.Allowed = true
		finalResult.Decision = "allow_tenant_fallback"
	} else {
		finalResult.Allowed = false
		finalResult.Decision = "deny_both_governing"
		finalResult.BlockReason = "Both zero-trust and tenant policies denied access"
	}
	
	return finalResult
}

// applyIntegratedMode applies integrated mode coordination logic
func (tspe *TenantSecurityPolicyEngine) applyIntegratedMode(tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	finalResult := &SecurityEvaluationResult{
		Request:          tenantResult.Request,
		EvaluationTime:   tenantResult.EvaluationTime,
		Violations:       tenantResult.Violations,
		AppliedRules:     tenantResult.AppliedRules,
		ZeroTrustOverlay: overlayResult,
	}
	
	// Integrated mode - use policy priority and coordination rules
	switch tspe.policyCoordination.PolicyPriority {
	case PolicyPriorityTenantFirst:
		finalResult.Allowed = tenantResult.Allowed
		finalResult.Decision = "integrated_tenant_first"
		
	case PolicyPriorityZeroTrustFirst:
		finalResult.Allowed = overlayResult.ZeroTrustGranted
		finalResult.Decision = "integrated_zero_trust_first"
		
	case PolicyPriorityBothRequired:
		finalResult.Allowed = tenantResult.Allowed && overlayResult.ZeroTrustGranted
		finalResult.Decision = "integrated_both_required"
		
	case PolicyPriorityEitherSufficient:
		finalResult.Allowed = tenantResult.Allowed || overlayResult.ZeroTrustGranted
		finalResult.Decision = "integrated_either_sufficient"
		
	default:
		// Default to both required
		finalResult.Allowed = tenantResult.Allowed && overlayResult.ZeroTrustGranted
		finalResult.Decision = "integrated_default"
	}
	
	if !finalResult.Allowed {
		finalResult.BlockReason = "Integrated policy evaluation denied access"
	}
	
	return finalResult
}

// applyConflictResolution applies conflict resolution strategy
func (tspe *TenantSecurityPolicyEngine) applyConflictResolution(finalResult, tenantResult *SecurityEvaluationResult, overlayResult *ZeroTrustOverlayResult) *SecurityEvaluationResult {
	switch tspe.policyCoordination.ConflictResolution {
	case ConflictResolutionDenyWins:
		// Any deny decision wins
		if !tenantResult.Allowed || !overlayResult.ZeroTrustGranted {
			finalResult.Allowed = false
			finalResult.Decision = "deny_conflict_resolution"
			finalResult.BlockReason = "Conflict resolution: deny wins"
		}
		
	case ConflictResolutionAllowWins:
		// Any allow decision wins
		if tenantResult.Allowed || overlayResult.ZeroTrustGranted {
			finalResult.Allowed = true
			finalResult.Decision = "allow_conflict_resolution"
			finalResult.BlockReason = ""
		}
		
	case ConflictResolutionHigherSecurity:
		// More restrictive decision wins (deny over allow)
		if !tenantResult.Allowed || !overlayResult.ZeroTrustGranted {
			finalResult.Allowed = false
			finalResult.Decision = "deny_higher_security"
			finalResult.BlockReason = "Conflict resolution: higher security wins"
		}
		
	case ConflictResolutionManualReview:
		// Flag for manual review
		finalResult.Allowed = false
		finalResult.Decision = "pending_manual_review"
		finalResult.BlockReason = "Policy conflict requires manual review"
		
		// Add manual review flag to violations
		manualReviewViolation := RuleViolation{
			RuleID:      "conflict_resolution",
			RuleName:    "Manual Review Required",
			Severity:    RuleSeverityHigh,
			Description: "Policy conflict detected between tenant and zero-trust policies",
			Details: map[string]interface{}{
				"tenant_decision":     tenantResult.Decision,
				"zero_trust_granted":  overlayResult.ZeroTrustGranted,
				"alignment_score":     overlayResult.AlignmentScore,
			},
		}
		finalResult.Violations = append(finalResult.Violations, manualReviewViolation)
	}
	
	return finalResult
}