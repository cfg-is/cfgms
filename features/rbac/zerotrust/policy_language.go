package zerotrust

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// PolicyDefinition represents the structure of a zero-trust policy in YAML/JSON format
type PolicyDefinition struct {
	APIVersion string         `json:"apiVersion" yaml:"apiVersion"`
	Kind       string         `json:"kind" yaml:"kind"`
	Metadata   PolicyMetadata `json:"metadata" yaml:"metadata"`
	Spec       PolicySpec     `json:"spec" yaml:"spec"`
}

// PolicyMetadata contains metadata about the policy
type PolicyMetadata struct {
	Name        string            `json:"name" yaml:"name"`
	Namespace   string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	CreatedBy   string            `json:"createdBy" yaml:"createdBy"`
	CreatedAt   time.Time         `json:"createdAt" yaml:"createdAt"`
	Version     string            `json:"version" yaml:"version"`
}

// PolicySpec defines the specification of a zero-trust policy
type PolicySpec struct {
	Description string           `json:"description" yaml:"description"`
	Priority    int              `json:"priority" yaml:"priority"`
	Scope       PolicyScopeSpec  `json:"scope" yaml:"scope"`
	Rules       []PolicyRuleSpec `json:"rules" yaml:"rules"`
	Enforcement EnforcementSpec  `json:"enforcement" yaml:"enforcement"`
	Compliance  ComplianceSpec   `json:"compliance,omitempty" yaml:"compliance,omitempty"`
	Integration IntegrationSpec  `json:"integration,omitempty" yaml:"integration,omitempty"`
	Monitoring  MonitoringSpec   `json:"monitoring,omitempty" yaml:"monitoring,omitempty"`
}

// PolicyScopeSpec defines the scope where the policy applies
type PolicyScopeSpec struct {
	Tenants    []string           `json:"tenants,omitempty" yaml:"tenants,omitempty"`
	Subjects   []SubjectSelector  `json:"subjects,omitempty" yaml:"subjects,omitempty"`
	Resources  []ResourceSelector `json:"resources,omitempty" yaml:"resources,omitempty"`
	Actions    []string           `json:"actions,omitempty" yaml:"actions,omitempty"`
	Conditions []ConditionSpec    `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

// SubjectSelector defines how to select subjects for policy application
type SubjectSelector struct {
	Type       string                      `json:"type" yaml:"type"`
	Patterns   []string                    `json:"patterns,omitempty" yaml:"patterns,omitempty"`
	Attributes map[string]AttributeMatcher `json:"attributes,omitempty" yaml:"attributes,omitempty"`
	Groups     []string                    `json:"groups,omitempty" yaml:"groups,omitempty"`
	Roles      []string                    `json:"roles,omitempty" yaml:"roles,omitempty"`
}

// ResourceSelector defines how to select resources for policy application
type ResourceSelector struct {
	Type       string                      `json:"type" yaml:"type"`
	Patterns   []string                    `json:"patterns,omitempty" yaml:"patterns,omitempty"`
	Attributes map[string]AttributeMatcher `json:"attributes,omitempty" yaml:"attributes,omitempty"`
	Tags       map[string]string           `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// AttributeMatcher defines how to match against attribute values
type AttributeMatcher struct {
	Operator string        `json:"operator" yaml:"operator"`
	Values   []interface{} `json:"values" yaml:"values"`
	Pattern  string        `json:"pattern,omitempty" yaml:"pattern,omitempty"`
}

// PolicyRuleSpec defines a single rule within a policy
type PolicyRuleSpec struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Type        string `json:"type" yaml:"type"` // "access", "compliance", "security"

	// Rule logic
	When []ConditionSpec `json:"when,omitempty" yaml:"when,omitempty"`
	Then ActionSpec      `json:"then" yaml:"then"`
	Else ActionSpec      `json:"else,omitempty" yaml:"else,omitempty"`

	// Never-trust-always-verify settings
	AlwaysValidate       bool          `json:"alwaysValidate" yaml:"alwaysValidate"`
	RequireExplicitGrant bool          `json:"requireExplicitGrant" yaml:"requireExplicitGrant"`
	ValidationInterval   time.Duration `json:"validationInterval,omitempty" yaml:"validationInterval,omitempty"`

	// Rule metadata
	Priority int      `json:"priority,omitempty" yaml:"priority,omitempty"`
	Enabled  bool     `json:"enabled" yaml:"enabled"`
	Tags     []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// ConditionSpec defines a condition that must be evaluated
type ConditionSpec struct {
	Field     string      `json:"field" yaml:"field"`
	Operator  string      `json:"operator" yaml:"operator"`
	Value     interface{} `json:"value" yaml:"value"`
	ValueType string      `json:"valueType,omitempty" yaml:"valueType,omitempty"`

	// Logical operators
	And []ConditionSpec `json:"and,omitempty" yaml:"and,omitempty"`
	Or  []ConditionSpec `json:"or,omitempty" yaml:"or,omitempty"`
	Not *ConditionSpec  `json:"not,omitempty" yaml:"not,omitempty"`
}

// ActionSpec defines actions to take when a rule is triggered
type ActionSpec struct {
	Decision     string                `json:"decision" yaml:"decision"` // "allow", "deny", "conditional"
	Requirements []RequirementSpec     `json:"requirements,omitempty" yaml:"requirements,omitempty"`
	Logging      LoggingSpec           `json:"logging,omitempty" yaml:"logging,omitempty"`
	Alerts       []AlertSpec           `json:"alerts,omitempty" yaml:"alerts,omitempty"`
	Integrations IntegrationActionSpec `json:"integrations,omitempty" yaml:"integrations,omitempty"`
}

// RequirementSpec defines additional requirements for access
type RequirementSpec struct {
	Type     string                 `json:"type" yaml:"type"`
	Config   map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
	Timeout  time.Duration          `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Optional bool                   `json:"optional,omitempty" yaml:"optional,omitempty"`
}

// LoggingSpec defines logging requirements
type LoggingSpec struct {
	Level       string        `json:"level" yaml:"level"`
	Fields      []string      `json:"fields,omitempty" yaml:"fields,omitempty"`
	Destination string        `json:"destination,omitempty" yaml:"destination,omitempty"`
	Retention   time.Duration `json:"retention,omitempty" yaml:"retention,omitempty"`
}

// AlertSpec defines alerting configuration
type AlertSpec struct {
	Type       string          `json:"type" yaml:"type"`
	Severity   string          `json:"severity" yaml:"severity"`
	Recipients []string        `json:"recipients" yaml:"recipients"`
	Template   string          `json:"template,omitempty" yaml:"template,omitempty"`
	Conditions []ConditionSpec `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

// IntegrationActionSpec defines actions for system integrations
type IntegrationActionSpec struct {
	RBAC           *RBACActionSpec           `json:"rbac,omitempty" yaml:"rbac,omitempty"`
	JIT            *JITActionSpec            `json:"jit,omitempty" yaml:"jit,omitempty"`
	Risk           *RiskActionSpec           `json:"risk,omitempty" yaml:"risk,omitempty"`
	Tenant         *TenantActionSpec         `json:"tenant,omitempty" yaml:"tenant,omitempty"`
	ContinuousAuth *ContinuousAuthActionSpec `json:"continuousAuth,omitempty" yaml:"continuousAuth,omitempty"`
}

// System-specific action specifications
type RBACActionSpec struct {
	RequireValidation   bool     `json:"requireValidation" yaml:"requireValidation"`
	OverrideDecision    bool     `json:"overrideDecision,omitempty" yaml:"overrideDecision,omitempty"`
	RequiredRoles       []string `json:"requiredRoles,omitempty" yaml:"requiredRoles,omitempty"`
	RequiredPermissions []string `json:"requiredPermissions,omitempty" yaml:"requiredPermissions,omitempty"`
}

type JITActionSpec struct {
	RequireJustification bool          `json:"requireJustification" yaml:"requireJustification"`
	MaxDuration          time.Duration `json:"maxDuration,omitempty" yaml:"maxDuration,omitempty"`
	RequireApproval      bool          `json:"requireApproval,omitempty" yaml:"requireApproval,omitempty"`
	Approvers            []string      `json:"approvers,omitempty" yaml:"approvers,omitempty"`
}

type RiskActionSpec struct {
	RequireAssessment bool     `json:"requireAssessment" yaml:"requireAssessment"`
	MaxRiskLevel      string   `json:"maxRiskLevel,omitempty" yaml:"maxRiskLevel,omitempty"`
	RequireMitigation bool     `json:"requireMitigation,omitempty" yaml:"requireMitigation,omitempty"`
	MitigationActions []string `json:"mitigationActions,omitempty" yaml:"mitigationActions,omitempty"`
}

type TenantActionSpec struct {
	EnforceIsolation        bool     `json:"enforceIsolation" yaml:"enforceIsolation"`
	RequireTenantValidation bool     `json:"requireTenantValidation" yaml:"requireTenantValidation"`
	AdditionalPolicies      []string `json:"additionalPolicies,omitempty" yaml:"additionalPolicies,omitempty"`
}

type ContinuousAuthActionSpec struct {
	RequireContinuousValidation bool          `json:"requireContinuousValidation" yaml:"requireContinuousValidation"`
	ValidationInterval          time.Duration `json:"validationInterval,omitempty" yaml:"validationInterval,omitempty"`
	SessionTimeout              time.Duration `json:"sessionTimeout,omitempty" yaml:"sessionTimeout,omitempty"`
	RequireReauth               bool          `json:"requireReauth,omitempty" yaml:"requireReauth,omitempty"`
}

// EnforcementSpec defines policy enforcement configuration
type EnforcementSpec struct {
	Mode            string        `json:"mode" yaml:"mode"`               // "enforcing", "auditing", "testing"
	FailureMode     string        `json:"failureMode" yaml:"failureMode"` // "secure", "open"
	GracePeriod     time.Duration `json:"gracePeriod,omitempty" yaml:"gracePeriod,omitempty"`
	MaxViolations   int           `json:"maxViolations,omitempty" yaml:"maxViolations,omitempty"`
	ViolationWindow time.Duration `json:"violationWindow,omitempty" yaml:"violationWindow,omitempty"`
}

// ComplianceSpec defines compliance framework requirements
type ComplianceSpec struct {
	Frameworks        []ComplianceFrameworkSpec `json:"frameworks" yaml:"frameworks"`
	AuditRequirements []AuditRequirementSpec    `json:"auditRequirements,omitempty" yaml:"auditRequirements,omitempty"`
	RetentionPolicy   RetentionPolicySpec       `json:"retentionPolicy,omitempty" yaml:"retentionPolicy,omitempty"`
}

type ComplianceFrameworkSpec struct {
	Name             string                 `json:"name" yaml:"name"`
	Version          string                 `json:"version,omitempty" yaml:"version,omitempty"`
	Controls         []string               `json:"controls" yaml:"controls"`
	RequirementLevel string                 `json:"requirementLevel" yaml:"requirementLevel"`
	CustomValidation []CustomValidationSpec `json:"customValidation,omitempty" yaml:"customValidation,omitempty"`
}

type CustomValidationSpec struct {
	Name             string   `json:"name" yaml:"name"`
	Logic            string   `json:"logic" yaml:"logic"`
	RequiredEvidence []string `json:"requiredEvidence,omitempty" yaml:"requiredEvidence,omitempty"`
}

type AuditRequirementSpec struct {
	Type       string   `json:"type" yaml:"type"`
	Level      string   `json:"level" yaml:"level"`
	Fields     []string `json:"fields" yaml:"fields"`
	Encryption bool     `json:"encryption,omitempty" yaml:"encryption,omitempty"`
}

type RetentionPolicySpec struct {
	Duration     time.Duration `json:"duration" yaml:"duration"`
	ArchiveAfter time.Duration `json:"archiveAfter,omitempty" yaml:"archiveAfter,omitempty"`
	DeleteAfter  time.Duration `json:"deleteAfter,omitempty" yaml:"deleteAfter,omitempty"`
}

// IntegrationSpec defines integration with existing systems
type IntegrationSpec struct {
	RBAC           *RBACIntegrationSpec           `json:"rbac,omitempty" yaml:"rbac,omitempty"`
	JIT            *JITIntegrationSpec            `json:"jit,omitempty" yaml:"jit,omitempty"`
	Risk           *RiskIntegrationSpec           `json:"risk,omitempty" yaml:"risk,omitempty"`
	Tenant         *TenantIntegrationSpec         `json:"tenant,omitempty" yaml:"tenant,omitempty"`
	ContinuousAuth *ContinuousAuthIntegrationSpec `json:"continuousAuth,omitempty" yaml:"continuousAuth,omitempty"`
}

type RBACIntegrationSpec struct {
	Enabled      bool    `json:"enabled" yaml:"enabled"`
	Weight       float64 `json:"weight,omitempty" yaml:"weight,omitempty"`
	Override     bool    `json:"override,omitempty" yaml:"override,omitempty"`
	FallbackMode string  `json:"fallbackMode,omitempty" yaml:"fallbackMode,omitempty"`
}

type JITIntegrationSpec struct {
	Enabled         bool          `json:"enabled" yaml:"enabled"`
	Weight          float64       `json:"weight,omitempty" yaml:"weight,omitempty"`
	MaxDuration     time.Duration `json:"maxDuration,omitempty" yaml:"maxDuration,omitempty"`
	RequireApproval bool          `json:"requireApproval,omitempty" yaml:"requireApproval,omitempty"`
}

type RiskIntegrationSpec struct {
	Enabled             bool     `json:"enabled" yaml:"enabled"`
	Weight              float64  `json:"weight,omitempty" yaml:"weight,omitempty"`
	ThresholdOverride   float64  `json:"thresholdOverride,omitempty" yaml:"thresholdOverride,omitempty"`
	RequiredMitigations []string `json:"requiredMitigations,omitempty" yaml:"requiredMitigations,omitempty"`
}

type TenantIntegrationSpec struct {
	Enabled                bool    `json:"enabled" yaml:"enabled"`
	Weight                 float64 `json:"weight,omitempty" yaml:"weight,omitempty"`
	EnforceIsolation       bool    `json:"enforceIsolation" yaml:"enforceIsolation"`
	OverrideTenantPolicies bool    `json:"overrideTenantPolicies,omitempty" yaml:"overrideTenantPolicies,omitempty"`
}

type ContinuousAuthIntegrationSpec struct {
	Enabled        bool          `json:"enabled" yaml:"enabled"`
	Weight         float64       `json:"weight,omitempty" yaml:"weight,omitempty"`
	RequireSession bool          `json:"requireSession" yaml:"requireSession"`
	SessionTimeout time.Duration `json:"sessionTimeout,omitempty" yaml:"sessionTimeout,omitempty"`
}

// MonitoringSpec defines monitoring and metrics configuration
type MonitoringSpec struct {
	Metrics   MetricsSpec           `json:"metrics,omitempty" yaml:"metrics,omitempty"`
	Alerts    []MonitoringAlertSpec `json:"alerts,omitempty" yaml:"alerts,omitempty"`
	Dashboard DashboardSpec         `json:"dashboard,omitempty" yaml:"dashboard,omitempty"`
}

type MetricsSpec struct {
	Enabled       bool               `json:"enabled" yaml:"enabled"`
	Interval      time.Duration      `json:"interval,omitempty" yaml:"interval,omitempty"`
	Labels        map[string]string  `json:"labels,omitempty" yaml:"labels,omitempty"`
	CustomMetrics []CustomMetricSpec `json:"customMetrics,omitempty" yaml:"customMetrics,omitempty"`
}

type CustomMetricSpec struct {
	Name        string   `json:"name" yaml:"name"`
	Type        string   `json:"type" yaml:"type"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Labels      []string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

type MonitoringAlertSpec struct {
	Name       string        `json:"name" yaml:"name"`
	Condition  string        `json:"condition" yaml:"condition"`
	Threshold  float64       `json:"threshold" yaml:"threshold"`
	Duration   time.Duration `json:"duration" yaml:"duration"`
	Recipients []string      `json:"recipients" yaml:"recipients"`
}

type DashboardSpec struct {
	Enabled bool                  `json:"enabled" yaml:"enabled"`
	Title   string                `json:"title,omitempty" yaml:"title,omitempty"`
	Widgets []DashboardWidgetSpec `json:"widgets,omitempty" yaml:"widgets,omitempty"`
}

type DashboardWidgetSpec struct {
	Type      string `json:"type" yaml:"type"`
	Title     string `json:"title" yaml:"title"`
	Query     string `json:"query" yaml:"query"`
	TimeRange string `json:"timeRange,omitempty" yaml:"timeRange,omitempty"`
}

// PolicyLanguageEngine provides policy parsing and validation capabilities
type PolicyLanguageEngine struct {
	validators map[string]PolicyValidator
	parsers    map[string]PolicyParser
	compilers  map[string]PolicyCompiler
}

// PolicyValidator validates policy definitions for correctness
type PolicyValidator interface {
	Validate(definition *PolicyDefinition) []ValidationError
}

// PolicyParser parses policy definitions from various formats
type PolicyParser interface {
	Parse(data []byte) (*PolicyDefinition, error)
	GetFormat() string
}

// PolicyCompiler compiles policy definitions to executable rules
type PolicyCompiler interface {
	Compile(definition *PolicyDefinition) (*ZeroTrustPolicy, error)
}

// ValidationError represents a policy validation error
type ValidationError struct {
	Field    string        `json:"field"`
	Message  string        `json:"message"`
	Severity ErrorSeverity `json:"severity"`
	Code     string        `json:"code"`
}

type ErrorSeverity string

const (
	ErrorSeverityError   ErrorSeverity = "error"
	ErrorSeverityWarning ErrorSeverity = "warning"
	ErrorSeverityInfo    ErrorSeverity = "info"
)

// NewPolicyLanguageEngine creates a new policy language engine
func NewPolicyLanguageEngine() *PolicyLanguageEngine {
	engine := &PolicyLanguageEngine{
		validators: make(map[string]PolicyValidator),
		parsers:    make(map[string]PolicyParser),
		compilers:  make(map[string]PolicyCompiler),
	}

	// Register default parsers
	engine.parsers["yaml"] = &YAMLPolicyParser{}
	engine.parsers["json"] = &JSONPolicyParser{}

	// Register default validators
	engine.validators["default"] = &DefaultPolicyValidator{}
	engine.validators["compliance"] = &CompliancePolicyValidator{}

	// Register default compiler
	engine.compilers["default"] = &DefaultPolicyCompiler{}

	return engine
}

// ParsePolicy parses a policy from YAML or JSON
func (p *PolicyLanguageEngine) ParsePolicy(data []byte, format string) (*PolicyDefinition, error) {
	parser, exists := p.parsers[format]
	if !exists {
		return nil, fmt.Errorf("unsupported policy format: %s", format)
	}

	return parser.Parse(data)
}

// ValidatePolicy validates a policy definition
func (p *PolicyLanguageEngine) ValidatePolicy(definition *PolicyDefinition) []ValidationError {
	var allErrors []ValidationError

	// Run all validators
	for _, validator := range p.validators {
		errors := validator.Validate(definition)
		allErrors = append(allErrors, errors...)
	}

	return allErrors
}

// CompilePolicy compiles a policy definition to executable form
func (p *PolicyLanguageEngine) CompilePolicy(definition *PolicyDefinition) (*ZeroTrustPolicy, error) {
	// First validate the policy
	validationErrors := p.ValidatePolicy(definition)

	// Check for blocking errors
	for _, err := range validationErrors {
		if err.Severity == ErrorSeverityError {
			return nil, fmt.Errorf("policy validation failed: %s", err.Message)
		}
	}

	// Compile the policy
	compiler := p.compilers["default"]
	return compiler.Compile(definition)
}

// Policy parser implementations

// YAMLPolicyParser parses policies from YAML format
type YAMLPolicyParser struct{}

func (y *YAMLPolicyParser) Parse(data []byte) (*PolicyDefinition, error) {
	var definition PolicyDefinition
	err := yaml.Unmarshal(data, &definition)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML policy: %w", err)
	}
	return &definition, nil
}

func (y *YAMLPolicyParser) GetFormat() string {
	return "yaml"
}

// JSONPolicyParser parses policies from JSON format
type JSONPolicyParser struct{}

func (j *JSONPolicyParser) Parse(data []byte) (*PolicyDefinition, error) {
	var definition PolicyDefinition
	err := json.Unmarshal(data, &definition)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON policy: %w", err)
	}
	return &definition, nil
}

func (j *JSONPolicyParser) GetFormat() string {
	return "json"
}

// Policy validator implementations

// DefaultPolicyValidator provides basic policy validation
type DefaultPolicyValidator struct{}

func (d *DefaultPolicyValidator) Validate(definition *PolicyDefinition) []ValidationError {
	var errors []ValidationError

	// Validate API version
	if definition.APIVersion == "" {
		errors = append(errors, ValidationError{
			Field:    "apiVersion",
			Message:  "apiVersion is required",
			Severity: ErrorSeverityError,
			Code:     "MISSING_API_VERSION",
		})
	}

	// Validate kind
	if definition.Kind != "ZeroTrustPolicy" {
		errors = append(errors, ValidationError{
			Field:    "kind",
			Message:  "kind must be 'ZeroTrustPolicy'",
			Severity: ErrorSeverityError,
			Code:     "INVALID_KIND",
		})
	}

	// Validate metadata
	if definition.Metadata.Name == "" {
		errors = append(errors, ValidationError{
			Field:    "metadata.name",
			Message:  "policy name is required",
			Severity: ErrorSeverityError,
			Code:     "MISSING_NAME",
		})
	}

	// Validate policy name format
	namePattern := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	if !namePattern.MatchString(definition.Metadata.Name) {
		errors = append(errors, ValidationError{
			Field:    "metadata.name",
			Message:  "policy name must match pattern: ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
			Severity: ErrorSeverityError,
			Code:     "INVALID_NAME_FORMAT",
		})
	}

	// Validate rules
	if len(definition.Spec.Rules) == 0 {
		errors = append(errors, ValidationError{
			Field:    "spec.rules",
			Message:  "at least one rule is required",
			Severity: ErrorSeverityError,
			Code:     "MISSING_RULES",
		})
	}

	// Validate individual rules
	for i, rule := range definition.Spec.Rules {
		if rule.ID == "" {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.rules[%d].id", i),
				Message:  "rule ID is required",
				Severity: ErrorSeverityError,
				Code:     "MISSING_RULE_ID",
			})
		}

		if rule.Then.Decision == "" {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.rules[%d].then.decision", i),
				Message:  "rule decision is required",
				Severity: ErrorSeverityError,
				Code:     "MISSING_RULE_DECISION",
			})
		}

		// Validate decision values
		validDecisions := map[string]bool{"allow": true, "deny": true, "conditional": true}
		if !validDecisions[rule.Then.Decision] {
			errors = append(errors, ValidationError{
				Field:    fmt.Sprintf("spec.rules[%d].then.decision", i),
				Message:  "decision must be 'allow', 'deny', or 'conditional'",
				Severity: ErrorSeverityError,
				Code:     "INVALID_RULE_DECISION",
			})
		}
	}

	// Validate enforcement mode
	validModes := map[string]bool{"enforcing": true, "auditing": true, "testing": true}
	if !validModes[definition.Spec.Enforcement.Mode] {
		errors = append(errors, ValidationError{
			Field:    "spec.enforcement.mode",
			Message:  "enforcement mode must be 'enforcing', 'auditing', or 'testing'",
			Severity: ErrorSeverityError,
			Code:     "INVALID_ENFORCEMENT_MODE",
		})
	}

	return errors
}

// CompliancePolicyValidator validates compliance-specific aspects
type CompliancePolicyValidator struct{}

func (c *CompliancePolicyValidator) Validate(definition *PolicyDefinition) []ValidationError {
	var errors []ValidationError

	// Validate compliance frameworks
	if len(definition.Spec.Compliance.Frameworks) > 0 {
		supportedFrameworks := map[string]bool{
			"SOC2": true, "ISO27001": true, "GDPR": true, "HIPAA": true,
		}

		for i, framework := range definition.Spec.Compliance.Frameworks {
			if !supportedFrameworks[framework.Name] {
				errors = append(errors, ValidationError{
					Field:    fmt.Sprintf("spec.compliance.frameworks[%d].name", i),
					Message:  "unsupported compliance framework",
					Severity: ErrorSeverityWarning,
					Code:     "UNSUPPORTED_FRAMEWORK",
				})
			}
		}
	}

	return errors
}

// Policy compiler implementation

// DefaultPolicyCompiler compiles policy definitions to executable policies
type DefaultPolicyCompiler struct{}

func (d *DefaultPolicyCompiler) Compile(definition *PolicyDefinition) (*ZeroTrustPolicy, error) {
	now := time.Now()

	// Create base policy
	policy := &ZeroTrustPolicy{
		ID:            fmt.Sprintf("policy-%s", definition.Metadata.Name),
		Name:          definition.Metadata.Name,
		Description:   definition.Spec.Description,
		Version:       definition.Metadata.Version,
		CreatedBy:     definition.Metadata.CreatedBy,
		CreatedAt:     definition.Metadata.CreatedAt,
		UpdatedAt:     now,
		EffectiveFrom: now,
		Status:        PolicyStatusActive,
		Priority:      PolicyPriority(definition.Spec.Priority),
	}

	// Set policy scope
	policy.Scope = PolicyScope{
		TenantIDs: definition.Spec.Scope.Tenants,
		Actions:   definition.Spec.Scope.Actions,
	}

	// Convert conditions
	for _, condSpec := range definition.Spec.Scope.Conditions {
		condition := PolicyCondition{
			Field:     condSpec.Field,
			Operator:  ConditionOperator(condSpec.Operator),
			Value:     condSpec.Value,
			ValueType: condSpec.ValueType,
		}
		policy.Scope.Conditions = append(policy.Scope.Conditions, condition)
	}

	// Set enforcement mode
	switch definition.Spec.Enforcement.Mode {
	case "enforcing":
		policy.EnforcementMode = PolicyEnforcementModeEnforcing
	case "auditing":
		policy.EnforcementMode = PolicyEnforcementModeAuditing
	case "testing":
		policy.EnforcementMode = PolicyEnforcementModeTesting
	default:
		return nil, fmt.Errorf("invalid enforcement mode: %s", definition.Spec.Enforcement.Mode)
	}

	// Compile rules
	for _, ruleSpec := range definition.Spec.Rules {
		switch ruleSpec.Type {
		case "access":
			accessRule, err := d.compileAccessRule(ruleSpec)
			if err != nil {
				return nil, fmt.Errorf("failed to compile access rule %s: %w", ruleSpec.ID, err)
			}
			policy.AccessRules = append(policy.AccessRules, *accessRule)
		case "compliance":
			complianceRule, err := d.compileComplianceRule(ruleSpec)
			if err != nil {
				return nil, fmt.Errorf("failed to compile compliance rule %s: %w", ruleSpec.ID, err)
			}
			policy.ComplianceRules = append(policy.ComplianceRules, *complianceRule)
		case "security":
			securityRule, err := d.compileSecurityRule(ruleSpec)
			if err != nil {
				return nil, fmt.Errorf("failed to compile security rule %s: %w", ruleSpec.ID, err)
			}
			policy.SecurityRules = append(policy.SecurityRules, *securityRule)
		default:
			return nil, fmt.Errorf("unsupported rule type: %s", ruleSpec.Type)
		}
	}

	// Set integration settings
	integrationSpec := definition.Spec.Integration
	if integrationSpec.RBAC != nil || integrationSpec.JIT != nil || integrationSpec.Risk != nil || integrationSpec.Tenant != nil {
		if definition.Spec.Integration.RBAC != nil && definition.Spec.Integration.RBAC.Enabled {
			policy.RBACIntegration = &RBACPolicyIntegration{
				RequireRBACValidation: true,
				OverrideRBAC:          definition.Spec.Integration.RBAC.Override,
				RBACWeight:            definition.Spec.Integration.RBAC.Weight,
			}
		}

		if definition.Spec.Integration.JIT != nil && definition.Spec.Integration.JIT.Enabled {
			policy.JITIntegration = &JITPolicyIntegration{
				RequireJITValidation: true,
				AllowJITOverride:     !definition.Spec.Integration.JIT.RequireApproval,
				JITWeight:            definition.Spec.Integration.JIT.Weight,
			}
		}

		if definition.Spec.Integration.Risk != nil && definition.Spec.Integration.Risk.Enabled {
			policy.RiskIntegration = &RiskPolicyIntegration{
				RequireRiskAssessment: true,
				RiskThreshold:         definition.Spec.Integration.Risk.ThresholdOverride,
				RiskWeight:            definition.Spec.Integration.Risk.Weight,
			}
		}

		if definition.Spec.Integration.Tenant != nil && definition.Spec.Integration.Tenant.Enabled {
			policy.TenantIntegration = &TenantPolicyIntegration{
				RequireTenantValidation: true,
				EnforceTenantIsolation:  definition.Spec.Integration.Tenant.EnforceIsolation,
				TenantWeight:            definition.Spec.Integration.Tenant.Weight,
			}
		}
	}

	return policy, nil
}

func (d *DefaultPolicyCompiler) compileAccessRule(spec PolicyRuleSpec) (*AccessRule, error) {
	rule := &AccessRule{
		ID:                   spec.ID,
		Name:                 spec.Name,
		Description:          spec.Description,
		RequireExplicitGrant: spec.RequireExplicitGrant,
		RequireRevalidation:  spec.AlwaysValidate,
		RevalidationInterval: spec.ValidationInterval,
	}

	// Compile conditions
	for _, condSpec := range spec.When {
		condition := PolicyCondition{
			Field:     condSpec.Field,
			Operator:  ConditionOperator(condSpec.Operator),
			Value:     condSpec.Value,
			ValueType: condSpec.ValueType,
		}
		rule.Conditions = append(rule.Conditions, condition)
	}

	// Set integration requirements based on action spec
	if spec.Then.Integrations.RBAC != nil {
		rule.RBACRequired = spec.Then.Integrations.RBAC.RequireValidation
	}
	if spec.Then.Integrations.JIT != nil {
		rule.JITRequired = spec.Then.Integrations.JIT.RequireJustification
	}
	if spec.Then.Integrations.Risk != nil {
		rule.RiskAssessmentRequired = spec.Then.Integrations.Risk.RequireAssessment
	}
	if spec.Then.Integrations.ContinuousAuth != nil {
		rule.ContinuousAuthRequired = spec.Then.Integrations.ContinuousAuth.RequireContinuousValidation
	}

	// Compile action
	rule.AllowAction = PolicyAction{
		Type:       PolicyActionType(spec.Then.Decision),
		Parameters: make(map[string]interface{}),
	}

	if spec.Else.Decision != "" {
		rule.DenyAction = PolicyAction{
			Type:       PolicyActionType(spec.Else.Decision),
			Parameters: make(map[string]interface{}),
		}
	}

	return rule, nil
}

func (d *DefaultPolicyCompiler) compileComplianceRule(spec PolicyRuleSpec) (*ComplianceRule, error) {
	rule := &ComplianceRule{
		ID:          spec.ID,
		Name:        spec.Name,
		Description: spec.Description,
	}

	// Implementation would parse compliance-specific rule details
	// This is a stub for now

	return rule, nil
}

func (d *DefaultPolicyCompiler) compileSecurityRule(spec PolicyRuleSpec) (*SecurityRule, error) {
	rule := &SecurityRule{
		ID:          spec.ID,
		Name:        spec.Name,
		Description: spec.Description,
	}

	// Implementation would parse security-specific rule details
	// This is a stub for now

	return rule, nil
}
