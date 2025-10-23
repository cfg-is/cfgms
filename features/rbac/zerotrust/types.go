// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package zerotrust

import (
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
)

// ZeroTrustAccessRequest represents a comprehensive access request for zero-trust evaluation
type ZeroTrustAccessRequest struct {
	// Standard access request information
	AccessRequest *common.AccessRequest `json:"access_request"`

	// Zero-trust context
	SessionID   string    `json:"session_id,omitempty"`
	RequestID   string    `json:"request_id"`
	RequestTime time.Time `json:"request_time"`

	// Subject context
	SubjectType       SubjectType            `json:"subject_type"`
	SubjectAttributes map[string]interface{} `json:"subject_attributes"`

	// Resource context
	ResourceType       string                 `json:"resource_type"`
	ResourceAttributes map[string]interface{} `json:"resource_attributes"`

	// Environmental context
	EnvironmentContext *EnvironmentContext `json:"environment_context"`
	SecurityContext    *SecurityContext    `json:"security_context"`

	// Request metadata
	SourceSystem  string          `json:"source_system"`
	RequestSource RequestSource   `json:"request_source"`
	Priority      RequestPriority `json:"priority"`
}

// ZeroTrustAccessResponse provides comprehensive zero-trust access evaluation results
type ZeroTrustAccessResponse struct {
	// Standard access decision
	Granted bool   `json:"granted"`
	Reason  string `json:"reason"`

	// Zero-trust evaluation details
	EvaluationID   string        `json:"evaluation_id"`
	EvaluationTime time.Time     `json:"evaluation_time"`
	ProcessingTime time.Duration `json:"processing_time"`

	// Policy evaluation results
	PoliciesEvaluated []string                  `json:"policies_evaluated"`
	PolicyResults     []*PolicyEvaluationResult `json:"policy_results"`

	// System integration results
	RBACResult           *RBACIntegrationResult   `json:"rbac_result,omitempty"`
	JITResult            *JITIntegrationResult    `json:"jit_result,omitempty"`
	RiskResult           *RiskIntegrationResult   `json:"risk_result,omitempty"`
	TenantResult         *TenantIntegrationResult `json:"tenant_result,omitempty"`
	ContinuousAuthResult *ContinuousAuthResult    `json:"continuous_auth_result,omitempty"`

	// Compliance validation
	ComplianceResults []*ComplianceValidationResult `json:"compliance_results"`
	ComplianceStatus  ComplianceStatus              `json:"compliance_status"`

	// Enforcement actions
	AppliedPolicies    []string             `json:"applied_policies"`
	EnforcementActions []*EnforcementAction `json:"enforcement_actions"`

	// Recommendations and next steps
	Recommendations []string          `json:"recommendations"`
	RequiredActions []*RequiredAction `json:"required_actions"`

	// Caching information
	FromCache   bool      `json:"from_cache"`
	CacheExpiry time.Time `json:"cache_expiry,omitempty"`

	// Audit trail
	AuditTrail []*AuditEntry `json:"audit_trail"`
}

// PolicyEvaluationContext provides context for policy evaluation
type PolicyEvaluationContext struct {
	Request      *ZeroTrustAccessRequest            `json:"request"`
	EvaluationID string                             `json:"evaluation_id"`
	StartTime    time.Time                          `json:"start_time"`
	Policies     []*ZeroTrustPolicy                 `json:"policies"`
	Results      map[string]*PolicyEvaluationResult `json:"results"`

	// Evaluation metadata
	EvaluationMode    EvaluationMode `json:"evaluation_mode"`
	MaxProcessingTime time.Duration  `json:"max_processing_time"`
	FailSecure        bool           `json:"fail_secure"`
}

// PolicyEvaluationResult represents the result of evaluating a single policy
type PolicyEvaluationResult struct {
	PolicyID      string `json:"policy_id"`
	PolicyName    string `json:"policy_name"`
	PolicyVersion string `json:"policy_version"`

	// Evaluation outcome
	Result     PolicyResult `json:"result"`
	Reason     string       `json:"reason"`
	Confidence float64      `json:"confidence"`

	// Rule evaluation details
	RuleResults []*RuleEvaluationResult `json:"rule_results"`

	// Processing metadata
	EvaluationTime time.Time     `json:"evaluation_time"`
	ProcessingTime time.Duration `json:"processing_time"`

	// Enforcement information
	EnforcementMode PolicyEnforcementMode `json:"enforcement_mode"`
	RequiredActions []*RequiredAction     `json:"required_actions"`
}

// RuleEvaluationResult represents the result of evaluating a single rule
type RuleEvaluationResult struct {
	RuleID   string   `json:"rule_id"`
	RuleName string   `json:"rule_name"`
	RuleType RuleType `json:"rule_type"`

	// Evaluation outcome
	Satisfied bool                   `json:"satisfied"`
	Reason    string                 `json:"reason"`
	Evidence  map[string]interface{} `json:"evidence"`

	// Processing metadata
	EvaluationTime time.Time     `json:"evaluation_time"`
	ProcessingTime time.Duration `json:"processing_time"`
}

// System integration result types

type SystemIntegrationResults struct {
	RBACResult           *RBACIntegrationResult   `json:"rbac_result,omitempty"`
	JITResult            *JITIntegrationResult    `json:"jit_result,omitempty"`
	RiskResult           *RiskIntegrationResult   `json:"risk_result,omitempty"`
	TenantResult         *TenantIntegrationResult `json:"tenant_result,omitempty"`
	ContinuousAuthResult *ContinuousAuthResult    `json:"continuous_auth_result,omitempty"`
}

type RBACIntegrationResult struct {
	Granted          bool          `json:"granted"`
	Reason           string        `json:"reason"`
	EffectiveRoles   []string      `json:"effective_roles"`
	PermissionSource string        `json:"permission_source"`
	ProcessingTime   time.Duration `json:"processing_time"`
}

type JITIntegrationResult struct {
	Granted          bool          `json:"granted"`
	JITAccessGranted bool          `json:"jit_access_granted"`
	AccessDuration   time.Duration `json:"access_duration,omitempty"`
	Justification    string        `json:"justification,omitempty"`
	ProcessingTime   time.Duration `json:"processing_time"`
}

type RiskIntegrationResult struct {
	RiskLevel          string        `json:"risk_level"`
	RiskScore          float64       `json:"risk_score"`
	RiskFactors        []string      `json:"risk_factors"`
	MitigationRequired bool          `json:"mitigation_required"`
	ProcessingTime     time.Duration `json:"processing_time"`
}

type TenantIntegrationResult struct {
	Granted               bool          `json:"granted"`
	TenantPoliciesApplied []string      `json:"tenant_policies_applied"`
	IsolationMaintained   bool          `json:"isolation_maintained"`
	ProcessingTime        time.Duration `json:"processing_time"`
}

type ContinuousAuthResult struct {
	Granted              bool          `json:"granted"`
	SessionValid         bool          `json:"session_valid"`
	RevalidationRequired bool          `json:"revalidation_required"`
	NextValidation       time.Time     `json:"next_validation,omitempty"`
	ProcessingTime       time.Duration `json:"processing_time"`
}

// Compliance validation types

type ComplianceValidationResults struct {
	OverallCompliance   bool                          `json:"overall_compliance"`
	FrameworkResults    []*ComplianceValidationResult `json:"framework_results"`
	ViolationsDetected  []*ComplianceViolation        `json:"violations_detected"`
	RemediationRequired []*RemediationAction          `json:"remediation_required"`
}

type ComplianceValidationResult struct {
	Framework         ComplianceFramework `json:"framework"`
	ControlsEvaluated []string            `json:"controls_evaluated"`
	ControlsCompliant []string            `json:"controls_compliant"`
	ControlsViolated  []string            `json:"controls_violated"`
	ComplianceRate    float64             `json:"compliance_rate"`
	ProcessingTime    time.Duration       `json:"processing_time"`
}

type ComplianceViolation struct {
	ViolationID         string               `json:"violation_id"`
	Framework           ComplianceFramework  `json:"framework"`
	ControlID           string               `json:"control_id"`
	ViolationType       string               `json:"violation_type"`
	Severity            ViolationSeverity    `json:"severity"`
	Description         string               `json:"description"`
	DetectedAt          time.Time            `json:"detected_at"`
	RequiredRemediation []*RemediationAction `json:"required_remediation"`
}

// Decision and action types

type AccessDecision struct {
	Granted       bool             `json:"granted"`
	Reason        string           `json:"reason"`
	Confidence    float64          `json:"confidence"`
	DecisionTime  time.Time        `json:"decision_time"`
	DecisionBasis []DecisionFactor `json:"decision_basis"`
}

type DecisionFactor struct {
	Type         DecisionFactorType `json:"type"`
	Source       string             `json:"source"`
	Weight       float64            `json:"weight"`
	Contribution string             `json:"contribution"`
}

type EnforcementAction struct {
	ActionID    string                 `json:"action_id"`
	ActionType  EnforcementActionType  `json:"action_type"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	ScheduledAt time.Time              `json:"scheduled_at"`
	ExecutedAt  time.Time              `json:"executed_at,omitempty"`
	Status      ActionStatus           `json:"status"`
	Result      ActionResult           `json:"result,omitempty"`
}

type RequiredAction struct {
	ActionID    string             `json:"action_id"`
	ActionType  RequiredActionType `json:"action_type"`
	Description string             `json:"description"`
	Priority    ActionPriority     `json:"priority"`
	DueBy       time.Time          `json:"due_by,omitempty"`
	CompletedAt time.Time          `json:"completed_at,omitempty"`
}

type RemediationAction struct {
	ActionID         string                `json:"action_id"`
	ActionType       RemediationActionType `json:"action_type"`
	Description      string                `json:"description"`
	Urgency          RemediationUrgency    `json:"urgency"`
	EstimatedTime    time.Duration         `json:"estimated_time"`
	ResponsibleParty string                `json:"responsible_party"`
}

// Context types

type EnvironmentContext struct {
	IPAddress   string       `json:"ip_address"`
	Location    *GeoLocation `json:"location,omitempty"`
	Network     *NetworkInfo `json:"network,omitempty"`
	Device      *DeviceInfo  `json:"device,omitempty"`
	TimeContext *TimeContext `json:"time_context,omitempty"`
}

type SecurityContext struct {
	AuthenticationMethod   string            `json:"authentication_method"`
	AuthenticationStrength AuthStrength      `json:"authentication_strength"`
	MFAVerified            bool              `json:"mfa_verified"`
	CertificateValidated   bool              `json:"certificate_validated"`
	ThreatIndicators       []ThreatIndicator `json:"threat_indicators"`
	TrustLevel             TrustLevel        `json:"trust_level"`
}

type GeoLocation struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Accuracy  int     `json:"accuracy"`
}

type NetworkInfo struct {
	ISP           string  `json:"isp"`
	ASN           string  `json:"asn"`
	Organization  string  `json:"organization"`
	ThreatScore   float64 `json:"threat_score"`
	VPNDetected   bool    `json:"vpn_detected"`
	ProxyDetected bool    `json:"proxy_detected"`
}

type DeviceInfo struct {
	DeviceID   string `json:"device_id"`
	DeviceType string `json:"device_type"`
	OS         string `json:"os"`
	OSVersion  string `json:"os_version"`
	Trusted    bool   `json:"trusted"`
	Registered bool   `json:"registered"`
	Compliant  bool   `json:"compliant"`
}

type TimeContext struct {
	RequestTime   time.Time `json:"request_time"`
	BusinessHours bool      `json:"business_hours"`
	TimeZone      string    `json:"time_zone"`
	DayOfWeek     string    `json:"day_of_week"`
	Holiday       bool      `json:"holiday,omitempty"`
}

type ThreatIndicator struct {
	Type        ThreatType     `json:"type"`
	Severity    ThreatSeverity `json:"severity"`
	Source      string         `json:"source"`
	Confidence  float64        `json:"confidence"`
	Description string         `json:"description"`
	DetectedAt  time.Time      `json:"detected_at"`
}

// Audit types

type AuditEntry struct {
	EntryID   string                 `json:"entry_id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType AuditEventType         `json:"event_type"`
	Actor     string                 `json:"actor"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Outcome   string                 `json:"outcome"`
	Details   map[string]interface{} `json:"details"`
}

// Policy integration types

type RBACPolicyIntegration struct {
	RequireRBACValidation bool    `json:"require_rbac_validation"`
	OverrideRBAC          bool    `json:"override_rbac"`
	RBACWeight            float64 `json:"rbac_weight"`
}

type JITPolicyIntegration struct {
	RequireJITValidation bool    `json:"require_jit_validation"`
	AllowJITOverride     bool    `json:"allow_jit_override"`
	JITWeight            float64 `json:"jit_weight"`
}

type RiskPolicyIntegration struct {
	RequireRiskAssessment bool    `json:"require_risk_assessment"`
	RiskThreshold         float64 `json:"risk_threshold"`
	RiskWeight            float64 `json:"risk_weight"`
}

type TenantPolicyIntegration struct {
	RequireTenantValidation bool    `json:"require_tenant_validation"`
	EnforceTenantIsolation  bool    `json:"enforce_tenant_isolation"`
	TenantWeight            float64 `json:"tenant_weight"`
}

// Configuration types

type PolicyCondition struct {
	Field     string            `json:"field"`
	Operator  ConditionOperator `json:"operator"`
	Value     interface{}       `json:"value"`
	ValueType string            `json:"value_type"`
}

type AccessRequirement struct {
	Type      RequirementType `json:"type"`
	Value     interface{}     `json:"value"`
	Mandatory bool            `json:"mandatory"`
}

type PolicyAction struct {
	Type       PolicyActionType       `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
}

type ViolationResponsePolicy struct {
	ImmediateActions    []PolicyAction `json:"immediate_actions"`
	EscalationActions   []PolicyAction `json:"escalation_actions"`
	NotificationTargets []string       `json:"notification_targets"`
}

// Configuration and validation types

type ThreatDetectionConfig struct {
	EnabledDetectors  []ThreatDetectorType `json:"enabled_detectors"`
	SensitivityLevel  ThreatSensitivity    `json:"sensitivity_level"`
	ResponseThreshold float64              `json:"response_threshold"`
}

type CertificateValidationConfig struct {
	RequireMutualTLS bool     `json:"require_mutual_tls"`
	ValidateChain    bool     `json:"validate_chain"`
	CheckRevocation  bool     `json:"check_revocation"`
	AllowedIssuers   []string `json:"allowed_issuers"`
}

type ComplianceValidationRule struct {
	RuleID           string   `json:"rule_id"`
	Description      string   `json:"description"`
	ValidationLogic  string   `json:"validation_logic"`
	RequiredEvidence []string `json:"required_evidence"`
}

type AuditRequirement struct {
	RequirementType    AuditRequirementType `json:"requirement_type"`
	RetentionPeriod    time.Duration        `json:"retention_period"`
	EncryptionRequired bool                 `json:"encryption_required"`
	AccessRestrictions []string             `json:"access_restrictions"`
}

// Enum types and constants

type SubjectType string

const (
	SubjectTypeUser    SubjectType = "user"
	SubjectTypeService SubjectType = "service"
	SubjectTypeDevice  SubjectType = "device"
	SubjectTypeSystem  SubjectType = "system"
)

type RequestSource string

const (
	RequestSourceAPI    RequestSource = "api"
	RequestSourceUI     RequestSource = "ui"
	RequestSourceCLI    RequestSource = "cli"
	RequestSourceSystem RequestSource = "system"
)

type RequestPriority string

const (
	RequestPriorityLow    RequestPriority = "low"
	RequestPriorityNormal RequestPriority = "normal"
	RequestPriorityHigh   RequestPriority = "high"
	RequestPriorityUrgent RequestPriority = "urgent"
)

type PolicyResult string

const (
	PolicyResultAllow       PolicyResult = "allow"
	PolicyResultDeny        PolicyResult = "deny"
	PolicyResultConditional PolicyResult = "conditional"
	PolicyResultError       PolicyResult = "error"
)

type RuleType string

const (
	RuleTypeAccess     RuleType = "access"
	RuleTypeCompliance RuleType = "compliance"
	RuleTypeSecurity   RuleType = "security"
)

type EvaluationMode string

const (
	EvaluationModeStrict   EvaluationMode = "strict"   // Fail on first deny
	EvaluationModeComplete EvaluationMode = "complete" // Evaluate all policies
)

type ComplianceStatus string

const (
	ComplianceStatusCompliant ComplianceStatus = "compliant"
	ComplianceStatusViolation ComplianceStatus = "violation"
	ComplianceStatusUnknown   ComplianceStatus = "unknown"
)

type DecisionFactorType string

const (
	DecisionFactorPolicy     DecisionFactorType = "policy"
	DecisionFactorRBAC       DecisionFactorType = "rbac"
	DecisionFactorJIT        DecisionFactorType = "jit"
	DecisionFactorRisk       DecisionFactorType = "risk"
	DecisionFactorTenant     DecisionFactorType = "tenant"
	DecisionFactorCompliance DecisionFactorType = "compliance"
)

type EnforcementActionType string

const (
	EnforcementActionAllow      EnforcementActionType = "allow"
	EnforcementActionDeny       EnforcementActionType = "deny"
	EnforcementActionLog        EnforcementActionType = "log"
	EnforcementActionAlert      EnforcementActionType = "alert"
	EnforcementActionQuarantine EnforcementActionType = "quarantine"
	EnforcementActionTerminate  EnforcementActionType = "terminate"
)

type RequiredActionType string

const (
	RequiredActionAuthenticate RequiredActionType = "authenticate"
	RequiredActionAuthorize    RequiredActionType = "authorize"
	RequiredActionValidate     RequiredActionType = "validate"
	RequiredActionReview       RequiredActionType = "review"
	RequiredActionApprove      RequiredActionType = "approve"
)

type RemediationActionType string

const (
	RemediationActionFix    RemediationActionType = "fix"
	RemediationActionUpdate RemediationActionType = "update"
	RemediationActionReview RemediationActionType = "review"
	RemediationActionNotify RemediationActionType = "notify"
)

type ActionStatus string

const (
	ActionStatusPending   ActionStatus = "pending"
	ActionStatusExecuting ActionStatus = "executing"
	ActionStatusCompleted ActionStatus = "completed"
	ActionStatusFailed    ActionStatus = "failed"
)

type ActionResult string

const (
	ActionResultSuccess ActionResult = "success"
	ActionResultFailure ActionResult = "failure"
	ActionResultPartial ActionResult = "partial"
)

type ActionPriority string

const (
	ActionPriorityLow      ActionPriority = "low"
	ActionPriorityMedium   ActionPriority = "medium"
	ActionPriorityHigh     ActionPriority = "high"
	ActionPriorityCritical ActionPriority = "critical"
)

type RemediationUrgency string

const (
	RemediationUrgencyLow      RemediationUrgency = "low"
	RemediationUrgencyMedium   RemediationUrgency = "medium"
	RemediationUrgencyHigh     RemediationUrgency = "high"
	RemediationUrgencyCritical RemediationUrgency = "critical"
)

type AuthStrength string

const (
	AuthStrengthWeak   AuthStrength = "weak"
	AuthStrengthMedium AuthStrength = "medium"
	AuthStrengthStrong AuthStrength = "strong"
)

type TrustLevel string

const (
	TrustLevelUntrusted TrustLevel = "untrusted"
	TrustLevelLow       TrustLevel = "low"
	TrustLevelMedium    TrustLevel = "medium"
	TrustLevelHigh      TrustLevel = "high"
)

type ThreatType string

const (
	ThreatTypeMalware    ThreatType = "malware"
	ThreatTypePhishing   ThreatType = "phishing"
	ThreatTypeBruteForce ThreatType = "brute_force"
	ThreatTypeAnomalous  ThreatType = "anomalous"
)

type ThreatSeverity string

const (
	ThreatSeverityLow      ThreatSeverity = "low"
	ThreatSeverityMedium   ThreatSeverity = "medium"
	ThreatSeverityHigh     ThreatSeverity = "high"
	ThreatSeverityCritical ThreatSeverity = "critical"
)

type AuditEventType string

const (
	AuditEventPolicyEvaluation  AuditEventType = "policy_evaluation"
	AuditEventAccessGranted     AuditEventType = "access_granted"
	AuditEventAccessDenied      AuditEventType = "access_denied"
	AuditEventViolationDetected AuditEventType = "violation_detected"
	AuditEventComplianceCheck   AuditEventType = "compliance_check"
)

type ConditionOperator string

const (
	ConditionOperatorEquals      ConditionOperator = "equals"
	ConditionOperatorNotEquals   ConditionOperator = "not_equals"
	ConditionOperatorContains    ConditionOperator = "contains"
	ConditionOperatorRegex       ConditionOperator = "regex"
	ConditionOperatorGreaterThan ConditionOperator = "greater_than"
	ConditionOperatorLessThan    ConditionOperator = "less_than"
	ConditionOperatorIn          ConditionOperator = "in"
	ConditionOperatorNotIn       ConditionOperator = "not_in"
)

type RequirementType string

const (
	RequirementTypeAuthentication  RequirementType = "authentication"
	RequirementTypeAuthorization   RequirementType = "authorization"
	RequirementTypeMFA             RequirementType = "mfa"
	RequirementTypeEncryption      RequirementType = "encryption"
	RequirementTypePolicy          RequirementType = "policy"
	RequirementTypeProcess         RequirementType = "process"
	RequirementTypePrivacy         RequirementType = "privacy"
	RequirementTypeSecurity        RequirementType = "security"
	RequirementTypeIdentification  RequirementType = "identification"
	RequirementTypeCertificate     RequirementType = "certificate"
	RequirementTypeIPWhitelist     RequirementType = "ip_whitelist"
	RequirementTypeTimeRestriction RequirementType = "time_restriction"
)

type PolicyActionType string

const (
	PolicyActionTypeAllow       PolicyActionType = "allow"
	PolicyActionTypeDeny        PolicyActionType = "deny"
	PolicyActionTypeConditional PolicyActionType = "conditional"
	PolicyActionTypeLog         PolicyActionType = "log"
	PolicyActionTypeAlert       PolicyActionType = "alert"
)

type ThreatDetectorType string

const (
	ThreatDetectorBehavioral  ThreatDetectorType = "behavioral"
	ThreatDetectorSignature   ThreatDetectorType = "signature"
	ThreatDetectorAnomaly     ThreatDetectorType = "anomaly"
	ThreatDetectorThreatIntel ThreatDetectorType = "threat_intel"
)

type ThreatSensitivity string

const (
	ThreatSensitivityLow    ThreatSensitivity = "low"
	ThreatSensitivityMedium ThreatSensitivity = "medium"
	ThreatSensitivityHigh   ThreatSensitivity = "high"
)

type AuditRequirementType string

const (
	AuditRequirementTypeAccess     AuditRequirementType = "access"
	AuditRequirementTypeChange     AuditRequirementType = "change"
	AuditRequirementTypeSystem     AuditRequirementType = "system"
	AuditRequirementTypeCompliance AuditRequirementType = "compliance"
)
