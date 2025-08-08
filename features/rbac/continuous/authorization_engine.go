package continuous

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
)

// RBACManager interface defines the RBAC operations needed by continuous authorization
type RBACManager interface {
	CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error)
	GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error)
	GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error)
	Initialize(ctx context.Context) error
}

// JITManager interface defines JIT operations needed by continuous authorization
type JITManager interface {
	CheckJITAccess(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error)
	// Add JIT methods as needed
}

// RiskManager interface defines risk operations needed by continuous authorization  
type RiskManager interface {
	EnhancedRiskAccessCheck(ctx context.Context, request *common.AccessRequest) (*RiskAccessResult, error)
	// Add risk methods as needed
}

// RiskAccessResult represents result from risk assessment
type RiskAccessResult struct {
	StandardResponse *common.AccessResponse `json:"standard_response"`
	// Add other fields as needed
}

// TenantSecurityMiddleware interface defines tenant security operations
type TenantSecurityMiddleware interface {
	GetPolicyEngine() TenantSecurityPolicyEngine
	// Add tenant security methods as needed
}

// RiskLevel represents risk assessment levels
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelModerate RiskLevel = "moderate" 
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// RuleSeverity represents the severity level of a rule
type RuleSeverity string

const (
	RuleSeverityLow      RuleSeverity = "low"
	RuleSeverityMedium   RuleSeverity = "medium" 
	RuleSeverityHigh     RuleSeverity = "high"
	RuleSeverityCritical RuleSeverity = "critical"
)

// AuthorizationMode defines different authorization modes
type AuthorizationMode string

const (
	AuthorizationModeContinuous AuthorizationMode = "continuous"
	AuthorizationModeTraditional AuthorizationMode = "traditional"
)

// PolicyEvaluationResult represents policy evaluation results
type PolicyEvaluationResult struct {
	SessionID           string            `json:"session_id"`
	EvaluationTime      time.Time         `json:"evaluation_time"`
	ComplianceStatus    bool              `json:"compliance_status"`
	AppliedPolicies     []string          `json:"applied_policies"`
	Violations          []PolicyViolation `json:"violations"`
	EnforcementActions  []EnforcementAction `json:"enforcement_actions"`
	RiskAssessment      *PolicyRiskAssessment `json:"risk_assessment"`
	RecommendedActions  []string          `json:"recommended_actions"`
}

// ContextStatus represents context validation status
type ContextStatus struct {
	Valid          bool      `json:"valid"`
	LastValidated  time.Time `json:"last_validated"`
	ChangeDetected bool      `json:"change_detected"`
}

// RiskAssessmentData represents risk assessment results
type RiskAssessmentData struct {
	CurrentRiskLevel RiskLevel   `json:"current_risk_level"`
	RiskScore        float64     `json:"risk_score"`
	RiskFactors      []RiskFactor `json:"risk_factors"`
}

// AdaptiveControl represents applied adaptive controls
type AdaptiveControl struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Status      string                 `json:"status"`
	AppliedAt   time.Time             `json:"applied_at"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// EnforcementAction represents a policy enforcement action
type EnforcementAction struct {
	ActionID         string                 `json:"action_id"`
	ActionType       string                 `json:"action_type"`
	Severity         string                 `json:"severity"`
	Description      string                 `json:"description"`
	Parameters       map[string]interface{} `json:"parameters"`
	ScheduledAt      time.Time              `json:"scheduled_at"`
	ExecutedAt       time.Time              `json:"executed_at"`
	Status           string                 `json:"status"`
	TriggeredBy      string                 `json:"triggered_by"`
	AffectedSessions []string               `json:"affected_sessions"`
	ErrorMessage     string                 `json:"error_message,omitempty"`
}

// PolicyRiskAssessment represents risk assessment from policy evaluation
type PolicyRiskAssessment struct {
	OverallRisk        float64           `json:"overall_risk"`
	RiskFactors        []PolicyRiskFactor `json:"risk_factors"`
	ComplianceImpact   float64           `json:"compliance_impact"`
	BusinessImpact     float64           `json:"business_impact"`
	SecurityImpact     float64           `json:"security_impact"`
	RecommendedActions []string          `json:"recommended_actions"`
}

// PolicyRiskFactor represents a risk factor in policy evaluation
type PolicyRiskFactor struct {
	Factor      string  `json:"factor"`
	Weight      float64 `json:"weight"`
	Score       float64 `json:"score"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// RiskFactor represents a risk factor
type RiskFactor struct {
	Type        string    `json:"type"`
	Category    string    `json:"category"`
	Severity    string    `json:"severity"`
	Score       float64   `json:"score"`
	Description string    `json:"description"`
	DetectedAt  time.Time `json:"detected_at"`
}

// ContinuousAuthorizationEngine provides real-time, per-action permission validation
// with dynamic permission updates and immediate revocation capabilities
type ContinuousAuthorizationEngine struct {
	// Core dependencies
	rbacManager         RBACManager
	jitManager         JITManager
	riskManager        RiskManager
	tenantSecurity     TenantSecurityMiddleware

	// Core components
	sessionRegistry    *SessionRegistry
	permissionCache    *CacheManager
	eventBus          *PermissionEventBus
	contextMonitor     *ContextMonitor
	policyEnforcer     *PolicyEnforcer

	// Configuration
	config            *ContinuousAuthConfig
	
	// Control
	stopChannel       chan struct{}
	running           bool
	mutex            sync.RWMutex

	// Statistics
	stats            *AuthorizationStats
}

// ContinuousAuthConfig contains configuration for the continuous authorization engine
type ContinuousAuthConfig struct {
	// Performance settings
	MaxAuthLatencyMs        int           `json:"max_auth_latency_ms"`        // Target < 10ms
	PermissionCacheTTL      time.Duration `json:"permission_cache_ttl"`       // Cache TTL
	SessionUpdateInterval   time.Duration `json:"session_update_interval"`    // Session monitoring interval
	
	// Permission propagation
	PropagationTimeoutMs    int           `json:"propagation_timeout_ms"`     // Target < 1000ms
	MaxRetryAttempts        int           `json:"max_retry_attempts"`         // Permission update retries
	
	// Risk integration
	EnableRiskReassessment  bool          `json:"enable_risk_reassessment"`   // Continuous risk monitoring
	RiskCheckInterval       time.Duration `json:"risk_check_interval"`        // Risk reassessment frequency
	
	// Policy enforcement
	EnableAutoTermination   bool          `json:"enable_auto_termination"`    // Auto-terminate on violations
	ViolationGracePeriod    time.Duration `json:"violation_grace_period"`     // Grace period before termination
	
	// Audit and monitoring
	EnableComprehensiveAudit bool         `json:"enable_comprehensive_audit"` // Log all authorization decisions
	AuditBufferSize         int           `json:"audit_buffer_size"`          // Audit event buffer
}

// AuthorizationStats tracks authorization engine statistics
type AuthorizationStats struct {
	// Authorization metrics
	TotalAuthChecks        int64         `json:"total_auth_checks"`
	AverageLatencyMs       float64       `json:"average_latency_ms"`
	AuthorizedRequests     int64         `json:"authorized_requests"`
	DeniedRequests         int64         `json:"denied_requests"`
	
	// Session metrics
	ActiveSessions         int           `json:"active_sessions"`
	SessionsTerminated     int64         `json:"sessions_terminated"`
	PermissionRevocations  int64         `json:"permission_revocations"`
	
	// Performance metrics
	CacheHitRate          float64       `json:"cache_hit_rate"`
	PropagationLatencyMs  float64       `json:"propagation_latency_ms"`
	PolicyViolations      int64         `json:"policy_violations"`
	
	// Update tracking
	LastUpdated           time.Time     `json:"last_updated"`
	
	mutex                 sync.RWMutex
}

// ContinuousAuthRequest represents a per-action authorization request
type ContinuousAuthRequest struct {
	// Standard access request fields
	*common.AccessRequest
	
	// Continuous authorization specific fields
	SessionID           string            `json:"session_id"`
	OperationType       OperationType     `json:"operation_type"`
	ResourceContext     map[string]string `json:"resource_context"`
	PreviousDecisionID  string            `json:"previous_decision_id,omitempty"`
	
	// Risk context (optional)
	CurrentRiskLevel    RiskLevel         `json:"current_risk_level,omitempty"`
	ContextChanged      bool              `json:"context_changed"`
	
	// Timing
	RequestTime         time.Time         `json:"request_time"`
}

// ContinuousAuthResponse represents the authorization decision with continuous context
type ContinuousAuthResponse struct {
	// Standard authorization response
	AccessResponse      *common.AccessResponse `json:"access_response"`
	
	// Continuous authorization specific fields
	DecisionID          string            `json:"decision_id"`
	DecisionTime        time.Time         `json:"decision_time"`
	ValidUntil          time.Time         `json:"valid_until"`
	SessionValid        bool              `json:"session_valid"`
	
	// Policy information
	AppliedPolicies     []string          `json:"applied_policies"`
	PolicyViolations    []PolicyViolation `json:"policy_violations"`
	PolicyEvaluation    *PolicyEvaluationResult `json:"policy_evaluation"`
	ContextStatus       *ContextStatus    `json:"context_status"`
	CacheHit            bool              `json:"cache_hit"`
	
	// Risk assessment information
	RiskAssessment      *RiskAssessmentData `json:"risk_assessment,omitempty"`
	
	// Adaptive controls
	AdaptiveControls    []AdaptiveControl `json:"adaptive_controls,omitempty"`
	
	// Performance metrics
	ProcessingLatencyMs int               `json:"processing_latency_ms"`
	CacheUsed           bool              `json:"cache_used"`
	
	// Next check requirements
	RequiresContinuousCheck bool          `json:"requires_continuous_check"`
	NextCheckTime          time.Time      `json:"next_check_time,omitempty"`
	
	// Action recommendations
	RecommendedActions  []ActionRecommendation `json:"recommended_actions"`
}

// OperationType defines the type of operation being authorized
type OperationType string

const (
	OperationTypeAPI        OperationType = "api"           // API call authorization
	OperationTypeResource   OperationType = "resource"      // Resource access
	OperationTypeData       OperationType = "data"          // Data access
	OperationTypeAdmin      OperationType = "admin"         // Administrative operation
	OperationTypeTerminal   OperationType = "terminal"      // Terminal session operation
	OperationTypeService    OperationType = "service"       // Service-to-service
	OperationTypeStandard   OperationType = "standard"      // Standard operation
	OperationTypeModerate   OperationType = "moderate"      // Moderate risk operation
	OperationTypeHighRisk   OperationType = "high_risk"     // High risk operation
	OperationTypeCritical   OperationType = "critical"      // Critical operation
)

// PolicyViolation represents a detected policy violation
type PolicyViolation struct {
	PolicyID      string                 `json:"policy_id"`
	RuleID        string                 `json:"rule_id"`
	RuleName      string                 `json:"rule_name"`
	ViolationType ViolationType          `json:"violation_type"`
	Severity      RuleSeverity           `json:"severity"`
	Description   string                 `json:"description"`
	Details       string                 `json:"details"`
	Context       map[string]interface{} `json:"context"`
	DetectedAt    time.Time              `json:"detected_at"`
}

// ActionRecommendation provides recommendations for improving security posture
type ActionRecommendation struct {
	Type        RecommendationType `json:"type"`
	Priority    string            `json:"priority"`
	Description string            `json:"description"`
	Action      string            `json:"action"`
	Deadline    time.Time         `json:"deadline,omitempty"`
}

// RecommendationType defines types of security recommendations
type RecommendationType string

const (
	RecommendationTypeSessionReauth     RecommendationType = "session_reauth"
	RecommendationTypePermissionReview  RecommendationType = "permission_review"
	RecommendationTypeRiskMitigation    RecommendationType = "risk_mitigation"
	RecommendationTypeComplianceAction  RecommendationType = "compliance_action"
	RecommendationTypePolicyUpdate      RecommendationType = "policy_update"
)

// NewContinuousAuthorizationEngine creates a new continuous authorization engine
func NewContinuousAuthorizationEngine(
	rbacManager RBACManager,
	jitManager JITManager,
	riskManager RiskManager,
	tenantSecurity TenantSecurityMiddleware,
	config *ContinuousAuthConfig,
) *ContinuousAuthorizationEngine {
	if config == nil {
		config = DefaultContinuousAuthConfig()
	}

	// Initialize core components
	sessionRegistry := NewSessionRegistry()
	permissionCache := NewCacheManager(config.PermissionCacheTTL, config.MaxAuthLatencyMs)
	eventBus := NewPermissionEventBus(1000) // Buffer size
	contextMonitor := NewContextMonitor(riskManager, config.RiskCheckInterval)
	policyEnforcer := NewPolicyEnforcer(tenantSecurity, config.EnableAutoTermination)

	return &ContinuousAuthorizationEngine{
		rbacManager:     rbacManager,
		jitManager:      jitManager,
		riskManager:     riskManager,
		tenantSecurity:  tenantSecurity,
		sessionRegistry: sessionRegistry,
		permissionCache: permissionCache,
		eventBus:       eventBus,
		contextMonitor:  contextMonitor,
		policyEnforcer:  policyEnforcer,
		config:         config,
		stopChannel:    make(chan struct{}),
		stats:          &AuthorizationStats{LastUpdated: time.Now()},
	}
}

// Start initializes and starts the continuous authorization engine
func (cae *ContinuousAuthorizationEngine) Start(ctx context.Context) error {
	cae.mutex.Lock()
	defer cae.mutex.Unlock()

	if cae.running {
		return fmt.Errorf("continuous authorization engine is already running")
	}

	// Initialize RBAC manager
	if cae.rbacManager != nil {
		if err := cae.rbacManager.Initialize(ctx); err != nil {
			return fmt.Errorf("failed to initialize RBAC manager: %w", err)
		}
	}

	// Start core components
	if err := cae.sessionRegistry.Start(ctx); err != nil {
		return fmt.Errorf("failed to start session registry: %w", err)
	}

	if err := cae.eventBus.Start(ctx); err != nil {
		return fmt.Errorf("failed to start permission event bus: %w", err)
	}

	if err := cae.contextMonitor.Start(ctx); err != nil {
		return fmt.Errorf("failed to start context monitor: %w", err)
	}

	if err := cae.policyEnforcer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start policy enforcer: %w", err)
	}

	// Start background processes
	go cae.sessionMonitoringLoop(ctx)
	go cae.permissionUpdateLoop(ctx)
	go cae.statisticsUpdateLoop(ctx)

	cae.running = true
	return nil
}

// Stop gracefully shuts down the continuous authorization engine
func (cae *ContinuousAuthorizationEngine) Stop() error {
	cae.mutex.Lock()
	defer cae.mutex.Unlock()

	if !cae.running {
		return fmt.Errorf("continuous authorization engine is not running")
	}

	// Signal shutdown
	close(cae.stopChannel)

	// Stop components
	cae.policyEnforcer.Stop()
	cae.contextMonitor.Stop()
	cae.eventBus.Stop()
	cae.sessionRegistry.Stop()

	cae.running = false
	return nil
}

// AuthorizeAction performs per-action continuous authorization
func (cae *ContinuousAuthorizationEngine) AuthorizeAction(ctx context.Context, request *ContinuousAuthRequest) (*ContinuousAuthResponse, error) {
	startTime := time.Now()
	
	// Validate request
	if request == nil {
		return nil, fmt.Errorf("authorization request cannot be nil")
	}
	
	if request.AccessRequest == nil {
		return nil, fmt.Errorf("access request cannot be nil")
	}
	
	if request.SubjectId == "" {
		return nil, fmt.Errorf("subject ID is required")
	}
	
	if request.SessionID == "" {
		return nil, fmt.Errorf("session ID is required")
	}
	
	// Update statistics
	cae.updateStatsOnRequest()

	// Apply timeout for performance requirements (< 10ms target)
	authCtx, cancel := context.WithTimeout(ctx, time.Duration(cae.config.MaxAuthLatencyMs)*time.Millisecond)
	defer cancel()

	// Generate decision ID for tracking
	decisionID := fmt.Sprintf("auth-%d-%s", time.Now().UnixNano(), request.SessionID)
	
	// Create response structure
	response := &ContinuousAuthResponse{
		DecisionID:   decisionID,
		DecisionTime: time.Now(),
		AccessResponse: &common.AccessResponse{
			Granted: false,
			Reason:  "",
		},
		AppliedPolicies:  make([]string, 0),
		PolicyViolations: make([]PolicyViolation, 0),
		RecommendedActions: make([]ActionRecommendation, 0),
	}

	// 1. Check session validity
	sessionValid, err := cae.sessionRegistry.ValidateSession(authCtx, request.SessionID, request.SubjectId)
	if err != nil {
		return cae.createErrorResponse(decisionID, fmt.Sprintf("session validation failed: %v", err), startTime), nil
	}
	
	response.SessionValid = sessionValid
	if !sessionValid {
		return cae.createDeniedResponse(decisionID, "session invalid or expired", startTime), nil
	}

	// 2. Check cache for recent authorization decision
	if cached := cae.permissionCache.GetCachedAuth(request); cached != nil && cae.isCacheValid(cached) {
		response = cae.enhanceWithCache(response, cached, startTime)
		response.CacheUsed = true
		cae.updateStatsOnDecision(true, startTime)
		return response, nil
	}

	// 3. Perform comprehensive authorization check
	authDecision, err := cae.performAuthorizationCheck(authCtx, request)
	if err != nil {
		return cae.createErrorResponse(decisionID, fmt.Sprintf("authorization check failed: %v", err), startTime), nil
	}

	// 4. Apply policy enforcement
	policyResult, err := cae.policyEnforcer.EvaluatePolicies(authCtx, request, authDecision)
	if err != nil {
		return cae.createErrorResponse(decisionID, fmt.Sprintf("policy evaluation failed: %v", err), startTime), nil
	}

	// 5. Build final response
	response.AccessResponse = authDecision
	response.AppliedPolicies = policyResult.AppliedPolicies
	response.PolicyViolations = policyResult.Violations
	response.ProcessingLatencyMs = int(time.Since(startTime).Milliseconds())

	// 6. Determine if continuous checking is required
	response.RequiresContinuousCheck = cae.requiresContinuousCheck(request, policyResult)
	if response.RequiresContinuousCheck {
		response.NextCheckTime = time.Now().Add(cae.config.SessionUpdateInterval)
	}

	// 7. Generate recommendations
	response.RecommendedActions = cae.generateActionRecommendations(request, authDecision, policyResult)

	// 8. Set validity period
	response.ValidUntil = time.Now().Add(cae.config.PermissionCacheTTL)

	// 9. Cache the decision
	cae.permissionCache.CacheAuth(request, response)

	// 10. Publish authorization event
	cae.eventBus.PublishAuthorizationEvent(&AuthorizationEvent{
		DecisionID:    decisionID,
		SessionID:     request.SessionID,
		SubjectID:     request.SubjectId,
		PermissionID:  request.PermissionId,
		Granted:       authDecision.Granted,
		Timestamp:     time.Now(),
		LatencyMs:     response.ProcessingLatencyMs,
	})

	// Update statistics
	cae.updateStatsOnDecision(authDecision.Granted, startTime)

	return response, nil
}

// performAuthorizationCheck conducts the comprehensive authorization evaluation
func (cae *ContinuousAuthorizationEngine) performAuthorizationCheck(ctx context.Context, request *ContinuousAuthRequest) (*common.AccessResponse, error) {
	// Use existing integrated access control for comprehensive evaluation
	accessRequest := request.AccessRequest
	
	// First check RBAC
	rbacResponse, err := cae.rbacManager.CheckPermission(ctx, accessRequest)
	if err != nil {
		// Return a denied response with system error message instead of returning error
		return &common.AccessResponse{
			Granted: false,
			Reason:  fmt.Sprintf("system error - RBAC check failed: %v", err),
		}, nil
	}

	// If RBAC denies, check JIT access
	if !rbacResponse.Granted {
		if cae.jitManager != nil {
			jitResponse, err := cae.jitManager.CheckJITAccess(ctx, accessRequest)
			if err == nil && jitResponse != nil && jitResponse.Granted {
				rbacResponse = jitResponse
			}
		}
	}

	// Apply risk-based adjustments if access is granted
	if rbacResponse.Granted && cae.riskManager != nil {
		riskResponse, err := cae.riskManager.EnhancedRiskAccessCheck(ctx, accessRequest)
		if err == nil && riskResponse.StandardResponse != nil {
			rbacResponse = riskResponse.StandardResponse
		}
	}

	return rbacResponse, nil
}

// RegisterSession registers a new session for continuous authorization
func (cae *ContinuousAuthorizationEngine) RegisterSession(ctx context.Context, sessionID, subjectID, tenantID string, metadata map[string]string) error {
	return cae.sessionRegistry.RegisterSession(ctx, sessionID, subjectID, tenantID, metadata)
}

// UnregisterSession removes a session from continuous authorization
func (cae *ContinuousAuthorizationEngine) UnregisterSession(ctx context.Context, sessionID string) error {
	// Clean up cached permissions for the session
	cae.permissionCache.EvictSessionCache(sessionID)
	
	// Remove from session registry
	return cae.sessionRegistry.UnregisterSession(ctx, sessionID)
}

// RevokePermissions immediately revokes permissions for a subject across all sessions
func (cae *ContinuousAuthorizationEngine) RevokePermissions(ctx context.Context, subjectID, tenantID string, permissions []string) error {
	startTime := time.Now()

	// Get all sessions for the subject
	sessions, err := cae.sessionRegistry.GetUserSessions(ctx, subjectID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Create permission revocation event
	revocationEvent := &PermissionRevocationEvent{
		EventID:     fmt.Sprintf("revoke-%d", time.Now().UnixNano()),
		SubjectID:   subjectID,
		TenantID:    tenantID,
		Permissions: permissions,
		Timestamp:   time.Now(),
		SessionIDs:  make([]string, len(sessions)),
	}

	for i, session := range sessions {
		revocationEvent.SessionIDs[i] = session.SessionID
	}

	// Publish revocation event for real-time propagation
	if err := cae.eventBus.PublishPermissionRevocation(revocationEvent); err != nil {
		return fmt.Errorf("failed to publish permission revocation: %w", err)
	}

	// Invalidate cache entries for affected sessions
	for _, session := range sessions {
		cae.permissionCache.EvictSubjectPermissions(session.SessionID, permissions)
	}

	// Update statistics
	cae.stats.mutex.Lock()
	cae.stats.PermissionRevocations++
	cae.stats.PropagationLatencyMs = float64(time.Since(startTime).Milliseconds())
	cae.stats.mutex.Unlock()

	return nil
}

// GetSessionStatus returns the current status of a session
func (cae *ContinuousAuthorizationEngine) GetSessionStatus(ctx context.Context, sessionID string) (*SessionStatus, error) {
	return cae.sessionRegistry.GetSessionStatus(ctx, sessionID)
}

// GetAuthorizationStats returns current authorization engine statistics
func (cae *ContinuousAuthorizationEngine) GetAuthorizationStats() *AuthorizationStats {
	cae.stats.mutex.RLock()
	defer cae.stats.mutex.RUnlock()

	// Return a copy to prevent data races
	return &AuthorizationStats{
		TotalAuthChecks:       cae.stats.TotalAuthChecks,
		AverageLatencyMs:      cae.stats.AverageLatencyMs,
		AuthorizedRequests:    cae.stats.AuthorizedRequests,
		DeniedRequests:        cae.stats.DeniedRequests,
		ActiveSessions:        cae.stats.ActiveSessions,
		SessionsTerminated:    cae.stats.SessionsTerminated,
		PermissionRevocations: cae.stats.PermissionRevocations,
		CacheHitRate:         cae.stats.CacheHitRate,
		PropagationLatencyMs: cae.stats.PropagationLatencyMs,
		PolicyViolations:     cae.stats.PolicyViolations,
		LastUpdated:          cae.stats.LastUpdated,
	}
}

// Background processing methods

// sessionMonitoringLoop continuously monitors sessions for policy compliance
func (cae *ContinuousAuthorizationEngine) sessionMonitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(cae.config.SessionUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cae.stopChannel:
			return
		case <-ticker.C:
			cae.performSessionHealthCheck(ctx)
		}
	}
}

// permissionUpdateLoop processes real-time permission updates
func (cae *ContinuousAuthorizationEngine) permissionUpdateLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-cae.stopChannel:
			return
		case event := <-cae.eventBus.SubscribeToEvents():
			cae.handlePermissionEvent(ctx, event)
		}
	}
}

// statisticsUpdateLoop updates engine statistics periodically
func (cae *ContinuousAuthorizationEngine) statisticsUpdateLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cae.stopChannel:
			return
		case <-ticker.C:
			cae.updateStatistics()
		}
	}
}

// Helper methods

func (cae *ContinuousAuthorizationEngine) createErrorResponse(decisionID, reason string, startTime time.Time) *ContinuousAuthResponse {
	return &ContinuousAuthResponse{
		DecisionID:   decisionID,
		DecisionTime: time.Now(),
		AccessResponse: &common.AccessResponse{
			Granted: false,
			Reason:  reason,
		},
		ProcessingLatencyMs: int(time.Since(startTime).Milliseconds()),
		SessionValid:        false,
	}
}

func (cae *ContinuousAuthorizationEngine) createDeniedResponse(decisionID, reason string, startTime time.Time) *ContinuousAuthResponse {
	return &ContinuousAuthResponse{
		DecisionID:   decisionID,
		DecisionTime: time.Now(),
		AccessResponse: &common.AccessResponse{
			Granted: false,
			Reason:  reason,
		},
		ProcessingLatencyMs: int(time.Since(startTime).Milliseconds()),
		SessionValid:        true, // Session might be valid but access denied
	}
}

func (cae *ContinuousAuthorizationEngine) isCacheValid(cached *CachedAuthDecision) bool {
	return time.Now().Before(cached.ValidUntil)
}

func (cae *ContinuousAuthorizationEngine) enhanceWithCache(response *ContinuousAuthResponse, cached *CachedAuthDecision, startTime time.Time) *ContinuousAuthResponse {
	response.AccessResponse = cached.AccessResponse
	response.ProcessingLatencyMs = int(time.Since(startTime).Milliseconds())
	response.ValidUntil = cached.ValidUntil
	return response
}

func (cae *ContinuousAuthorizationEngine) requiresContinuousCheck(request *ContinuousAuthRequest, policyResult *PolicyEvaluationResult) bool {
	// Require continuous checking for high-risk operations, privileged access, or policy violations
	return request.OperationType == OperationTypeAdmin ||
		len(policyResult.Violations) > 0 ||
		request.CurrentRiskLevel >= RiskLevelHigh
}

func (cae *ContinuousAuthorizationEngine) generateActionRecommendations(request *ContinuousAuthRequest, authDecision *common.AccessResponse, policyResult *PolicyEvaluationResult) []ActionRecommendation {
	recommendations := make([]ActionRecommendation, 0)

	// Add recommendations based on policy violations
	if len(policyResult.Violations) > 0 {
		recommendations = append(recommendations, ActionRecommendation{
			Type:        RecommendationTypePolicyUpdate,
			Priority:    "high",
			Description: "Policy violations detected - review security policies",
			Action:      "review_security_policies",
			Deadline:    time.Now().Add(24 * time.Hour),
		})
	}

	// Add risk-based recommendations
	if request.CurrentRiskLevel >= RiskLevelHigh {
		recommendations = append(recommendations, ActionRecommendation{
			Type:        RecommendationTypeRiskMitigation,
			Priority:    "high",
			Description: "High risk level detected - implement additional security measures",
			Action:      "implement_additional_security_measures",
			Deadline:    time.Now().Add(1 * time.Hour),
		})
	}

	return recommendations
}

func (cae *ContinuousAuthorizationEngine) performSessionHealthCheck(ctx context.Context) {
	sessions := cae.sessionRegistry.GetAllSessions()
	for _, session := range sessions {
		// Check session context and update if needed
		cae.contextMonitor.CheckSessionContext(ctx, session)
	}
}

func (cae *ContinuousAuthorizationEngine) handlePermissionEvent(ctx context.Context, event interface{}) {
	// Process different types of permission events
	switch e := event.(type) {
	case *PermissionRevocationEvent:
		// Handle permission revocation
		cae.processPermissionRevocation(ctx, e)
	case *AuthorizationEvent:
		// Update authorization metrics
		cae.updateAuthorizationMetrics(e)
	}
}

func (cae *ContinuousAuthorizationEngine) processPermissionRevocation(ctx context.Context, event *PermissionRevocationEvent) {
	// Invalidate affected sessions and cache entries
	for _, sessionID := range event.SessionIDs {
		cae.permissionCache.EvictSubjectPermissions(sessionID, event.Permissions)
	}
}

func (cae *ContinuousAuthorizationEngine) updateAuthorizationMetrics(event *AuthorizationEvent) {
	cae.stats.mutex.Lock()
	defer cae.stats.mutex.Unlock()

	// Update running averages
	cae.stats.TotalAuthChecks++
	if event.Granted {
		cae.stats.AuthorizedRequests++
	} else {
		cae.stats.DeniedRequests++
	}

	// Update average latency using exponential moving average
	alpha := 0.1 // Smoothing factor
	cae.stats.AverageLatencyMs = (1-alpha)*cae.stats.AverageLatencyMs + alpha*float64(event.LatencyMs)
}

func (cae *ContinuousAuthorizationEngine) updateStatistics() {
	cae.stats.mutex.Lock()
	defer cae.stats.mutex.Unlock()

	// Update session count
	cae.stats.ActiveSessions = cae.sessionRegistry.GetSessionCount()

	// Update cache hit rate
	cae.stats.CacheHitRate = cae.permissionCache.GetHitRate()

	// Update timestamp
	cae.stats.LastUpdated = time.Now()
}

func (cae *ContinuousAuthorizationEngine) updateStatsOnRequest() {
	cae.stats.mutex.Lock()
	defer cae.stats.mutex.Unlock()
	// Increment will happen in updateAuthorizationMetrics
}

func (cae *ContinuousAuthorizationEngine) updateStatsOnDecision(granted bool, startTime time.Time) {
	// This will be handled by the authorization event processing
}

// DefaultContinuousAuthConfig returns default configuration for continuous authorization
func DefaultContinuousAuthConfig() *ContinuousAuthConfig {
	return &ContinuousAuthConfig{
		MaxAuthLatencyMs:        10,                    // 10ms target latency
		PermissionCacheTTL:      5 * time.Minute,       // 5 minute cache TTL
		SessionUpdateInterval:   30 * time.Second,      // 30 second session monitoring
		PropagationTimeoutMs:    1000,                  // 1 second propagation target
		MaxRetryAttempts:        3,                     // 3 retry attempts
		EnableRiskReassessment:  true,                  // Enable continuous risk monitoring
		RiskCheckInterval:       2 * time.Minute,       // 2 minute risk checks
		EnableAutoTermination:   true,                  // Enable auto-termination
		ViolationGracePeriod:    30 * time.Second,      // 30 second grace period
		EnableComprehensiveAudit: true,                 // Enable comprehensive audit logging
		AuditBufferSize:         10000,                 // 10k audit event buffer
	}
}