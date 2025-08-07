package integration

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/jit"
	"github.com/cfgis/cfgms/features/rbac/risk"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/features/tenant/security"
)

// EnhancedAccessControlManager provides unified access control combining RBAC, JIT, and Risk-based controls
type EnhancedAccessControlManager struct {
	rbacManager              rbac.RBACManager
	tenantManager           *tenant.Manager
	tenantSecurity          *security.TenantSecurityMiddleware
	jitIntegrationManager   *jit.JITIntegrationManager
	riskIntegrationManager  *risk.RiskBasedAccessIntegration
	integrationMode         IntegrationMode
	fallbackBehavior        FallbackBehavior
	performanceConfig       *PerformanceConfig
}

// IntegrationMode defines how the different access control systems are integrated
type IntegrationMode string

const (
	// IntegrationModeSequential evaluates RBAC -> JIT -> Risk in sequence
	IntegrationModeSequential IntegrationMode = "sequential"
	// IntegrationModeParallel evaluates all systems in parallel and combines results
	IntegrationModeParallel   IntegrationMode = "parallel"
	// IntegrationModeRiskFirst evaluates risk first to determine appropriate controls
	IntegrationModeRiskFirst  IntegrationMode = "risk_first"
)

// FallbackBehavior defines behavior when components fail
type FallbackBehavior string

const (
	// FallbackBehaviorDeny denies access if any component fails
	FallbackBehaviorDeny    FallbackBehavior = "deny"
	// FallbackBehaviorAllow allows access if core RBAC succeeds, even if other components fail
	FallbackBehaviorAllow   FallbackBehavior = "allow"
	// FallbackBehaviorDegrade gracefully degrades to simpler access control on component failure
	FallbackBehaviorDegrade FallbackBehavior = "degrade"
)

// PerformanceConfig defines performance-related configuration
type PerformanceConfig struct {
	MaxProcessingTime    time.Duration `json:"max_processing_time"`
	EnableCaching        bool          `json:"enable_caching"`
	CacheTimeout         time.Duration `json:"cache_timeout"`
	EnableParallelEval   bool          `json:"enable_parallel_eval"`
	RiskAssessmentTimeout time.Duration `json:"risk_assessment_timeout"`
}

// EnhancedAccessResponse provides comprehensive access control results
type EnhancedAccessResponse struct {
	// Standard access response
	StandardResponse *common.AccessResponse `json:"standard_response"`
	
	// Component-specific results
	RBACResult       *RBACValidationResult              `json:"rbac_result"`
	TenantSecurity   *security.TenantSecurityValidationResult `json:"tenant_security"`
	JITAccess        *jit.JITAccessValidationResult     `json:"jit_access"`
	RiskAssessment   *risk.RiskAssessmentResult         `json:"risk_assessment"`
	
	// Applied controls and recommendations
	AppliedControls  []risk.AdaptiveControlInstance     `json:"applied_controls"`
	Recommendations  []AccessRecommendation             `json:"recommendations"`
	
	// Processing metadata
	ProcessingTime   time.Duration                      `json:"processing_time"`
	ComponentLatency map[string]time.Duration           `json:"component_latency"`
	FallbacksUsed    []string                          `json:"fallbacks_used"`
	
	// Risk and compliance metadata
	RiskFactorsSummary *risk.RiskFactorsSummary         `json:"risk_factors_summary"`
	ComplianceStatus   *ComplianceStatus                `json:"compliance_status"`
}

// RBACValidationResult contains RBAC-specific validation results
type RBACValidationResult struct {
	HasPermission      bool                             `json:"has_permission"`
	EffectiveRoles     []string                         `json:"effective_roles"`
	PermissionSource   string                           `json:"permission_source"` // "direct", "role", "inheritance"
	HierarchyPath      []string                         `json:"hierarchy_path"`
	ValidationTime     time.Time                        `json:"validation_time"`
}

// AccessRecommendation provides recommendations for improving access control
type AccessRecommendation struct {
	Type        RecommendationType `json:"type"`
	Priority    string            `json:"priority"`
	Description string            `json:"description"`
	Action      string            `json:"action"`
	Rationale   string            `json:"rationale"`
}

// ComplianceStatus provides compliance-related status information
type ComplianceStatus struct {
	OverallCompliant  bool              `json:"overall_compliant"`
	Frameworks        map[string]bool   `json:"frameworks"` // framework -> compliant
	Violations        []string          `json:"violations"`
	RequiredActions   []string          `json:"required_actions"`
}

// RecommendationType defines types of access recommendations
type RecommendationType string

const (
	RecommendationTypeRoleOptimization    RecommendationType = "role_optimization"
	RecommendationTypeSecurityImprovement RecommendationType = "security_improvement"
	RecommendationTypeComplianceAction    RecommendationType = "compliance_action"
	RecommendationTypeRiskMitigation      RecommendationType = "risk_mitigation"
	RecommendationTypeAccessReview        RecommendationType = "access_review"
)

// NewEnhancedAccessControlManager creates a new enhanced access control manager
func NewEnhancedAccessControlManager(
	rbacManager rbac.RBACManager,
	tenantManager *tenant.Manager,
	tenantSecurity *security.TenantSecurityMiddleware,
) *EnhancedAccessControlManager {
	
	// Initialize component managers
	jitIntegrationManager := jit.NewJITIntegrationManager(rbacManager, tenantManager, tenantSecurity)
	riskIntegrationManager := risk.NewRiskBasedAccessIntegration(rbacManager, jitIntegrationManager, tenantSecurity)
	
	return &EnhancedAccessControlManager{
		rbacManager:             rbacManager,
		tenantManager:          tenantManager,
		tenantSecurity:         tenantSecurity,
		jitIntegrationManager:  jitIntegrationManager,
		riskIntegrationManager: riskIntegrationManager,
		integrationMode:        IntegrationModeSequential, // Default to sequential
		fallbackBehavior:       FallbackBehaviorDegrade,   // Default to graceful degradation
		performanceConfig: &PerformanceConfig{
			MaxProcessingTime:     5 * time.Second,
			EnableCaching:         true,
			CacheTimeout:          10 * time.Minute,
			EnableParallelEval:    false,
			RiskAssessmentTimeout: 2 * time.Second,
		},
	}
}

// Initialize initializes all access control components
func (eacm *EnhancedAccessControlManager) Initialize(ctx context.Context) error {
	// Initialize RBAC system
	if err := eacm.rbacManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize RBAC manager: %w", err)
	}

	// Initialize JIT access system
	if err := eacm.jitIntegrationManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize JIT integration: %w", err)
	}

	return nil
}

// CheckAccess performs comprehensive access control evaluation
func (eacm *EnhancedAccessControlManager) CheckAccess(ctx context.Context, request *common.AccessRequest) (*EnhancedAccessResponse, error) {
	startTime := time.Now()
	
	// Create response structure
	response := &EnhancedAccessResponse{
		ComponentLatency: make(map[string]time.Duration),
		FallbacksUsed:    make([]string, 0),
		Recommendations:  make([]AccessRecommendation, 0),
	}

	// Apply processing timeout
	processCtx, cancel := context.WithTimeout(ctx, eacm.performanceConfig.MaxProcessingTime)
	defer cancel()

	// Perform access evaluation based on integration mode
	switch eacm.integrationMode {
	case IntegrationModeSequential:
		err := eacm.evaluateSequential(processCtx, request, response)
		if err != nil {
			return eacm.handleEvaluationError(ctx, request, response, err)
		}
	case IntegrationModeRiskFirst:
		err := eacm.evaluateRiskFirst(processCtx, request, response)
		if err != nil {
			return eacm.handleEvaluationError(ctx, request, response, err)
		}
	default:
		return nil, fmt.Errorf("unsupported integration mode: %s", eacm.integrationMode)
	}

	// Generate recommendations
	eacm.generateRecommendations(ctx, request, response)

	// Set processing metadata
	response.ProcessingTime = time.Since(startTime)

	return response, nil
}

// evaluateSequential performs sequential evaluation: RBAC -> JIT -> Risk
func (eacm *EnhancedAccessControlManager) evaluateSequential(ctx context.Context, request *common.AccessRequest, response *EnhancedAccessResponse) error {
	
	// Step 1: Core RBAC evaluation
	rbacStart := time.Now()
	rbacResult, err := eacm.evaluateRBACAccess(ctx, request)
	if err != nil {
		return fmt.Errorf("RBAC evaluation failed: %w", err)
	}
	response.RBACResult = rbacResult
	response.ComponentLatency["rbac"] = time.Since(rbacStart)

	// Step 2: JIT access evaluation (if RBAC didn't grant access)
	jitStart := time.Now()
	if !rbacResult.HasPermission {
		jitResponse, err := eacm.jitIntegrationManager.EnhancedAccessCheck(ctx, request)
		if err != nil {
			// JIT failure is not fatal if we have fallback behavior
			if eacm.fallbackBehavior == FallbackBehaviorDeny {
				return fmt.Errorf("JIT evaluation failed: %w", err)
			}
			response.FallbacksUsed = append(response.FallbacksUsed, "jit_fallback")
		} else {
			response.TenantSecurity = jitResponse.TenantSecurity
			response.JITAccess = jitResponse.JITAccess
			response.StandardResponse = jitResponse.StandardResponse
		}
	} else {
		// RBAC granted access, create appropriate response
		response.StandardResponse = &common.AccessResponse{
			Granted:            true,
			Reason:             "Access granted by RBAC",
			AppliedPermissions: []string{request.PermissionId},
		}
	}
	response.ComponentLatency["jit"] = time.Since(jitStart)

	// Step 3: Risk assessment (always perform for granted access)
	riskStart := time.Now()
	if response.StandardResponse != nil && response.StandardResponse.Granted {
		riskCtx, cancel := context.WithTimeout(ctx, eacm.performanceConfig.RiskAssessmentTimeout)
		defer cancel()
		
		riskResponse, err := eacm.riskIntegrationManager.EnhancedRiskAccessCheck(riskCtx, request)
		if err != nil {
			// Risk assessment failure handling based on fallback behavior
			switch eacm.fallbackBehavior {
			case FallbackBehaviorDeny:
				return fmt.Errorf("risk assessment failed: %w", err)
			case FallbackBehaviorAllow:
				response.FallbacksUsed = append(response.FallbacksUsed, "risk_fallback")
			case FallbackBehaviorDegrade:
				// Apply conservative controls
				response.FallbacksUsed = append(response.FallbacksUsed, "risk_degraded")
				eacm.applyConservativeRiskControls(response)
			}
		} else {
			// Risk assessment succeeded - use risk-aware decision
			response.StandardResponse = riskResponse.StandardResponse
			response.RiskAssessment = riskResponse.RiskAssessment
			response.AppliedControls = riskResponse.AppliedControls
			response.RiskFactorsSummary = riskResponse.RiskFactorsSummary
		}
	}
	response.ComponentLatency["risk"] = time.Since(riskStart)

	return nil
}

// evaluateRiskFirst performs risk-first evaluation to determine appropriate controls
func (eacm *EnhancedAccessControlManager) evaluateRiskFirst(ctx context.Context, request *common.AccessRequest, response *EnhancedAccessResponse) error {
	// Step 1: Quick risk assessment to determine security posture
	riskStart := time.Now()
	riskResponse, err := eacm.riskIntegrationManager.EnhancedRiskAccessCheck(ctx, request)
	if err != nil {
		// Fall back to sequential evaluation if risk assessment fails
		response.FallbacksUsed = append(response.FallbacksUsed, "risk_first_fallback")
		return eacm.evaluateSequential(ctx, request, response)
	}
	response.ComponentLatency["risk"] = time.Since(riskStart)
	
	response.RiskAssessment = riskResponse.RiskAssessment
	response.RiskFactorsSummary = riskResponse.RiskFactorsSummary

	// Step 2: Apply appropriate access control rigor based on risk level
	switch riskResponse.RiskAssessment.RiskLevel {
	case risk.RiskLevelMinimal, risk.RiskLevelLow:
		// Low risk - streamlined access control
		return eacm.evaluateStreamlined(ctx, request, response)
	case risk.RiskLevelModerate:
		// Moderate risk - standard access control
		return eacm.evaluateSequential(ctx, request, response)
	case risk.RiskLevelHigh, risk.RiskLevelCritical, risk.RiskLevelExtreme:
		// High risk - comprehensive access control
		return eacm.evaluateComprehensive(ctx, request, response)
	}

	return nil
}

// evaluateStreamlined performs streamlined evaluation for low-risk access
func (eacm *EnhancedAccessControlManager) evaluateStreamlined(ctx context.Context, request *common.AccessRequest, response *EnhancedAccessResponse) error {
	// Just RBAC + minimal controls for low risk
	rbacResult, err := eacm.evaluateRBACAccess(ctx, request)
	if err != nil {
		return err
	}
	response.RBACResult = rbacResult

	if rbacResult.HasPermission {
		response.StandardResponse = &common.AccessResponse{
			Granted:            true,
			Reason:             "Access granted by streamlined evaluation",
			AppliedPermissions: []string{request.PermissionId},
		}
	} else {
		response.StandardResponse = &common.AccessResponse{
			Granted:   false,
			Reason:    "Access denied by RBAC",
		}
	}

	return nil
}

// evaluateComprehensive performs comprehensive evaluation for high-risk access
func (eacm *EnhancedAccessControlManager) evaluateComprehensive(ctx context.Context, request *common.AccessRequest, response *EnhancedAccessResponse) error {
	// Full RBAC + JIT + Risk + additional security measures
	err := eacm.evaluateSequential(ctx, request, response)
	if err != nil {
		return err
	}

	// Add comprehensive security measures for high-risk access
	if response.StandardResponse != nil && response.StandardResponse.Granted {
		// Note: High-risk access detected (metadata would be handled by logging/audit system)

		// Add high-risk access recommendations
		response.Recommendations = append(response.Recommendations, AccessRecommendation{
			Type:        RecommendationTypeRiskMitigation,
			Priority:    "critical",
			Description: "High-risk access detected - implement additional monitoring",
			Action:      "enable_comprehensive_monitoring",
			Rationale:   fmt.Sprintf("Risk level: %s requires enhanced oversight", response.RiskAssessment.RiskLevel),
		})
	}

	return nil
}

// Helper methods

func (eacm *EnhancedAccessControlManager) evaluateRBACAccess(ctx context.Context, request *common.AccessRequest) (*RBACValidationResult, error) {
	// Perform standard RBAC check
	accessResponse, err := eacm.rbacManager.CheckPermission(ctx, request)
	if err != nil {
		return nil, err
	}

	// Get effective permissions for metadata
	effectivePermissions, err := eacm.rbacManager.GetEffectivePermissions(ctx, request.SubjectId, request.TenantId)
	if err != nil {
		// Don't fail on metadata error
		effectivePermissions = []*common.Permission{}
	}

	// Build validation result
	result := &RBACValidationResult{
		HasPermission:    accessResponse.Granted,
		EffectiveRoles:   []string{}, // Would be populated from role assignments
		PermissionSource: "direct",   // Would be determined from permission source
		HierarchyPath:    []string{}, // Would be populated from role hierarchy
		ValidationTime:   time.Now(),
	}

	// Extract permission metadata if available
	if len(effectivePermissions) > 0 {
		result.PermissionSource = "role" // Assume role-based if effective permissions exist
	}

	return result, nil
}

func (eacm *EnhancedAccessControlManager) handleEvaluationError(ctx context.Context, request *common.AccessRequest, response *EnhancedAccessResponse, err error) (*EnhancedAccessResponse, error) {
	switch eacm.fallbackBehavior {
	case FallbackBehaviorDeny:
		return nil, err
	case FallbackBehaviorAllow:
		// Try to perform basic RBAC check
		rbacResult, rbacErr := eacm.evaluateRBACAccess(ctx, request)
		if rbacErr != nil {
			return nil, fmt.Errorf("fallback RBAC check failed: %w", rbacErr)
		}
		response.RBACResult = rbacResult
		response.FallbacksUsed = append(response.FallbacksUsed, "evaluation_error_fallback")
		if rbacResult.HasPermission {
			response.StandardResponse = &common.AccessResponse{
				Granted:            true,
				Reason:             "Access granted by fallback RBAC",
				AppliedPermissions: []string{request.PermissionId},
			}
		}
		return response, nil
	case FallbackBehaviorDegrade:
		// Implement graceful degradation
		response.FallbacksUsed = append(response.FallbacksUsed, "graceful_degradation")
		response.StandardResponse = &common.AccessResponse{
			Granted:   false,
			Reason:    "Access denied due to system degradation",
		}
		return response, nil
	}

	return nil, err
}

func (eacm *EnhancedAccessControlManager) applyConservativeRiskControls(response *EnhancedAccessResponse) {
	// Apply conservative controls when risk assessment fails
	conservativeControl := risk.AdaptiveControlInstance{
		ID:           fmt.Sprintf("conservative-%d", time.Now().UnixNano()),
		DefinitionID: "conservative_monitoring",
		Status:       risk.ControlStatusActive,
		AppliedAt:    time.Now(),
		Parameters: map[string]interface{}{
			"monitoring_level": "enhanced",
			"session_timeout":  15, // 15 minutes
			"reason":          "risk_assessment_fallback",
		},
	}
	response.AppliedControls = append(response.AppliedControls, conservativeControl)
}

func (eacm *EnhancedAccessControlManager) generateRecommendations(ctx context.Context, request *common.AccessRequest, response *EnhancedAccessResponse) {
	// Generate recommendations based on evaluation results
	
	// Role optimization recommendations
	if response.RBACResult != nil && len(response.RBACResult.EffectiveRoles) > 5 {
		response.Recommendations = append(response.Recommendations, AccessRecommendation{
			Type:        RecommendationTypeRoleOptimization,
			Priority:    "medium",
			Description: "User has many effective roles - consider role consolidation",
			Action:      "review_role_assignments",
			Rationale:   fmt.Sprintf("User has %d effective roles", len(response.RBACResult.EffectiveRoles)),
		})
	}

	// Security improvement recommendations
	if response.RiskAssessment != nil && response.RiskAssessment.RiskLevel >= risk.RiskLevelHigh {
		response.Recommendations = append(response.Recommendations, AccessRecommendation{
			Type:        RecommendationTypeSecurityImprovement,
			Priority:    "high",
			Description: "High-risk access pattern detected",
			Action:      "implement_additional_security_measures",
			Rationale:   fmt.Sprintf("Risk level %s requires enhanced security", response.RiskAssessment.RiskLevel),
		})
	}

	// Access review recommendations
	if response.JITAccess != nil && response.JITAccess.HasJITAccess {
		response.Recommendations = append(response.Recommendations, AccessRecommendation{
			Type:        RecommendationTypeAccessReview,
			Priority:    "medium",
			Description: "JIT access granted - schedule access review",
			Action:      "schedule_access_review",
			Rationale:   "JIT access indicates non-standard access pattern",
		})
	}
}

// Configuration methods

func (eacm *EnhancedAccessControlManager) SetIntegrationMode(mode IntegrationMode) {
	eacm.integrationMode = mode
}

func (eacm *EnhancedAccessControlManager) SetFallbackBehavior(behavior FallbackBehavior) {
	eacm.fallbackBehavior = behavior
}

func (eacm *EnhancedAccessControlManager) UpdatePerformanceConfig(config *PerformanceConfig) {
	eacm.performanceConfig = config
}

// GetIntegrationStatus returns the current status of all integration components
func (eacm *EnhancedAccessControlManager) GetIntegrationStatus(ctx context.Context) map[string]interface{} {
	return map[string]interface{}{
		"integration_mode":   eacm.integrationMode,
		"fallback_behavior":  eacm.fallbackBehavior,
		"performance_config": eacm.performanceConfig,
		"components": map[string]bool{
			"rbac_manager":    eacm.rbacManager != nil,
			"jit_integration": eacm.jitIntegrationManager != nil,
			"risk_integration": eacm.riskIntegrationManager != nil,
			"tenant_security": eacm.tenantSecurity != nil,
		},
	}
}