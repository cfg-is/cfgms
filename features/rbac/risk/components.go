// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package risk

import (
	"context"
	"fmt"
	"time"
)

// RiskPolicyEngine manages and evaluates risk-based policies
type RiskPolicyEngine struct {
	policies       map[string]*RiskPolicy
	ruleEvaluator  *PolicyRuleEvaluator
	decisionEngine *PolicyDecisionEngine
}

// PolicyRuleEvaluator evaluates policy rules
type PolicyRuleEvaluator struct {
	conditionEvaluator *ConditionEvaluator
	expressionEngine   *ExpressionEngine
}

// PolicyDecisionEngine makes policy decisions
type PolicyDecisionEngine struct {
	conflictResolver *PolicyConflictResolver
	priorityManager  *PolicyPriorityManager
}

// RiskAuditLogger logs risk assessment activities
type RiskAuditLogger struct {
	auditStore     *RiskAuditStore
	logFormatter   *RiskLogFormatter
	eventPublisher *RiskEventPublisher
}

// RiskAssessmentCache provides caching for risk assessments
type RiskAssessmentCache struct {
	cache           map[string]*CachedRiskAssessment
	expirationTime  time.Duration
	maxSize         int
	cleanupInterval time.Duration
}

// CachedRiskAssessment represents a cached risk assessment
type CachedRiskAssessment struct {
	Result      *RiskAssessmentResult `json:"result"`
	CreatedAt   time.Time             `json:"created_at"`
	ExpiresAt   time.Time             `json:"expires_at"`
	RequestHash string                `json:"request_hash"`
}

// NewRiskPolicyEngine creates a new risk policy engine
func NewRiskPolicyEngine() *RiskPolicyEngine {
	return &RiskPolicyEngine{
		policies:       make(map[string]*RiskPolicy),
		ruleEvaluator:  NewPolicyRuleEvaluator(),
		decisionEngine: NewPolicyDecisionEngine(),
	}
}

// EvaluatePolicies evaluates policies against a risk assessment
func (rpe *RiskPolicyEngine) EvaluatePolicies(ctx context.Context, request *RiskAssessmentRequest, result *RiskAssessmentResult) (*PolicyEvaluationResult, error) {
	policyResult := &PolicyEvaluationResult{
		AppliedRules:    make([]string, 0),
		Violations:      make([]string, 0),
		Recommendations: make([]string, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Get applicable policies for the tenant
	applicablePolicies := rpe.getApplicablePolicies(request.AccessRequest.TenantId)

	// Evaluate each policy
	for _, policy := range applicablePolicies {
		if !policy.Enabled {
			continue
		}

		policyDecision, err := rpe.evaluatePolicy(ctx, policy, request, result)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate policy %s: %w", policy.ID, err)
		}

		// Merge policy decision into overall result
		rpe.mergePolicyDecision(policyResult, policyDecision)
	}

	// Resolve conflicts and determine final decision
	finalDecision, err := rpe.decisionEngine.ResolveDecision(ctx, policyResult)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy decision: %w", err)
	}
	policyResult.Decision = finalDecision

	return policyResult, nil
}

// evaluatePolicy evaluates a single policy
func (rpe *RiskPolicyEngine) evaluatePolicy(ctx context.Context, policy *RiskPolicy, request *RiskAssessmentRequest, result *RiskAssessmentResult) (*PolicyEvaluationResult, error) {
	policyResult := &PolicyEvaluationResult{
		PolicyID:        policy.ID,
		AppliedRules:    make([]string, 0),
		Violations:      make([]string, 0),
		Recommendations: make([]string, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Evaluate each rule in the policy
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		ruleMatches, err := rpe.ruleEvaluator.EvaluateRule(ctx, &rule, request, result)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate rule %s: %w", rule.ID, err)
		}

		if ruleMatches {
			policyResult.AppliedRules = append(policyResult.AppliedRules, rule.ID)

			// Apply rule action
			switch rule.Action {
			case PolicyActionDeny:
				policyResult.Decision = string(PolicyActionDeny)
				policyResult.Violations = append(policyResult.Violations,
					fmt.Sprintf("Rule %s requires access denial", rule.ID))
			case PolicyActionChallenge:
				policyResult.Decision = string(PolicyActionChallenge)
			case PolicyActionRequireApproval:
				policyResult.Decision = string(PolicyActionRequireApproval)
			case PolicyActionMonitor:
				policyResult.Recommendations = append(policyResult.Recommendations,
					fmt.Sprintf("Enhanced monitoring required by rule %s", rule.ID))
			}
		}
	}

	return policyResult, nil
}

// getApplicablePolicies gets policies applicable to a tenant
func (rpe *RiskPolicyEngine) getApplicablePolicies(tenantID string) []*RiskPolicy {
	applicablePolicies := make([]*RiskPolicy, 0)

	for _, policy := range rpe.policies {
		if policy.TenantID == "" || policy.TenantID == tenantID {
			applicablePolicies = append(applicablePolicies, policy)
		}
	}

	return applicablePolicies
}

// mergePolicyDecision merges a policy decision into the overall result
func (rpe *RiskPolicyEngine) mergePolicyDecision(overall *PolicyEvaluationResult, policy *PolicyEvaluationResult) {
	overall.AppliedRules = append(overall.AppliedRules, policy.AppliedRules...)
	overall.Violations = append(overall.Violations, policy.Violations...)
	overall.Recommendations = append(overall.Recommendations, policy.Recommendations...)

	// Merge metadata
	for key, value := range policy.Metadata {
		overall.Metadata[key] = value
	}

	// Decision precedence: deny > require_approval > challenge > monitor > allow
	if policy.Decision != "" {
		if overall.Decision == "" || rpe.hasHigherPrecedence(policy.Decision, overall.Decision) {
			overall.Decision = policy.Decision
		}
	}
}

// hasHigherPrecedence checks if decision1 has higher precedence than decision2
func (rpe *RiskPolicyEngine) hasHigherPrecedence(decision1, decision2 string) bool {
	precedence := map[string]int{
		string(PolicyActionAllow):           1,
		string(PolicyActionMonitor):         2,
		string(PolicyActionChallenge):       3,
		string(PolicyActionRequireApproval): 4,
		string(PolicyActionDeny):            5,
	}

	return precedence[decision1] > precedence[decision2]
}

// NewRiskAuditLogger creates a new risk audit logger
func NewRiskAuditLogger() *RiskAuditLogger {
	return &RiskAuditLogger{
		auditStore:     NewRiskAuditStore(),
		logFormatter:   NewRiskLogFormatter(),
		eventPublisher: NewRiskEventPublisher(),
	}
}

// LogRiskAssessment logs a risk assessment
func (ral *RiskAuditLogger) LogRiskAssessment(ctx context.Context, request *RiskAssessmentRequest, result *RiskAssessmentResult) error {
	auditEntry := &RiskAuditEntry{
		ID:              fmt.Sprintf("risk-%d", time.Now().UnixNano()),
		Timestamp:       time.Now(),
		EventType:       "risk_assessment",
		UserID:          request.UserContext.UserID,
		TenantID:        request.AccessRequest.TenantId,
		ResourceID:      request.AccessRequest.ResourceId,
		RiskScore:       result.OverallRiskScore,
		RiskLevel:       string(result.RiskLevel),
		AccessDecision:  string(result.AccessDecision),
		ConfidenceScore: result.ConfidenceScore,
		ProcessingTime:  time.Since(result.AssessedAt),
		Metadata: map[string]interface{}{
			"request_id":         result.RequestID,
			"risk_factors_count": len(result.RiskFactors),
			"controls_count":     len(result.RequiredControls),
			"actions_count":      len(result.RecommendedActions),
		},
	}

	// Store audit entry
	if err := ral.auditStore.StoreAuditEntry(ctx, auditEntry); err != nil {
		return fmt.Errorf("failed to store audit entry: %w", err)
	}

	// Publish audit event for real-time processing
	if err := ral.eventPublisher.PublishRiskEvent(ctx, auditEntry); err != nil {
		// Log but don't fail the assessment
		fmt.Printf("Failed to publish risk event: %v", err)
	}

	return nil
}

// NewRiskAssessmentCache creates a new risk assessment cache
func NewRiskAssessmentCache() *RiskAssessmentCache {
	cache := &RiskAssessmentCache{
		cache:           make(map[string]*CachedRiskAssessment),
		expirationTime:  15 * time.Minute, // Default 15 minute cache
		maxSize:         1000,             // Maximum 1000 cached assessments
		cleanupInterval: 5 * time.Minute,  // Cleanup every 5 minutes
	}

	// Start cleanup routine
	go cache.startCleanupRoutine()

	return cache
}

// Get retrieves a cached risk assessment
func (rac *RiskAssessmentCache) Get(request *RiskAssessmentRequest) *RiskAssessmentResult {
	requestHash := rac.generateRequestHash(request)

	cached, exists := rac.cache[requestHash]
	if !exists {
		return nil
	}

	// Check if cache entry has expired
	if time.Now().After(cached.ExpiresAt) {
		delete(rac.cache, requestHash)
		return nil
	}

	return cached.Result
}

// Store stores a risk assessment in cache
func (rac *RiskAssessmentCache) Store(request *RiskAssessmentRequest, result *RiskAssessmentResult) {
	// Check cache size limit
	if len(rac.cache) >= rac.maxSize {
		rac.evictOldestEntry()
	}

	requestHash := rac.generateRequestHash(request)
	expiresAt := time.Now().Add(rac.expirationTime)

	// Adjust expiration based on risk level (higher risk = shorter cache time)
	switch result.RiskLevel {
	case RiskLevelExtreme, RiskLevelCritical:
		expiresAt = time.Now().Add(2 * time.Minute) // Very short cache for high risk
	case RiskLevelHigh:
		expiresAt = time.Now().Add(5 * time.Minute)
	case RiskLevelModerate:
		expiresAt = time.Now().Add(10 * time.Minute)
	}

	cached := &CachedRiskAssessment{
		Result:      result,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		RequestHash: requestHash,
	}

	rac.cache[requestHash] = cached
}

// generateRequestHash generates a hash for the request for caching
func (rac *RiskAssessmentCache) generateRequestHash(request *RiskAssessmentRequest) string {
	if request == nil || request.AccessRequest == nil {
		return fmt.Sprintf("nil-request-%d", time.Now().Unix()/300)
	}

	// Include resource sensitivity in the hash to ensure proper cache isolation
	resourceSensitivity := "unknown"
	if request.ResourceContext != nil {
		resourceSensitivity = string(request.ResourceContext.Sensitivity)
	}

	// Include environmental context for proper cache isolation
	accessTime := "unknown"
	businessHours := "unknown"
	country := "unknown"
	if request.EnvironmentContext != nil {
		accessTime = request.EnvironmentContext.AccessTime.Format("2006-01-02T15:04:05Z07:00")
		if request.EnvironmentContext.BusinessHours {
			businessHours = "true"
		} else {
			businessHours = "false"
		}
		if request.EnvironmentContext.GeoLocation != nil {
			country = request.EnvironmentContext.GeoLocation.Country
		}
	}

	// Simplified hash generation - in practice would use proper hashing
	return fmt.Sprintf("%s-%s-%s-%s-%s-%s-%s-%d",
		request.AccessRequest.SubjectId,
		request.AccessRequest.ResourceId,
		request.AccessRequest.PermissionId,
		resourceSensitivity,
		businessHours,
		accessTime,
		country,
		time.Now().Unix()/300) // 5-minute buckets
}

// evictOldestEntry removes the oldest cache entry
func (rac *RiskAssessmentCache) evictOldestEntry() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range rac.cache {
		if oldestKey == "" || cached.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.CreatedAt
		}
	}

	if oldestKey != "" {
		delete(rac.cache, oldestKey)
	}
}

// startCleanupRoutine starts the cache cleanup routine
func (rac *RiskAssessmentCache) startCleanupRoutine() {
	ticker := time.NewTicker(rac.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rac.cleanup()
	}
}

// cleanup removes expired cache entries
func (rac *RiskAssessmentCache) cleanup() {
	now := time.Now()
	expiredKeys := make([]string, 0)

	for key, cached := range rac.cache {
		if now.After(cached.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(rac.cache, key)
	}
}

// Supporting audit types

// RiskAuditEntry represents a risk audit log entry
type RiskAuditEntry struct {
	ID              string                 `json:"id"`
	Timestamp       time.Time              `json:"timestamp"`
	EventType       string                 `json:"event_type"`
	UserID          string                 `json:"user_id"`
	TenantID        string                 `json:"tenant_id"`
	ResourceID      string                 `json:"resource_id"`
	RiskScore       float64                `json:"risk_score"`
	RiskLevel       string                 `json:"risk_level"`
	AccessDecision  string                 `json:"access_decision"`
	ConfidenceScore float64                `json:"confidence_score"`
	ProcessingTime  time.Duration          `json:"processing_time"`
	IPAddress       string                 `json:"ip_address,omitempty"`
	UserAgent       string                 `json:"user_agent,omitempty"`
	Location        string                 `json:"location,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// Factory functions for supporting components

func NewPolicyRuleEvaluator() *PolicyRuleEvaluator {
	return &PolicyRuleEvaluator{
		conditionEvaluator: &ConditionEvaluator{},
		expressionEngine:   &ExpressionEngine{},
	}
}

func (pre *PolicyRuleEvaluator) EvaluateRule(ctx context.Context, rule *RiskPolicyRule, request *RiskAssessmentRequest, result *RiskAssessmentResult) (bool, error) {
	// Simplified rule evaluation
	if rule.Condition == "" {
		return true, nil
	}

	// Basic condition evaluation
	switch rule.Condition {
	case "risk_level >= high":
		return result.RiskLevel == RiskLevelHigh || result.RiskLevel == RiskLevelCritical || result.RiskLevel == RiskLevelExtreme, nil
	case "risk_level >= critical":
		return result.RiskLevel == RiskLevelCritical || result.RiskLevel == RiskLevelExtreme, nil
	case "confidence < 70":
		return result.ConfidenceScore < 70.0, nil
	case "after_hours":
		return !request.EnvironmentContext.BusinessHours, nil
	default:
		return true, nil // Default to matching if condition is not recognized
	}
}

func NewPolicyDecisionEngine() *PolicyDecisionEngine {
	return &PolicyDecisionEngine{
		conflictResolver: &PolicyConflictResolver{},
		priorityManager:  &PolicyPriorityManager{},
	}
}

func (pde *PolicyDecisionEngine) ResolveDecision(ctx context.Context, policyResult *PolicyEvaluationResult) (string, error) {
	// Return the decision if already set
	if policyResult.Decision != "" {
		return policyResult.Decision, nil
	}

	// Default decision based on violations
	if len(policyResult.Violations) > 0 {
		return string(PolicyActionDeny), nil
	}

	// No policy decision - let risk-based decision logic determine the outcome
	return "", nil
}

func NewRiskAuditStore() *RiskAuditStore {
	return &RiskAuditStore{
		entries: make(map[string]*RiskAuditEntry),
	}
}

func (ras *RiskAuditStore) StoreAuditEntry(ctx context.Context, entry *RiskAuditEntry) error {
	// Simplified storage - in practice would use persistent storage
	ras.entries[entry.ID] = entry
	return nil
}

func NewRiskLogFormatter() *RiskLogFormatter {
	return &RiskLogFormatter{}
}

func NewRiskEventPublisher() *RiskEventPublisher {
	return &RiskEventPublisher{}
}

func (rep *RiskEventPublisher) PublishRiskEvent(ctx context.Context, entry *RiskAuditEntry) error {
	// Simplified event publishing - in practice would use message queue
	return nil
}

// Supporting types (simplified implementations)
type ConditionEvaluator struct{}
type ExpressionEngine struct{}
type PolicyConflictResolver struct{}
type PolicyPriorityManager struct{}

type RiskAuditStore struct {
	entries map[string]*RiskAuditEntry
}

type RiskLogFormatter struct{}
type RiskEventPublisher struct{}
