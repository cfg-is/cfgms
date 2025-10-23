// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package zerotrust

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PolicyEvaluator provides high-performance policy evaluation with caching
type PolicyEvaluator struct {
	engine          *ZeroTrustPolicyEngine
	cache           *PolicyCache
	evaluators      map[string]RuleEvaluator
	conditionEngine *ConditionEngine

	// Performance configuration
	maxEvaluationTime time.Duration
	enableParallel    bool

	// Statistics
	stats *EvaluatorStats
}

// RuleEvaluator evaluates specific types of rules
type RuleEvaluator interface {
	EvaluateRule(ctx context.Context, rule interface{}, request *ZeroTrustAccessRequest) (*RuleEvaluationResult, error)
	GetRuleType() string
}

// ConditionEngine evaluates policy conditions
type ConditionEngine struct {
	operators       map[ConditionOperator]ConditionOperatorFunc
	fieldExtractors map[string]FieldExtractorFunc
	mutex           sync.RWMutex
}

// ConditionOperatorFunc implements a condition operator
type ConditionOperatorFunc func(fieldValue interface{}, conditionValue interface{}) (bool, error)

// FieldExtractorFunc extracts field values from requests
type FieldExtractorFunc func(request *ZeroTrustAccessRequest) (interface{}, error)

// Cache types are defined in cache.go

// EvaluatorStats tracks policy evaluator performance statistics
type EvaluatorStats struct {
	TotalEvaluations      int64
	SuccessfulEvaluations int64
	FailedEvaluations     int64
	CachedEvaluations     int64

	AverageEvaluationTime time.Duration
	MaxEvaluationTime     time.Duration
	MinEvaluationTime     time.Duration

	ParallelEvaluations   int64
	SequentialEvaluations int64

	CacheHitRate   float64
	L1CacheHitRate float64
	L2CacheHitRate float64

	RuleEvaluationsPerType map[string]int64

	LastUpdated time.Time
	mutex       sync.RWMutex
}

// NewPolicyEvaluator creates a new high-performance policy evaluator
func NewPolicyEvaluator(engine *ZeroTrustPolicyEngine) *PolicyEvaluator {
	evaluator := &PolicyEvaluator{
		engine:            engine,
		cache:             NewPolicyCache(engine.config.CacheTTL),
		evaluators:        make(map[string]RuleEvaluator),
		conditionEngine:   NewConditionEngine(),
		maxEvaluationTime: engine.config.MaxEvaluationTime,
		enableParallel:    true,
		stats:             NewEvaluatorStats(),
	}

	// Register rule evaluators
	evaluator.registerRuleEvaluators()

	return evaluator
}

// EvaluateAll evaluates all applicable policies for a request
func (p *PolicyEvaluator) EvaluateAll(ctx context.Context, evalCtx *PolicyEvaluationContext) ([]*PolicyEvaluationResult, error) {
	startTime := time.Now()

	// Create evaluation context with timeout
	evalCtxWithTimeout, cancel := context.WithTimeout(ctx, p.maxEvaluationTime)
	defer cancel()

	var results []*PolicyEvaluationResult
	var evaluationErrors []error

	// Determine evaluation mode
	if p.enableParallel && len(evalCtx.Policies) > 1 {
		results, evaluationErrors = p.evaluateParallel(evalCtxWithTimeout, evalCtx)
	} else {
		results, evaluationErrors = p.evaluateSequential(evalCtxWithTimeout, evalCtx)
	}

	// Update statistics
	processingTime := time.Since(startTime)
	p.updateStats(len(evalCtx.Policies), len(evaluationErrors) == 0, processingTime)

	// Handle evaluation errors
	if len(evaluationErrors) > 0 {
		return results, fmt.Errorf("policy evaluation errors: %v", evaluationErrors)
	}

	return results, nil
}

// evaluateParallel evaluates multiple policies in parallel
func (p *PolicyEvaluator) evaluateParallel(ctx context.Context, evalCtx *PolicyEvaluationContext) ([]*PolicyEvaluationResult, []error) {
	var wg sync.WaitGroup
	resultChan := make(chan *PolicyEvaluationResult, len(evalCtx.Policies))
	errorChan := make(chan error, len(evalCtx.Policies))

	// Start parallel evaluation
	for _, policy := range evalCtx.Policies {
		wg.Add(1)
		go func(pol *ZeroTrustPolicy) {
			defer wg.Done()

			result, err := p.evaluatePolicy(ctx, pol, evalCtx.Request)
			if err != nil {
				errorChan <- err
			} else {
				resultChan <- result
			}
		}(policy)
	}

	// Wait for completion
	wg.Wait()
	close(resultChan)
	close(errorChan)

	// Collect results
	var results []*PolicyEvaluationResult
	for result := range resultChan {
		results = append(results, result)
	}

	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	p.stats.mutex.Lock()
	p.stats.ParallelEvaluations++
	p.stats.mutex.Unlock()

	return results, errors
}

// evaluateSequential evaluates policies one by one
func (p *PolicyEvaluator) evaluateSequential(ctx context.Context, evalCtx *PolicyEvaluationContext) ([]*PolicyEvaluationResult, []error) {
	var results []*PolicyEvaluationResult
	var errors []error

	for _, policy := range evalCtx.Policies {
		result, err := p.evaluatePolicy(ctx, policy, evalCtx.Request)
		if err != nil {
			errors = append(errors, err)
		} else {
			results = append(results, result)
		}

		// Check for context cancellation
		select {
		case <-ctx.Done():
			return results, append(errors, ctx.Err())
		default:
		}
	}

	p.stats.mutex.Lock()
	p.stats.SequentialEvaluations++
	p.stats.mutex.Unlock()

	return results, errors
}

// evaluatePolicy evaluates a single policy against a request
func (p *PolicyEvaluator) evaluatePolicy(ctx context.Context, policy *ZeroTrustPolicy, request *ZeroTrustAccessRequest) (*PolicyEvaluationResult, error) {
	startTime := time.Now()

	// Check cache first
	cacheKey := p.generateCacheKey(policy.ID, request)
	if cachedResult := p.cache.Get(cacheKey); cachedResult != nil {
		p.stats.mutex.Lock()
		p.stats.CachedEvaluations++
		p.stats.mutex.Unlock()

		return cachedResult, nil
	}

	// Create evaluation result
	result := &PolicyEvaluationResult{
		PolicyID:        policy.ID,
		PolicyName:      policy.Name,
		PolicyVersion:   policy.Version,
		EvaluationTime:  startTime,
		EnforcementMode: policy.EnforcementMode,
		RuleResults:     make([]*RuleEvaluationResult, 0),
	}

	// Evaluate access rules
	for _, rule := range policy.AccessRules {
		ruleResult, err := p.evaluateAccessRule(ctx, &rule, request)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate access rule %s: %w", rule.ID, err)
		}
		result.RuleResults = append(result.RuleResults, ruleResult)
	}

	// Evaluate compliance rules
	for _, rule := range policy.ComplianceRules {
		ruleResult, err := p.evaluateComplianceRule(ctx, &rule, request)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate compliance rule %s: %w", rule.ID, err)
		}
		result.RuleResults = append(result.RuleResults, ruleResult)
	}

	// Evaluate security rules
	for _, rule := range policy.SecurityRules {
		ruleResult, err := p.evaluateSecurityRule(ctx, &rule, request)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate security rule %s: %w", rule.ID, err)
		}
		result.RuleResults = append(result.RuleResults, ruleResult)
	}

	// Determine overall policy result
	result.Result, result.Reason, result.Confidence = p.determinePolicyResult(result.RuleResults)
	result.ProcessingTime = time.Since(startTime)

	// Cache the result
	p.cache.Put(cacheKey, result)

	return result, nil
}

// Rule evaluation methods

func (p *PolicyEvaluator) evaluateAccessRule(ctx context.Context, rule *AccessRule, request *ZeroTrustAccessRequest) (*RuleEvaluationResult, error) {
	startTime := time.Now()

	result := &RuleEvaluationResult{
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		RuleType:       RuleTypeAccess,
		EvaluationTime: startTime,
		Evidence:       make(map[string]interface{}),
	}

	// Evaluate rule conditions
	satisfied, reason, evidence := p.evaluateConditions(ctx, rule.Conditions, request)

	result.Satisfied = satisfied
	result.Reason = reason
	result.Evidence = evidence
	result.ProcessingTime = time.Since(startTime)

	// Update rule evaluation stats
	p.updateRuleStats("access")

	return result, nil
}

func (p *PolicyEvaluator) evaluateComplianceRule(ctx context.Context, rule *ComplianceRule, request *ZeroTrustAccessRequest) (*RuleEvaluationResult, error) {
	startTime := time.Now()

	result := &RuleEvaluationResult{
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		RuleType:       RuleTypeCompliance,
		EvaluationTime: startTime,
		Evidence:       make(map[string]interface{}),
	}

	// Evaluate compliance-specific logic
	satisfied, reason := p.evaluateComplianceLogic(ctx, rule, request)

	result.Satisfied = satisfied
	result.Reason = reason
	result.ProcessingTime = time.Since(startTime)

	// Update rule evaluation stats
	p.updateRuleStats("compliance")

	return result, nil
}

func (p *PolicyEvaluator) evaluateSecurityRule(ctx context.Context, rule *SecurityRule, request *ZeroTrustAccessRequest) (*RuleEvaluationResult, error) {
	startTime := time.Now()

	result := &RuleEvaluationResult{
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		RuleType:       RuleTypeSecurity,
		EvaluationTime: startTime,
		Evidence:       make(map[string]interface{}),
	}

	// Evaluate security-specific logic
	satisfied, reason := p.evaluateSecurityLogic(ctx, rule, request)

	result.Satisfied = satisfied
	result.Reason = reason
	result.ProcessingTime = time.Since(startTime)

	// Update rule evaluation stats
	p.updateRuleStats("security")

	return result, nil
}

// Condition evaluation

func (p *PolicyEvaluator) evaluateConditions(ctx context.Context, conditions []PolicyCondition, request *ZeroTrustAccessRequest) (bool, string, map[string]interface{}) {
	if len(conditions) == 0 {
		return true, "No conditions to evaluate", make(map[string]interface{})
	}

	evidence := make(map[string]interface{})

	for _, condition := range conditions {
		satisfied, reason, condEvidence := p.evaluateCondition(ctx, condition, request)

		// Merge evidence
		for k, v := range condEvidence {
			evidence[k] = v
		}

		if !satisfied {
			return false, fmt.Sprintf("Condition failed: %s", reason), evidence
		}
	}

	return true, "All conditions satisfied", evidence
}

func (p *PolicyEvaluator) evaluateCondition(ctx context.Context, condition PolicyCondition, request *ZeroTrustAccessRequest) (bool, string, map[string]interface{}) {
	evidence := make(map[string]interface{})

	// Extract field value from request
	fieldValue, err := p.conditionEngine.ExtractFieldValue(condition.Field, request)
	if err != nil {
		return false, fmt.Sprintf("Failed to extract field %s: %v", condition.Field, err), evidence
	}

	evidence[condition.Field] = fieldValue
	evidence[fmt.Sprintf("%s_operator", condition.Field)] = string(condition.Operator)
	evidence[fmt.Sprintf("%s_expected", condition.Field)] = condition.Value

	// Evaluate condition using operator
	satisfied, err := p.conditionEngine.EvaluateOperator(condition.Operator, fieldValue, condition.Value)
	if err != nil {
		return false, fmt.Sprintf("Operator evaluation failed: %v", err), evidence
	}

	reason := fmt.Sprintf("Field %s %s %v", condition.Field, condition.Operator, condition.Value)
	if satisfied {
		reason = fmt.Sprintf("✓ %s", reason)
	} else {
		reason = fmt.Sprintf("✗ %s", reason)
	}

	return satisfied, reason, evidence
}

// Helper methods

func (p *PolicyEvaluator) determinePolicyResult(ruleResults []*RuleEvaluationResult) (PolicyResult, string, float64) {
	if len(ruleResults) == 0 {
		return PolicyResultDeny, "No rules evaluated", 0.0
	}

	satisfiedCount := 0

	for _, result := range ruleResults {
		if result.Satisfied {
			satisfiedCount++
		}
	}

	confidence := float64(satisfiedCount) / float64(len(ruleResults))

	if satisfiedCount == len(ruleResults) {
		return PolicyResultAllow, fmt.Sprintf("All %d rules satisfied", len(ruleResults)), confidence
	} else if satisfiedCount > 0 {
		return PolicyResultConditional, fmt.Sprintf("%d/%d rules satisfied", satisfiedCount, len(ruleResults)), confidence
	} else {
		return PolicyResultDeny, fmt.Sprintf("No rules satisfied (%d total)", len(ruleResults)), confidence
	}
}

func (p *PolicyEvaluator) evaluateComplianceLogic(ctx context.Context, rule *ComplianceRule, request *ZeroTrustAccessRequest) (bool, string) {
	// Implementation stub - would evaluate compliance-specific logic
	return true, "Compliance logic not fully implemented"
}

func (p *PolicyEvaluator) evaluateSecurityLogic(ctx context.Context, rule *SecurityRule, request *ZeroTrustAccessRequest) (bool, string) {
	// Implementation stub - would evaluate security-specific logic
	return true, "Security logic not fully implemented"
}

func (p *PolicyEvaluator) generateCacheKey(policyID string, request *ZeroTrustAccessRequest) string {
	// Generate a deterministic cache key based on policy and request
	return fmt.Sprintf("%s:%s:%s:%s:%s",
		policyID,
		request.AccessRequest.SubjectId,
		request.AccessRequest.TenantId,
		request.AccessRequest.PermissionId,
		request.RequestID)
}

func (p *PolicyEvaluator) registerRuleEvaluators() {
	// Register built-in rule evaluators
	// Implementation would register specific evaluators for different rule types
}

func (p *PolicyEvaluator) updateStats(policyCount int, success bool, processingTime time.Duration) {
	p.stats.mutex.Lock()
	defer p.stats.mutex.Unlock()

	p.stats.TotalEvaluations++
	if success {
		p.stats.SuccessfulEvaluations++
	} else {
		p.stats.FailedEvaluations++
	}

	// Update timing statistics using exponential moving average
	alpha := 0.1
	if p.stats.AverageEvaluationTime == 0 {
		p.stats.AverageEvaluationTime = processingTime
	} else {
		avgNanos := float64(p.stats.AverageEvaluationTime.Nanoseconds())
		newNanos := float64(processingTime.Nanoseconds())
		p.stats.AverageEvaluationTime = time.Duration(int64((1-alpha)*avgNanos + alpha*newNanos))
	}

	if processingTime > p.stats.MaxEvaluationTime {
		p.stats.MaxEvaluationTime = processingTime
	}

	if p.stats.MinEvaluationTime == 0 || processingTime < p.stats.MinEvaluationTime {
		p.stats.MinEvaluationTime = processingTime
	}

	p.stats.LastUpdated = time.Now()
}

func (p *PolicyEvaluator) updateRuleStats(ruleType string) {
	p.stats.mutex.Lock()
	defer p.stats.mutex.Unlock()

	if p.stats.RuleEvaluationsPerType == nil {
		p.stats.RuleEvaluationsPerType = make(map[string]int64)
	}

	p.stats.RuleEvaluationsPerType[ruleType]++
}

// GetStats returns current evaluator statistics
func (p *PolicyEvaluator) GetStats() *EvaluatorStats {
	p.stats.mutex.RLock()
	defer p.stats.mutex.RUnlock()

	// Return a copy to prevent external modification (without copying mutex)
	ruleEvaluationsPerType := make(map[string]int64)
	if p.stats.RuleEvaluationsPerType != nil {
		for k, v := range p.stats.RuleEvaluationsPerType {
			ruleEvaluationsPerType[k] = v
		}
	}

	return &EvaluatorStats{
		TotalEvaluations:       p.stats.TotalEvaluations,
		SuccessfulEvaluations:  p.stats.SuccessfulEvaluations,
		FailedEvaluations:      p.stats.FailedEvaluations,
		CachedEvaluations:      p.stats.CachedEvaluations,
		AverageEvaluationTime:  p.stats.AverageEvaluationTime,
		MaxEvaluationTime:      p.stats.MaxEvaluationTime,
		MinEvaluationTime:      p.stats.MinEvaluationTime,
		ParallelEvaluations:    p.stats.ParallelEvaluations,
		SequentialEvaluations:  p.stats.SequentialEvaluations,
		CacheHitRate:           p.stats.CacheHitRate,
		L1CacheHitRate:         p.stats.L1CacheHitRate,
		L2CacheHitRate:         p.stats.L2CacheHitRate,
		RuleEvaluationsPerType: ruleEvaluationsPerType,
		LastUpdated:            p.stats.LastUpdated,
	}
}

// NewEvaluatorStats creates new evaluator statistics
func NewEvaluatorStats() *EvaluatorStats {
	return &EvaluatorStats{
		RuleEvaluationsPerType: make(map[string]int64),
		LastUpdated:            time.Now(),
	}
}

// Condition Engine implementation

// NewConditionEngine creates a new condition engine
func NewConditionEngine() *ConditionEngine {
	engine := &ConditionEngine{
		operators:       make(map[ConditionOperator]ConditionOperatorFunc),
		fieldExtractors: make(map[string]FieldExtractorFunc),
	}

	// Register default operators
	engine.registerDefaultOperators()
	engine.registerDefaultFieldExtractors()

	return engine
}

// ExtractFieldValue extracts a field value from a request
func (c *ConditionEngine) ExtractFieldValue(field string, request *ZeroTrustAccessRequest) (interface{}, error) {
	c.mutex.RLock()
	extractor, exists := c.fieldExtractors[field]
	c.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no extractor for field: %s", field)
	}

	return extractor(request)
}

// EvaluateOperator evaluates a condition operator
func (c *ConditionEngine) EvaluateOperator(operator ConditionOperator, fieldValue, conditionValue interface{}) (bool, error) {
	c.mutex.RLock()
	operatorFunc, exists := c.operators[operator]
	c.mutex.RUnlock()

	if !exists {
		return false, fmt.Errorf("unsupported operator: %s", operator)
	}

	return operatorFunc(fieldValue, conditionValue)
}

func (c *ConditionEngine) registerDefaultOperators() {
	c.operators[ConditionOperatorEquals] = func(fieldValue, conditionValue interface{}) (bool, error) {
		return fieldValue == conditionValue, nil
	}

	c.operators[ConditionOperatorNotEquals] = func(fieldValue, conditionValue interface{}) (bool, error) {
		return fieldValue != conditionValue, nil
	}

	c.operators[ConditionOperatorContains] = func(fieldValue, conditionValue interface{}) (bool, error) {
		fieldStr, ok1 := fieldValue.(string)
		condStr, ok2 := conditionValue.(string)
		if !ok1 || !ok2 {
			return false, fmt.Errorf("contains operator requires string values")
		}
		return fmt.Sprintf("%v", fieldStr) == fmt.Sprintf("%v", condStr), nil
	}

	// Add more operators as needed
}

func (c *ConditionEngine) registerDefaultFieldExtractors() {
	c.fieldExtractors["subject.id"] = func(request *ZeroTrustAccessRequest) (interface{}, error) {
		return request.AccessRequest.SubjectId, nil
	}

	c.fieldExtractors["tenant.id"] = func(request *ZeroTrustAccessRequest) (interface{}, error) {
		return request.AccessRequest.TenantId, nil
	}

	c.fieldExtractors["permission.id"] = func(request *ZeroTrustAccessRequest) (interface{}, error) {
		return request.AccessRequest.PermissionId, nil
	}

	c.fieldExtractors["resource.type"] = func(request *ZeroTrustAccessRequest) (interface{}, error) {
		return request.ResourceType, nil
	}

	c.fieldExtractors["environment.ip"] = func(request *ZeroTrustAccessRequest) (interface{}, error) {
		if request.EnvironmentContext != nil {
			return request.EnvironmentContext.IPAddress, nil
		}
		return "", nil
	}

	c.fieldExtractors["security.mfa_verified"] = func(request *ZeroTrustAccessRequest) (interface{}, error) {
		if request.SecurityContext != nil {
			return request.SecurityContext.MFAVerified, nil
		}
		return false, nil
	}

	c.fieldExtractors["request.time"] = func(request *ZeroTrustAccessRequest) (interface{}, error) {
		return request.RequestTime, nil
	}

	// Add more field extractors as needed
}
