// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package drift provides rule engine for custom drift detection policies.

package drift

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// ruleEngine implements the RuleEngine interface for custom drift detection rules.
type ruleEngine struct {
	logger logging.Logger
	config *RuleEngineConfig
	rules  map[string]*DriftRule // keyed by rule ID
	stats  *RuleEngineStats
}

// RuleEngineConfig defines configuration for the rule engine.
type RuleEngineConfig struct {
	// Rule evaluation
	MaxRuleEvaluationTime  time.Duration `json:"max_rule_evaluation_time" yaml:"max_rule_evaluation_time"`
	EnableParallelRuleEval bool          `json:"enable_parallel_rule_eval" yaml:"enable_parallel_rule_eval"`
	MaxConcurrentRules     int           `json:"max_concurrent_rules" yaml:"max_concurrent_rules"`

	// Rule management
	MaxRulesPerEngine      int  `json:"max_rules_per_engine" yaml:"max_rules_per_engine"`
	EnableRuleValidation   bool `json:"enable_rule_validation" yaml:"enable_rule_validation"`
	EnableRuleOptimization bool `json:"enable_rule_optimization" yaml:"enable_rule_optimization"`

	// Performance
	EnableRuleCache bool          `json:"enable_rule_cache" yaml:"enable_rule_cache"`
	RuleCacheSize   int           `json:"rule_cache_size" yaml:"rule_cache_size"`
	RuleCacheTTL    time.Duration `json:"rule_cache_ttl" yaml:"rule_cache_ttl"`

	// Statistics
	EnableDetailedStats  bool          `json:"enable_detailed_stats" yaml:"enable_detailed_stats"`
	StatsRetentionPeriod time.Duration `json:"stats_retention_period" yaml:"stats_retention_period"`
}

// RuleEngineStats provides statistics about rule engine operation.
type RuleEngineStats struct {
	TotalRules       int                  `json:"total_rules"`
	ActiveRules      int                  `json:"active_rules"`
	RulesEvaluated   int64                `json:"rules_evaluated"`
	RulesMatched     int64                `json:"rules_matched"`
	AverageEvalTime  time.Duration        `json:"average_eval_time"`
	RulePerformance  map[string]*RulePerf `json:"rule_performance"`
	LastEvaluation   *time.Time           `json:"last_evaluation,omitempty"`
	EvaluationErrors int64                `json:"evaluation_errors"`
}

// RulePerf tracks performance statistics for individual rules.
type RulePerf struct {
	RuleID          string        `json:"rule_id"`
	EvaluationCount int64         `json:"evaluation_count"`
	MatchCount      int64         `json:"match_count"`
	AverageTime     time.Duration `json:"average_time"`
	TotalTime       time.Duration `json:"total_time"`
	ErrorCount      int64         `json:"error_count"`
	LastEvaluation  time.Time     `json:"last_evaluation"`
	MatchRate       float64       `json:"match_rate"`
}

// NewRuleEngine creates a new rule engine with the specified configuration.
func NewRuleEngine(config *RuleEngineConfig, logger logging.Logger) (RuleEngine, error) {
	if config == nil {
		config = DefaultRuleEngineConfig()
	}

	if err := validateRuleEngineConfig(config); err != nil {
		return nil, fmt.Errorf("invalid rule engine config: %w", err)
	}

	engine := &ruleEngine{
		logger: logger,
		config: config,
		rules:  make(map[string]*DriftRule),
		stats: &RuleEngineStats{
			RulePerformance: make(map[string]*RulePerf),
		},
	}

	if logger != nil {
		logger.Info("Rule engine initialized",
			"max_rules", config.MaxRulesPerEngine,
			"parallel_eval", config.EnableParallelRuleEval,
			"rule_cache", config.EnableRuleCache)
	}

	return engine, nil
}

// EvaluateRules evaluates all active rules against a drift event.
func (re *ruleEngine) EvaluateRules(ctx context.Context, event *DriftEvent) (*RuleResult, error) {
	startTime := time.Now()
	defer func() {
		re.stats.AverageEvalTime = time.Since(startTime)
		now := time.Now()
		re.stats.LastEvaluation = &now
	}()

	// Check for timeout
	if re.config.MaxRuleEvaluationTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, re.config.MaxRuleEvaluationTime)
		defer cancel()
	}

	if re.logger != nil {
		re.logger.Debug("Evaluating rules against drift event",
			"event_id", event.ID,
			"device_id", event.DeviceID,
			"total_rules", len(re.rules),
			"active_rules", re.stats.ActiveRules)
	}

	// Get active rules sorted by priority
	activeRules := re.getActiveRulesSorted()
	if len(activeRules) == 0 {
		// No rules to evaluate - create default result
		return &RuleResult{
			RuleID:      "default",
			Matched:     true,
			Confidence:  event.Confidence,
			Actions:     []RuleAction{ActionLog},
			Message:     "No custom rules defined, using default behavior",
			EvaluatedAt: time.Now(),
		}, nil
	}

	// Evaluate rules
	var bestResult *RuleResult
	var evaluatedRules int64

	for _, rule := range activeRules {
		select {
		case <-ctx.Done():
			return bestResult, ctx.Err()
		default:
		}

		result, err := re.evaluateRule(ctx, rule, event)
		if err != nil {
			re.stats.EvaluationErrors++
			if re.logger != nil {
				re.logger.Error("Failed to evaluate rule",
					"error", err,
					"rule_id", rule.ID,
					"event_id", event.ID)
			}
			continue
		}

		evaluatedRules++

		// Update rule statistics
		re.updateRuleStats(rule.ID, result, time.Since(startTime))

		// If rule matched, use it as the result
		if result.Matched {
			bestResult = result
			re.stats.RulesMatched++

			// Update rule trigger count
			rule.TriggeredCount++
			now := time.Now()
			rule.LastTriggered = &now

			if re.logger != nil {
				re.logger.Debug("Rule matched",
					"rule_id", rule.ID,
					"rule_name", rule.Name,
					"event_id", event.ID,
					"confidence", result.Confidence)
			}

			// If this is a high-priority rule, stop evaluation
			if rule.Priority >= 8 {
				break
			}
		}
	}

	re.stats.RulesEvaluated += evaluatedRules

	// If no rules matched, create a default result
	if bestResult == nil {
		bestResult = &RuleResult{
			RuleID:      "default",
			Matched:     true,
			Confidence:  event.Confidence,
			Actions:     []RuleAction{ActionLog},
			Message:     "No rules matched, using default behavior",
			EvaluatedAt: time.Now(),
		}
	}

	if re.logger != nil {
		re.logger.Debug("Rule evaluation completed",
			"event_id", event.ID,
			"rules_evaluated", evaluatedRules,
			"best_rule", bestResult.RuleID,
			"matched", bestResult.Matched,
			"confidence", bestResult.Confidence,
			"evaluation_time", time.Since(startTime))
	}

	return bestResult, nil
}

// AddRule adds a new drift detection rule.
func (re *ruleEngine) AddRule(rule *DriftRule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	// Validate rule
	if re.config.EnableRuleValidation {
		if err := re.validateRule(rule); err != nil {
			return fmt.Errorf("rule validation failed: %w", err)
		}
	}

	// Check capacity
	if len(re.rules) >= re.config.MaxRulesPerEngine {
		return fmt.Errorf("maximum number of rules exceeded (%d)", re.config.MaxRulesPerEngine)
	}

	// Set timestamps
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now()
	}
	rule.UpdatedAt = time.Now()

	// Add to rules map
	re.rules[rule.ID] = rule

	// Update statistics
	re.updateStats()

	// Initialize performance tracking
	if re.config.EnableDetailedStats {
		re.stats.RulePerformance[rule.ID] = &RulePerf{
			RuleID: rule.ID,
		}
	}

	if re.logger != nil {
		re.logger.Info("Rule added",
			"rule_id", rule.ID,
			"rule_name", rule.Name,
			"priority", rule.Priority,
			"enabled", rule.Enabled)
	}

	return nil
}

// RemoveRule removes a drift detection rule.
func (re *ruleEngine) RemoveRule(ruleID string) error {
	if _, exists := re.rules[ruleID]; !exists {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	// Remove from rules map
	delete(re.rules, ruleID)

	// Remove performance statistics
	delete(re.stats.RulePerformance, ruleID)

	// Update statistics
	re.updateStats()

	if re.logger != nil {
		re.logger.Info("Rule removed", "rule_id", ruleID)
	}

	return nil
}

// GetRules returns all active rules.
func (re *ruleEngine) GetRules() []*DriftRule {
	rules := make([]*DriftRule, 0, len(re.rules))

	for _, rule := range re.rules {
		// Create a copy to avoid modification
		ruleCopy := *rule
		rules = append(rules, &ruleCopy)
	}

	return rules
}

// ValidateRules validates drift detection rules configuration.
func (re *ruleEngine) ValidateRules(rules []*DriftRule) error {
	for _, rule := range rules {
		if err := re.validateRule(rule); err != nil {
			return fmt.Errorf("invalid rule %s: %w", rule.ID, err)
		}
	}
	return nil
}

// TestRule tests a rule against sample data.
func (re *ruleEngine) TestRule(rule *DriftRule, testData *DNAComparison) (*RuleResult, error) {
	if rule == nil {
		return nil, fmt.Errorf("rule cannot be nil")
	}

	if testData == nil {
		return nil, fmt.Errorf("test data cannot be nil")
	}

	// Create a test event from the comparison
	testEvent := &DriftEvent{
		ID:        "test-event",
		DeviceID:  testData.DeviceID,
		Timestamp: testData.ComparedAt,
		Changes:   make([]*AttributeChange, 0),
		Severity:  SeverityInfo,
		Category:  CategoryConfiguration,
	}

	// Generate test changes
	for attr, prevValue := range testData.Previous.Attributes {
		if currValue, exists := testData.Current.Attributes[attr]; exists && prevValue != currValue {
			testEvent.Changes = append(testEvent.Changes, &AttributeChange{
				Attribute:     attr,
				PreviousValue: prevValue,
				CurrentValue:  currValue,
				ChangeType:    ChangeTypeModified,
				Severity:      SeverityInfo,
				Category:      "test",
			})
		}
	}

	// Evaluate the rule
	ctx := context.Background()
	return re.evaluateRule(ctx, rule, testEvent)
}

// Close releases rule engine resources.
func (re *ruleEngine) Close() error {
	if re.logger != nil {
		re.logger.Info("Closing rule engine")
	}
	return nil
}

// Private methods

func (re *ruleEngine) evaluateRule(ctx context.Context, rule *DriftRule, event *DriftEvent) (*RuleResult, error) {
	startTime := time.Now()

	if !rule.Enabled {
		return &RuleResult{
			RuleID:      rule.ID,
			Matched:     false,
			Confidence:  0.0,
			Actions:     []RuleAction{},
			Message:     "Rule is disabled",
			EvaluatedAt: time.Now(),
		}, nil
	}

	// Evaluate all conditions
	conditionResults := make([]bool, len(rule.Conditions))

	for i, condition := range rule.Conditions {
		result, err := re.evaluateCondition(condition, event)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate condition %d: %w", i, err)
		}
		conditionResults[i] = result
	}

	// Apply logical operator
	matched := re.applyLogicalOperator(rule.Operator, conditionResults)

	result := &RuleResult{
		RuleID:      rule.ID,
		Matched:     matched,
		Actions:     rule.Actions,
		EvaluatedAt: time.Now(),
	}

	if matched {
		result.Confidence = re.calculateRuleConfidence(rule, event)
		result.Message = fmt.Sprintf("Rule '%s' matched: %s", rule.Name, rule.Description)
	} else {
		result.Confidence = 0.0
		result.Message = fmt.Sprintf("Rule '%s' did not match", rule.Name)
	}

	if re.logger != nil {
		re.logger.Debug("Rule evaluated",
			"rule_id", rule.ID,
			"matched", matched,
			"confidence", result.Confidence,
			"evaluation_time", time.Since(startTime))
	}

	return result, nil
}

func (re *ruleEngine) evaluateCondition(condition *RuleCondition, event *DriftEvent) (bool, error) {
	switch condition.Type {
	case ConditionAttributeMatch:
		return re.evaluateAttributeMatch(condition, event)
	case ConditionAttributeChange:
		return re.evaluateAttributeChange(condition, event)
	case ConditionThreshold:
		return re.evaluateThreshold(condition, event)
	case ConditionPattern:
		return re.evaluatePattern(condition, event)
	case ConditionFrequency:
		return re.evaluateFrequency(condition, event)
	default:
		return false, fmt.Errorf("unknown condition type: %s", condition.Type)
	}
}

func (re *ruleEngine) evaluateAttributeMatch(condition *RuleCondition, event *DriftEvent) (bool, error) {
	if condition.Attribute == "" {
		return false, fmt.Errorf("attribute is required for attribute_match condition")
	}

	for _, change := range event.Changes {
		// Check if attribute matches
		if matched, err := regexp.MatchString(condition.Attribute, change.Attribute); err != nil {
			return false, fmt.Errorf("invalid attribute regex: %w", err)
		} else if !matched {
			continue
		}

		// Check value condition
		switch condition.Operator {
		case "equals":
			if change.CurrentValue == condition.Value {
				return true, nil
			}
		case "contains":
			if strings.Contains(change.CurrentValue, condition.Value) {
				return true, nil
			}
		case "regex":
			if matched, err := regexp.MatchString(condition.Pattern, change.CurrentValue); err != nil {
				return false, fmt.Errorf("invalid pattern regex: %w", err)
			} else if matched {
				return true, nil
			}
		default:
			return false, fmt.Errorf("unsupported operator: %s", condition.Operator)
		}
	}

	return false, nil
}

func (re *ruleEngine) evaluateAttributeChange(condition *RuleCondition, event *DriftEvent) (bool, error) {
	if condition.Attribute == "" {
		return false, fmt.Errorf("attribute is required for attribute_change condition")
	}

	for _, change := range event.Changes {
		if matched, err := regexp.MatchString(condition.Attribute, change.Attribute); err != nil {
			return false, fmt.Errorf("invalid attribute regex: %w", err)
		} else if matched {
			switch condition.Operator {
			case "changed":
				return change.PreviousValue != change.CurrentValue, nil
			case "added":
				return change.ChangeType == ChangeTypeAdded, nil
			case "removed":
				return change.ChangeType == ChangeTypeRemoved, nil
			case "modified":
				return change.ChangeType == ChangeTypeModified, nil
			default:
				return false, fmt.Errorf("unsupported operator: %s", condition.Operator)
			}
		}
	}

	return false, nil
}

func (re *ruleEngine) evaluateThreshold(condition *RuleCondition, event *DriftEvent) (bool, error) {
	if condition.Attribute == "" {
		return false, fmt.Errorf("attribute is required for threshold condition")
	}

	for _, change := range event.Changes {
		if matched, err := regexp.MatchString(condition.Attribute, change.Attribute); err != nil {
			return false, fmt.Errorf("invalid attribute regex: %w", err)
		} else if !matched {
			continue
		}

		// Parse numeric values
		prevNum, prevErr := strconv.ParseFloat(change.PreviousValue, 64)
		currNum, currErr := strconv.ParseFloat(change.CurrentValue, 64)

		if prevErr != nil || currErr != nil {
			continue // Skip non-numeric values
		}

		switch condition.Operator {
		case "greater_than":
			return currNum > condition.Threshold, nil
		case "less_than":
			return currNum < condition.Threshold, nil
		case "change_greater_than":
			change := currNum - prevNum
			if change < 0 {
				change = -change
			}
			return change > condition.Threshold, nil
		case "percentage_change_greater_than":
			if prevNum != 0 {
				percentChange := ((currNum - prevNum) / prevNum) * 100
				if percentChange < 0 {
					percentChange = -percentChange
				}
				return percentChange > condition.Threshold, nil
			}
		default:
			return false, fmt.Errorf("unsupported threshold operator: %s", condition.Operator)
		}
	}

	return false, nil
}

func (re *ruleEngine) evaluatePattern(condition *RuleCondition, event *DriftEvent) (bool, error) {
	if condition.Pattern == "" {
		return false, fmt.Errorf("pattern is required for pattern condition")
	}

	// Compile regex pattern
	regex, err := regexp.Compile(condition.Pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}

	// Check event properties
	switch condition.Operator {
	case "event_title":
		return regex.MatchString(event.Title), nil
	case "event_description":
		return regex.MatchString(event.Description), nil
	case "device_id":
		return regex.MatchString(event.DeviceID), nil
	case "attribute_name":
		for _, change := range event.Changes {
			if regex.MatchString(change.Attribute) {
				return true, nil
			}
		}
	case "attribute_value":
		for _, change := range event.Changes {
			if regex.MatchString(change.CurrentValue) || regex.MatchString(change.PreviousValue) {
				return true, nil
			}
		}
	default:
		return false, fmt.Errorf("unsupported pattern operator: %s", condition.Operator)
	}

	return false, nil
}

func (re *ruleEngine) evaluateFrequency(condition *RuleCondition, event *DriftEvent) (bool, error) {
	// Frequency conditions would typically require historical data
	// For now, just check the number of changes in the current event
	changeCount := len(event.Changes)

	switch condition.Operator {
	case "changes_greater_than":
		return float64(changeCount) > condition.Threshold, nil
	case "changes_less_than":
		return float64(changeCount) < condition.Threshold, nil
	default:
		return false, fmt.Errorf("unsupported frequency operator: %s", condition.Operator)
	}
}

func (re *ruleEngine) applyLogicalOperator(operator RuleOperator, results []bool) bool {
	if len(results) == 0 {
		return false
	}

	switch operator {
	case OperatorAND:
		for _, result := range results {
			if !result {
				return false
			}
		}
		return true
	case OperatorOR:
		for _, result := range results {
			if result {
				return true
			}
		}
		return false
	default:
		// Default to AND
		for _, result := range results {
			if !result {
				return false
			}
		}
		return true
	}
}

func (re *ruleEngine) calculateRuleConfidence(rule *DriftRule, event *DriftEvent) float64 {
	baseConfidence := event.Confidence

	// Adjust confidence based on rule priority
	priorityBonus := float64(rule.Priority) * 0.05
	confidence := baseConfidence + priorityBonus

	// Adjust based on rule complexity (more conditions = higher confidence if matched)
	complexityBonus := float64(len(rule.Conditions)) * 0.02
	confidence += complexityBonus

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (re *ruleEngine) getActiveRulesSorted() []*DriftRule {
	var activeRules []*DriftRule

	for _, rule := range re.rules {
		if rule.Enabled {
			activeRules = append(activeRules, rule)
		}
	}

	// Sort by priority (highest first)
	for i := 0; i < len(activeRules); i++ {
		for j := i + 1; j < len(activeRules); j++ {
			if activeRules[i].Priority < activeRules[j].Priority {
				activeRules[i], activeRules[j] = activeRules[j], activeRules[i]
			}
		}
	}

	return activeRules
}

func (re *ruleEngine) updateStats() {
	re.stats.TotalRules = len(re.rules)

	activeCount := 0
	for _, rule := range re.rules {
		if rule.Enabled {
			activeCount++
		}
	}
	re.stats.ActiveRules = activeCount
}

func (re *ruleEngine) updateRuleStats(ruleID string, result *RuleResult, duration time.Duration) {
	if !re.config.EnableDetailedStats {
		return
	}

	perf, exists := re.stats.RulePerformance[ruleID]
	if !exists {
		perf = &RulePerf{RuleID: ruleID}
		re.stats.RulePerformance[ruleID] = perf
	}

	perf.EvaluationCount++
	perf.TotalTime += duration
	perf.AverageTime = perf.TotalTime / time.Duration(perf.EvaluationCount)
	perf.LastEvaluation = time.Now()

	if result.Matched {
		perf.MatchCount++
	}

	if perf.EvaluationCount > 0 {
		perf.MatchRate = float64(perf.MatchCount) / float64(perf.EvaluationCount)
	}
}

func (re *ruleEngine) validateRule(rule *DriftRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}

	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}

	if len(rule.Conditions) == 0 {
		return fmt.Errorf("at least one condition is required")
	}

	// Validate conditions
	for i, condition := range rule.Conditions {
		if err := re.validateCondition(condition); err != nil {
			return fmt.Errorf("condition %d: %w", i, err)
		}
	}

	// Validate priority
	if rule.Priority < 1 || rule.Priority > 10 {
		return fmt.Errorf("priority must be between 1 and 10")
	}

	return nil
}

func (re *ruleEngine) validateCondition(condition *RuleCondition) error {
	if condition.Type == "" {
		return fmt.Errorf("condition type is required")
	}

	if condition.Operator == "" {
		return fmt.Errorf("condition operator is required")
	}

	// Validate regex patterns
	if condition.Pattern != "" {
		if _, err := regexp.Compile(condition.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	if condition.Attribute != "" {
		if _, err := regexp.Compile(condition.Attribute); err != nil {
			return fmt.Errorf("invalid attribute regex: %w", err)
		}
	}

	return nil
}

// DefaultRuleEngineConfig returns a default configuration for the rule engine.
func DefaultRuleEngineConfig() *RuleEngineConfig {
	return &RuleEngineConfig{
		MaxRuleEvaluationTime:  30 * time.Second,
		EnableParallelRuleEval: true,
		MaxConcurrentRules:     10,
		MaxRulesPerEngine:      100,
		EnableRuleValidation:   true,
		EnableRuleOptimization: true,
		EnableRuleCache:        true,
		RuleCacheSize:          1000,
		RuleCacheTTL:           24 * time.Hour,
		EnableDetailedStats:    true,
		StatsRetentionPeriod:   30 * 24 * time.Hour, // 30 days
	}
}

func validateRuleEngineConfig(config *RuleEngineConfig) error {
	if config.MaxRulesPerEngine <= 0 {
		return fmt.Errorf("max rules per engine must be positive")
	}

	if config.MaxConcurrentRules <= 0 {
		config.MaxConcurrentRules = 10
	}

	if config.RuleCacheSize < 0 {
		return fmt.Errorf("rule cache size must be non-negative")
	}

	return nil
}
