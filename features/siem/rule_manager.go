package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"gopkg.in/yaml.v3"
)

// RuleManagerImpl implements configurable rule management for SIEM detection rules.
// It supports loading rules from multiple sources (files, databases) with hot-reload
// capabilities and comprehensive rule validation.
type RuleManagerImpl struct {
	logger *logging.ModuleLogger

	// Rule storage
	rules          map[string]*DetectionRule
	rulesByTenant  map[string][]*DetectionRule
	rulesByCategory map[string][]*DetectionRule
	mutex          sync.RWMutex

	// Configuration
	config RuleConfig

	// Hot reload support
	watcher         *FileWatcher
	lastReloadTime  time.Time
	reloadInterval  time.Duration
	autoReloadStop  chan struct{}

	// Pattern and correlation managers
	patternMatcher  PatternMatcher
	eventCorrelator EventCorrelator

	// Statistics
	totalRules      int64
	enabledRules    int64
	lastLoadTime    time.Time
	loadErrors      int64
	statsLock       sync.RWMutex
}

// FileWatcher monitors rule files for changes
type FileWatcher struct {
	watchedPaths map[string]time.Time
	mutex        sync.RWMutex
}

// NewRuleManager creates a new rule manager
func NewRuleManager(patternMatcher PatternMatcher, eventCorrelator EventCorrelator) *RuleManagerImpl {
	logger := logging.ForModule("siem.rule_manager").WithField("component", "rules")

	return &RuleManagerImpl{
		logger:          logger,
		rules:           make(map[string]*DetectionRule),
		rulesByTenant:   make(map[string][]*DetectionRule),
		rulesByCategory: make(map[string][]*DetectionRule),
		patternMatcher:  patternMatcher,
		eventCorrelator: eventCorrelator,
		watcher:         NewFileWatcher(),
		autoReloadStop:  make(chan struct{}),
	}
}

// NewFileWatcher creates a new file watcher
func NewFileWatcher() *FileWatcher {
	return &FileWatcher{
		watchedPaths: make(map[string]time.Time),
	}
}

// LoadRules loads rules from configuration
func (rm *RuleManagerImpl) LoadRules(ctx context.Context, config RuleConfig) error {
	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := rm.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Loading SIEM rules",
		"source", config.Source,
		"path", config.Path,
		"format", config.Format,
		"auto_reload", config.AutoReload)

	rm.mutex.Lock()
	rm.config = config
	rm.mutex.Unlock()

	// Load initial rules
	if err := rm.loadRulesFromSource(ctx, config); err != nil {
		rm.statsLock.Lock()
		rm.loadErrors++
		rm.statsLock.Unlock()
		return fmt.Errorf("failed to load rules: %w", err)
	}

	// Set up auto-reload if enabled
	if config.AutoReload && config.ReloadInterval > 0 {
		rm.reloadInterval = config.ReloadInterval
		go rm.autoReloadLoop(ctx)
	}

	rm.lastLoadTime = time.Now()
	logger.InfoCtx(ctx, "Successfully loaded SIEM rules",
		"total_rules", rm.totalRules,
		"enabled_rules", rm.enabledRules)

	return nil
}

// loadRulesFromSource loads rules from the configured source
func (rm *RuleManagerImpl) loadRulesFromSource(ctx context.Context, config RuleConfig) error {
	switch config.Source {
	case "file":
		return rm.loadRulesFromFile(ctx, config.Path, config.Format)
	case "directory":
		return rm.loadRulesFromDirectory(ctx, config.Path, config.Format)
	case "database":
		return rm.loadRulesFromDatabase(ctx, config)
	default:
		return fmt.Errorf("unsupported rule source: %s", config.Source)
	}
}

// loadRulesFromFile loads rules from a single file
func (rm *RuleManagerImpl) loadRulesFromFile(ctx context.Context, filePath, format string) error {
	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := rm.logger.WithTenant(tenantID)

	logger.DebugCtx(ctx, "Loading rules from file",
		"file_path", filePath,
		"format", format)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read rule file: %w", err)
	}

	// Track file for hot reload
	rm.watcher.AddPath(filePath)

	return rm.parseRules(ctx, data, format, filePath)
}

// loadRulesFromDirectory loads rules from all files in a directory
func (rm *RuleManagerImpl) loadRulesFromDirectory(ctx context.Context, dirPath, format string) error {
	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := rm.logger.WithTenant(tenantID)

	logger.DebugCtx(ctx, "Loading rules from directory",
		"directory_path", dirPath,
		"format", format)

	var loadedFiles int
	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Check file extension matches format
		if !rm.matchesFormat(path, format) {
			return nil
		}

		logger.DebugCtx(ctx, "Loading rules from file", "file", path)

		data, err := os.ReadFile(path)
		if err != nil {
			logger.ErrorCtx(ctx, "Failed to read rule file",
				"file", path,
				"error", err.Error())
			return nil // Continue with other files
		}

		// Track file for hot reload
		rm.watcher.AddPath(path)

		if err := rm.parseRules(ctx, data, format, path); err != nil {
			logger.ErrorCtx(ctx, "Failed to parse rule file",
				"file", path,
				"error", err.Error())
			return nil // Continue with other files
		}

		loadedFiles++
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory: %w", err)
	}

	logger.InfoCtx(ctx, "Completed directory rule loading",
		"files_loaded", loadedFiles)

	return nil
}

// loadRulesFromDatabase loads rules from database (stub for future implementation)
func (rm *RuleManagerImpl) loadRulesFromDatabase(ctx context.Context, config RuleConfig) error {
	// TODO: Implement database rule loading
	return fmt.Errorf("database rule loading not yet implemented")
}

// parseRules parses rule data in the specified format
func (rm *RuleManagerImpl) parseRules(ctx context.Context, data []byte, format, source string) error {
	var rules []*DetectionRule

	switch strings.ToLower(format) {
	case "yaml", "yml":
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return fmt.Errorf("failed to parse YAML rules: %w", err)
		}
	case "json":
		if err := json.Unmarshal(data, &rules); err != nil {
			return fmt.Errorf("failed to parse JSON rules: %w", err)
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	// Validate and add rules
	for _, rule := range rules {
		if rule == nil {
			continue
		}

		// Set source information
		if rule.CreatedAt.IsZero() {
			rule.CreatedAt = time.Now()
		}
		rule.UpdatedAt = time.Now()

		if err := rm.AddRule(rule); err != nil {
			rm.logger.ErrorCtx(ctx, "Failed to add rule",
				"rule_id", rule.ID,
				"source", source,
				"error", err.Error())
			continue
		}
	}

	return nil
}

// matchesFormat checks if a file matches the expected format
func (rm *RuleManagerImpl) matchesFormat(filePath, format string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch strings.ToLower(format) {
	case "yaml", "yml":
		return ext == ".yaml" || ext == ".yml"
	case "json":
		return ext == ".json"
	default:
		return false
	}
}

// AddRule adds a new detection rule
func (rm *RuleManagerImpl) AddRule(rule *DetectionRule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	if err := rm.ValidateRule(rule); err != nil {
		return fmt.Errorf("invalid rule: %w", err)
	}

	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// Set timestamps if not set
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now()
	}
	rule.UpdatedAt = time.Now()

	// Store rule
	rm.rules[rule.ID] = rule

	// Update indexes
	rm.updateIndexes(rule)

	// Add patterns to pattern matcher
	if rm.patternMatcher != nil {
		for _, pattern := range rule.Patterns {
			if err := rm.patternMatcher.AddPattern(pattern); err != nil {
				rm.logger.Error("Failed to add pattern to matcher",
					"pattern_id", pattern.ID,
					"rule_id", rule.ID,
					"error", err.Error())
			}
		}
	}

	// Add correlation rules to event correlator
	if rm.eventCorrelator != nil && rule.Correlation != nil {
		if err := rm.eventCorrelator.AddCorrelationRule(rule.Correlation); err != nil {
			rm.logger.Error("Failed to add correlation rule",
				"rule_id", rule.ID,
				"correlation_id", rule.Correlation.ID,
				"error", err.Error())
		}
	}

	// Update statistics
	rm.statsLock.Lock()
	rm.totalRules = int64(len(rm.rules))
	if rule.Enabled {
		rm.enabledRules++
	}
	rm.statsLock.Unlock()

	rm.logger.Info("Added detection rule",
		"rule_id", rule.ID,
		"name", rule.Name,
		"severity", rule.Severity,
		"enabled", rule.Enabled,
		"pattern_count", len(rule.Patterns))

	return nil
}

// UpdateRule updates an existing detection rule
func (rm *RuleManagerImpl) UpdateRule(rule *DetectionRule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	if err := rm.ValidateRule(rule); err != nil {
		return fmt.Errorf("invalid rule: %w", err)
	}

	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	existingRule, exists := rm.rules[rule.ID]
	if !exists {
		return fmt.Errorf("rule '%s' not found", rule.ID)
	}

	// Preserve creation time
	rule.CreatedAt = existingRule.CreatedAt
	rule.UpdatedAt = time.Now()

	// Update rule
	rm.rules[rule.ID] = rule

	// Update indexes
	rm.updateIndexes(rule)

	// Update patterns in pattern matcher
	if rm.patternMatcher != nil {
		// Remove old patterns
		for _, pattern := range existingRule.Patterns {
			if err := rm.patternMatcher.RemovePattern(pattern.ID); err != nil {
				rm.logger.Error("Failed to remove old pattern from matcher",
					"pattern_id", pattern.ID,
					"rule_id", rule.ID,
					"error", err.Error())
			}
		}
		// Add new patterns
		for _, pattern := range rule.Patterns {
			if err := rm.patternMatcher.AddPattern(pattern); err != nil {
				rm.logger.Error("Failed to update pattern in matcher",
					"pattern_id", pattern.ID,
					"rule_id", rule.ID,
					"error", err.Error())
			}
		}
	}

	// Update correlation rules
	if rm.eventCorrelator != nil {
		if existingRule.Correlation != nil {
			if err := rm.eventCorrelator.RemoveCorrelationRule(existingRule.Correlation.ID); err != nil {
				rm.logger.Error("Failed to remove old correlation rule",
					"rule_id", rule.ID,
					"correlation_id", existingRule.Correlation.ID,
					"error", err.Error())
			}
		}
		if rule.Correlation != nil {
			if err := rm.eventCorrelator.AddCorrelationRule(rule.Correlation); err != nil {
				rm.logger.Error("Failed to update correlation rule",
					"rule_id", rule.ID,
					"correlation_id", rule.Correlation.ID,
					"error", err.Error())
			}
		}
	}

	rm.logger.Info("Updated detection rule",
		"rule_id", rule.ID,
		"name", rule.Name)

	return nil
}

// RemoveRule removes a detection rule
func (rm *RuleManagerImpl) RemoveRule(ruleID string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	rule, exists := rm.rules[ruleID]
	if !exists {
		return fmt.Errorf("rule '%s' not found", ruleID)
	}

	// Remove from pattern matcher
	if rm.patternMatcher != nil {
		for _, pattern := range rule.Patterns {
			if err := rm.patternMatcher.RemovePattern(pattern.ID); err != nil {
				rm.logger.Error("Failed to remove pattern from matcher",
					"pattern_id", pattern.ID,
					"rule_id", ruleID,
					"error", err.Error())
			}
		}
	}

	// Remove from event correlator
	if rm.eventCorrelator != nil && rule.Correlation != nil {
		if err := rm.eventCorrelator.RemoveCorrelationRule(rule.Correlation.ID); err != nil {
			rm.logger.Error("Failed to remove correlation rule",
				"rule_id", ruleID,
				"correlation_id", rule.Correlation.ID,
				"error", err.Error())
		}
	}

	// Remove from main storage
	delete(rm.rules, ruleID)

	// Update indexes
	rm.removeFromIndexes(rule)

	// Update statistics
	rm.statsLock.Lock()
	rm.totalRules = int64(len(rm.rules))
	if rule.Enabled {
		rm.enabledRules--
	}
	rm.statsLock.Unlock()

	rm.logger.Info("Removed detection rule",
		"rule_id", ruleID,
		"name", rule.Name)

	return nil
}

// GetRule retrieves a rule by ID
func (rm *RuleManagerImpl) GetRule(ruleID string) (*DetectionRule, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	rule, exists := rm.rules[ruleID]
	if !exists {
		return nil, fmt.Errorf("rule '%s' not found", ruleID)
	}

	// Return a copy to prevent external modification
	ruleCopy := *rule
	return &ruleCopy, nil
}

// ListRules lists rules with optional filtering
func (rm *RuleManagerImpl) ListRules(filter *RuleFilter) ([]*DetectionRule, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	var rules []*DetectionRule

	// Start with all rules or filter by indexes
	var candidateRules []*DetectionRule
	if filter != nil {
		if filter.TenantID != "" {
			candidateRules = rm.rulesByTenant[filter.TenantID]
		} else if filter.Category != "" {
			candidateRules = rm.rulesByCategory[filter.Category]
		}
	}

	if candidateRules == nil {
		candidateRules = make([]*DetectionRule, 0, len(rm.rules))
		for _, rule := range rm.rules {
			candidateRules = append(candidateRules, rule)
		}
	}

	// Apply filters
	for _, rule := range candidateRules {
		if rm.matchesFilter(rule, filter) {
			// Return a copy to prevent external modification
			ruleCopy := *rule
			rules = append(rules, &ruleCopy)
		}
	}

	// Apply pagination
	if filter != nil && (filter.Limit > 0 || filter.Offset > 0) {
		start := filter.Offset
		if start >= len(rules) {
			return []*DetectionRule{}, nil
		}

		end := len(rules)
		if filter.Limit > 0 && start+filter.Limit < end {
			end = start + filter.Limit
		}

		rules = rules[start:end]
	}

	return rules, nil
}

// matchesFilter checks if a rule matches the given filter
func (rm *RuleManagerImpl) matchesFilter(rule *DetectionRule, filter *RuleFilter) bool {
	if filter == nil {
		return true
	}

	if filter.TenantID != "" && rule.TenantID != filter.TenantID {
		return false
	}

	if filter.Enabled != nil && rule.Enabled != *filter.Enabled {
		return false
	}

	if filter.Severity != "" && rule.Severity != filter.Severity {
		return false
	}

	if filter.Category != "" && rule.Category != filter.Category {
		return false
	}

	if len(filter.Tags) > 0 {
		ruleTagSet := make(map[string]bool)
		for _, tag := range rule.Tags {
			ruleTagSet[tag] = true
		}
		for _, filterTag := range filter.Tags {
			if !ruleTagSet[filterTag] {
				return false
			}
		}
	}

	if filter.CreatedAfter != nil && rule.CreatedAt.Before(*filter.CreatedAfter) {
		return false
	}

	if filter.CreatedBefore != nil && rule.CreatedAt.After(*filter.CreatedBefore) {
		return false
	}

	return true
}

// ValidateRule validates a rule configuration
func (rm *RuleManagerImpl) ValidateRule(rule *DetectionRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	if rule.Name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}

	if rule.Severity == "" {
		return fmt.Errorf("rule severity cannot be empty")
	}

	// Validate severity
	validSeverities := map[EventSeverity]bool{
		SeverityCritical: true,
		SeverityHigh:     true,
		SeverityMedium:   true,
		SeverityLow:      true,
		SeverityInfo:     true,
	}
	if !validSeverities[rule.Severity] {
		return fmt.Errorf("invalid severity: %s", rule.Severity)
	}

	// Validate time window
	if rule.TimeWindow <= 0 {
		return fmt.Errorf("time window must be greater than zero")
	}

	if rule.TimeWindow > 24*time.Hour {
		return fmt.Errorf("time window cannot exceed 24 hours")
	}

	// Validate patterns
	for i, pattern := range rule.Patterns {
		if pattern.ID == "" {
			return fmt.Errorf("pattern %d: ID cannot be empty", i)
		}
		if pattern.Pattern == "" {
			return fmt.Errorf("pattern %d: pattern string cannot be empty", i)
		}
	}

	// Validate actions
	for i, action := range rule.Actions {
		if action.Type == "" {
			return fmt.Errorf("action %d: type cannot be empty", i)
		}
	}

	return nil
}

// updateIndexes updates rule indexes for efficient filtering
func (rm *RuleManagerImpl) updateIndexes(rule *DetectionRule) {
	// Remove from existing indexes first
	rm.removeFromIndexes(rule)

	// Add to tenant index
	if rule.TenantID != "" {
		rm.rulesByTenant[rule.TenantID] = append(rm.rulesByTenant[rule.TenantID], rule)
	}

	// Add to category index
	if rule.Category != "" {
		rm.rulesByCategory[rule.Category] = append(rm.rulesByCategory[rule.Category], rule)
	}
}

// removeFromIndexes removes a rule from all indexes
func (rm *RuleManagerImpl) removeFromIndexes(rule *DetectionRule) {
	// Remove from tenant index
	if rule.TenantID != "" {
		rules := rm.rulesByTenant[rule.TenantID]
		for i, r := range rules {
			if r.ID == rule.ID {
				rm.rulesByTenant[rule.TenantID] = append(rules[:i], rules[i+1:]...)
				break
			}
		}
		if len(rm.rulesByTenant[rule.TenantID]) == 0 {
			delete(rm.rulesByTenant, rule.TenantID)
		}
	}

	// Remove from category index
	if rule.Category != "" {
		rules := rm.rulesByCategory[rule.Category]
		for i, r := range rules {
			if r.ID == rule.ID {
				rm.rulesByCategory[rule.Category] = append(rules[:i], rules[i+1:]...)
				break
			}
		}
		if len(rm.rulesByCategory[rule.Category]) == 0 {
			delete(rm.rulesByCategory, rule.Category)
		}
	}
}

// autoReloadLoop runs automatic rule reloading
func (rm *RuleManagerImpl) autoReloadLoop(ctx context.Context) {
	ticker := time.NewTicker(rm.reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.autoReloadStop:
			return
		case <-ticker.C:
			if rm.shouldReload() {
				if err := rm.reloadRules(ctx); err != nil {
					rm.logger.ErrorCtx(ctx, "Auto-reload failed",
						"error", err.Error())
				}
			}
		}
	}
}

// shouldReload checks if rules should be reloaded based on file changes
func (rm *RuleManagerImpl) shouldReload() bool {
	return rm.watcher.HasChanges()
}

// reloadRules reloads all rules from the configured source
func (rm *RuleManagerImpl) reloadRules(ctx context.Context) error {
	rm.logger.InfoCtx(ctx, "Reloading SIEM rules")

	// Clear existing rules
	rm.mutex.Lock()
	oldRuleCount := len(rm.rules)
	rm.rules = make(map[string]*DetectionRule)
	rm.rulesByTenant = make(map[string][]*DetectionRule)
	rm.rulesByCategory = make(map[string][]*DetectionRule)
	rm.mutex.Unlock()

	// Reload from source
	if err := rm.loadRulesFromSource(ctx, rm.config); err != nil {
		return fmt.Errorf("failed to reload rules: %w", err)
	}

	rm.lastReloadTime = time.Now()

	rm.logger.InfoCtx(ctx, "Successfully reloaded SIEM rules",
		"old_rules", oldRuleCount,
		"new_rules", rm.totalRules)

	return nil
}

// AddPath adds a file path to the watcher
func (fw *FileWatcher) AddPath(path string) {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()

	if stat, err := os.Stat(path); err == nil {
		fw.watchedPaths[path] = stat.ModTime()
	}
}

// HasChanges checks if any watched files have changed
func (fw *FileWatcher) HasChanges() bool {
	fw.mutex.RLock()
	defer fw.mutex.RUnlock()

	for path, lastMod := range fw.watchedPaths {
		if stat, err := os.Stat(path); err == nil {
			if stat.ModTime().After(lastMod) {
				fw.watchedPaths[path] = stat.ModTime()
				return true
			}
		}
	}

	return false
}

// GetStatistics returns rule management statistics
func (rm *RuleManagerImpl) GetStatistics() map[string]interface{} {
	rm.statsLock.RLock()
	defer rm.statsLock.RUnlock()

	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	return map[string]interface{}{
		"total_rules":        rm.totalRules,
		"enabled_rules":      rm.enabledRules,
		"disabled_rules":     rm.totalRules - rm.enabledRules,
		"tenant_count":       int64(len(rm.rulesByTenant)),
		"category_count":     int64(len(rm.rulesByCategory)),
		"last_load_time":     rm.lastLoadTime,
		"last_reload_time":   rm.lastReloadTime,
		"load_errors":        rm.loadErrors,
		"auto_reload":        rm.config.AutoReload,
		"reload_interval":    rm.reloadInterval.String(),
		"watched_files":      int64(len(rm.watcher.watchedPaths)),
	}
}