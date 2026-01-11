// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package drift provides smart filtering to reduce false positive drift events.

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

// filter implements the Filter interface for reducing false positive drift events.
type filter struct {
	logger    logging.Logger
	config    *FilterConfig
	whitelist []*WhitelistPattern
	stats     *FilterStats
}

// FilterConfig defines configuration for drift event filtering.
type FilterConfig struct {
	// Filtering behavior
	EnableSmartFiltering   bool    `json:"enable_smart_filtering" yaml:"enable_smart_filtering"`
	FalsePositiveThreshold float64 `json:"false_positive_threshold" yaml:"false_positive_threshold"` // 0.0-1.0

	// Temporal filtering
	EnableTemporalFiltering bool          `json:"enable_temporal_filtering" yaml:"enable_temporal_filtering"`
	TemporalWindow          time.Duration `json:"temporal_window" yaml:"temporal_window"`         // Window to consider for patterns
	MinChangeInterval       time.Duration `json:"min_change_interval" yaml:"min_change_interval"` // Minimum interval between significant changes

	// Value-based filtering
	IgnorePercentageChanges bool    `json:"ignore_percentage_changes" yaml:"ignore_percentage_changes"`
	PercentageThreshold     float64 `json:"percentage_threshold" yaml:"percentage_threshold"` // Ignore changes smaller than this %
	IgnoreTemporaryFiles    bool    `json:"ignore_temporary_files" yaml:"ignore_temporary_files"`
	IgnoreLogRotation       bool    `json:"ignore_log_rotation" yaml:"ignore_log_rotation"`

	// Pattern-based filtering
	IgnorePatterns     []string `json:"ignore_patterns" yaml:"ignore_patterns"`         // Regex patterns to ignore
	TemporaryPatterns  []string `json:"temporary_patterns" yaml:"temporary_patterns"`   // Patterns for temporary values
	VolatileAttributes []string `json:"volatile_attributes" yaml:"volatile_attributes"` // Attributes that change frequently

	// Machine learning filtering
	EnableMLFiltering     bool    `json:"enable_ml_filtering" yaml:"enable_ml_filtering"`
	MLConfidenceThreshold float64 `json:"ml_confidence_threshold" yaml:"ml_confidence_threshold"`

	// Performance
	MaxFilterTime            time.Duration `json:"max_filter_time" yaml:"max_filter_time"`
	EnableParallelProcessing bool          `json:"enable_parallel_processing" yaml:"enable_parallel_processing"`
}

// NewFilter creates a new drift event filter with the specified configuration.
func NewFilter(config *FilterConfig, logger logging.Logger) (Filter, error) {
	if config == nil {
		config = DefaultFilterConfig()
	}

	if err := validateFilterConfig(config); err != nil {
		return nil, fmt.Errorf("invalid filter config: %w", err)
	}

	f := &filter{
		logger:    logger,
		config:    config,
		whitelist: make([]*WhitelistPattern, 0),
		stats:     &FilterStats{},
	}

	// Initialize with default whitelist patterns
	f.initializeDefaultWhitelist()

	if logger != nil {
		logger.Info("Drift event filter initialized",
			"smart_filtering", config.EnableSmartFiltering,
			"temporal_filtering", config.EnableTemporalFiltering,
			"ml_filtering", config.EnableMLFiltering,
			"whitelist_patterns", len(f.whitelist))
	}

	return f, nil
}

// FilterEvents filters out false positive drift events.
func (f *filter) FilterEvents(ctx context.Context, events []*DriftEvent) ([]*DriftEvent, error) {
	startTime := time.Now()
	defer func() {
		f.stats.AverageFilterTime = time.Since(startTime)
	}()

	if len(events) == 0 {
		return events, nil
	}

	// Check for timeout
	if f.config.MaxFilterTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.config.MaxFilterTime)
		defer cancel()
	}

	if f.logger != nil {
		f.logger.Debug("Starting drift event filtering", "input_events", len(events))
	}

	var filteredEvents []*DriftEvent

	for _, event := range events {
		select {
		case <-ctx.Done():
			return filteredEvents, ctx.Err()
		default:
		}

		f.stats.EventsProcessed++

		// Apply various filtering stages
		if f.shouldFilterEvent(ctx, event) {
			f.stats.EventsFiltered++
			if f.logger != nil {
				f.logger.Debug("Event filtered out",
					"event_id", event.ID,
					"device_id", event.DeviceID,
					"severity", event.Severity,
					"change_count", event.ChangeCount)
			}
			continue
		}

		// Filter individual changes within the event
		filteredChanges := f.filterChanges(ctx, event.Changes)
		if len(filteredChanges) == 0 {
			// All changes were filtered out
			f.stats.EventsFiltered++
			continue
		}

		// Update event with filtered changes
		if len(filteredChanges) != len(event.Changes) {
			event.Changes = filteredChanges
			event.ChangeCount = len(filteredChanges)
			// Recalculate event metrics
			event.Confidence = f.recalculateConfidence(event)
			event.RiskScore = f.recalculateRiskScore(event)
		}

		filteredEvents = append(filteredEvents, event)
	}

	// Update statistics
	f.stats.FilteringRate = float64(f.stats.EventsFiltered) / float64(f.stats.EventsProcessed)

	if f.logger != nil {
		f.logger.Debug("Drift event filtering completed",
			"input_events", len(events),
			"output_events", len(filteredEvents),
			"filtered_count", f.stats.EventsFiltered,
			"filter_time", time.Since(startTime))
	}

	return filteredEvents, nil
}

// IsExpectedChange determines if a change is expected/normal.
func (f *filter) IsExpectedChange(change *AttributeChange) (bool, string) {
	// Check whitelist patterns
	for _, pattern := range f.whitelist {
		if f.matchesWhitelistPattern(change, pattern) {
			f.stats.WhitelistMatches++
			return true, pattern.Reason
		}
	}

	// Check for volatile attributes
	if f.isVolatileAttribute(change.Attribute) {
		return true, "Attribute is marked as volatile and changes frequently"
	}

	// Check for temporary file patterns
	if f.config.IgnoreTemporaryFiles && f.isTemporaryFile(change.Attribute, change.CurrentValue) {
		return true, "Change relates to temporary files"
	}

	// Check for log rotation patterns
	if f.config.IgnoreLogRotation && f.isLogRotation(change) {
		return true, "Change appears to be from log rotation"
	}

	// Check for percentage-based changes
	if f.config.IgnorePercentageChanges && f.isSmallPercentageChange(change) {
		return true, fmt.Sprintf("Change is below percentage threshold (%.2f%%)", f.config.PercentageThreshold)
	}

	// Check ignore patterns
	for _, pattern := range f.config.IgnorePatterns {
		if matched, _ := regexp.MatchString(pattern, change.Attribute); matched {
			return true, fmt.Sprintf("Attribute matches ignore pattern: %s", pattern)
		}
	}

	return false, ""
}

// AddWhitelist adds an attribute pattern to the whitelist.
func (f *filter) AddWhitelist(pattern *WhitelistPattern) error {
	if pattern.ID == "" {
		pattern.ID = f.generateWhitelistID(pattern)
	}

	if pattern.CreatedAt.IsZero() {
		pattern.CreatedAt = time.Now()
	}

	// Validate pattern
	if pattern.Pattern != "" {
		if _, err := regexp.Compile(pattern.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	f.whitelist = append(f.whitelist, pattern)

	if f.logger != nil {
		f.logger.Info("Whitelist pattern added",
			"pattern_id", pattern.ID,
			"name", pattern.Name,
			"attribute", pattern.Attribute)
	}

	return nil
}

// RemoveWhitelist removes a whitelist pattern.
func (f *filter) RemoveWhitelist(patternID string) error {
	for i, pattern := range f.whitelist {
		if pattern.ID == patternID {
			// Remove from slice
			f.whitelist = append(f.whitelist[:i], f.whitelist[i+1:]...)

			if f.logger != nil {
				f.logger.Info("Whitelist pattern removed", "pattern_id", patternID)
			}
			return nil
		}
	}

	return fmt.Errorf("whitelist pattern not found: %s", patternID)
}

// GetFilterStats returns filtering statistics.
func (f *filter) GetFilterStats() *FilterStats {
	// Return a copy to avoid race conditions
	stats := *f.stats
	return &stats
}

// Close releases filter resources.
func (f *filter) Close() error {
	if f.logger != nil {
		f.logger.Info("Closing drift event filter")
	}
	return nil
}

// Private methods

func (f *filter) shouldFilterEvent(ctx context.Context, event *DriftEvent) bool {
	// Filter very low confidence events
	if event.Confidence < f.config.FalsePositiveThreshold {
		return true
	}

	// Filter events with only info-level changes if below threshold
	if event.Severity == SeverityInfo && event.Confidence < 0.7 {
		return true
	}

	// Temporal filtering
	if f.config.EnableTemporalFiltering {
		if f.isRecentDuplicateEvent(event) {
			return true
		}
	}

	// ML-based filtering
	if f.config.EnableMLFiltering {
		if f.isMLFilteredEvent(event) {
			return true
		}
	}

	return false
}

func (f *filter) filterChanges(ctx context.Context, changes []*AttributeChange) []*AttributeChange {
	var filteredChanges []*AttributeChange

	for _, change := range changes {
		if expected, _ := f.IsExpectedChange(change); !expected {
			filteredChanges = append(filteredChanges, change)
		}
	}

	return filteredChanges
}

func (f *filter) matchesWhitelistPattern(change *AttributeChange, pattern *WhitelistPattern) bool {
	// Check if pattern is expired
	if pattern.ValidUntil != nil && time.Now().After(*pattern.ValidUntil) {
		return false
	}

	// Check attribute match
	if pattern.Attribute != "" {
		if matched, _ := regexp.MatchString(pattern.Attribute, change.Attribute); !matched {
			return false
		}
	}

	// Check pattern match
	if pattern.Pattern != "" {
		// Check both previous and current values
		if matched, _ := regexp.MatchString(pattern.Pattern, change.PreviousValue); matched {
			return true
		}
		if matched, _ := regexp.MatchString(pattern.Pattern, change.CurrentValue); matched {
			return true
		}
	}

	return false
}

func (f *filter) isVolatileAttribute(attribute string) bool {
	attributeLower := strings.ToLower(attribute)

	for _, volatile := range f.config.VolatileAttributes {
		if matched, _ := regexp.MatchString(volatile, attributeLower); matched {
			return true
		}
	}

	// Built-in volatile patterns
	volatilePatterns := []string{
		".*uptime.*",
		".*load.*",
		".*usage.*",
		".*temp.*",
		".*timestamp.*",
		".*pid.*",
		".*session.*",
	}

	for _, pattern := range volatilePatterns {
		if matched, _ := regexp.MatchString(pattern, attributeLower); matched {
			return true
		}
	}

	return false
}

func (f *filter) isTemporaryFile(attribute, value string) bool {
	tempPatterns := []string{
		`/tmp/.*`,
		`/var/tmp/.*`,
		`.*\.tmp$`,
		`.*\.temp$`,
		`.*\.log\.\d+$`,
		`.*~$`,
		`.*\.swp$`,
		`.*\.bak$`,
	}

	valueLower := strings.ToLower(value)
	attributeLower := strings.ToLower(attribute)

	for _, pattern := range tempPatterns {
		if matched, _ := regexp.MatchString(pattern, valueLower); matched {
			return true
		}
		if matched, _ := regexp.MatchString(pattern, attributeLower); matched {
			return true
		}
	}

	return false
}

func (f *filter) isLogRotation(change *AttributeChange) bool {
	// Check for log file rotation patterns
	logPatterns := []string{
		`.*\.log\.\d+$`,
		`.*\.log\.\d{4}-\d{2}-\d{2}$`,
		`.*\.log\.gz$`,
		`.*\.log\.zip$`,
	}

	attributeLower := strings.ToLower(change.Attribute)
	prevValueLower := strings.ToLower(change.PreviousValue)
	currValueLower := strings.ToLower(change.CurrentValue)

	// Check if attribute relates to logging
	if !strings.Contains(attributeLower, "log") {
		return false
	}

	for _, pattern := range logPatterns {
		if matched, _ := regexp.MatchString(pattern, prevValueLower); matched {
			return true
		}
		if matched, _ := regexp.MatchString(pattern, currValueLower); matched {
			return true
		}
	}

	// Check for size-based log rotation (file size changes)
	if strings.Contains(attributeLower, "size") || strings.Contains(attributeLower, "bytes") {
		// Parse numeric values to see if it's a significant change
		prevNum, prevErr := f.parseNumericValue(change.PreviousValue)
		currNum, currErr := f.parseNumericValue(change.CurrentValue)

		if prevErr == nil && currErr == nil {
			// If current value is much smaller than previous, likely log rotation
			if currNum < prevNum*0.1 && prevNum > 1000 {
				return true
			}
		}
	}

	return false
}

func (f *filter) isSmallPercentageChange(change *AttributeChange) bool {
	// Parse numeric values
	prevNum, prevErr := f.parseNumericValue(change.PreviousValue)
	currNum, currErr := f.parseNumericValue(change.CurrentValue)

	if prevErr != nil || currErr != nil {
		return false
	}

	// Avoid division by zero
	if prevNum == 0 {
		return currNum == 0
	}

	// Calculate percentage change
	percentageChange := ((currNum - prevNum) / prevNum) * 100
	if percentageChange < 0 {
		percentageChange = -percentageChange
	}

	return percentageChange < f.config.PercentageThreshold
}

func (f *filter) parseNumericValue(value string) (float64, error) {
	// Clean the value (remove units, whitespace, etc.)
	cleaned := strings.TrimSpace(value)
	cleaned = regexp.MustCompile(`[^\d\.\-\+]`).ReplaceAllString(cleaned, "")

	return strconv.ParseFloat(cleaned, 64)
}

func (f *filter) isRecentDuplicateEvent(event *DriftEvent) bool {
	// This would typically check against a cache or database of recent events
	// For now, just return false as we don't have event history
	return false
}

func (f *filter) isMLFilteredEvent(event *DriftEvent) bool {
	// Placeholder for ML-based filtering
	// Would typically use trained models to identify false positives
	return false
}

func (f *filter) recalculateConfidence(event *DriftEvent) float64 {
	if len(event.Changes) == 0 {
		return 0.0
	}

	confidence := 0.5

	criticalCount := 0
	warningCount := 0

	for _, change := range event.Changes {
		switch change.Severity {
		case SeverityCritical:
			criticalCount++
		case SeverityWarning:
			warningCount++
		}
	}

	confidence += float64(criticalCount) * 0.3
	confidence += float64(warningCount) * 0.1

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (f *filter) recalculateRiskScore(event *DriftEvent) float64 {
	if len(event.Changes) == 0 {
		return 0.0
	}

	riskScore := 0.0

	for _, change := range event.Changes {
		switch change.Severity {
		case SeverityCritical:
			riskScore += 0.8
		case SeverityWarning:
			riskScore += 0.4
		case SeverityInfo:
			riskScore += 0.1
		}

		if change.Category == "security" {
			riskScore += 0.3
		}
	}

	maxPossibleRisk := float64(len(event.Changes)) * 1.1
	if maxPossibleRisk > 0 {
		riskScore = riskScore / maxPossibleRisk
	}

	if riskScore > 1.0 {
		riskScore = 1.0
	}

	return riskScore
}

func (f *filter) generateWhitelistID(pattern *WhitelistPattern) string {
	return fmt.Sprintf("whitelist-%d", time.Now().UnixNano())
}

func (f *filter) initializeDefaultWhitelist() {
	defaultPatterns := []*WhitelistPattern{
		{
			ID:        "default-timestamp",
			Name:      "Timestamp Updates",
			Attribute: ".*timestamp.*",
			Pattern:   `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`,
			Reason:    "Regular timestamp updates are expected",
			CreatedAt: time.Now(),
		},
		{
			ID:        "default-uptime",
			Name:      "System Uptime",
			Attribute: ".*uptime.*",
			Pattern:   `\d+`,
			Reason:    "System uptime changes continuously",
			CreatedAt: time.Now(),
		},
		{
			ID:        "default-load",
			Name:      "System Load",
			Attribute: ".*load.*",
			Pattern:   `\d+\.\d+`,
			Reason:    "System load varies continuously",
			CreatedAt: time.Now(),
		},
		{
			ID:        "default-temp-files",
			Name:      "Temporary Files",
			Attribute: ".*",
			Pattern:   `.*/tmp/.*|.*\.tmp$|.*\.temp$`,
			Reason:    "Temporary files change frequently",
			CreatedAt: time.Now(),
		},
		{
			ID:        "default-process-ids",
			Name:      "Process IDs",
			Attribute: ".*pid.*",
			Pattern:   `\d+`,
			Reason:    "Process IDs change on restart",
			CreatedAt: time.Now(),
		},
	}

	f.whitelist = append(f.whitelist, defaultPatterns...)
}

// DefaultFilterConfig returns a default configuration for drift event filtering.
func DefaultFilterConfig() *FilterConfig {
	return &FilterConfig{
		EnableSmartFiltering:    true,
		FalsePositiveThreshold:  0.3,
		EnableTemporalFiltering: true,
		TemporalWindow:          24 * time.Hour,
		MinChangeInterval:       5 * time.Minute,
		IgnorePercentageChanges: true,
		PercentageThreshold:     5.0, // Ignore changes smaller than 5%
		IgnoreTemporaryFiles:    true,
		IgnoreLogRotation:       true,
		IgnorePatterns: []string{
			".*timestamp.*",
			".*last_updated.*",
			".*uptime.*",
			".*load_average.*",
			".*temp$",
			".*usage$",
			".*pid.*",
			".*session.*",
		},
		TemporaryPatterns: []string{
			`.*/tmp/.*`,
			`.*\.tmp$`,
			`.*\.temp$`,
			`.*~$`,
			`.*\.swp$`,
		},
		VolatileAttributes: []string{
			".*uptime.*",
			".*load.*",
			".*usage.*",
			".*temp.*",
			".*timestamp.*",
			".*pid.*",
			".*session.*",
			".*memory_free.*",
			".*disk_free.*",
		},
		EnableMLFiltering:        false,
		MLConfidenceThreshold:    0.8,
		MaxFilterTime:            10 * time.Second,
		EnableParallelProcessing: true,
	}
}

func validateFilterConfig(config *FilterConfig) error {
	if config.FalsePositiveThreshold < 0 || config.FalsePositiveThreshold > 1 {
		return fmt.Errorf("false positive threshold must be between 0 and 1")
	}

	if config.MLConfidenceThreshold < 0 || config.MLConfidenceThreshold > 1 {
		return fmt.Errorf("ML confidence threshold must be between 0 and 1")
	}

	if config.PercentageThreshold < 0 {
		return fmt.Errorf("percentage threshold must be non-negative")
	}

	// Validate regex patterns
	for i, pattern := range config.IgnorePatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid ignore pattern %d: %w", i, err)
		}
	}

	for i, pattern := range config.TemporaryPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid temporary pattern %d: %w", i, err)
		}
	}

	for i, pattern := range config.VolatileAttributes {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid volatile attribute pattern %d: %w", i, err)
		}
	}

	return nil
}
