package siem

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// PatternMatcherImpl implements high-performance pattern matching for SIEM log analysis.
// It supports regex patterns, string matching, and field-specific pattern detection
// with optimized batch processing capabilities.
type PatternMatcherImpl struct {
	logger   *logging.ModuleLogger
	patterns map[string]*CompiledPattern
	mutex    sync.RWMutex

	// Performance optimization
	regexCache map[string]*regexp.Regexp

	// Statistics
	matchCount   int64
	processCount int64
	errorCount   int64
	statsLock    sync.RWMutex
}

// CompiledPattern represents a compiled pattern for efficient matching
type CompiledPattern struct {
	*DetectionPattern
	CompiledRegex  *regexp.Regexp
	FieldMatchers  map[string]*regexp.Regexp
	LastUsed       time.Time
	MatchCount     int64
	ProcessingTime time.Duration
}

// NewPatternMatcher creates a new pattern matcher with optimization features
func NewPatternMatcher() *PatternMatcherImpl {
	logger := logging.ForModule("siem.pattern_matcher").WithField("component", "matcher")

	return &PatternMatcherImpl{
		logger:     logger,
		patterns:   make(map[string]*CompiledPattern),
		regexCache: make(map[string]*regexp.Regexp),
	}
}

// AddPattern adds a new pattern for detection with compilation and validation
func (pm *PatternMatcherImpl) AddPattern(pattern *DetectionPattern) error {
	if pattern == nil {
		return fmt.Errorf("pattern cannot be nil")
	}

	if pattern.ID == "" {
		return fmt.Errorf("pattern ID cannot be empty")
	}

	if pattern.Pattern == "" {
		return fmt.Errorf("pattern string cannot be empty")
	}

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Compile the pattern based on type
	compiled := &CompiledPattern{
		DetectionPattern: pattern,
		FieldMatchers:    make(map[string]*regexp.Regexp),
		LastUsed:         time.Now(),
	}

	var err error
	switch pattern.PatternType {
	case PatternTypeRegex:
		// Compile main regex pattern
		flags := ""
		if !pattern.CaseSensitive {
			flags = "(?i)"
		}
		compiled.CompiledRegex, err = regexp.Compile(flags + pattern.Pattern)
		if err != nil {
			return fmt.Errorf("failed to compile regex pattern '%s': %w", pattern.Pattern, err)
		}

		// Compile field-specific patterns if specified
		for _, field := range pattern.Fields {
			compiled.FieldMatchers[field] = compiled.CompiledRegex
		}

	case PatternTypeContains, PatternTypeEquals, PatternTypeStartsWith, PatternTypeEndsWith:
		// For non-regex patterns, we'll handle them in matching logic
		// No pre-compilation needed

	default:
		return fmt.Errorf("unsupported pattern type: %s", pattern.PatternType)
	}

	// Store compiled pattern
	pm.patterns[pattern.ID] = compiled

	pm.logger.Info("Added detection pattern",
		"pattern_id", pattern.ID,
		"pattern_type", pattern.PatternType,
		"fields", pattern.Fields,
		"case_sensitive", pattern.CaseSensitive)

	return nil
}

// RemovePattern removes a pattern by ID
func (pm *PatternMatcherImpl) RemovePattern(patternID string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.patterns[patternID]; !exists {
		return fmt.Errorf("pattern '%s' not found", patternID)
	}

	delete(pm.patterns, patternID)

	pm.logger.Info("Removed detection pattern", "pattern_id", patternID)
	return nil
}

// MatchEntry checks if a single log entry matches any patterns
func (pm *PatternMatcherImpl) MatchEntry(entry interfaces.LogEntry) ([]*PatternMatch, error) {
	return pm.MatchBatch([]interfaces.LogEntry{entry})
}

// MatchBatch processes a batch of log entries efficiently for pattern matching
func (pm *PatternMatcherImpl) MatchBatch(entries []interfaces.LogEntry) ([]*PatternMatch, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	defer func() {
		pm.statsLock.Lock()
		pm.processCount += int64(len(entries))
		pm.statsLock.Unlock()
	}()

	pm.mutex.RLock()
	patterns := make([]*CompiledPattern, 0, len(pm.patterns))
	for _, pattern := range pm.patterns {
		if pattern.Enabled {
			patterns = append(patterns, pattern)
		}
	}
	pm.mutex.RUnlock()

	if len(patterns) == 0 {
		return nil, nil
	}

	// Process entries in parallel for better performance with large batches
	if len(entries) > 50 { // Parallel processing threshold
		return pm.processEntriesParallel(entries, patterns)
	} else {
		return pm.processEntriesSequential(entries, patterns)
	}
}

// processEntriesSequential processes entries sequentially (for small batches)
func (pm *PatternMatcherImpl) processEntriesSequential(entries []interfaces.LogEntry,
	patterns []*CompiledPattern) ([]*PatternMatch, error) {

	var matches []*PatternMatch

	for _, entry := range entries {
		entryMatches := pm.matchEntryAgainstPatterns(entry, patterns)
		matches = append(matches, entryMatches...)
	}

	return matches, nil
}

// processEntriesParallel processes entries in parallel (for large batches)
func (pm *PatternMatcherImpl) processEntriesParallel(entries []interfaces.LogEntry,
	patterns []*CompiledPattern) ([]*PatternMatch, error) {

	var matches []*PatternMatch
	var matchesMutex sync.Mutex
	var wg sync.WaitGroup

	// Process in chunks to balance parallelism and memory usage
	chunkSize := 25
	for i := 0; i < len(entries); i += chunkSize {
		end := i + chunkSize
		if end > len(entries) {
			end = len(entries)
		}

		chunk := entries[i:end]

		wg.Add(1)
		go func(chunk []interfaces.LogEntry) {
			defer wg.Done()

			var chunkMatches []*PatternMatch
			for _, entry := range chunk {
				entryMatches := pm.matchEntryAgainstPatterns(entry, patterns)
				chunkMatches = append(chunkMatches, entryMatches...)
			}

			matchesMutex.Lock()
			matches = append(matches, chunkMatches...)
			matchesMutex.Unlock()
		}(chunk)
	}

	wg.Wait()
	return matches, nil
}

// matchEntryAgainstPatterns matches a single entry against all patterns
func (pm *PatternMatcherImpl) matchEntryAgainstPatterns(entry interfaces.LogEntry,
	patterns []*CompiledPattern) []*PatternMatch {

	var matches []*PatternMatch

	for _, pattern := range patterns {
		// Check tenant isolation
		if pattern.TenantID != "" && pattern.TenantID != entry.TenantID {
			continue
		}

		entryMatches := pm.matchEntryAgainstPattern(entry, pattern)
		matches = append(matches, entryMatches...)

		// Update pattern statistics
		pattern.LastUsed = time.Now()
		if len(entryMatches) > 0 {
			pattern.MatchCount += int64(len(entryMatches))
		}
	}

	return matches
}

// matchEntryAgainstPattern matches a single entry against a single pattern
func (pm *PatternMatcherImpl) matchEntryAgainstPattern(entry interfaces.LogEntry,
	pattern *CompiledPattern) []*PatternMatch {

	var matches []*PatternMatch

	// Define fields to check
	fieldsToCheck := []struct {
		name  string
		value string
	}{
		{"message", entry.Message},
		{"level", entry.Level},
		{"service_name", entry.ServiceName},
		{"component", entry.Component},
		{"hostname", entry.Hostname},
		{"app_name", entry.AppName},
	}

	// Add custom fields
	for key, value := range entry.Fields {
		if valueStr, ok := value.(string); ok {
			fieldsToCheck = append(fieldsToCheck, struct {
				name  string
				value string
			}{key, valueStr})
		}
	}

	// If specific fields are configured, only check those
	if len(pattern.Fields) > 0 {
		targetFields := make(map[string]bool)
		for _, field := range pattern.Fields {
			targetFields[field] = true
		}

		var filteredFields []struct {
			name  string
			value string
		}

		for _, field := range fieldsToCheck {
			if targetFields[field.name] {
				filteredFields = append(filteredFields, field)
			}
		}
		fieldsToCheck = filteredFields
	}

	// Check each field against the pattern
	for _, field := range fieldsToCheck {
		if field.value == "" {
			continue
		}

		match := pm.checkFieldMatch(field.name, field.value, pattern)
		if match != nil {
			match.LogEntry = entry
			match.Timestamp = entry.Timestamp
			match.PatternID = pattern.ID
			matches = append(matches, match)
		}
	}

	return matches
}

// checkFieldMatch checks if a field value matches a pattern
func (pm *PatternMatcherImpl) checkFieldMatch(fieldName, fieldValue string,
	pattern *CompiledPattern) *PatternMatch {

	var matched bool
	var matchedText string
	confidence := 1.0 // Default confidence

	switch pattern.PatternType {
	case PatternTypeRegex:
		if pattern.CompiledRegex != nil {
			if pattern.CompiledRegex.MatchString(fieldValue) {
				matched = true
				matchedText = pattern.CompiledRegex.FindString(fieldValue)
				// Calculate confidence based on match length vs total length
				confidence = float64(len(matchedText)) / float64(len(fieldValue))
				if confidence > 1.0 {
					confidence = 1.0
				}
			}
		}

	case PatternTypeContains:
		searchText := pattern.Pattern
		searchTarget := fieldValue
		if !pattern.CaseSensitive {
			searchText = strings.ToLower(searchText)
			searchTarget = strings.ToLower(searchTarget)
		}
		if strings.Contains(searchTarget, searchText) {
			matched = true
			matchedText = pattern.Pattern
			confidence = float64(len(pattern.Pattern)) / float64(len(fieldValue))
		}

	case PatternTypeEquals:
		searchText := pattern.Pattern
		searchTarget := fieldValue
		if !pattern.CaseSensitive {
			searchText = strings.ToLower(searchText)
			searchTarget = strings.ToLower(searchTarget)
		}
		if searchTarget == searchText {
			matched = true
			matchedText = fieldValue
			confidence = 1.0
		}

	case PatternTypeStartsWith:
		searchText := pattern.Pattern
		searchTarget := fieldValue
		if !pattern.CaseSensitive {
			searchText = strings.ToLower(searchText)
			searchTarget = strings.ToLower(searchTarget)
		}
		if strings.HasPrefix(searchTarget, searchText) {
			matched = true
			matchedText = pattern.Pattern
			confidence = float64(len(pattern.Pattern)) / float64(len(fieldValue))
		}

	case PatternTypeEndsWith:
		searchText := pattern.Pattern
		searchTarget := fieldValue
		if !pattern.CaseSensitive {
			searchText = strings.ToLower(searchText)
			searchTarget = strings.ToLower(searchTarget)
		}
		if strings.HasSuffix(searchTarget, searchText) {
			matched = true
			matchedText = pattern.Pattern
			confidence = float64(len(pattern.Pattern)) / float64(len(fieldValue))
		}
	}

	if !matched {
		return nil
	}

	return &PatternMatch{
		PatternID:   pattern.ID,
		MatchedText: matchedText,
		Field:       fieldName,
		Confidence:  confidence,
		Metadata: map[string]interface{}{
			"pattern_type": pattern.PatternType,
			"pattern_name": pattern.Name,
			"priority":     pattern.Priority,
		},
	}
}

// GetStatistics returns pattern matching statistics
func (pm *PatternMatcherImpl) GetStatistics() map[string]interface{} {
	pm.statsLock.RLock()
	defer pm.statsLock.RUnlock()

	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_patterns":  len(pm.patterns),
		"total_matches":   pm.matchCount,
		"total_processed": pm.processCount,
		"total_errors":    pm.errorCount,
		"pattern_details": make(map[string]interface{}),
	}

	// Add per-pattern statistics
	patternDetails := make(map[string]interface{})
	for id, pattern := range pm.patterns {
		patternDetails[id] = map[string]interface{}{
			"name":            pattern.Name,
			"type":            pattern.PatternType,
			"match_count":     pattern.MatchCount,
			"last_used":       pattern.LastUsed,
			"processing_time": pattern.ProcessingTime,
			"enabled":         pattern.Enabled,
		}
	}
	stats["pattern_details"] = patternDetails

	return stats
}

// ClearPatterns removes all patterns (useful for testing)
func (pm *PatternMatcherImpl) ClearPatterns() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.patterns = make(map[string]*CompiledPattern)
	pm.logger.Info("Cleared all detection patterns")
}
