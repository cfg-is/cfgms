// Package drift provides DNA drift detection implementation.

package drift

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

// detector implements the Detector interface for DNA drift detection.
type detector struct {
	logger     logging.Logger
	config     *DetectorConfig
	rules      []*DriftRule
	filter     Filter
	ruleEngine RuleEngine
	stats      *DetectorStats
}

// DetectorConfig defines configuration for drift detection.
type DetectorConfig struct {
	// Detection sensitivity
	DefaultSeverity     DriftSeverity `json:"default_severity" yaml:"default_severity"`
	ConfidenceThreshold float64       `json:"confidence_threshold" yaml:"confidence_threshold"` // 0.0-1.0

	// Change categorization
	CriticalAttributes []string `json:"critical_attributes" yaml:"critical_attributes"`
	SecurityAttributes []string `json:"security_attributes" yaml:"security_attributes"`
	IgnoredAttributes  []string `json:"ignored_attributes" yaml:"ignored_attributes"`

	// Thresholds
	MaxChangesPerEvent int     `json:"max_changes_per_event" yaml:"max_changes_per_event"`
	NumericThreshold   float64 `json:"numeric_threshold" yaml:"numeric_threshold"`

	// Performance
	MaxComparisonTime time.Duration `json:"max_comparison_time" yaml:"max_comparison_time"`
	EnableBatchMode   bool          `json:"enable_batch_mode" yaml:"enable_batch_mode"`
	BatchSize         int           `json:"batch_size" yaml:"batch_size"`

	// Machine learning
	EnableMLDetection bool    `json:"enable_ml_detection" yaml:"enable_ml_detection"`
	AnomalyThreshold  float64 `json:"anomaly_threshold" yaml:"anomaly_threshold"`
}

// NewDetector creates a new drift detector with the specified configuration.
func NewDetector(config *DetectorConfig, logger logging.Logger) (Detector, error) {
	if config == nil {
		config = DefaultDetectorConfig()
	}

	if err := validateDetectorConfig(config); err != nil {
		return nil, fmt.Errorf("invalid detector config: %w", err)
	}

	d := &detector{
		logger: logger,
		config: config,
		rules:  make([]*DriftRule, 0),
		stats: &DetectorStats{
			RulesTriggered: make(map[string]int64),
		},
	}

	// Initialize filter
	filterConfig := &FilterConfig{
		EnableSmartFiltering:    true,
		FalsePositiveThreshold:  config.ConfidenceThreshold,
		EnableTemporalFiltering: true,
		TemporalWindow:          24 * time.Hour,
		MinChangeInterval:       5 * time.Minute,
		IgnorePercentageChanges: true,
		PercentageThreshold:     5.0,
		IgnoreTemporaryFiles:    true,
		IgnoreLogRotation:       true,
		IgnorePatterns:          config.IgnoredAttributes,
		VolatileAttributes:      config.IgnoredAttributes,
		MaxFilterTime:           10 * time.Second,
	}
	filter, err := NewFilter(filterConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize filter: %w", err)
	}
	d.filter = filter

	// Initialize rule engine
	ruleEngineConfig := &RuleEngineConfig{
		MaxRuleEvaluationTime:  30 * time.Second,
		EnableParallelRuleEval: true,
		MaxConcurrentRules:     10,
		MaxRulesPerEngine:      100,
		EnableRuleValidation:   true,
		EnableDetailedStats:    true,
	}
	ruleEngine, err := NewRuleEngine(ruleEngineConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize rule engine: %w", err)
	}
	d.ruleEngine = ruleEngine

	if logger != nil {
		logger.Info("Drift detector initialized",
			"confidence_threshold", config.ConfidenceThreshold,
			"critical_attributes", len(config.CriticalAttributes),
			"ml_enabled", config.EnableMLDetection)
	}

	return d, nil
}

// DetectDrift compares two DNA states and returns detected drift events.
func (d *detector) DetectDrift(ctx context.Context, previous, current *commonpb.DNA) ([]*DriftEvent, error) {
	startTime := time.Now()

	// Validate inputs
	if previous == nil || current == nil {
		return nil, fmt.Errorf("both previous and current DNA must be provided")
	}

	if previous.Id != current.Id {
		return nil, fmt.Errorf("DNA IDs must match for comparison")
	}

	// Check for timeout
	if d.config.MaxComparisonTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.config.MaxComparisonTime)
		defer cancel()
	}

	if d.logger != nil {
		d.logger.Debug("Starting drift detection",
			"device_id", previous.Id,
			"previous_attributes", len(previous.Attributes),
			"current_attributes", len(current.Attributes))
	}

	// Perform diff analysis
	changes, err := d.analyzeDNAChanges(ctx, previous, current)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze DNA changes: %w", err)
	}

	// Generate drift events from changes
	events, err := d.generateDriftEvents(ctx, previous, current, changes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate drift events: %w", err)
	}

	// Apply filtering to reduce false positives
	filteredEvents, err := d.filter.FilterEvents(ctx, events)
	if err != nil {
		if d.logger != nil {
			d.logger.Error("Failed to filter drift events", "error", err)
		}
		filteredEvents = events // Use unfiltered events as fallback
	}

	// Apply rules to events
	finalEvents := make([]*DriftEvent, 0, len(filteredEvents))
	for _, event := range filteredEvents {
		result, err := d.ruleEngine.EvaluateRules(ctx, event)
		if err != nil {
			if d.logger != nil {
				d.logger.Error("Failed to evaluate rules for event", "error", err, "event_id", event.ID)
			}
			finalEvents = append(finalEvents, event)
			continue
		}

		if result.Matched {
			// Update event based on rule result
			event.RulesTriggered = append(event.RulesTriggered, result.RuleID)
			event.Confidence = result.Confidence
			finalEvents = append(finalEvents, event)

			// Update rule statistics
			d.stats.RulesTriggered[result.RuleID]++
		}
	}

	// Update statistics
	d.updateStats(startTime, changes, finalEvents)

	if d.logger != nil {
		d.logger.Debug("Drift detection completed",
			"device_id", previous.Id,
			"changes_detected", len(changes),
			"events_generated", len(events),
			"events_after_filter", len(filteredEvents),
			"final_events", len(finalEvents),
			"detection_time", time.Since(startTime))
	}

	return finalEvents, nil
}

// DetectDriftBatch processes multiple DNA comparisons efficiently.
func (d *detector) DetectDriftBatch(ctx context.Context, comparisons []*DNAComparison) ([]*DriftEvent, error) {
	if !d.config.EnableBatchMode {
		// Process individually
		var allEvents []*DriftEvent
		for _, comp := range comparisons {
			events, err := d.DetectDrift(ctx, comp.Previous, comp.Current)
			if err != nil {
				if d.logger != nil {
					d.logger.Error("Failed to detect drift in batch", "error", err, "device_id", comp.DeviceID)
				}
				continue
			}
			allEvents = append(allEvents, events...)
		}
		return allEvents, nil
	}

	// Process in batches
	batchSize := d.config.BatchSize
	if batchSize <= 0 {
		batchSize = 10
	}

	var allEvents []*DriftEvent
	for i := 0; i < len(comparisons); i += batchSize {
		end := i + batchSize
		if end > len(comparisons) {
			end = len(comparisons)
		}

		batch := comparisons[i:end]
		for _, comp := range batch {
			events, err := d.DetectDrift(ctx, comp.Previous, comp.Current)
			if err != nil {
				if d.logger != nil {
					d.logger.Error("Failed to detect drift in batch", "error", err, "device_id", comp.DeviceID)
				}
				continue
			}
			allEvents = append(allEvents, events...)
		}

		// Check for context cancellation
		select {
		case <-ctx.Done():
			return allEvents, ctx.Err()
		default:
		}
	}

	return allEvents, nil
}

// ValidateRules validates drift detection rules configuration.
func (d *detector) ValidateRules(rules []*DriftRule) error {
	for _, rule := range rules {
		if err := d.validateRule(rule); err != nil {
			return fmt.Errorf("invalid rule %s: %w", rule.ID, err)
		}
	}
	return nil
}

// UpdateRules updates the active drift detection rules.
func (d *detector) UpdateRules(rules []*DriftRule) error {
	if err := d.ValidateRules(rules); err != nil {
		return err
	}

	d.rules = make([]*DriftRule, len(rules))
	copy(d.rules, rules)

	// Update rule engine
	return d.ruleEngine.AddRule(nil) // Bulk update would be implemented
}

// GetStats returns drift detection statistics.
func (d *detector) GetStats() *DetectorStats {
	// Return a copy to avoid race conditions
	stats := *d.stats
	stats.RulesTriggered = make(map[string]int64)
	for k, v := range d.stats.RulesTriggered {
		stats.RulesTriggered[k] = v
	}
	return &stats
}

// Close releases detector resources.
func (d *detector) Close() error {
	if d.logger != nil {
		d.logger.Info("Closing drift detector")
	}

	var errs []error

	if d.filter != nil {
		if err := d.filter.(interface{ Close() error }).Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close filter: %w", err))
		}
	}

	if d.ruleEngine != nil {
		if err := d.ruleEngine.(interface{ Close() error }).Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close rule engine: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing detector: %v", errs)
	}

	return nil
}

// analyzeDNAChanges performs detailed comparison of DNA states.
func (d *detector) analyzeDNAChanges(ctx context.Context, previous, current *commonpb.DNA) ([]*AttributeChange, error) {
	var changes []*AttributeChange

	// Get all unique attributes
	allAttributes := make(map[string]bool)
	for attr := range previous.Attributes {
		allAttributes[attr] = true
	}
	for attr := range current.Attributes {
		allAttributes[attr] = true
	}

	// Analyze each attribute
	for attribute := range allAttributes {
		select {
		case <-ctx.Done():
			return changes, ctx.Err()
		default:
		}

		// Skip ignored attributes
		if d.isIgnoredAttribute(attribute) {
			continue
		}

		prevValue, prevExists := previous.Attributes[attribute]
		currValue, currExists := current.Attributes[attribute]

		var change *AttributeChange

		switch {
		case !prevExists && currExists:
			// New attribute added
			change = &AttributeChange{
				Attribute:     attribute,
				PreviousValue: "",
				CurrentValue:  currValue,
				ChangeType:    ChangeTypeAdded,
				Severity:      d.categorizeSeverity(attribute, "", currValue),
				Category:      d.categorizeAttribute(attribute),
				Impact:        d.assessImpact(attribute, "", currValue, ChangeTypeAdded),
			}

		case prevExists && !currExists:
			// Attribute removed
			change = &AttributeChange{
				Attribute:     attribute,
				PreviousValue: prevValue,
				CurrentValue:  "",
				ChangeType:    ChangeTypeRemoved,
				Severity:      d.categorizeSeverity(attribute, prevValue, ""),
				Category:      d.categorizeAttribute(attribute),
				Impact:        d.assessImpact(attribute, prevValue, "", ChangeTypeRemoved),
			}

		case prevExists && currExists && prevValue != currValue:
			// Attribute modified
			change = &AttributeChange{
				Attribute:     attribute,
				PreviousValue: prevValue,
				CurrentValue:  currValue,
				ChangeType:    ChangeTypeModified,
				Severity:      d.categorizeSeverity(attribute, prevValue, currValue),
				Category:      d.categorizeAttribute(attribute),
				Impact:        d.assessImpact(attribute, prevValue, currValue, ChangeTypeModified),
			}
		}

		if change != nil {
			changes = append(changes, change)
		}
	}

	// Sort changes by severity and attribute name
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Severity != changes[j].Severity {
			return d.severityWeight(changes[i].Severity) > d.severityWeight(changes[j].Severity)
		}
		return changes[i].Attribute < changes[j].Attribute
	})

	return changes, nil
}

// generateDriftEvents creates drift events from detected changes.
func (d *detector) generateDriftEvents(ctx context.Context, previous, current *commonpb.DNA, changes []*AttributeChange) ([]*DriftEvent, error) {
	if len(changes) == 0 {
		return nil, nil
	}

	// Group changes by category and severity for logical event creation
	eventGroups := d.groupChanges(changes)

	var events []*DriftEvent

	for category, categoryChanges := range eventGroups {
		for severity, severityChanges := range categoryChanges {
			event := &DriftEvent{
				ID:            d.generateEventID(current.Id, category, severity),
				DeviceID:      current.Id,
				Timestamp:     time.Now(),
				Severity:      severity,
				Category:      DriftCategory(category),
				Changes:       severityChanges,
				ChangeCount:   len(severityChanges),
				PreviousDNA:   previous,
				CurrentDNA:    current,
				DetectionTime: time.Since(time.Now()), // Will be updated by caller
				Confidence:    d.calculateConfidence(severityChanges),
				RiskScore:     d.calculateRiskScore(severityChanges),
				Impact:        d.calculateImpact(severityChanges),
				Status:        StatusNew,
			}

			// Generate human-readable title and description
			event.Title, event.Description = d.generateEventDescription(event)

			events = append(events, event)
		}
	}

	return events, nil
}

// Helper methods

func (d *detector) isIgnoredAttribute(attribute string) bool {
	for _, ignored := range d.config.IgnoredAttributes {
		if matched, _ := regexp.MatchString(ignored, attribute); matched {
			return true
		}
	}
	return false
}

func (d *detector) categorizeSeverity(attribute, prevValue, currValue string) DriftSeverity {
	// Check if it's a critical attribute
	for _, critical := range d.config.CriticalAttributes {
		if matched, _ := regexp.MatchString(critical, attribute); matched {
			return SeverityCritical
		}
	}

	// Check if it's a security attribute
	for _, security := range d.config.SecurityAttributes {
		if matched, _ := regexp.MatchString(security, attribute); matched {
			return SeverityCritical
		}
	}

	// Special cases for known critical changes
	if d.isCriticalChange(attribute, prevValue, currValue) {
		return SeverityCritical
	}

	// Default severity based on attribute category
	category := d.categorizeAttribute(attribute)
	switch category {
	case "security":
		return SeverityCritical
	case "hardware":
		return SeverityWarning
	case "network":
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

func (d *detector) categorizeAttribute(attribute string) string {
	attributeLower := strings.ToLower(attribute)

	// Security-related attributes
	securityKeywords := []string{"password", "key", "cert", "auth", "security", "firewall", "permission", "user", "group"}
	for _, keyword := range securityKeywords {
		if strings.Contains(attributeLower, keyword) {
			return "security"
		}
	}

	// Hardware-related attributes
	hardwareKeywords := []string{"cpu", "memory", "disk", "hardware", "arch", "motherboard", "bios"}
	for _, keyword := range hardwareKeywords {
		if strings.Contains(attributeLower, keyword) {
			return "hardware"
		}
	}

	// Network-related attributes
	networkKeywords := []string{"ip", "mac", "network", "interface", "route", "dns", "hostname"}
	for _, keyword := range networkKeywords {
		if strings.Contains(attributeLower, keyword) {
			return "network"
		}
	}

	// Software-related attributes
	softwareKeywords := []string{"software", "package", "service", "process", "os", "kernel", "version"}
	for _, keyword := range softwareKeywords {
		if strings.Contains(attributeLower, keyword) {
			return "software"
		}
	}

	return "configuration"
}

func (d *detector) assessImpact(attribute, prevValue, currValue string, changeType ChangeType) string {
	category := d.categorizeAttribute(attribute)

	switch category {
	case "security":
		switch changeType {
		case ChangeTypeAdded:
			return fmt.Sprintf("New security configuration added: %s", attribute)
		case ChangeTypeRemoved:
			return fmt.Sprintf("Security configuration removed: %s", attribute)
		case ChangeTypeModified:
			return fmt.Sprintf("Security configuration changed: %s", attribute)
		}
	case "hardware":
		switch changeType {
		case ChangeTypeAdded:
			return fmt.Sprintf("New hardware detected: %s", attribute)
		case ChangeTypeRemoved:
			return fmt.Sprintf("Hardware no longer detected: %s", attribute)
		case ChangeTypeModified:
			return fmt.Sprintf("Hardware configuration changed: %s", attribute)
		}
	case "network":
		switch changeType {
		case ChangeTypeAdded:
			return fmt.Sprintf("New network configuration: %s", attribute)
		case ChangeTypeRemoved:
			return fmt.Sprintf("Network configuration removed: %s", attribute)
		case ChangeTypeModified:
			return fmt.Sprintf("Network configuration changed: %s", attribute)
		}
	default:
		switch changeType {
		case ChangeTypeAdded:
			return fmt.Sprintf("New attribute added: %s", attribute)
		case ChangeTypeRemoved:
			return fmt.Sprintf("Attribute removed: %s", attribute)
		case ChangeTypeModified:
			return fmt.Sprintf("Configuration changed: %s", attribute)
		}
	}

	return "Configuration drift detected"
}

func (d *detector) isCriticalChange(attribute, prevValue, currValue string) bool {
	// Define patterns for critical changes
	criticalPatterns := map[string][]string{
		"firewall":   {"enabled", "disabled", "active", "inactive"},
		"security":   {"on", "off", "enabled", "disabled"},
		"admin":      {"true", "false", "1", "0"},
		"root":       {"enabled", "disabled", "locked", "unlocked"},
		"encryption": {"enabled", "disabled", "on", "off"},
	}

	attributeLower := strings.ToLower(attribute)
	prevLower := strings.ToLower(prevValue)
	currLower := strings.ToLower(currValue)

	for pattern, values := range criticalPatterns {
		if strings.Contains(attributeLower, pattern) {
			for _, value := range values {
				if (prevLower == value || currLower == value) && prevLower != currLower {
					return true
				}
			}
		}
	}

	return false
}

func (d *detector) groupChanges(changes []*AttributeChange) map[string]map[DriftSeverity][]*AttributeChange {
	groups := make(map[string]map[DriftSeverity][]*AttributeChange)

	for _, change := range changes {
		category := change.Category
		severity := change.Severity

		if groups[category] == nil {
			groups[category] = make(map[DriftSeverity][]*AttributeChange)
		}

		groups[category][severity] = append(groups[category][severity], change)
	}

	return groups
}

func (d *detector) generateEventID(deviceID, category string, severity DriftSeverity) string {
	timestamp := time.Now().Unix()
	data := fmt.Sprintf("%s-%s-%s-%d", deviceID, category, severity, timestamp)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("drift-%x", hash[:8])
}

func (d *detector) calculateConfidence(changes []*AttributeChange) float64 {
	if len(changes) == 0 {
		return 0.0
	}

	// Base confidence on the number and severity of changes
	confidence := 0.5 // Base confidence

	criticalCount := 0
	warningCount := 0

	for _, change := range changes {
		switch change.Severity {
		case SeverityCritical:
			criticalCount++
		case SeverityWarning:
			warningCount++
		}
	}

	// Increase confidence based on critical changes
	confidence += float64(criticalCount) * 0.3
	confidence += float64(warningCount) * 0.1

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (d *detector) calculateRiskScore(changes []*AttributeChange) float64 {
	if len(changes) == 0 {
		return 0.0
	}

	riskScore := 0.0

	for _, change := range changes {
		switch change.Severity {
		case SeverityCritical:
			riskScore += 0.8
		case SeverityWarning:
			riskScore += 0.4
		case SeverityInfo:
			riskScore += 0.1
		}

		// Additional risk for security-related changes
		if change.Category == "security" {
			riskScore += 0.3
		}
	}

	// Normalize to 0-1 range
	maxPossibleRisk := float64(len(changes)) * 1.1
	if maxPossibleRisk > 0 {
		riskScore = riskScore / maxPossibleRisk
	}

	if riskScore > 1.0 {
		riskScore = 1.0
	}

	return riskScore
}

func (d *detector) calculateImpact(changes []*AttributeChange) DriftImpact {
	if len(changes) == 0 {
		return ImpactLow
	}

	criticalCount := 0
	warningCount := 0

	for _, change := range changes {
		switch change.Severity {
		case SeverityCritical:
			criticalCount++
		case SeverityWarning:
			warningCount++
		}
	}

	if criticalCount > 0 {
		return ImpactHigh
	}

	if warningCount >= 3 {
		return ImpactMedium
	}

	if warningCount > 0 || len(changes) >= 5 {
		return ImpactMedium
	}

	return ImpactLow
}

func (d *detector) generateEventDescription(event *DriftEvent) (string, string) {
	changeCount := len(event.Changes)
	category := string(event.Category)
	severity := string(event.Severity)

	// Generate title
	severityTitle := severity
	if severity != "" {
		runes := []rune(severity)
		runes[0] = unicode.ToUpper(runes[0])
		severityTitle = string(runes)
	}
	title := fmt.Sprintf("%s %s drift detected (%d changes)",
		severityTitle, category, changeCount)

	// Generate description
	var descriptionParts []string

	// Summary
	descriptionParts = append(descriptionParts,
		fmt.Sprintf("Detected %d %s configuration changes on device %s",
			changeCount, category, event.DeviceID))

	// List key changes (up to 5)
	maxListed := 5
	if changeCount > 0 {
		descriptionParts = append(descriptionParts, "\nKey changes:")
		for i, change := range event.Changes {
			if i >= maxListed {
				descriptionParts = append(descriptionParts,
					fmt.Sprintf("... and %d more changes", changeCount-maxListed))
				break
			}

			changeDesc := fmt.Sprintf("- %s: %s → %s",
				change.Attribute, change.PreviousValue, change.CurrentValue)
			if len(changeDesc) > 100 {
				changeDesc = changeDesc[:97] + "..."
			}
			descriptionParts = append(descriptionParts, changeDesc)
		}
	}

	// Risk assessment
	descriptionParts = append(descriptionParts,
		fmt.Sprintf("\nRisk Score: %.2f | Confidence: %.2f | Impact: %s",
			event.RiskScore, event.Confidence, event.Impact))

	description := strings.Join(descriptionParts, "\n")

	return title, description
}

func (d *detector) severityWeight(severity DriftSeverity) int {
	switch severity {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func (d *detector) validateRule(rule *DriftRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}

	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}

	if len(rule.Conditions) == 0 {
		return fmt.Errorf("at least one condition is required")
	}

	for i, condition := range rule.Conditions {
		if condition.Type == "" {
			return fmt.Errorf("condition %d: type is required", i)
		}

		if condition.Operator == "" {
			return fmt.Errorf("condition %d: operator is required", i)
		}
	}

	return nil
}

func (d *detector) updateStats(startTime time.Time, changes []*AttributeChange, events []*DriftEvent) {
	d.stats.TotalComparisons++
	d.stats.AverageDetectionTime = time.Since(startTime)

	if len(events) > 0 {
		d.stats.DriftEventsDetected += int64(len(events))
		now := time.Now()
		d.stats.LastDetection = &now

		for _, event := range events {
			switch event.Severity {
			case SeverityCritical:
				d.stats.CriticalEvents++
			case SeverityWarning:
				d.stats.WarningEvents++
			case SeverityInfo:
				d.stats.InfoEvents++
			}
		}
	}
}

// DefaultDetectorConfig returns a default configuration for drift detection.
func DefaultDetectorConfig() *DetectorConfig {
	return &DetectorConfig{
		DefaultSeverity:     SeverityInfo,
		ConfidenceThreshold: 0.5,
		CriticalAttributes: []string{
			".*firewall.*",
			".*security.*",
			".*admin.*",
			".*root.*",
			".*password.*",
			".*key.*",
			".*cert.*",
		},
		SecurityAttributes: []string{
			".*auth.*",
			".*permission.*",
			".*user.*",
			".*group.*",
			".*encryption.*",
		},
		IgnoredAttributes: []string{
			"timestamp",
			"last_updated",
			"uptime",
			"load_average",
			".*_temp$",
			".*_usage$",
		},
		MaxChangesPerEvent: 50,
		NumericThreshold:   10.0,
		MaxComparisonTime:  30 * time.Second,
		EnableBatchMode:    true,
		BatchSize:          10,
		EnableMLDetection:  false,
		AnomalyThreshold:   0.8,
	}
}

func validateDetectorConfig(config *DetectorConfig) error {
	if config.ConfidenceThreshold < 0 || config.ConfidenceThreshold > 1 {
		return fmt.Errorf("confidence threshold must be between 0 and 1")
	}

	if config.AnomalyThreshold < 0 || config.AnomalyThreshold > 1 {
		return fmt.Errorf("anomaly threshold must be between 0 and 1")
	}

	if config.MaxChangesPerEvent <= 0 {
		return fmt.Errorf("max changes per event must be positive")
	}

	if config.BatchSize <= 0 {
		config.BatchSize = 10
	}

	return nil
}
