// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package diff implements impact analysis for configuration changes
package diff

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// DefaultImpactAnalyzer implements the ImpactAnalyzer interface
// with comprehensive change impact assessment capabilities
type DefaultImpactAnalyzer struct {
	// impactRules define rules for determining impact levels
	impactRules []ImpactRule

	// categoryRules define rules for categorizing changes
	categoryRules []CategoryRule

	// riskRules define rules for risk assessment
	riskRules []RiskRule
}

// ImpactRule defines how to assess the impact of a configuration change
type ImpactRule struct {
	// Name is the rule name
	Name string

	// PathPattern is a regex pattern to match configuration paths
	PathPattern *regexp.Regexp

	// ValuePattern is a regex pattern to match values (optional)
	ValuePattern *regexp.Regexp

	// ChangeType specifies which change types this rule applies to
	ChangeType []DiffType

	// Impact is the impact level assigned by this rule
	Impact ImpactLevel

	// Category is the change category assigned by this rule
	Category ChangeCategory

	// RequiresRestart indicates if changes require service restart
	RequiresRestart bool

	// RequiresDowntime indicates if changes require downtime
	RequiresDowntime bool

	// BreakingChange indicates if this is a breaking change
	BreakingChange bool

	// SecurityImplications describes security implications
	SecurityImplications []string

	// Description describes why this rule applies
	Description string
}

// CategoryRule defines how to categorize configuration changes
type CategoryRule struct {
	Name         string
	PathPattern  *regexp.Regexp
	ValuePattern *regexp.Regexp
	Category     ChangeCategory
	Description  string
}

// RiskRule defines how to assess risk for configuration changes
type RiskRule struct {
	Name        string
	PathPattern *regexp.Regexp
	Condition   func(*DiffEntry, *ConfigStructure) bool
	RiskFactor  RiskFactor
	Description string
}

// NewDefaultImpactAnalyzer creates a new DefaultImpactAnalyzer with default rules
func NewDefaultImpactAnalyzer() *DefaultImpactAnalyzer {
	analyzer := &DefaultImpactAnalyzer{
		impactRules:   initializeDefaultImpactRules(),
		categoryRules: initializeDefaultCategoryRules(),
		riskRules:     initializeDefaultRiskRules(),
	}
	return analyzer
}

// AnalyzeChange analyzes the impact of a single change
func (ia *DefaultImpactAnalyzer) AnalyzeChange(ctx context.Context, entry *DiffEntry, structure *ConfigStructure) (*ChangeImpact, error) {
	impact := &ChangeImpact{
		Level:                ImpactLevelLow,
		Category:             ChangeCategoryValue,
		Description:          "Configuration value change",
		AffectedSystems:      []string{},
		RequiresRestart:      false,
		RequiresDowntime:     false,
		BreakingChange:       false,
		SecurityImplications: []string{},
		RollbackComplexity:   ImpactLevelLow,
	}

	// Apply impact rules
	for _, rule := range ia.impactRules {
		if ia.ruleMatches(rule, entry) {
			impact.Level = rule.Impact
			impact.Category = rule.Category
			impact.RequiresRestart = rule.RequiresRestart
			impact.RequiresDowntime = rule.RequiresDowntime
			impact.BreakingChange = rule.BreakingChange
			impact.SecurityImplications = append(impact.SecurityImplications, rule.SecurityImplications...)
			impact.Description = rule.Description
			break // Use first matching rule
		}
	}

	// Enhance impact with structural analysis
	if structure != nil {
		ia.enhanceWithStructuralAnalysis(impact, entry, structure)
	}

	// Determine affected systems
	impact.AffectedSystems = ia.determineAffectedSystems(entry, structure)

	// Assess rollback complexity
	impact.RollbackComplexity = ia.assessRollbackComplexity(entry, impact)

	return impact, nil
}

// AnalyzeChanges analyzes the impact of multiple changes
func (ia *DefaultImpactAnalyzer) AnalyzeChanges(ctx context.Context, entries []DiffEntry, structure *ConfigStructure) ([]ChangeImpact, error) {
	var impacts []ChangeImpact

	for _, entry := range entries {
		impact, err := ia.AnalyzeChange(ctx, &entry, structure)
		if err != nil {
			return nil, fmt.Errorf("failed to analyze change at %s: %w", entry.Path, err)
		}
		impacts = append(impacts, *impact)
	}

	// Analyze interaction effects between changes
	ia.analyzeInteractionEffects(impacts, entries)

	return impacts, nil
}

// AssessRisk assesses the overall risk of a set of changes
func (ia *DefaultImpactAnalyzer) AssessRisk(ctx context.Context, result *ComparisonResult) (*RiskAssessment, error) {
	assessment := &RiskAssessment{
		OverallRisk:            ImpactLevelLow,
		RiskFactors:            []RiskFactor{},
		Recommendations:        []string{},
		RequiredApprovals:      []ApprovalRequirement{},
		TestingRecommendations: []string{},
	}

	// Analyze individual change impacts
	var allImpacts []ChangeImpact
	for _, entry := range result.Entries {
		allImpacts = append(allImpacts, entry.Impact)
	}

	// Determine overall risk level
	assessment.OverallRisk = ia.calculateOverallRisk(allImpacts)

	// Identify risk factors
	assessment.RiskFactors = ia.identifyRiskFactors(result)

	// Generate recommendations
	assessment.Recommendations = ia.generateRecommendations(result, assessment.RiskFactors)

	// Determine required approvals
	assessment.RequiredApprovals = ia.determineRequiredApprovals(result, assessment.OverallRisk)

	// Generate testing recommendations
	assessment.TestingRecommendations = ia.generateTestingRecommendations(result, allImpacts)

	return assessment, nil
}

// ruleMatches checks if an impact rule matches a diff entry
func (ia *DefaultImpactAnalyzer) ruleMatches(rule ImpactRule, entry *DiffEntry) bool {
	// Check change type
	if len(rule.ChangeType) > 0 {
		found := false
		for _, ct := range rule.ChangeType {
			if entry.Type == ct {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check path pattern
	if rule.PathPattern != nil && !rule.PathPattern.MatchString(entry.Path) {
		return false
	}

	// Check value pattern
	if rule.ValuePattern != nil {
		var valueStr string
		if entry.NewValue != nil {
			valueStr = fmt.Sprintf("%v", entry.NewValue)
		} else if entry.OldValue != nil {
			valueStr = fmt.Sprintf("%v", entry.OldValue)
		}

		if !rule.ValuePattern.MatchString(valueStr) {
			return false
		}
	}

	return true
}

// enhanceWithStructuralAnalysis enhances impact assessment with structural analysis
func (ia *DefaultImpactAnalyzer) enhanceWithStructuralAnalysis(impact *ChangeImpact, entry *DiffEntry, structure *ConfigStructure) {
	// Find the section this change belongs to
	var relevantSection *ConfigSection
	for _, section := range structure.Sections {
		if ia.pathBelongsToSection(entry.Path, section) {
			relevantSection = &section
			break
		}
	}

	if relevantSection != nil {
		// Enhance impact based on section type
		switch relevantSection.Type {
		case "security", "authentication", "authorization":
			if impact.Level < ImpactLevelHigh {
				impact.Level = ImpactLevelHigh
			}
			impact.Category = ChangeCategorySecurity
			impact.SecurityImplications = append(impact.SecurityImplications, "Security configuration change")

		case "database", "connection":
			if impact.Level < ImpactLevelMedium {
				impact.Level = ImpactLevelMedium
			}
			impact.RequiresRestart = true

		case "network", "networking":
			if impact.Level < ImpactLevelMedium {
				impact.Level = ImpactLevelMedium
			}
			impact.Category = ChangeCategoryNetwork
			impact.RequiresRestart = true

		case "server", "service":
			impact.RequiresRestart = true
		}
	}

	// Check for dependencies
	for _, dep := range structure.Dependencies {
		if dep.From == entry.Path || dep.To == entry.Path {
			// This change affects dependencies
			if impact.Level < ImpactLevelMedium {
				impact.Level = ImpactLevelMedium
			}
			impact.Description += " (affects dependencies)"
		}
	}
}

// pathBelongsToSection checks if a path belongs to a configuration section
func (ia *DefaultImpactAnalyzer) pathBelongsToSection(path string, section ConfigSection) bool {
	return strings.HasPrefix(path, section.Path)
}

// determineAffectedSystems determines which systems might be affected by a change
func (ia *DefaultImpactAnalyzer) determineAffectedSystems(entry *DiffEntry, structure *ConfigStructure) []string {
	var systems []string

	pathLower := strings.ToLower(entry.Path)

	// Determine affected systems based on path patterns
	if strings.Contains(pathLower, "database") || strings.Contains(pathLower, "db") {
		systems = append(systems, "database")
	}
	if strings.Contains(pathLower, "cache") || strings.Contains(pathLower, "redis") {
		systems = append(systems, "cache")
	}
	if strings.Contains(pathLower, "auth") || strings.Contains(pathLower, "security") {
		systems = append(systems, "authentication", "authorization")
	}
	if strings.Contains(pathLower, "network") || strings.Contains(pathLower, "port") {
		systems = append(systems, "networking")
	}
	if strings.Contains(pathLower, "log") || strings.Contains(pathLower, "monitor") {
		systems = append(systems, "logging", "monitoring")
	}

	return systems
}

// assessRollbackComplexity assesses how difficult it would be to rollback a change
func (ia *DefaultImpactAnalyzer) assessRollbackComplexity(entry *DiffEntry, impact *ChangeImpact) ImpactLevel {
	// Base complexity on change type
	switch entry.Type {
	case DiffTypeAdd:
		return ImpactLevelLow // Easy to remove
	case DiffTypeDelete:
		return ImpactLevelHigh // Hard to restore without backup
	case DiffTypeModify:
		return ImpactLevelMedium // Need to know previous value
	case DiffTypeMove:
		return ImpactLevelMedium // Need to reverse the move
	}

	// Increase complexity for breaking changes
	if impact.BreakingChange {
		return ImpactLevelHigh
	}

	// Increase complexity for security changes
	if impact.Category == ChangeCategorySecurity {
		return ImpactLevelHigh
	}

	return ImpactLevelLow
}

// analyzeInteractionEffects analyzes how multiple changes might interact
func (ia *DefaultImpactAnalyzer) analyzeInteractionEffects(impacts []ChangeImpact, entries []DiffEntry) {
	// Look for potentially problematic combinations
	hasSecurityChanges := false
	hasNetworkChanges := false
	hasBreakingChanges := false

	for _, impact := range impacts {
		if impact.Category == ChangeCategorySecurity {
			hasSecurityChanges = true
		}
		if impact.Category == ChangeCategoryNetwork {
			hasNetworkChanges = true
		}
		if impact.BreakingChange {
			hasBreakingChanges = true
		}
	}

	// Enhance impacts based on combinations
	for i := range impacts {
		if hasSecurityChanges && hasNetworkChanges {
			impacts[i].SecurityImplications = append(impacts[i].SecurityImplications,
				"Combined security and network changes increase attack surface")
		}

		if hasBreakingChanges && len(impacts) > 1 {
			impacts[i].Description += " (part of multiple breaking changes)"
		}
	}
}

// calculateOverallRisk calculates the overall risk level from individual impacts
func (ia *DefaultImpactAnalyzer) calculateOverallRisk(impacts []ChangeImpact) ImpactLevel {
	maxLevel := ImpactLevelLow
	criticalCount := 0
	highCount := 0
	breakingCount := 0

	for _, impact := range impacts {
		switch impact.Level {
		case ImpactLevelCritical:
			criticalCount++
			maxLevel = ImpactLevelCritical
		case ImpactLevelHigh:
			highCount++
			if maxLevel < ImpactLevelHigh {
				maxLevel = ImpactLevelHigh
			}
		case ImpactLevelMedium:
			if maxLevel < ImpactLevelMedium {
				maxLevel = ImpactLevelMedium
			}
		}

		if impact.BreakingChange {
			breakingCount++
		}
	}

	// Escalate risk based on counts
	if criticalCount > 0 || breakingCount > 2 {
		return ImpactLevelCritical
	}
	if highCount > 3 || breakingCount > 0 {
		return ImpactLevelHigh
	}

	return maxLevel
}

// identifyRiskFactors identifies specific risk factors in the changes
func (ia *DefaultImpactAnalyzer) identifyRiskFactors(result *ComparisonResult) []RiskFactor {
	var factors []RiskFactor

	// Count different types of changes
	securityChanges := 0
	breakingChanges := 0
	networkChanges := 0

	for _, entry := range result.Entries {
		if entry.Impact.Category == ChangeCategorySecurity {
			securityChanges++
		}
		if entry.Impact.BreakingChange {
			breakingChanges++
		}
		if entry.Impact.Category == ChangeCategoryNetwork {
			networkChanges++
		}
	}

	// Add risk factors based on analysis
	if securityChanges > 0 {
		factors = append(factors, RiskFactor{
			Factor:      "security_changes",
			Level:       ImpactLevelHigh,
			Description: fmt.Sprintf("%d security-related changes", securityChanges),
			Mitigation:  "Review security implications and test authentication/authorization",
		})
	}

	if breakingChanges > 0 {
		factors = append(factors, RiskFactor{
			Factor:      "breaking_changes",
			Level:       ImpactLevelCritical,
			Description: fmt.Sprintf("%d breaking changes", breakingChanges),
			Mitigation:  "Plan rollback strategy and notify affected users",
		})
	}

	if networkChanges > 0 {
		factors = append(factors, RiskFactor{
			Factor:      "network_changes",
			Level:       ImpactLevelMedium,
			Description: fmt.Sprintf("%d network configuration changes", networkChanges),
			Mitigation:  "Test connectivity and firewall rules",
		})
	}

	if len(result.Entries) > 20 {
		factors = append(factors, RiskFactor{
			Factor:      "large_changeset",
			Level:       ImpactLevelMedium,
			Description: fmt.Sprintf("%d total changes (large changeset)", len(result.Entries)),
			Mitigation:  "Consider breaking into smaller deployments",
		})
	}

	return factors
}

// generateRecommendations generates recommendations based on risk analysis
func (ia *DefaultImpactAnalyzer) generateRecommendations(result *ComparisonResult, factors []RiskFactor) []string {
	var recommendations []string

	for _, factor := range factors {
		recommendations = append(recommendations, factor.Mitigation)
	}

	// Add general recommendations based on change patterns
	if result.Summary.BreakingChanges > 0 {
		recommendations = append(recommendations, "Create rollback plan before deployment")
		recommendations = append(recommendations, "Test in staging environment first")
	}

	if result.Summary.SecurityChanges > 0 {
		recommendations = append(recommendations, "Perform security review")
		recommendations = append(recommendations, "Update security documentation")
	}

	return recommendations
}

// determineRequiredApprovals determines what approvals are required
func (ia *DefaultImpactAnalyzer) determineRequiredApprovals(result *ComparisonResult, riskLevel ImpactLevel) []ApprovalRequirement {
	var approvals []ApprovalRequirement

	// Base approvals on risk level
	switch riskLevel {
	case ImpactLevelCritical:
		approvals = append(approvals, ApprovalRequirement{
			Type:      "security_review",
			Required:  true,
			Reason:    "Critical risk changes require security review",
			Approvers: []string{"security-team", "principal-engineer"},
		})
		approvals = append(approvals, ApprovalRequirement{
			Type:      "management_approval",
			Required:  true,
			Reason:    "Critical changes require management approval",
			Approvers: []string{"engineering-manager", "director"},
		})
	case ImpactLevelHigh:
		approvals = append(approvals, ApprovalRequirement{
			Type:      "peer_review",
			Required:  true,
			Reason:    "High impact changes require peer review",
			Approvers: []string{"senior-engineer", "tech-lead"},
		})
	}

	// Additional approvals based on change types
	if result.Summary.SecurityChanges > 0 {
		approvals = append(approvals, ApprovalRequirement{
			Type:      "security_review",
			Required:  true,
			Reason:    "Security changes require security team approval",
			Approvers: []string{"security-team"},
		})
	}

	return approvals
}

// generateTestingRecommendations generates testing recommendations
func (ia *DefaultImpactAnalyzer) generateTestingRecommendations(result *ComparisonResult, impacts []ChangeImpact) []string {
	var recommendations []string

	// Base recommendations on change characteristics
	hasSecurityChanges := false
	hasNetworkChanges := false
	requiresRestart := false

	for _, impact := range impacts {
		if impact.Category == ChangeCategorySecurity {
			hasSecurityChanges = true
		}
		if impact.Category == ChangeCategoryNetwork {
			hasNetworkChanges = true
		}
		if impact.RequiresRestart {
			requiresRestart = true
		}
	}

	// Generate specific testing recommendations
	if hasSecurityChanges {
		recommendations = append(recommendations, "Test authentication and authorization flows")
		recommendations = append(recommendations, "Verify security policies are applied correctly")
	}

	if hasNetworkChanges {
		recommendations = append(recommendations, "Test network connectivity")
		recommendations = append(recommendations, "Verify firewall rules and port accessibility")
	}

	if requiresRestart {
		recommendations = append(recommendations, "Test service restart procedures")
		recommendations = append(recommendations, "Verify graceful shutdown and startup")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Run standard integration tests")
	}

	return recommendations
}

// initializeDefaultImpactRules creates default impact assessment rules
func initializeDefaultImpactRules() []ImpactRule {
	var rules []ImpactRule

	// Security-related rules
	rules = append(rules, ImpactRule{
		Name:                 "security_config_change",
		PathPattern:          regexp.MustCompile(`(?i)(auth|security|ssl|tls|certificate|key|token|password)`),
		ChangeType:           []DiffType{DiffTypeAdd, DiffTypeDelete, DiffTypeModify},
		Impact:               ImpactLevelHigh,
		Category:             ChangeCategorySecurity,
		RequiresRestart:      true,
		BreakingChange:       true,
		SecurityImplications: []string{"Authentication/authorization configuration change"},
		Description:          "Security configuration change requires careful review",
	})

	// Database configuration rules
	rules = append(rules, ImpactRule{
		Name:             "database_config_change",
		PathPattern:      regexp.MustCompile(`(?i)(database|db|connection|host|port|username|schema)`),
		ChangeType:       []DiffType{DiffTypeModify, DiffTypeDelete},
		Impact:           ImpactLevelHigh,
		Category:         ChangeCategoryStructural,
		RequiresRestart:  true,
		RequiresDowntime: true,
		Description:      "Database configuration change may cause service disruption",
	})

	// Network configuration rules
	rules = append(rules, ImpactRule{
		Name:            "network_config_change",
		PathPattern:     regexp.MustCompile(`(?i)(network|port|host|url|endpoint|proxy)`),
		ChangeType:      []DiffType{DiffTypeModify, DiffTypeDelete},
		Impact:          ImpactLevelMedium,
		Category:        ChangeCategoryNetwork,
		RequiresRestart: true,
		Description:     "Network configuration change affects connectivity",
	})

	// Feature flag rules
	rules = append(rules, ImpactRule{
		Name:        "feature_flag_change",
		PathPattern: regexp.MustCompile(`(?i)(feature|flag|enabled|disabled)`),
		ChangeType:  []DiffType{DiffTypeModify},
		Impact:      ImpactLevelMedium,
		Category:    ChangeCategoryValue,
		Description: "Feature flag change affects application behavior",
	})

	// Logging configuration rules
	rules = append(rules, ImpactRule{
		Name:        "logging_config_change",
		PathPattern: regexp.MustCompile(`(?i)(log|logging|level|output|format)`),
		ChangeType:  []DiffType{DiffTypeModify},
		Impact:      ImpactLevelLow,
		Category:    ChangeCategoryValue,
		Description: "Logging configuration change",
	})

	return rules
}

// initializeDefaultCategoryRules creates default categorization rules
func initializeDefaultCategoryRules() []CategoryRule {
	var rules []CategoryRule

	rules = append(rules, CategoryRule{
		Name:        "security_category",
		PathPattern: regexp.MustCompile(`(?i)(auth|security|ssl|tls|certificate|key|token)`),
		Category:    ChangeCategorySecurity,
		Description: "Security-related configuration",
	})

	rules = append(rules, CategoryRule{
		Name:        "network_category",
		PathPattern: regexp.MustCompile(`(?i)(network|port|host|url|endpoint)`),
		Category:    ChangeCategoryNetwork,
		Description: "Network-related configuration",
	})

	rules = append(rules, CategoryRule{
		Name:        "access_category",
		PathPattern: regexp.MustCompile(`(?i)(access|permission|role|user|group)`),
		Category:    ChangeCategoryAccess,
		Description: "Access control configuration",
	})

	return rules
}

// initializeDefaultRiskRules creates default risk assessment rules
func initializeDefaultRiskRules() []RiskRule {
	var rules []RiskRule

	rules = append(rules, RiskRule{
		Name:        "multiple_security_changes",
		PathPattern: regexp.MustCompile(`(?i)(auth|security|ssl|tls)`),
		Condition: func(entry *DiffEntry, structure *ConfigStructure) bool {
			return entry.Impact.Category == ChangeCategorySecurity
		},
		RiskFactor: RiskFactor{
			Factor:      "security_risk",
			Level:       ImpactLevelHigh,
			Description: "Multiple security configuration changes",
			Mitigation:  "Comprehensive security testing required",
		},
		Description: "Multiple security changes increase risk",
	})

	return rules
}
