// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package diff implements semantic analysis for configuration structures
package diff

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultSemanticAnalyzer implements the SemanticAnalyzer interface
// with comprehensive configuration structure analysis capabilities
type DefaultSemanticAnalyzer struct {
	// Patterns define known configuration patterns for different formats
	patterns map[string][]ConfigPattern
}

// NewDefaultSemanticAnalyzer creates a new DefaultSemanticAnalyzer
func NewDefaultSemanticAnalyzer() *DefaultSemanticAnalyzer {
	return &DefaultSemanticAnalyzer{
		patterns: initializeDefaultPatterns(),
	}
}

// AnalyzeStructure analyzes the structure of a configuration
func (sa *DefaultSemanticAnalyzer) AnalyzeStructure(ctx context.Context, config []byte, format string) (*ConfigStructure, error) {
	// Parse the configuration
	var data interface{}
	switch strings.ToLower(format) {
	case "json":
		if err := json.Unmarshal(config, &data); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	case "yaml", "yml":
		if err := yaml.Unmarshal(config, &data); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	// Analyze the structure
	structure := &ConfigStructure{
		Format:   format,
		Sections: []ConfigSection{},
	}

	// Detect schema if possible
	structure.Schema = sa.detectSchema(data, format)

	// Analyze sections
	if rootMap, ok := data.(map[string]interface{}); ok {
		sections, deps := sa.analyzeSections("", rootMap)
		structure.Sections = sections
		structure.Dependencies = deps
	}

	// Detect patterns
	patterns := sa.detectConfigPatterns(data, format)
	structure.Patterns = patterns

	return structure, nil
}

// CompareStructures compares two configuration structures
func (sa *DefaultSemanticAnalyzer) CompareStructures(ctx context.Context, from, to *ConfigStructure) ([]StructuralChange, error) {
	var changes []StructuralChange

	// Compare sections
	sectionChanges := sa.compareSections(from.Sections, to.Sections)
	changes = append(changes, sectionChanges...)

	// Compare dependencies
	depChanges := sa.compareDependencies(from.Dependencies, to.Dependencies)
	changes = append(changes, depChanges...)

	// Compare patterns
	patternChanges := sa.comparePatterns(from.Patterns, to.Patterns)
	changes = append(changes, patternChanges...)

	return changes, nil
}

// DetectPatterns detects common configuration patterns
func (sa *DefaultSemanticAnalyzer) DetectPatterns(ctx context.Context, config []byte, format string) ([]ConfigPattern, error) {
	// Parse the configuration
	var data interface{}
	switch strings.ToLower(format) {
	case "json":
		if err := json.Unmarshal(config, &data); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	case "yaml", "yml":
		if err := yaml.Unmarshal(config, &data); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	return sa.detectConfigPatterns(data, format), nil
}

// detectSchema attempts to detect the configuration schema
func (sa *DefaultSemanticAnalyzer) detectSchema(data interface{}, format string) string {
	if rootMap, ok := data.(map[string]interface{}); ok {
		// Look for common schema indicators
		if _, hasVersion := rootMap["version"]; hasVersion {
			if _, hasKind := rootMap["kind"]; hasKind {
				return "kubernetes"
			}
		}

		// Check for Kubernetes with apiVersion instead of version
		if _, hasAPIVersion := rootMap["apiVersion"]; hasAPIVersion {
			if _, hasKind := rootMap["kind"]; hasKind {
				return "kubernetes"
			}
		}

		if _, hasServices := rootMap["services"]; hasServices {
			return "docker-compose"
		}

		if _, hasPackage := rootMap["package"]; hasPackage {
			return "npm"
		}

		if _, hasName := rootMap["name"]; hasName {
			if _, hasMain := rootMap["main"]; hasMain {
				return "package.json"
			}
		}

		// Check for Terraform
		if _, hasResource := rootMap["resource"]; hasResource {
			return "terraform"
		}

		// Check for Ansible
		if _, hasHosts := rootMap["hosts"]; hasHosts {
			return "ansible-playbook"
		}
	}

	return "unknown"
}

// analyzeSections recursively analyzes configuration sections
func (sa *DefaultSemanticAnalyzer) analyzeSections(path string, data map[string]interface{}) ([]ConfigSection, []SectionDependency) {
	var sections []ConfigSection
	var dependencies []SectionDependency

	for key, value := range data {
		sectionPath := buildPath(path, key)

		section := ConfigSection{
			Name: key,
			Path: sectionPath,
			Type: sa.detectSectionType(key, value),
		}

		// Analyze nested structures
		if nestedMap, ok := value.(map[string]interface{}); ok {
			childSections, childDeps := sa.analyzeSections(sectionPath, nestedMap)
			section.Children = childSections
			dependencies = append(dependencies, childDeps...)
		}

		// Extract properties
		section.Properties = sa.extractProperties(value)

		sections = append(sections, section)

		// Detect dependencies
		deps := sa.detectSectionDependencies(sectionPath, value, data)
		dependencies = append(dependencies, deps...)
	}

	return sections, dependencies
}

// detectSectionType determines the type of a configuration section
func (sa *DefaultSemanticAnalyzer) detectSectionType(key string, value interface{}) string {
	// Type detection based on key names
	switch strings.ToLower(key) {
	case "database", "db":
		return "database"
	case "server", "http", "api":
		return "server"
	case "security", "auth", "authentication":
		return "security"
	case "logging", "logs":
		return "logging"
	case "cache", "redis", "memcached":
		return "cache"
	case "monitoring", "metrics":
		return "monitoring"
	case "network", "networking":
		return "network"
	case "storage", "filesystem":
		return "storage"
	}

	// Type detection based on value structure
	if valueMap, ok := value.(map[string]interface{}); ok {
		if _, hasHost := valueMap["host"]; hasHost {
			if _, hasPort := valueMap["port"]; hasPort {
				return "connection"
			}
		}

		if _, hasEnabled := valueMap["enabled"]; hasEnabled {
			return "feature"
		}

		if _, hasLevel := valueMap["level"]; hasLevel {
			return "logging"
		}
	}

	// Default type based on value type
	if value == nil {
		return "unknown"
	}

	switch reflect.TypeOf(value).Kind() {
	case reflect.Map:
		return "object"
	case reflect.Slice:
		return "array"
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Float64, reflect.Int:
		return "number"
	default:
		return "unknown"
	}
}

// extractProperties extracts key properties from a configuration value
func (sa *DefaultSemanticAnalyzer) extractProperties(value interface{}) map[string]interface{} {
	properties := make(map[string]interface{})

	if valueMap, ok := value.(map[string]interface{}); ok {
		// Extract common important properties
		importantKeys := []string{
			"enabled", "disabled", "host", "port", "url", "path",
			"timeout", "retry", "version", "type", "mode",
		}

		for _, key := range importantKeys {
			if val, exists := valueMap[key]; exists {
				properties[key] = val
			}
		}
	}

	return properties
}

// detectSectionDependencies detects dependencies between configuration sections
func (sa *DefaultSemanticAnalyzer) detectSectionDependencies(sectionPath string, sectionValue interface{}, rootData map[string]interface{}) []SectionDependency {
	var dependencies []SectionDependency

	if sectionMap, ok := sectionValue.(map[string]interface{}); ok {
		// Look for references to other sections
		for _, value := range sectionMap {
			if strValue, ok := value.(string); ok {
				// Check if this looks like a reference to another section
				if strings.HasPrefix(strValue, "${") && strings.HasSuffix(strValue, "}") {
					// Variable reference
					ref := strings.TrimSuffix(strings.TrimPrefix(strValue, "${"), "}")
					dependencies = append(dependencies, SectionDependency{
						From:        sectionPath,
						To:          ref,
						Type:        "variable_reference",
						Description: fmt.Sprintf("References variable %s", ref),
					})
				} else if strings.Contains(strValue, ".") {
					// Possible path reference
					parts := strings.Split(strValue, ".")
					if len(parts) > 1 && sa.sectionExists(parts[0], rootData) {
						dependencies = append(dependencies, SectionDependency{
							From:        sectionPath,
							To:          parts[0],
							Type:        "path_reference",
							Description: fmt.Sprintf("References path %s", strValue),
						})
					}
				}
			}
		}

		// Look for implicit dependencies based on naming patterns
		parentPath := getParentPath(sectionPath)
		if parentPath != "" {
			dependencies = append(dependencies, SectionDependency{
				From:        sectionPath,
				To:          parentPath,
				Type:        "parent_child",
				Description: "Parent-child relationship",
			})
		}
	}

	return dependencies
}

// sectionExists checks if a section exists in the root data
func (sa *DefaultSemanticAnalyzer) sectionExists(sectionName string, rootData map[string]interface{}) bool {
	_, exists := rootData[sectionName]
	return exists
}

// detectConfigPatterns detects common configuration patterns
func (sa *DefaultSemanticAnalyzer) detectConfigPatterns(data interface{}, format string) []ConfigPattern {
	var patterns []ConfigPattern

	// Get predefined patterns for this format
	if formatPatterns, exists := sa.patterns[format]; exists {
		patterns = append(patterns, formatPatterns...)
	}

	// Detect runtime patterns
	runtimePatterns := sa.detectRuntimePatterns(data, "")
	patterns = append(patterns, runtimePatterns...)

	return patterns
}

// detectRuntimePatterns detects patterns at runtime based on data structure
func (sa *DefaultSemanticAnalyzer) detectRuntimePatterns(data interface{}, path string) []ConfigPattern {
	var patterns []ConfigPattern

	if dataMap, ok := data.(map[string]interface{}); ok {
		// Detect common patterns
		patterns = append(patterns, sa.detectConnectionPattern(dataMap, path)...)
		patterns = append(patterns, sa.detectSecurityPattern(dataMap, path)...)
		patterns = append(patterns, sa.detectLoggingPattern(dataMap, path)...)
		patterns = append(patterns, sa.detectServicePattern(dataMap, path)...)

		// Recursively analyze nested structures
		for key, value := range dataMap {
			childPath := buildPath(path, key)
			childPatterns := sa.detectRuntimePatterns(value, childPath)
			patterns = append(patterns, childPatterns...)
		}
	}

	return patterns
}

// detectConnectionPattern detects connection configuration patterns
func (sa *DefaultSemanticAnalyzer) detectConnectionPattern(data map[string]interface{}, path string) []ConfigPattern {
	var patterns []ConfigPattern

	hasHost := false
	hasPort := false

	for keyName := range data {
		switch strings.ToLower(keyName) {
		case "host", "hostname", "server":
			hasHost = true
		case "port":
			hasPort = true
		}
	}

	if hasHost && hasPort {
		patterns = append(patterns, ConfigPattern{
			Name:        "connection_config",
			Type:        "connection",
			Path:        path,
			Confidence:  0.9,
			Description: "Connection configuration with host and port",
		})
	}

	return patterns
}

// detectSecurityPattern detects security configuration patterns
func (sa *DefaultSemanticAnalyzer) detectSecurityPattern(data map[string]interface{}, path string) []ConfigPattern {
	var patterns []ConfigPattern

	securityKeys := []string{"auth", "authentication", "authorization", "security", "ssl", "tls", "certificate", "key", "token"}

	for keyName := range data {
		for _, secKey := range securityKeys {
			if strings.Contains(strings.ToLower(keyName), secKey) {
				patterns = append(patterns, ConfigPattern{
					Name:        "security_config",
					Type:        "security",
					Path:        buildPath(path, keyName),
					Confidence:  0.8,
					Description: fmt.Sprintf("Security configuration: %s", keyName),
				})
				break
			}
		}
	}

	return patterns
}

// detectLoggingPattern detects logging configuration patterns
func (sa *DefaultSemanticAnalyzer) detectLoggingPattern(data map[string]interface{}, path string) []ConfigPattern {
	var patterns []ConfigPattern

	loggingKeys := []string{"log", "logging", "logger", "level", "output", "format"}

	for keyName := range data {
		for _, logKey := range loggingKeys {
			if strings.Contains(strings.ToLower(keyName), logKey) {
				patterns = append(patterns, ConfigPattern{
					Name:        "logging_config",
					Type:        "logging",
					Path:        buildPath(path, keyName),
					Confidence:  0.8,
					Description: fmt.Sprintf("Logging configuration: %s", keyName),
				})
				break
			}
		}
	}

	return patterns
}

// detectServicePattern detects service configuration patterns
func (sa *DefaultSemanticAnalyzer) detectServicePattern(data map[string]interface{}, path string) []ConfigPattern {
	var patterns []ConfigPattern

	serviceKeys := []string{"service", "server", "daemon", "worker", "process"}

	for keyName := range data {
		for _, svcKey := range serviceKeys {
			if strings.Contains(strings.ToLower(keyName), svcKey) {
				patterns = append(patterns, ConfigPattern{
					Name:        "service_config",
					Type:        "service",
					Path:        buildPath(path, keyName),
					Confidence:  0.7,
					Description: fmt.Sprintf("Service configuration: %s", keyName),
				})
				break
			}
		}
	}

	return patterns
}

// compareSections compares two sets of configuration sections
func (sa *DefaultSemanticAnalyzer) compareSections(from, to []ConfigSection) []StructuralChange {
	var changes []StructuralChange

	// Create maps for easier comparison
	fromMap := make(map[string]ConfigSection)
	toMap := make(map[string]ConfigSection)

	for _, section := range from {
		fromMap[section.Path] = section
	}
	for _, section := range to {
		toMap[section.Path] = section
	}

	// Find added, removed, and modified sections
	for path, fromSection := range fromMap {
		if toSection, exists := toMap[path]; exists {
			// Section exists in both, check for modifications
			if fromSection.Type != toSection.Type || fromSection.Name != toSection.Name {
				changes = append(changes, StructuralChange{
					Type:        StructuralChangeTypeSectionRenamed,
					Path:        path,
					Description: fmt.Sprintf("Section %s modified (type: %s->%s)", path, fromSection.Type, toSection.Type),
					Impact:      ChangeImpact{Level: ImpactLevelMedium, Category: ChangeCategoryStructural},
				})
			}
		} else {
			// Section removed
			changes = append(changes, StructuralChange{
				Type:        StructuralChangeTypeSectionRemoved,
				Path:        path,
				Description: fmt.Sprintf("Section %s removed", path),
				Impact:      ChangeImpact{Level: ImpactLevelHigh, Category: ChangeCategoryStructural},
			})
		}
	}

	for path, toSection := range toMap {
		if _, exists := fromMap[path]; !exists {
			// Section added
			changes = append(changes, StructuralChange{
				Type:        StructuralChangeTypeSectionAdded,
				Path:        path,
				Description: fmt.Sprintf("Section %s added (type: %s)", path, toSection.Type),
				Impact:      ChangeImpact{Level: ImpactLevelMedium, Category: ChangeCategoryStructural},
			})
		}
	}

	return changes
}

// compareDependencies compares two sets of section dependencies
func (sa *DefaultSemanticAnalyzer) compareDependencies(from, to []SectionDependency) []StructuralChange {
	var changes []StructuralChange

	// Create maps for easier comparison
	fromMap := make(map[string]SectionDependency)
	toMap := make(map[string]SectionDependency)

	for _, dep := range from {
		key := fmt.Sprintf("%s->%s", dep.From, dep.To)
		fromMap[key] = dep
	}
	for _, dep := range to {
		key := fmt.Sprintf("%s->%s", dep.From, dep.To)
		toMap[key] = dep
	}

	// Find added and removed dependencies
	for key, dep := range fromMap {
		if _, exists := toMap[key]; !exists {
			changes = append(changes, StructuralChange{
				Type:        StructuralChangeTypeDependencyRemoved,
				Path:        dep.From,
				Description: fmt.Sprintf("Dependency removed: %s -> %s", dep.From, dep.To),
				Impact:      ChangeImpact{Level: ImpactLevelMedium, Category: ChangeCategoryStructural},
			})
		}
	}

	for key, dep := range toMap {
		if _, exists := fromMap[key]; !exists {
			changes = append(changes, StructuralChange{
				Type:        StructuralChangeTypeDependencyAdded,
				Path:        dep.From,
				Description: fmt.Sprintf("Dependency added: %s -> %s", dep.From, dep.To),
				Impact:      ChangeImpact{Level: ImpactLevelMedium, Category: ChangeCategoryStructural},
			})
		}
	}

	return changes
}

// comparePatterns compares two sets of configuration patterns
func (sa *DefaultSemanticAnalyzer) comparePatterns(from, to []ConfigPattern) []StructuralChange {
	var changes []StructuralChange

	// Simple pattern comparison - could be enhanced
	if len(from) != len(to) {
		changes = append(changes, StructuralChange{
			Type:        StructuralChangeTypePatternChanged,
			Path:        "",
			Description: fmt.Sprintf("Pattern count changed: %d -> %d", len(from), len(to)),
			Impact:      ChangeImpact{Level: ImpactLevelLow, Category: ChangeCategoryStructural},
		})
	}

	return changes
}

// initializeDefaultPatterns initializes predefined patterns for common formats
func initializeDefaultPatterns() map[string][]ConfigPattern {
	patterns := make(map[string][]ConfigPattern)

	// JSON patterns
	patterns["json"] = []ConfigPattern{
		{
			Name:        "package_json",
			Type:        "package_manager",
			Confidence:  0.9,
			Description: "NPM package.json configuration",
		},
	}

	// YAML patterns
	patterns["yaml"] = []ConfigPattern{
		{
			Name:        "kubernetes_manifest",
			Type:        "orchestration",
			Confidence:  0.9,
			Description: "Kubernetes resource manifest",
		},
		{
			Name:        "docker_compose",
			Type:        "container",
			Confidence:  0.9,
			Description: "Docker Compose configuration",
		},
		{
			Name:        "ansible_playbook",
			Type:        "automation",
			Confidence:  0.9,
			Description: "Ansible playbook configuration",
		},
	}

	return patterns
}
