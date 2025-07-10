package validation

import (
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/steward/config"
)

// ResourceNameUniquenessRule ensures all resource names are unique within a configuration
type ResourceNameUniquenessRule struct{}

func (r *ResourceNameUniquenessRule) Name() string {
	return "resource_name_uniqueness"
}

func (r *ResourceNameUniquenessRule) Validate(configInterface interface{}) []ValidationIssue {
	cfg, ok := configInterface.(config.StewardConfig)
	if !ok {
		return []ValidationIssue{{
			Level:   ValidationLevelError,
			Field:   "config",
			Message: "Invalid configuration type for resource name validation",
			Code:    "INVALID_CONFIG_TYPE",
		}}
	}

	var issues []ValidationIssue
	nameMap := make(map[string]int)

	for i, resource := range cfg.Resources {
		if prevIndex, exists := nameMap[resource.Name]; exists {
			issues = append(issues, ValidationIssue{
				Level:   ValidationLevelError,
				Field:   fmt.Sprintf("resources[%d].name", i),
				Message: fmt.Sprintf("Duplicate resource name '%s' (also used in resources[%d])", resource.Name, prevIndex),
				Code:    "DUPLICATE_RESOURCE_NAME",
				Suggestion: fmt.Sprintf("Use a unique name for this resource, such as '%s-2' or '%s-%s'", resource.Name, resource.Name, resource.Module),
				Context: map[string]interface{}{
					"duplicate_name":   resource.Name,
					"first_occurrence": prevIndex,
					"current_index":    i,
				},
			})
		}
		nameMap[resource.Name] = i
	}

	return issues
}

// ModuleCompatibilityRule validates module compatibility and requirements
type ModuleCompatibilityRule struct{}

func (r *ModuleCompatibilityRule) Name() string {
	return "module_compatibility"
}

func (r *ModuleCompatibilityRule) Validate(configInterface interface{}) []ValidationIssue {
	cfg, ok := configInterface.(config.StewardConfig)
	if !ok {
		return []ValidationIssue{{
			Level:   ValidationLevelError,
			Field:   "config",
			Message: "Invalid configuration type for module compatibility validation",
			Code:    "INVALID_CONFIG_TYPE",
		}}
	}

	var issues []ValidationIssue

	for i, resource := range cfg.Resources {
		fieldPrefix := fmt.Sprintf("resources[%d]", i)

		// Check for module-specific compatibility issues
		switch resource.Module {
		case "directory":
			issues = append(issues, r.validateDirectoryModule(resource, fieldPrefix)...)
		case "file":
			issues = append(issues, r.validateFileModule(resource, fieldPrefix)...)
		case "package":
			issues = append(issues, r.validatePackageModule(resource, fieldPrefix)...)
		case "firewall":
			issues = append(issues, r.validateFirewallModule(resource, fieldPrefix)...)
		}
	}

	return issues
}

func (r *ModuleCompatibilityRule) validateDirectoryModule(resource config.ResourceConfig, fieldPrefix string) []ValidationIssue {
	var issues []ValidationIssue

	// Check for required fields
	if path, exists := resource.Config["path"]; !exists || path == "" {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelCritical,
			Field:      fieldPrefix + ".config.path",
			Message:    "Directory module requires a 'path' field",
			Code:       "MISSING_REQUIRED_FIELD",
			Suggestion: "Add a 'path' field with an absolute directory path",
		})
	}

	if permissions, exists := resource.Config["permissions"]; !exists {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelError,
			Field:      fieldPrefix + ".config.permissions",
			Message:    "Directory module requires a 'permissions' field",
			Code:       "MISSING_REQUIRED_FIELD",
			Suggestion: "Add a 'permissions' field with octal permissions (e.g., 755)",
		})
	} else if perm, ok := permissions.(int); ok && (perm < 0 || perm > 511) {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelError,
			Field:      fieldPrefix + ".config.permissions",
			Message:    fmt.Sprintf("Invalid permissions value: %d", perm),
			Code:       "INVALID_PERMISSIONS",
			Suggestion: "Use decimal permissions between 0 and 511 (e.g., 493 for rwxr-xr-x)",
		})
	}

	return issues
}

func (r *ModuleCompatibilityRule) validateFileModule(resource config.ResourceConfig, fieldPrefix string) []ValidationIssue {
	var issues []ValidationIssue

	// Check for required fields
	if path, exists := resource.Config["path"]; !exists || path == "" {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelCritical,
			Field:      fieldPrefix + ".config.path",
			Message:    "File module requires a 'path' field",
			Code:       "MISSING_REQUIRED_FIELD",
			Suggestion: "Add a 'path' field with an absolute file path",
		})
	}

	// Check for content or source
	hasContent := false
	if content, exists := resource.Config["content"]; exists && content != "" {
		hasContent = true
	}
	if source, exists := resource.Config["source"]; exists && source != "" {
		if hasContent {
			issues = append(issues, ValidationIssue{
				Level:      ValidationLevelError,
				Field:      fieldPrefix + ".config",
				Message:    "File module cannot have both 'content' and 'source' fields",
				Code:       "CONFLICTING_FIELDS",
				Suggestion: "Use either 'content' for inline content or 'source' for external file, not both",
			})
		}
		hasContent = true
	}

	if !hasContent {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelWarning,
			Field:      fieldPrefix + ".config",
			Message:    "File module should specify either 'content' or 'source'",
			Code:       "MISSING_CONTENT_SOURCE",
			Suggestion: "Add a 'content' field for inline content or 'source' field for external file",
		})
	}

	return issues
}

func (r *ModuleCompatibilityRule) validatePackageModule(resource config.ResourceConfig, fieldPrefix string) []ValidationIssue {
	var issues []ValidationIssue

	// Check for required fields
	if name, exists := resource.Config["name"]; !exists || name == "" {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelCritical,
			Field:      fieldPrefix + ".config.name",
			Message:    "Package module requires a 'name' field",
			Code:       "MISSING_REQUIRED_FIELD",
			Suggestion: "Add a 'name' field with the package name",
		})
	}

	if state, exists := resource.Config["state"]; !exists {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelError,
			Field:      fieldPrefix + ".config.state",
			Message:    "Package module requires a 'state' field",
			Code:       "MISSING_REQUIRED_FIELD",
			Suggestion: "Add a 'state' field with value 'present' or 'absent'",
		})
	} else if stateStr, ok := state.(string); ok && stateStr != "present" && stateStr != "absent" {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelError,
			Field:      fieldPrefix + ".config.state",
			Message:    fmt.Sprintf("Invalid package state: %s", stateStr),
			Code:       "INVALID_PACKAGE_STATE",
			Suggestion: "Use 'present' to install the package or 'absent' to remove it",
		})
	}

	return issues
}

func (r *ModuleCompatibilityRule) validateFirewallModule(resource config.ResourceConfig, fieldPrefix string) []ValidationIssue {
	var issues []ValidationIssue

	// Check for required fields
	if state, exists := resource.Config["state"]; !exists {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelError,
			Field:      fieldPrefix + ".config.state",
			Message:    "Firewall module requires a 'state' field",
			Code:       "MISSING_REQUIRED_FIELD",
			Suggestion: "Add a 'state' field with value 'enabled' or 'disabled'",
		})
	} else if stateStr, ok := state.(string); ok && stateStr != "enabled" && stateStr != "disabled" {
		issues = append(issues, ValidationIssue{
			Level:      ValidationLevelError,
			Field:      fieldPrefix + ".config.state",
			Message:    fmt.Sprintf("Invalid firewall state: %s", stateStr),
			Code:       "INVALID_FIREWALL_STATE",
			Suggestion: "Use 'enabled' to enable the firewall or 'disabled' to disable it",
		})
	}

	return issues
}

// ResourceDependencyRule validates dependencies between resources
type ResourceDependencyRule struct{}

func (r *ResourceDependencyRule) Name() string {
	return "resource_dependency"
}

func (r *ResourceDependencyRule) Validate(configInterface interface{}) []ValidationIssue {
	cfg, ok := configInterface.(config.StewardConfig)
	if !ok {
		return []ValidationIssue{{
			Level:   ValidationLevelError,
			Field:   "config",
			Message: "Invalid configuration type for resource dependency validation",
			Code:    "INVALID_CONFIG_TYPE",
		}}
	}

	var issues []ValidationIssue

	// Build a map of directory paths for dependency checking
	directoryPaths := make(map[string]int)
	for i, resource := range cfg.Resources {
		if resource.Module == "directory" {
			if path, exists := resource.Config["path"]; exists {
				if pathStr, ok := path.(string); ok {
					directoryPaths[pathStr] = i
				}
			}
		}
	}

	// Check if files have parent directories defined
	for i, resource := range cfg.Resources {
		if resource.Module == "file" {
			if path, exists := resource.Config["path"]; exists {
				if pathStr, ok := path.(string); ok {
					parentDir := getParentDirectory(pathStr)
					if parentDir != "/" && parentDir != "" {
						if _, hasParentDir := directoryPaths[parentDir]; !hasParentDir {
							issues = append(issues, ValidationIssue{
								Level:   ValidationLevelWarning,
								Field:   fmt.Sprintf("resources[%d].config.path", i),
								Message: fmt.Sprintf("File path '%s' does not have a corresponding directory resource for '%s'", pathStr, parentDir),
								Code:    "MISSING_PARENT_DIRECTORY",
								Suggestion: fmt.Sprintf("Consider adding a directory resource for '%s' to ensure the parent directory exists", parentDir),
								Context: map[string]interface{}{
									"file_path":   pathStr,
									"parent_dir":  parentDir,
									"file_index":  i,
								},
							})
						}
					}
				}
			}
		}
	}

	return issues
}

// getParentDirectory returns the parent directory of a given path
func getParentDirectory(path string) string {
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash <= 0 {
		return "/"
	}
	return path[:lastSlash]
}

// SecurityBestPracticesRule validates security best practices
type SecurityBestPracticesRule struct{}

func (r *SecurityBestPracticesRule) Name() string {
	return "security_best_practices"
}

func (r *SecurityBestPracticesRule) Validate(configInterface interface{}) []ValidationIssue {
	cfg, ok := configInterface.(config.StewardConfig)
	if !ok {
		return []ValidationIssue{{
			Level:   ValidationLevelError,
			Field:   "config",
			Message: "Invalid configuration type for security validation",
			Code:    "INVALID_CONFIG_TYPE",
		}}
	}

	var issues []ValidationIssue

	for i, resource := range cfg.Resources {
		fieldPrefix := fmt.Sprintf("resources[%d]", i)

		switch resource.Module {
		case "directory":
			issues = append(issues, r.validateDirectorySecurity(resource, fieldPrefix)...)
		case "file":
			issues = append(issues, r.validateFileSecurity(resource, fieldPrefix)...)
		case "firewall":
			issues = append(issues, r.validateFirewallSecurity(resource, fieldPrefix)...)
		}
	}

	return issues
}

func (r *SecurityBestPracticesRule) validateDirectorySecurity(resource config.ResourceConfig, fieldPrefix string) []ValidationIssue {
	var issues []ValidationIssue

	if permissions, exists := resource.Config["permissions"]; exists {
		if perm, ok := permissions.(int); ok {
			// Check for overly permissive directories
			if perm&0007 == 0007 { // World writable
				issues = append(issues, ValidationIssue{
					Level:      ValidationLevelWarning,
					Field:      fieldPrefix + ".config.permissions",
					Message:    "Directory is world-writable, which may pose a security risk",
					Code:       "WORLD_WRITABLE_DIRECTORY",
					Suggestion: "Consider removing write permissions for 'other' (e.g., use 755 instead of 777)",
					Context: map[string]interface{}{
						"permissions": fmt.Sprintf("%o", perm),
					},
				})
			}
		}
	}

	return issues
}

func (r *SecurityBestPracticesRule) validateFileSecurity(resource config.ResourceConfig, fieldPrefix string) []ValidationIssue {
	var issues []ValidationIssue

	if permissions, exists := resource.Config["permissions"]; exists {
		if perm, ok := permissions.(int); ok {
			// Check for overly permissive files
			if perm&0002 != 0 { // World writable
				issues = append(issues, ValidationIssue{
					Level:      ValidationLevelWarning,
					Field:      fieldPrefix + ".config.permissions",
					Message:    "File is world-writable, which may pose a security risk",
					Code:       "WORLD_WRITABLE_FILE",
					Suggestion: "Consider removing write permissions for 'other' (e.g., use 644 instead of 646)",
					Context: map[string]interface{}{
						"permissions": fmt.Sprintf("%o", perm),
					},
				})
			}

			// Check for executable files
			if perm&0111 != 0 { // Executable
				issues = append(issues, ValidationIssue{
					Level:      ValidationLevelInfo,
					Field:      fieldPrefix + ".config.permissions",
					Message:    "File has execute permissions",
					Code:       "EXECUTABLE_FILE",
					Suggestion: "Ensure execute permissions are intentional for this file",
					Context: map[string]interface{}{
						"permissions": fmt.Sprintf("%o", perm),
					},
				})
			}
		}
	}

	// Check for sensitive content in files
	if content, exists := resource.Config["content"]; exists {
		if contentStr, ok := content.(string); ok {
			if r.containsSensitiveData(contentStr) {
				issues = append(issues, ValidationIssue{
					Level:      ValidationLevelWarning,
					Field:      fieldPrefix + ".config.content",
					Message:    "File content may contain sensitive data",
					Code:       "POTENTIAL_SENSITIVE_DATA",
					Suggestion: "Avoid storing passwords, keys, or tokens in configuration files. Use external secret management instead",
				})
			}
		}
	}

	return issues
}

func (r *SecurityBestPracticesRule) validateFirewallSecurity(resource config.ResourceConfig, fieldPrefix string) []ValidationIssue {
	var issues []ValidationIssue

	if state, exists := resource.Config["state"]; exists {
		if stateStr, ok := state.(string); ok && stateStr == "disabled" {
			issues = append(issues, ValidationIssue{
				Level:      ValidationLevelWarning,
				Field:      fieldPrefix + ".config.state",
				Message:    "Firewall is disabled, which may reduce system security",
				Code:       "FIREWALL_DISABLED",
				Suggestion: "Consider enabling the firewall with appropriate rules for better security",
			})
		}
	}

	// Check firewall rules if present
	if rules, exists := resource.Config["rules"]; exists {
		if rulesSlice, ok := rules.([]interface{}); ok {
			for ruleIndex, rule := range rulesSlice {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
					if action, exists := ruleMap["action"]; exists && action == "allow" {
						if source, exists := ruleMap["source"]; !exists || source == "0.0.0.0/0" || source == "::/0" {
							issues = append(issues, ValidationIssue{
								Level:      ValidationLevelWarning,
								Field:      fmt.Sprintf("%s.config.rules[%d]", fieldPrefix, ruleIndex),
								Message:    "Firewall rule allows traffic from any source",
								Code:       "OVERLY_PERMISSIVE_FIREWALL_RULE",
								Suggestion: "Consider restricting the source to specific IP addresses or networks",
							})
						}
					}
				}
			}
		}
	}

	return issues
}

// containsSensitiveData checks if content contains potentially sensitive information
func (r *SecurityBestPracticesRule) containsSensitiveData(content string) bool {
	lowerContent := strings.ToLower(content)
	sensitivePatterns := []string{
		"password",
		"passwd",
		"secret",
		"token",
		"api_key",
		"apikey",
		"private_key",
		"privatekey",
		"certificate",
		"-----begin",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	return false
}