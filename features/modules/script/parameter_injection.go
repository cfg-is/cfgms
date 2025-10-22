package script

import (
	"fmt"
	"regexp"
	"strings"
)

// ParameterInjector handles injection of DNA and configuration parameters into scripts
type ParameterInjector struct {
	dnaProvider    DNAProvider
	configProvider ConfigProvider
	customVars     map[string]string
}

// DNAProvider interface for retrieving DNA properties
type DNAProvider interface {
	GetProperty(path string) (interface{}, error)
}

// ConfigProvider interface for retrieving configuration values
type ConfigProvider interface {
	GetValue(path string) (interface{}, error)
}

// NewParameterInjector creates a new parameter injector
func NewParameterInjector(dnaProvider DNAProvider, configProvider ConfigProvider) *ParameterInjector {
	return &ParameterInjector{
		dnaProvider:    dnaProvider,
		configProvider: configProvider,
		customVars:     make(map[string]string),
	}
}

// SetCustomVariable sets a custom variable for injection
func (pi *ParameterInjector) SetCustomVariable(name string, value string) {
	pi.customVars[name] = value
}

// InjectParameters injects parameters into script content
// Supports:
// - $DNA.Property.Path - Injects DNA properties (e.g., $DNA.OS.Version)
// - $CompanySettings.Path - Injects company/tenant settings (e.g., $CompanySettings.BackupPath)
// - $CustomVar - Injects custom variables
func (pi *ParameterInjector) InjectParameters(content string, parameters map[string]string) (string, error) {
	result := content

	// Inject custom parameters first (highest priority)
	for key, value := range parameters {
		placeholder := fmt.Sprintf("$%s", key)
		result = strings.ReplaceAll(result, placeholder, value)
	}

	// Inject DNA properties
	result, err := pi.injectDNAProperties(result)
	if err != nil {
		return "", fmt.Errorf("failed to inject DNA properties: %w", err)
	}

	// Inject company settings/config
	result, err = pi.injectConfigSettings(result)
	if err != nil {
		return "", fmt.Errorf("failed to inject config settings: %w", err)
	}

	// Inject custom variables
	for key, value := range pi.customVars {
		placeholder := fmt.Sprintf("$%s", key)
		result = strings.ReplaceAll(result, placeholder, value)
	}

	return result, nil
}

// injectDNAProperties finds and replaces $DNA.* placeholders
func (pi *ParameterInjector) injectDNAProperties(content string) (string, error) {
	if pi.dnaProvider == nil {
		return content, nil // No DNA provider, skip injection
	}

	// Regex to find $DNA.Property.Path patterns
	dnaPattern := regexp.MustCompile(`\$DNA\.([A-Za-z0-9_.]+)`)
	matches := dnaPattern.FindAllStringSubmatch(content, -1)

	result := content
	errors := make([]string, 0)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		placeholder := match[0]  // Full match: $DNA.OS.Version
		propertyPath := match[1] // Property path: OS.Version

		// Get DNA property
		value, err := pi.dnaProvider.GetProperty(propertyPath)
		if err != nil {
			errors = append(errors, fmt.Sprintf("DNA property %s not found: %v", propertyPath, err))
			continue
		}

		// Convert value to string
		valueStr := fmt.Sprintf("%v", value)
		result = strings.ReplaceAll(result, placeholder, valueStr)
	}

	if len(errors) > 0 {
		return result, fmt.Errorf("DNA injection errors: %s", strings.Join(errors, "; "))
	}

	return result, nil
}

// injectConfigSettings finds and replaces $CompanySettings.* and $TenantPolicy.* placeholders
func (pi *ParameterInjector) injectConfigSettings(content string) (string, error) {
	if pi.configProvider == nil {
		return content, nil // No config provider, skip injection
	}

	// Regex to find $CompanySettings.* and $TenantPolicy.* patterns
	configPattern := regexp.MustCompile(`\$(CompanySettings|TenantPolicy)\.([A-Za-z0-9_.]+)`)
	matches := configPattern.FindAllStringSubmatch(content, -1)

	result := content
	errors := make([]string, 0)

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}

		placeholder := match[0]  // Full match: $CompanySettings.BackupPath
		configType := match[1]   // CompanySettings or TenantPolicy
		propertyPath := match[2] // BackupPath

		// Construct full config path
		fullPath := fmt.Sprintf("%s.%s", configType, propertyPath)

		// Get config value
		value, err := pi.configProvider.GetValue(fullPath)
		if err != nil {
			errors = append(errors, fmt.Sprintf("config setting %s not found: %v", fullPath, err))
			continue
		}

		// Convert value to string
		valueStr := fmt.Sprintf("%v", value)
		result = strings.ReplaceAll(result, placeholder, valueStr)
	}

	if len(errors) > 0 {
		return result, fmt.Errorf("config injection errors: %s", strings.Join(errors, "; "))
	}

	return result, nil
}

// ExtractRequiredParameters extracts all parameter placeholders from script content
func ExtractRequiredParameters(content string) []string {
	params := make(map[string]bool)

	// Find DNA parameters
	dnaPattern := regexp.MustCompile(`\$DNA\.([A-Za-z0-9_.]+)`)
	dnaMatches := dnaPattern.FindAllStringSubmatch(content, -1)
	for _, match := range dnaMatches {
		if len(match) >= 2 {
			params["DNA."+match[1]] = true
		}
	}

	// Find config parameters
	configPattern := regexp.MustCompile(`\$(CompanySettings|TenantPolicy)\.([A-Za-z0-9_.]+)`)
	configMatches := configPattern.FindAllStringSubmatch(content, -1)
	for _, match := range configMatches {
		if len(match) >= 3 {
			params[match[1]+"."+match[2]] = true
		}
	}

	// Find custom parameters (any $Variable that's not DNA or Config)
	customPattern := regexp.MustCompile(`\$([A-Za-z][A-Za-z0-9_]*)`)
	customMatches := customPattern.FindAllStringSubmatch(content, -1)
	for _, match := range customMatches {
		if len(match) >= 2 {
			paramName := match[1]
			// Skip if it's DNA or CompanySettings/TenantPolicy
			if !strings.HasPrefix(paramName, "DNA") &&
				!strings.HasPrefix(paramName, "CompanySettings") &&
				!strings.HasPrefix(paramName, "TenantPolicy") {
				params[paramName] = true
			}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(params))
	for param := range params {
		result = append(result, param)
	}

	return result
}

// ValidateParameters validates that all required parameters can be resolved
func (pi *ParameterInjector) ValidateParameters(content string, providedParams map[string]string) error {
	required := ExtractRequiredParameters(content)
	missing := make([]string, 0)

	for _, param := range required {
		// Check if parameter starts with DNA or Config prefix
		if strings.HasPrefix(param, "DNA.") {
			if pi.dnaProvider == nil {
				missing = append(missing, param+" (no DNA provider configured)")
			}
			continue
		}

		if strings.HasPrefix(param, "CompanySettings.") || strings.HasPrefix(param, "TenantPolicy.") {
			if pi.configProvider == nil {
				missing = append(missing, param+" (no config provider configured)")
			}
			continue
		}

		// Custom parameter - check if provided
		if _, ok := providedParams[param]; !ok {
			if _, ok := pi.customVars[param]; !ok {
				missing = append(missing, param)
			}
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required parameters: %s", strings.Join(missing, ", "))
	}

	return nil
}

// SimpleDNAProvider is a simple implementation of DNAProvider for testing/basic use
type SimpleDNAProvider struct {
	properties map[string]interface{}
}

// NewSimpleDNAProvider creates a new simple DNA provider
func NewSimpleDNAProvider(properties map[string]interface{}) *SimpleDNAProvider {
	return &SimpleDNAProvider{
		properties: properties,
	}
}

// GetProperty retrieves a property by path (e.g., "OS.Version")
func (p *SimpleDNAProvider) GetProperty(path string) (interface{}, error) {
	// Split path into parts
	parts := strings.Split(path, ".")

	// Navigate through nested maps
	current := interface{}(p.properties)
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("property path %s not found: invalid structure at %s", path, part)
		}

		value, exists := m[part]
		if !exists {
			return nil, fmt.Errorf("property path %s not found: %s does not exist", path, part)
		}

		current = value
	}

	return current, nil
}

// SimpleConfigProvider is a simple implementation of ConfigProvider for testing/basic use
type SimpleConfigProvider struct {
	settings map[string]interface{}
}

// NewSimpleConfigProvider creates a new simple config provider
func NewSimpleConfigProvider(settings map[string]interface{}) *SimpleConfigProvider {
	return &SimpleConfigProvider{
		settings: settings,
	}
}

// GetValue retrieves a config value by path (e.g., "CompanySettings.BackupPath")
func (p *SimpleConfigProvider) GetValue(path string) (interface{}, error) {
	// Split path into parts
	parts := strings.Split(path, ".")

	// Navigate through nested maps
	current := interface{}(p.settings)
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("config path %s not found: invalid structure at %s", path, part)
		}

		value, exists := m[part]
		if !exists {
			return nil, fmt.Errorf("config path %s not found: %s does not exist", path, part)
		}

		current = value
	}

	return current, nil
}
