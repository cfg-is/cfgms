// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package templates

import (
	"context"
	"fmt"
	"strings"
)

// DefaultVariableResolver implements the VariableResolver interface
type DefaultVariableResolver struct {
	dnaProvider   DNAProvider
	configService ConfigService // Interface to config inheritance system
}

// ConfigService provides access to configuration inheritance
type ConfigService interface {
	// GetInheritedVariables returns variables from parent configurations
	GetInheritedVariables(ctx context.Context, targetType, targetID string) (map[string]interface{}, error)
}

// NewVariableResolver creates a new variable resolver
func NewVariableResolver(dnaProvider DNAProvider, configService ConfigService) VariableResolver {
	return &DefaultVariableResolver{
		dnaProvider:   dnaProvider,
		configService: configService,
	}
}

// Resolve resolves all variables for a template context
func (r *DefaultVariableResolver) Resolve(ctx context.Context, template *Template, targetType, targetID string) (*TemplateContext, error) {
	context := &TemplateContext{
		Variables:          make(map[string]interface{}),
		DNA:                make(map[string]interface{}),
		InheritedVariables: make(map[string]interface{}),
		LocalVariables:     make(map[string]interface{}),
		Functions:          make(map[string]interface{}),
		TargetType:         targetType,
		TargetID:           targetID,
	}

	// 1. Load DNA properties (lowest precedence for conflicts)
	if r.dnaProvider != nil {
		dna, err := r.dnaProvider.GetDNA(ctx, targetType, targetID)
		if err != nil {
			// DNA is optional - log but don't fail
			context.DNA = make(map[string]interface{})
		} else {
			context.DNA = dna
		}
	}

	// 2. Load inherited variables (medium precedence)
	if r.configService != nil {
		inherited, err := r.configService.GetInheritedVariables(ctx, targetType, targetID)
		if err != nil {
			// Inherited variables are optional - log but don't fail
			context.InheritedVariables = make(map[string]interface{})
		} else {
			context.InheritedVariables = inherited
		}
	}

	// 3. Use local template variables (highest precedence)
	context.LocalVariables = template.Variables

	// 4. Merge variables in precedence order
	// Start with DNA properties (but don't include DNA.* keys directly)
	for key, value := range context.DNA {
		if !strings.HasPrefix(key, "DNA.") {
			context.Variables[key] = value
		}
	}

	// Override with inherited variables
	for key, value := range context.InheritedVariables {
		context.Variables[key] = value
	}

	// Override with local variables (highest precedence)
	for key, value := range context.LocalVariables {
		context.Variables[key] = value
	}

	return context, nil
}

// ResolveVariable resolves a specific variable
func (r *DefaultVariableResolver) ResolveVariable(ctx context.Context, name string, context *TemplateContext) (interface{}, error) {
	// Handle DNA properties specially
	if strings.HasPrefix(name, "DNA.") {
		return r.resolveDNAProperty(name[4:], context.DNA)
	}

	// Check variables in precedence order
	if value, exists := context.LocalVariables[name]; exists {
		return value, nil
	}

	if value, exists := context.InheritedVariables[name]; exists {
		return value, nil
	}

	if value, exists := context.DNA[name]; exists {
		return value, nil
	}

	return nil, &TemplateError{
		Type:    "UNDEFINED_VARIABLE",
		Message: fmt.Sprintf("Variable '%s' is undefined", name),
	}
}

// GetPrecedence returns variable precedence order
func (r *DefaultVariableResolver) GetPrecedence() []string {
	return []string{
		"local_variables",
		"inherited_variables",
		"dna_properties",
	}
}

// Helper methods

func (r *DefaultVariableResolver) resolveDNAProperty(property string, dna map[string]interface{}) (interface{}, error) {
	parts := strings.Split(property, ".")
	current := dna

	for i, part := range parts {
		if current == nil {
			return nil, &TemplateError{
				Type:    "UNDEFINED_VARIABLE",
				Message: fmt.Sprintf("DNA property '%s' is undefined", property),
			}
		}

		if value, exists := current[part]; exists {
			if i == len(parts)-1 {
				// Last part - return the value
				return value, nil
			}

			// Navigate deeper
			if next, ok := value.(map[string]interface{}); ok {
				current = next
			} else {
				return nil, &TemplateError{
					Type:    "INVALID_PROPERTY",
					Message: fmt.Sprintf("Cannot access property '%s' on non-object value", strings.Join(parts[:i+1], ".")),
				}
			}
		} else {
			return nil, &TemplateError{
				Type:    "UNDEFINED_VARIABLE",
				Message: fmt.Sprintf("DNA property '%s' is undefined", property),
			}
		}
	}

	return nil, &TemplateError{
		Type:    "UNDEFINED_VARIABLE",
		Message: fmt.Sprintf("DNA property '%s' is undefined", property),
	}
}

// MockDNAProvider provides DNA properties for testing
type MockDNAProvider struct {
	data map[string]map[string]interface{}
}

// NewMockDNAProvider creates a new mock DNA provider
func NewMockDNAProvider() *MockDNAProvider {
	return &MockDNAProvider{
		data: make(map[string]map[string]interface{}),
	}
}

// SetDNA sets DNA data for a target
func (m *MockDNAProvider) SetDNA(targetType, targetID string, dna map[string]interface{}) {
	key := fmt.Sprintf("%s:%s", targetType, targetID)
	m.data[key] = dna
}

// GetDNA returns DNA properties for a target
func (m *MockDNAProvider) GetDNA(ctx context.Context, targetType, targetID string) (map[string]interface{}, error) {
	key := fmt.Sprintf("%s:%s", targetType, targetID)
	if data, exists := m.data[key]; exists {
		return data, nil
	}

	// Return empty DNA if not found
	return make(map[string]interface{}), nil
}

// GetProperty returns a specific DNA property
func (m *MockDNAProvider) GetProperty(ctx context.Context, targetType, targetID, property string) (interface{}, error) {
	dna, err := m.GetDNA(ctx, targetType, targetID)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(property, ".")
	current := dna

	for _, part := range parts {
		if current == nil {
			return nil, fmt.Errorf("property not found: %s", property)
		}

		if value, exists := current[part]; exists {
			if next, ok := value.(map[string]interface{}); ok {
				current = next
			} else {
				return value, nil
			}
		} else {
			return nil, fmt.Errorf("property not found: %s", property)
		}
	}

	return current, nil
}

// ListProperties returns available DNA properties for a target
func (m *MockDNAProvider) ListProperties(ctx context.Context, targetType, targetID string) ([]string, error) {
	dna, err := m.GetDNA(ctx, targetType, targetID)
	if err != nil {
		return nil, err
	}

	var properties []string
	m.collectProperties("", dna, &properties)
	return properties, nil
}

func (m *MockDNAProvider) collectProperties(prefix string, data map[string]interface{}, properties *[]string) {
	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		*properties = append(*properties, fullKey)

		if nested, ok := value.(map[string]interface{}); ok {
			m.collectProperties(fullKey, nested, properties)
		}
	}
}

// MockConfigService provides inherited variables for testing
type MockConfigService struct {
	data map[string]map[string]interface{}
}

// NewMockConfigService creates a new mock config service
func NewMockConfigService() *MockConfigService {
	return &MockConfigService{
		data: make(map[string]map[string]interface{}),
	}
}

// SetInheritedVariables sets inherited variables for a target
func (m *MockConfigService) SetInheritedVariables(targetType, targetID string, variables map[string]interface{}) {
	key := fmt.Sprintf("%s:%s", targetType, targetID)
	m.data[key] = variables
}

// GetInheritedVariables returns variables from parent configurations
func (m *MockConfigService) GetInheritedVariables(ctx context.Context, targetType, targetID string) (map[string]interface{}, error) {
	key := fmt.Sprintf("%s:%s", targetType, targetID)
	if data, exists := m.data[key]; exists {
		return data, nil
	}

	// Return empty variables if not found
	return make(map[string]interface{}), nil
}
