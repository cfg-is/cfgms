package workflow

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// WorkflowTemplate represents a reusable workflow template
type WorkflowTemplate struct {
	// Template metadata
	ID           string               `yaml:"id" json:"id"`
	Name         string               `yaml:"name" json:"name"`
	Description  string               `yaml:"description,omitempty" json:"description,omitempty"`
	Version      SemanticVersion      `yaml:"version" json:"version"`
	Author       string               `yaml:"author,omitempty" json:"author,omitempty"`

	// Template inheritance
	Extends      string               `yaml:"extends,omitempty" json:"extends,omitempty"`    // Parent template ID
	Abstract     bool                 `yaml:"abstract,omitempty" json:"abstract,omitempty"` // Cannot be instantiated directly

	// Template parameters
	Parameters   []TemplateParameter  `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	Defaults     map[string]interface{} `yaml:"defaults,omitempty" json:"defaults,omitempty"`

	// Template content
	Workflow     Workflow             `yaml:"workflow" json:"workflow"`

	// Template metadata
	Tags         []string             `yaml:"tags,omitempty" json:"tags,omitempty"`
	Category     string               `yaml:"category,omitempty" json:"category,omitempty"`
	CreatedAt    time.Time            `yaml:"created_at" json:"created_at"`
	UpdatedAt    time.Time            `yaml:"updated_at" json:"updated_at"`
	CreatedBy    string               `yaml:"created_by,omitempty" json:"created_by,omitempty"`

	// Validation and compatibility
	RequiredFeatures []string         `yaml:"required_features,omitempty" json:"required_features,omitempty"`
	MinEngineVersion SemanticVersion  `yaml:"min_engine_version,omitempty" json:"min_engine_version,omitempty"`
	Compatibility    []string         `yaml:"compatibility,omitempty" json:"compatibility,omitempty"`
}

// TemplateParameter defines a parameter that can be passed to a template
type TemplateParameter struct {
	Name         string      `yaml:"name" json:"name"`
	Type         ParameterType `yaml:"type" json:"type"`
	Description  string      `yaml:"description,omitempty" json:"description,omitempty"`
	Required     bool        `yaml:"required,omitempty" json:"required,omitempty"`
	Default      interface{} `yaml:"default,omitempty" json:"default,omitempty"`
	Options      []interface{} `yaml:"options,omitempty" json:"options,omitempty"` // For enum-like parameters
	Pattern      string      `yaml:"pattern,omitempty" json:"pattern,omitempty"`   // Validation pattern
	MinValue     interface{} `yaml:"min_value,omitempty" json:"min_value,omitempty"`
	MaxValue     interface{} `yaml:"max_value,omitempty" json:"max_value,omitempty"`
	MinLength    int         `yaml:"min_length,omitempty" json:"min_length,omitempty"`
	MaxLength    int         `yaml:"max_length,omitempty" json:"max_length,omitempty"`
}

// ParameterType defines the type of a template parameter
type ParameterType string

const (
	ParameterTypeString  ParameterType = "string"
	ParameterTypeInt     ParameterType = "int"
	ParameterTypeFloat   ParameterType = "float"
	ParameterTypeBool    ParameterType = "bool"
	ParameterTypeArray   ParameterType = "array"
	ParameterTypeObject  ParameterType = "object"
	ParameterTypeEnum    ParameterType = "enum"
)

// TemplateInstance represents an instantiated template with specific parameters
type TemplateInstance struct {
	ID           string                 `yaml:"id" json:"id"`
	TemplateID   string                 `yaml:"template_id" json:"template_id"`
	TemplateName string                 `yaml:"template_name" json:"template_name"`
	Parameters   map[string]interface{} `yaml:"parameters" json:"parameters"`
	Workflow     Workflow               `yaml:"workflow" json:"workflow"`
	CreatedAt    time.Time              `yaml:"created_at" json:"created_at"`
	CreatedBy    string                 `yaml:"created_by,omitempty" json:"created_by,omitempty"`
}

// TemplateEngine handles template processing and instantiation
type TemplateEngine struct {
	templates map[string]*WorkflowTemplate
}

// NewTemplateEngine creates a new template engine
func NewTemplateEngine() *TemplateEngine {
	return &TemplateEngine{
		templates: make(map[string]*WorkflowTemplate),
	}
}

// RegisterTemplate registers a template with the engine
func (te *TemplateEngine) RegisterTemplate(template *WorkflowTemplate) error {
	if err := te.ValidateTemplate(template); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	te.templates[template.ID] = template
	return nil
}

// GetTemplate retrieves a template by ID
func (te *TemplateEngine) GetTemplate(id string) (*WorkflowTemplate, error) {
	template, exists := te.templates[id]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", id)
	}
	return template, nil
}

// ListTemplates returns all registered templates
func (te *TemplateEngine) ListTemplates() []*WorkflowTemplate {
	templates := make([]*WorkflowTemplate, 0, len(te.templates))
	for _, template := range te.templates {
		templates = append(templates, template)
	}
	return templates
}

// InstantiateTemplate creates a workflow instance from a template
func (te *TemplateEngine) InstantiateTemplate(ctx context.Context, templateID string, parameters map[string]interface{}) (*TemplateInstance, error) {
	template, err := te.GetTemplate(templateID)
	if err != nil {
		return nil, err
	}

	if template.Abstract {
		return nil, fmt.Errorf("cannot instantiate abstract template: %s", templateID)
	}

	// Resolve template inheritance chain
	resolvedTemplate, err := te.ResolveInheritance(template)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve template inheritance: %w", err)
	}

	// Validate parameters
	if err := te.ValidateParameters(resolvedTemplate, parameters); err != nil {
		return nil, fmt.Errorf("parameter validation failed: %w", err)
	}

	// Merge with defaults
	mergedParams := te.MergeWithDefaults(resolvedTemplate, parameters)

	// Process template substitutions
	workflow, err := te.ProcessTemplateSubstitutions(resolvedTemplate.Workflow, mergedParams)
	if err != nil {
		return nil, fmt.Errorf("template substitution failed: %w", err)
	}

	instance := &TemplateInstance{
		ID:           generateTemplateInstanceID(),
		TemplateID:   templateID,
		TemplateName: template.Name,
		Parameters:   mergedParams,
		Workflow:     workflow,
		CreatedAt:    time.Now(),
	}

	return instance, nil
}

// ValidateTemplate validates a template definition
func (te *TemplateEngine) ValidateTemplate(template *WorkflowTemplate) error {
	if template.ID == "" {
		return fmt.Errorf("template ID is required")
	}

	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}

	// Validate parameter definitions
	paramNames := make(map[string]bool)
	for _, param := range template.Parameters {
		if param.Name == "" {
			return fmt.Errorf("parameter name is required")
		}

		if paramNames[param.Name] {
			return fmt.Errorf("duplicate parameter name: %s", param.Name)
		}
		paramNames[param.Name] = true

		if err := te.validateParameterType(param); err != nil {
			return fmt.Errorf("invalid parameter %s: %w", param.Name, err)
		}
	}

	// Validate workflow structure
	if template.Workflow.Name == "" {
		return fmt.Errorf("workflow name is required")
	}

	return nil
}

// ValidateParameters validates instance parameters against template
func (te *TemplateEngine) ValidateParameters(template *WorkflowTemplate, parameters map[string]interface{}) error {
	// Check required parameters
	for _, param := range template.Parameters {
		if param.Required {
			if _, exists := parameters[param.Name]; !exists {
				if param.Default == nil {
					return fmt.Errorf("required parameter missing: %s", param.Name)
				}
			}
		}
	}

	// Validate parameter values
	for name, value := range parameters {
		param := te.findParameter(template, name)
		if param == nil {
			return fmt.Errorf("unknown parameter: %s", name)
		}

		if err := te.validateParameterValue(*param, value); err != nil {
			return fmt.Errorf("invalid value for parameter %s: %w", name, err)
		}
	}

	return nil
}

// ResolveInheritance resolves template inheritance chain
func (te *TemplateEngine) ResolveInheritance(template *WorkflowTemplate) (*WorkflowTemplate, error) {
	if template.Extends == "" {
		return template, nil
	}

	// Get parent template
	parent, err := te.GetTemplate(template.Extends)
	if err != nil {
		return nil, fmt.Errorf("parent template not found: %s", template.Extends)
	}

	// Resolve parent's inheritance first
	resolvedParent, err := te.ResolveInheritance(parent)
	if err != nil {
		return nil, err
	}

	// Merge child with resolved parent
	merged := te.mergeTemplates(resolvedParent, template)
	return merged, nil
}

// MergeWithDefaults merges parameters with template defaults
func (te *TemplateEngine) MergeWithDefaults(template *WorkflowTemplate, parameters map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{})

	// Start with defaults
	for k, v := range template.Defaults {
		merged[k] = v
	}

	// Add parameter defaults
	for _, param := range template.Parameters {
		if param.Default != nil {
			merged[param.Name] = param.Default
		}
	}

	// Override with provided parameters
	for k, v := range parameters {
		merged[k] = v
	}

	return merged
}

// ProcessTemplateSubstitutions processes template variable substitutions
func (te *TemplateEngine) ProcessTemplateSubstitutions(workflow Workflow, parameters map[string]interface{}) (Workflow, error) {
	// Convert workflow to string for processing
	workflowStr := te.workflowToString(workflow)

	// Process substitutions
	processedStr, err := te.processSubstitutions(workflowStr, parameters)
	if err != nil {
		return workflow, err
	}

	// Convert back to workflow
	processedWorkflow, err := te.stringToWorkflow(processedStr)
	if err != nil {
		return workflow, err
	}

	return processedWorkflow, nil
}

// Helper functions

func (te *TemplateEngine) validateParameterType(param TemplateParameter) error {
	switch param.Type {
	case ParameterTypeString, ParameterTypeInt, ParameterTypeFloat, ParameterTypeBool, ParameterTypeArray, ParameterTypeObject, ParameterTypeEnum:
		return nil
	default:
		return fmt.Errorf("unsupported parameter type: %s", param.Type)
	}
}

func (te *TemplateEngine) findParameter(template *WorkflowTemplate, name string) *TemplateParameter {
	for _, param := range template.Parameters {
		if param.Name == name {
			return &param
		}
	}
	return nil
}

func (te *TemplateEngine) validateParameterValue(param TemplateParameter, value interface{}) error {
	// Type validation
	switch param.Type {
	case ParameterTypeString:
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string, got %T", value)
		}
		if param.Pattern != "" {
			matched, err := regexp.MatchString(param.Pattern, value.(string))
			if err != nil {
				return fmt.Errorf("pattern validation failed: %w", err)
			}
			if !matched {
				return fmt.Errorf("value does not match pattern: %s", param.Pattern)
			}
		}
		if param.MinLength > 0 && len(value.(string)) < param.MinLength {
			return fmt.Errorf("string too short, minimum length: %d", param.MinLength)
		}
		if param.MaxLength > 0 && len(value.(string)) > param.MaxLength {
			return fmt.Errorf("string too long, maximum length: %d", param.MaxLength)
		}
	case ParameterTypeInt:
		if _, ok := value.(int); !ok {
			return fmt.Errorf("expected int, got %T", value)
		}
	case ParameterTypeBool:
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected bool, got %T", value)
		}
	case ParameterTypeEnum:
		if len(param.Options) > 0 {
			found := false
			for _, option := range param.Options {
				if value == option {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("value not in allowed options")
			}
		}
	}

	return nil
}

func (te *TemplateEngine) mergeTemplates(parent, child *WorkflowTemplate) *WorkflowTemplate {
	merged := &WorkflowTemplate{
		ID:          child.ID,
		Name:        child.Name,
		Description: child.Description,
		Version:     child.Version,
		Author:      child.Author,
		Extends:     "", // Clear extends after merging
		Abstract:    child.Abstract,
		Workflow:    child.Workflow, // Child workflow takes precedence
	}

	// Merge parameters (child parameters override parent)
	paramMap := make(map[string]TemplateParameter)
	for _, param := range parent.Parameters {
		paramMap[param.Name] = param
	}
	for _, param := range child.Parameters {
		paramMap[param.Name] = param
	}

	merged.Parameters = make([]TemplateParameter, 0, len(paramMap))
	for _, param := range paramMap {
		merged.Parameters = append(merged.Parameters, param)
	}

	// Merge defaults (child defaults override parent)
	merged.Defaults = make(map[string]interface{})
	for k, v := range parent.Defaults {
		merged.Defaults[k] = v
	}
	for k, v := range child.Defaults {
		merged.Defaults[k] = v
	}

	// Copy other fields from child
	merged.Tags = append(merged.Tags, child.Tags...)
	merged.Category = child.Category
	merged.CreatedAt = child.CreatedAt
	merged.UpdatedAt = child.UpdatedAt
	merged.CreatedBy = child.CreatedBy
	merged.RequiredFeatures = append(merged.RequiredFeatures, child.RequiredFeatures...)
	merged.MinEngineVersion = child.MinEngineVersion
	merged.Compatibility = append(merged.Compatibility, child.Compatibility...)

	return merged
}

func (te *TemplateEngine) processSubstitutions(content string, parameters map[string]interface{}) (string, error) {
	// Simple template substitution using ${parameter_name} syntax
	// This could be extended to support more complex templating

	result := content

	// Replace ${param_name} with parameter values
	re := regexp.MustCompile(`\$\{([^}]+)\}`)
	matches := re.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		placeholder := match[0]
		paramName := match[1]

		if value, exists := parameters[paramName]; exists {
			// Convert value to string representation
			valueStr := fmt.Sprintf("%v", value)
			result = strings.ReplaceAll(result, placeholder, valueStr)
		} else {
			return "", fmt.Errorf("undefined parameter in template: %s", paramName)
		}
	}

	return result, nil
}

// workflowToString and stringToWorkflow would need proper YAML marshaling/unmarshaling
// This is a simplified implementation for demonstration
func (te *TemplateEngine) workflowToString(workflow Workflow) string {
	// In a real implementation, this would use yaml.Marshal
	return fmt.Sprintf("workflow: %+v", workflow)
}

func (te *TemplateEngine) stringToWorkflow(content string) (Workflow, error) {
	// In a real implementation, this would use yaml.Unmarshal
	// For now, return the original workflow
	return Workflow{}, nil
}

// Utility functions

func generateTemplateInstanceID() string {
	return fmt.Sprintf("instance_%d", time.Now().UnixNano())
}