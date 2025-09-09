// Package templates provides a configuration template engine for CFGMS.
// It enables dynamic, reusable configurations with variable substitution,
// conditionals, loops, and integration with DNA properties and config inheritance.
package templates

import (
	"context"
	"fmt"
	"time"
)

// Template represents a configuration template
type Template struct {
	// ID is the unique template identifier
	ID string `json:"id"`
	
	// Name is the human-readable template name
	Name string `json:"name"`
	
	// Content is the raw template content
	Content []byte `json:"content"`
	
	// Variables are the declared variables in the template
	Variables map[string]interface{} `json:"variables"`
	
	// Extends references parent template for inheritance
	Extends string `json:"extends,omitempty"`
	
	// Includes are templates included by this template
	Includes []string `json:"includes"`
	
	// Version is the template version
	Version string `json:"version"`
	
	// Description describes the template purpose
	Description string `json:"description"`
	
	// Tags are metadata tags for the template
	Tags []string `json:"tags"`
	
	// CreatedAt is when the template was created
	CreatedAt time.Time `json:"created_at"`
	
	// UpdatedAt is when the template was last updated
	UpdatedAt time.Time `json:"updated_at"`
	
	// Metadata contains additional template information
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// TemplateContext provides the execution context for template rendering
type TemplateContext struct {
	// Variables are the resolved variables (local + inherited + DNA)
	Variables map[string]interface{}
	
	// DNA contains real-time system properties
	DNA map[string]interface{}
	
	// InheritedVariables from parent configurations
	InheritedVariables map[string]interface{}
	
	// LocalVariables declared in the current template
	LocalVariables map[string]interface{}
	
	// Functions are available template functions
	Functions map[string]interface{}
	
	// TargetType is what type of entity this template targets
	TargetType string
	
	// TargetID is the ID of the target entity
	TargetID string
}

// RenderOptions configure template rendering behavior
type RenderOptions struct {
	// MaxDepth limits template inheritance depth
	MaxDepth int
	
	// MaxIncludes limits number of included templates
	MaxIncludes int
	
	// Timeout for template rendering
	Timeout time.Duration
	
	// StrictMode fails on undefined variables
	StrictMode bool
	
	// ValidateOutput validates rendered configuration
	ValidateOutput bool
	
	// SandboxMode enables security sandbox
	SandboxMode bool
}

// RenderResult contains the result of template rendering
type RenderResult struct {
	// Content is the rendered configuration
	Content []byte
	
	// Variables used during rendering
	Variables map[string]interface{}
	
	// Templates that were processed
	Templates []string
	
	// Duration of rendering
	Duration time.Duration
	
	// Warnings generated during rendering
	Warnings []TemplateWarning
	
	// Metadata about the rendering process
	Metadata map[string]interface{}
}

// TemplateWarning represents a non-fatal issue during rendering
type TemplateWarning struct {
	// Type of warning
	Type string
	
	// Message describing the warning
	Message string
	
	// Line number in the template (if applicable)
	Line int
	
	// Column number in the template (if applicable)
	Column int
	
	// Context provides additional information
	Context map[string]interface{}
}

// TemplateEngine handles template parsing and execution
type TemplateEngine interface {
	// Parse parses a template and returns a Template object
	Parse(ctx context.Context, content []byte, options ParseOptions) (*Template, error)
	
	// Render renders a template with the given context
	Render(ctx context.Context, template *Template, context *TemplateContext, options RenderOptions) (*RenderResult, error)
	
	// Validate validates a template for syntax and semantic errors
	Validate(ctx context.Context, template *Template) (*ValidationResult, error)
	
	// RegisterFunction adds a custom function to the engine
	RegisterFunction(name string, fn interface{}) error
	
	// ListFunctions returns available template functions
	ListFunctions() []string
}

// ParseOptions configure template parsing behavior
type ParseOptions struct {
	// AllowUndefinedVariables permits undefined variable references
	AllowUndefinedVariables bool
	
	// MaxVariableDepth limits variable reference depth
	MaxVariableDepth int
	
	// StrictSyntax enforces strict template syntax
	StrictSyntax bool
}

// ValidationResult contains template validation results
type ValidationResult struct {
	// Valid indicates if the template is valid
	Valid bool
	
	// Errors are validation errors that prevent rendering
	Errors []ValidationError
	
	// Warnings are non-fatal validation issues
	Warnings []ValidationWarning
	
	// UsedVariables are variables referenced in the template
	UsedVariables []string
	
	// RequiredFunctions are functions required by the template
	RequiredFunctions []string
	
	// Dependencies are templates this template depends on
	Dependencies []string
}

// ValidationError represents a template validation error
type ValidationError struct {
	// Type of error
	Type string
	
	// Message describing the error
	Message string
	
	// Line number where error occurred
	Line int
	
	// Column number where error occurred
	Column int
	
	// Context provides additional error information
	Context map[string]interface{}
}

// ValidationWarning represents a template validation warning
type ValidationWarning struct {
	// Type of warning
	Type string
	
	// Message describing the warning
	Message string
	
	// Line number where warning occurred
	Line int
	
	// Column number where warning occurred
	Column int
	
	// Context provides additional warning information
	Context map[string]interface{}
}

// TemplateStore handles template storage and retrieval
type TemplateStore interface {
	// Get retrieves a template by ID
	Get(ctx context.Context, id string) (*Template, error)
	
	// Save saves a template
	Save(ctx context.Context, template *Template) error
	
	// Delete deletes a template
	Delete(ctx context.Context, id string) error
	
	// List lists templates matching the filter
	List(ctx context.Context, filter TemplateFilter) ([]*Template, error)
	
	// Exists checks if a template exists
	Exists(ctx context.Context, id string) (bool, error)
}

// TemplateFilter defines criteria for listing templates
type TemplateFilter struct {
	// Tags to filter by
	Tags []string
	
	// NamePattern to match template names
	NamePattern string
	
	// CreatedAfter filters templates created after this time
	CreatedAfter *time.Time
	
	// CreatedBefore filters templates created before this time
	CreatedBefore *time.Time
	
	// Limit results
	Limit int
	
	// Offset for pagination
	Offset int
}

// DNAProvider provides access to DNA properties
type DNAProvider interface {
	// GetDNA returns DNA properties for a target
	GetDNA(ctx context.Context, targetType, targetID string) (map[string]interface{}, error)
	
	// GetProperty returns a specific DNA property
	GetProperty(ctx context.Context, targetType, targetID, property string) (interface{}, error)
	
	// ListProperties returns available DNA properties for a target
	ListProperties(ctx context.Context, targetType, targetID string) ([]string, error)
}

// VariableResolver resolves variables from multiple sources
type VariableResolver interface {
	// Resolve resolves all variables for a template context
	Resolve(ctx context.Context, template *Template, targetType, targetID string) (*TemplateContext, error)
	
	// ResolveVariable resolves a specific variable
	ResolveVariable(ctx context.Context, name string, context *TemplateContext) (interface{}, error)
	
	// GetPrecedence returns variable precedence order
	GetPrecedence() []string
}

// TemplateInheritance handles template inheritance and extension
type TemplateInheritance interface {
	// GetParent returns the parent template
	GetParent(ctx context.Context, template *Template) (*Template, error)
	
	// MergeTemplates merges child template with parent
	MergeTemplates(ctx context.Context, child, parent *Template) (*Template, error)
	
	// ResolveInheritance resolves the full inheritance chain
	ResolveInheritance(ctx context.Context, template *Template) (*Template, error)
}

// Built-in template function types

// StringFunction defines string manipulation functions
type StringFunction interface {
	Lower(s string) string
	Upper(s string) string
	Trim(s string) string
	Replace(s, old, new string) string
	Split(s, sep string) []string
	Join(slice []string, sep string) string
	Contains(s, substr string) bool
	HasPrefix(s, prefix string) bool
	HasSuffix(s, suffix string) bool
}

// MathFunction defines mathematical functions
type MathFunction interface {
	Add(a, b interface{}) (interface{}, error)
	Sub(a, b interface{}) (interface{}, error)
	Mul(a, b interface{}) (interface{}, error)
	Div(a, b interface{}) (interface{}, error)
	Mod(a, b interface{}) (interface{}, error)
	Max(a, b interface{}) (interface{}, error)
	Min(a, b interface{}) (interface{}, error)
	Abs(a interface{}) (interface{}, error)
}

// LogicFunction defines logical operations
type LogicFunction interface {
	And(values ...bool) bool
	Or(values ...bool) bool
	Not(value bool) bool
	If(condition bool, trueVal, falseVal interface{}) interface{}
}

// DataFunction defines data manipulation functions
type DataFunction interface {
	First(slice []interface{}) interface{}
	Last(slice []interface{}) interface{}
	Index(slice []interface{}, i int) interface{}
	Length(data interface{}) int
	Filter(slice []interface{}, predicate func(interface{}) bool) []interface{}
	Map(slice []interface{}, transform func(interface{}) interface{}) []interface{}
	Contains(slice []interface{}, item interface{}) bool
}

// TimeFunction defines time and date functions
type TimeFunction interface {
	Now() time.Time
	Format(t time.Time, layout string) string
	Parse(value, layout string) (time.Time, error)
	Add(t time.Time, duration time.Duration) time.Time
	Sub(t1, t2 time.Time) time.Duration
}

// Error types

// TemplateError represents a template-related error
type TemplateError struct {
	Type    string
	Message string
	Line    int
	Column  int
	Context map[string]interface{}
}

func (e *TemplateError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s at line %d, column %d: %s", e.Type, e.Line, e.Column, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Common template errors
var (
	ErrTemplateNotFound = &TemplateError{
		Type:    "TEMPLATE_NOT_FOUND",
		Message: "Template not found",
	}
	
	ErrInvalidSyntax = &TemplateError{
		Type:    "INVALID_SYNTAX",
		Message: "Invalid template syntax",
	}
	
	ErrUndefinedVariable = &TemplateError{
		Type:    "UNDEFINED_VARIABLE",
		Message: "Undefined variable",
	}
	
	ErrCircularDependency = &TemplateError{
		Type:    "CIRCULAR_DEPENDENCY",
		Message: "Circular template dependency",
	}
	
	ErrRenderTimeout = &TemplateError{
		Type:    "RENDER_TIMEOUT",
		Message: "Template rendering timeout",
	}
	
	ErrInvalidFunction = &TemplateError{
		Type:    "INVALID_FUNCTION",
		Message: "Invalid template function",
	}
)