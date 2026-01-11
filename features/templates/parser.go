// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package templates

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultTemplateEngine implements the TemplateEngine interface
type DefaultTemplateEngine struct {
	functions   map[string]interface{}
	store       TemplateStore
	dnaProvider DNAProvider
}

// NewTemplateEngine creates a new template engine
func NewTemplateEngine(store TemplateStore, dnaProvider DNAProvider) TemplateEngine {
	engine := &DefaultTemplateEngine{
		functions:   make(map[string]interface{}),
		store:       store,
		dnaProvider: dnaProvider,
	}

	// Register built-in functions
	engine.registerBuiltinFunctions()

	return engine
}

// Parse parses a template and returns a Template object
func (e *DefaultTemplateEngine) Parse(ctx context.Context, content []byte, options ParseOptions) (*Template, error) {
	template := &Template{
		Content:   content,
		Variables: make(map[string]interface{}),
		Includes:  []string{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Parse the template content
	if err := e.parseTemplate(template, options); err != nil {
		return nil, err
	}

	return template, nil
}

// Render renders a template with the given context
func (e *DefaultTemplateEngine) Render(ctx context.Context, template *Template, templateContext *TemplateContext, options RenderOptions) (*RenderResult, error) {
	startTime := time.Now()

	result := &RenderResult{
		Variables: make(map[string]interface{}),
		Templates: []string{template.ID},
		Warnings:  []TemplateWarning{},
		Metadata:  make(map[string]interface{}),
	}

	// Set timeout
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Render the template
	rendered, err := e.renderTemplate(ctx, template, templateContext, options, result)
	if err != nil {
		return nil, err
	}

	result.Content = rendered
	result.Duration = time.Since(startTime)

	return result, nil
}

// Validate validates a template for syntax and semantic errors
func (e *DefaultTemplateEngine) Validate(ctx context.Context, template *Template) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:             true,
		Errors:            []ValidationError{},
		Warnings:          []ValidationWarning{},
		UsedVariables:     []string{},
		RequiredFunctions: []string{},
		Dependencies:      []string{},
	}

	// Parse and validate syntax
	if err := e.validateSyntax(template, result); err != nil {
		return result, err
	}

	// Validate variable references
	e.validateVariables(template, result)

	// Validate function calls
	e.validateFunctions(template, result)

	// Validate dependencies
	e.validateDependencies(template, result)

	result.Valid = len(result.Errors) == 0

	return result, nil
}

// RegisterFunction adds a custom function to the engine
func (e *DefaultTemplateEngine) RegisterFunction(name string, fn interface{}) error {
	e.functions[name] = fn
	return nil
}

// ListFunctions returns available template functions
func (e *DefaultTemplateEngine) ListFunctions() []string {
	functions := make([]string, 0, len(e.functions))
	for name := range e.functions {
		functions = append(functions, name)
	}
	return functions
}

// Template parsing methods

func (e *DefaultTemplateEngine) parseTemplate(template *Template, options ParseOptions) error {
	content := string(template.Content)
	lines := strings.Split(content, "\n")

	var variables map[string]interface{}
	var extends string
	var includes []string

	// Look for variables section at the top
	if variables, content = e.extractVariables(content); variables != nil {
		template.Variables = variables
	}

	// Look for $extend directive
	if extends, content = e.extractExtends(content); extends != "" {
		template.Extends = extends
	}

	// Look for $include directives
	includes = e.extractIncludes(content)
	template.Includes = includes

	// Validate syntax
	if err := e.validateTemplateSyntax(lines, options); err != nil {
		return err
	}

	// Update content with processed version
	template.Content = []byte(content)

	return nil
}

func (e *DefaultTemplateEngine) extractVariables(content string) (map[string]interface{}, string) {
	lines := strings.Split(content, "\n")
	var variableLines []string
	var remainingLines []string
	inVariables := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "variables:" {
			inVariables = true
			continue
		}

		if inVariables {
			// Check if we're still in the variables section
			if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") || trimmed == "" {
				variableLines = append(variableLines, line)
			} else {
				// End of variables section
				remainingLines = append(remainingLines, lines[i:]...)
				break
			}
		} else if !inVariables {
			remainingLines = append(remainingLines, line)
		}
	}

	if len(variableLines) == 0 {
		return nil, content
	}

	// Parse variables YAML
	variablesYAML := "variables:\n" + strings.Join(variableLines, "\n")
	var parsed struct {
		Variables map[string]interface{} `yaml:"variables"`
	}

	if err := yaml.Unmarshal([]byte(variablesYAML), &parsed); err != nil {
		return nil, content
	}

	return parsed.Variables, strings.Join(remainingLines, "\n")
}

func (e *DefaultTemplateEngine) extractExtends(content string) (string, string) {
	re := regexp.MustCompile(`^\$extend\s+"([^"]+)"`)
	lines := strings.Split(content, "\n")
	var extends string
	var remainingLines []string

	for _, line := range lines {
		if match := re.FindStringSubmatch(strings.TrimSpace(line)); match != nil {
			extends = match[1]
		} else {
			remainingLines = append(remainingLines, line)
		}
	}

	return extends, strings.Join(remainingLines, "\n")
}

func (e *DefaultTemplateEngine) extractIncludes(content string) []string {
	re := regexp.MustCompile(`\$include\s+"([^"]+)"`)
	matches := re.FindAllStringSubmatch(content, -1)

	var includes []string
	for _, match := range matches {
		includes = append(includes, match[1])
	}

	return includes
}

func (e *DefaultTemplateEngine) validateTemplateSyntax(lines []string, options ParseOptions) error {
	// Track control flow nesting
	var stack []string

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check for control flow directives
		if strings.HasPrefix(trimmed, "$if ") {
			stack = append(stack, "if")
		} else if strings.HasPrefix(trimmed, "$elif ") {
			if len(stack) == 0 || stack[len(stack)-1] != "if" {
				return &TemplateError{
					Type:    "INVALID_SYNTAX",
					Message: "$elif without matching $if",
					Line:    i + 1,
				}
			}
		} else if trimmed == "$else" {
			if len(stack) == 0 || stack[len(stack)-1] != "if" {
				return &TemplateError{
					Type:    "INVALID_SYNTAX",
					Message: "$else without matching $if",
					Line:    i + 1,
				}
			}
		} else if trimmed == "$endif" {
			if len(stack) == 0 || stack[len(stack)-1] != "if" {
				return &TemplateError{
					Type:    "INVALID_SYNTAX",
					Message: "$endif without matching $if",
					Line:    i + 1,
				}
			}
			stack = stack[:len(stack)-1]
		} else if strings.HasPrefix(trimmed, "$for ") {
			stack = append(stack, "for")
		} else if trimmed == "$endfor" {
			if len(stack) == 0 || stack[len(stack)-1] != "for" {
				return &TemplateError{
					Type:    "INVALID_SYNTAX",
					Message: "$endfor without matching $for",
					Line:    i + 1,
				}
			}
			stack = stack[:len(stack)-1]
		}
	}

	// Check for unclosed blocks
	if len(stack) > 0 {
		return &TemplateError{
			Type:    "INVALID_SYNTAX",
			Message: fmt.Sprintf("Unclosed %s block", stack[len(stack)-1]),
		}
	}

	return nil
}

// Template rendering methods

func (e *DefaultTemplateEngine) renderTemplate(ctx context.Context, template *Template, templateContext *TemplateContext, options RenderOptions, result *RenderResult) ([]byte, error) {
	content := string(template.Content)

	// Process variable substitutions
	content = e.processVariables(content, templateContext, result)

	// Process control flow
	content, err := e.processControlFlow(content, templateContext, result)
	if err != nil {
		return nil, err
	}

	// Process includes
	content, err = e.processIncludes(ctx, content, templateContext, options, result)
	if err != nil {
		return nil, err
	}

	return []byte(content), nil
}

func (e *DefaultTemplateEngine) processVariables(content string, context *TemplateContext, result *RenderResult) string {
	// Control flow keywords that should not be treated as variables
	controlFlowKeywords := map[string]bool{
		"if":      true,
		"elif":    true,
		"else":    true,
		"endif":   true,
		"for":     true,
		"endfor":  true,
		"include": true,
		"extend":  true,
	}

	// Replace $variable references (but not control flow)
	re := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_.]*)`)

	return re.ReplaceAllStringFunc(content, func(match string) string {
		varName := match[1:] // Remove the $

		// Skip control flow keywords
		if controlFlowKeywords[varName] {
			return match
		}

		// Check for DNA properties
		if strings.HasPrefix(varName, "DNA.") {
			if value, exists := e.getDNAProperty(varName[4:], context.DNA); exists {
				return fmt.Sprintf("%v", value)
			}
		}

		// Check variables in precedence order
		if value, exists := context.Variables[varName]; exists {
			return fmt.Sprintf("%v", value)
		}

		// Variable not found - add warning
		result.Warnings = append(result.Warnings, TemplateWarning{
			Type:    "UNDEFINED_VARIABLE",
			Message: fmt.Sprintf("Variable '%s' is undefined", varName),
		})

		return match // Return original if not found
	})
}

func (e *DefaultTemplateEngine) getDNAProperty(property string, dna map[string]interface{}) (interface{}, bool) {
	parts := strings.Split(property, ".")
	current := dna

	for _, part := range parts {
		if current == nil {
			return nil, false
		}

		if value, exists := current[part]; exists {
			if i := len(parts) - 1; part == parts[i] {
				return value, true
			}
			if next, ok := value.(map[string]interface{}); ok {
				current = next
			} else {
				return nil, false
			}
		} else {
			return nil, false
		}
	}

	return nil, false
}

func (e *DefaultTemplateEngine) processControlFlow(content string, context *TemplateContext, result *RenderResult) (string, error) {
	lines := strings.Split(content, "\n")
	var output []string
	var skip []bool // Stack to track if we should skip lines

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Handle control flow
		if strings.HasPrefix(trimmed, "$if ") {
			condition := strings.TrimSpace(trimmed[4:])
			shouldInclude, err := e.evaluateCondition(condition, context)
			if err != nil {
				return "", err
			}
			skip = append(skip, !shouldInclude)
			continue
		} else if strings.HasPrefix(trimmed, "$elif ") {
			if len(skip) > 0 {
				condition := strings.TrimSpace(trimmed[6:])
				shouldInclude, err := e.evaluateCondition(condition, context)
				if err != nil {
					return "", err
				}
				skip[len(skip)-1] = !shouldInclude
			}
			continue
		} else if trimmed == "$else" {
			if len(skip) > 0 {
				skip[len(skip)-1] = !skip[len(skip)-1]
			}
			continue
		} else if trimmed == "$endif" {
			if len(skip) > 0 {
				skip = skip[:len(skip)-1]
			}
			continue
		}

		// Check if we should skip this line
		shouldSkip := false
		for _, s := range skip {
			if s {
				shouldSkip = true
				break
			}
		}

		if !shouldSkip {
			output = append(output, line)
		}
	}

	return strings.Join(output, "\n"), nil
}

func (e *DefaultTemplateEngine) evaluateCondition(condition string, context *TemplateContext) (bool, error) {
	// Simple condition evaluation - in production would use a proper expression parser

	// Handle equality checks
	if strings.Contains(condition, "==") {
		parts := strings.Split(condition, "==")
		if len(parts) != 2 {
			return false, fmt.Errorf("invalid condition: %s", condition)
		}

		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])

		// Remove quotes
		left = strings.Trim(left, "\"'")
		right = strings.Trim(right, "\"'")

		// Resolve variables
		leftVal := e.resolveValue(left, context)
		rightVal := e.resolveValue(right, context)

		return fmt.Sprintf("%v", leftVal) == fmt.Sprintf("%v", rightVal), nil
	}

	// Handle boolean variables
	condition = strings.Trim(condition, "\"'")
	if strings.HasPrefix(condition, "$") {
		varName := condition[1:]
		if value, exists := context.Variables[varName]; exists {
			if boolVal, ok := value.(bool); ok {
				return boolVal, nil
			}
		}
	}

	// Handle literal boolean values
	if condition == "true" {
		return true, nil
	}
	if condition == "false" {
		return false, nil
	}

	return false, fmt.Errorf("unsupported condition: %s", condition)
}

func (e *DefaultTemplateEngine) resolveValue(value string, context *TemplateContext) interface{} {
	if strings.HasPrefix(value, "$") {
		varName := value[1:]

		// Check for DNA properties
		if strings.HasPrefix(varName, "DNA.") {
			if dnaValue, exists := e.getDNAProperty(varName[4:], context.DNA); exists {
				return dnaValue
			}
		}

		// Check variables
		if varValue, exists := context.Variables[varName]; exists {
			return varValue
		}
	}

	// Try to parse as number
	if intVal, err := strconv.Atoi(value); err == nil {
		return intVal
	}

	if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
		return floatVal
	}

	// Try to parse as boolean
	if boolVal, err := strconv.ParseBool(value); err == nil {
		return boolVal
	}

	return value
}

func (e *DefaultTemplateEngine) processIncludes(ctx context.Context, content string, context *TemplateContext, options RenderOptions, result *RenderResult) (string, error) {
	re := regexp.MustCompile(`\$include\s+"([^"]+)"`)

	return re.ReplaceAllStringFunc(content, func(match string) string {
		matches := re.FindStringSubmatch(match)
		if len(matches) < 2 {
			return match
		}

		templateID := matches[1]

		// Load included template
		includedTemplate, err := e.store.Get(ctx, templateID)
		if err != nil {
			result.Warnings = append(result.Warnings, TemplateWarning{
				Type:    "INCLUDE_ERROR",
				Message: fmt.Sprintf("Failed to load included template '%s': %v", templateID, err),
			})
			return match
		}

		// Render included template
		includedResult, err := e.renderTemplate(ctx, includedTemplate, context, options, result)
		if err != nil {
			result.Warnings = append(result.Warnings, TemplateWarning{
				Type:    "INCLUDE_ERROR",
				Message: fmt.Sprintf("Failed to render included template '%s': %v", templateID, err),
			})
			return match
		}

		result.Templates = append(result.Templates, templateID)
		return string(includedResult)
	}), nil
}

// Validation methods

func (e *DefaultTemplateEngine) validateSyntax(template *Template, result *ValidationResult) error {
	lines := strings.Split(string(template.Content), "\n")
	return e.validateTemplateSyntax(lines, ParseOptions{})
}

func (e *DefaultTemplateEngine) validateVariables(template *Template, result *ValidationResult) {
	content := string(template.Content)
	re := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_.]*)`)

	matches := re.FindAllStringSubmatch(content, -1)
	usedVars := make(map[string]bool)

	for _, match := range matches {
		varName := match[1]
		usedVars[varName] = true
	}

	for varName := range usedVars {
		result.UsedVariables = append(result.UsedVariables, varName)
	}
}

func (e *DefaultTemplateEngine) validateFunctions(template *Template, result *ValidationResult) {
	// Function validation would go here
	// For now, we'll assume all referenced functions are valid
}

func (e *DefaultTemplateEngine) validateDependencies(template *Template, result *ValidationResult) {
	result.Dependencies = append(result.Dependencies, template.Includes...)
	if template.Extends != "" {
		result.Dependencies = append(result.Dependencies, template.Extends)
	}
}

// Built-in functions registration

func (e *DefaultTemplateEngine) registerBuiltinFunctions() {
	// String functions
	e.functions["string.lower"] = strings.ToLower
	e.functions["string.upper"] = strings.ToUpper
	e.functions["string.trim"] = strings.TrimSpace
	e.functions["string.replace"] = strings.ReplaceAll

	// Math functions
	e.functions["math.add"] = func(a, b interface{}) interface{} {
		return e.toFloat(a) + e.toFloat(b)
	}
	e.functions["math.sub"] = func(a, b interface{}) interface{} {
		return e.toFloat(a) - e.toFloat(b)
	}
	e.functions["math.mul"] = func(a, b interface{}) interface{} {
		return e.toFloat(a) * e.toFloat(b)
	}

	// Utility functions
	e.functions["default"] = func(value, defaultValue interface{}) interface{} {
		if value == nil {
			return defaultValue
		}
		return value
	}
}

func (e *DefaultTemplateEngine) toFloat(value interface{}) float64 {
	switch v := value.(type) {
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case float64:
		return v
	case float32:
		return float64(v)
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0
}
