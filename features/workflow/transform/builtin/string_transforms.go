// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package builtin provides built-in transform implementations
//
// This package contains ready-to-use transforms that demonstrate the extensible
// transform framework and provide common data transformation capabilities.
// These transforms serve as both functional tools and examples for implementing
// custom transforms.
package builtin

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/workflow/transform"
)

// StringTransform categories and implementations

// UppercaseTransform converts strings to uppercase
type UppercaseTransform struct {
	transform.BaseTransform
}

// NewUppercaseTransform creates a new uppercase transform
func NewUppercaseTransform() *UppercaseTransform {
	t := &UppercaseTransform{}

	// Set metadata
	t.SetMetadata(transform.TransformMetadata{
		Name:        "uppercase",
		Version:     "1.0.0",
		Description: "Converts input strings to uppercase",
		Category:    transform.CategoryString,
		Tags:        []string{"string", "case", "text"},
		Author:      "CFGMS",
		Examples: []transform.TransformExample{
			{
				Name:        "Basic uppercase",
				Description: "Convert a simple string to uppercase",
				Input:       map[string]interface{}{"text": "hello world"},
				Config:      map[string]interface{}{},
				Output:      map[string]interface{}{"text": "HELLO WORLD"},
			},
		},
		SupportsChaining: true,
	})

	// Set schema
	t.SetSchema(transform.TransformSchema{
		InputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"text": {
					Type:        "string",
					Description: "The text to convert to uppercase",
				},
			},
			Required: []string{"text"},
		},
		OutputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"text": {
					Type:        "string",
					Description: "The uppercased text",
				},
			},
		},
		ConfigSchema: transform.SchemaDefinition{
			Type:        "object",
			Description: "No configuration required",
		},
	})

	return t
}

// Execute performs the uppercase transformation
func (t *UppercaseTransform) Execute(ctx context.Context, transformCtx transform.TransformContext) (transform.TransformResult, error) {
	startTime := time.Now()

	text := transformCtx.GetString("text")
	if text == "" {
		return transform.TransformResult{
			Success: false,
			Error:   "input 'text' is required and must be a non-empty string",
		}, nil
	}

	result := transform.TransformResult{
		Data: map[string]interface{}{
			"text": strings.ToUpper(text),
		},
		Success:  true,
		Duration: time.Since(startTime),
	}

	return result, nil
}

// Validate validates the transform configuration
func (t *UppercaseTransform) Validate(config map[string]interface{}) error {
	// No configuration validation needed for this simple transform
	return nil
}

// LowercaseTransform converts strings to lowercase
type LowercaseTransform struct {
	transform.BaseTransform
}

// NewLowercaseTransform creates a new lowercase transform
func NewLowercaseTransform() *LowercaseTransform {
	t := &LowercaseTransform{}

	t.SetMetadata(transform.TransformMetadata{
		Name:        "lowercase",
		Version:     "1.0.0",
		Description: "Converts input strings to lowercase",
		Category:    transform.CategoryString,
		Tags:        []string{"string", "case", "text"},
		Author:      "CFGMS",
		Examples: []transform.TransformExample{
			{
				Name:        "Basic lowercase",
				Description: "Convert a simple string to lowercase",
				Input:       map[string]interface{}{"text": "HELLO WORLD"},
				Config:      map[string]interface{}{},
				Output:      map[string]interface{}{"text": "hello world"},
			},
		},
		SupportsChaining: true,
	})

	t.SetSchema(transform.TransformSchema{
		InputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"text": {Type: "string", Description: "The text to convert to lowercase"},
			},
			Required: []string{"text"},
		},
		OutputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"text": {Type: "string", Description: "The lowercased text"},
			},
		},
	})

	return t
}

// Execute performs the lowercase transformation
func (t *LowercaseTransform) Execute(ctx context.Context, transformCtx transform.TransformContext) (transform.TransformResult, error) {
	startTime := time.Now()

	text := transformCtx.GetString("text")
	if text == "" {
		return transform.TransformResult{
			Success: false,
			Error:   "input 'text' is required and must be a non-empty string",
		}, nil
	}

	return transform.TransformResult{
		Data: map[string]interface{}{
			"text": strings.ToLower(text),
		},
		Success:  true,
		Duration: time.Since(startTime),
	}, nil
}

// TrimTransform removes whitespace from strings
type TrimTransform struct {
	transform.BaseTransform
}

// NewTrimTransform creates a new trim transform
func NewTrimTransform() *TrimTransform {
	t := &TrimTransform{}

	t.SetMetadata(transform.TransformMetadata{
		Name:        "trim",
		Version:     "1.0.0",
		Description: "Removes leading and trailing whitespace from strings",
		Category:    transform.CategoryString,
		Tags:        []string{"string", "whitespace", "clean"},
		Author:      "CFGMS",
		Examples: []transform.TransformExample{
			{
				Name:        "Basic trim",
				Description: "Remove whitespace from a string",
				Input:       map[string]interface{}{"text": "  hello world  "},
				Config:      map[string]interface{}{},
				Output:      map[string]interface{}{"text": "hello world"},
			},
			{
				Name:        "Custom characters",
				Description: "Remove custom characters",
				Input:       map[string]interface{}{"text": "...hello world..."},
				Config:      map[string]interface{}{"characters": "."},
				Output:      map[string]interface{}{"text": "hello world"},
			},
		},
		SupportsChaining: true,
	})

	t.SetSchema(transform.TransformSchema{
		InputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"text": {Type: "string", Description: "The text to trim"},
			},
			Required: []string{"text"},
		},
		OutputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"text": {Type: "string", Description: "The trimmed text"},
			},
		},
		ConfigSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"characters": {
					Type:        "string",
					Description: "Custom characters to trim (default: whitespace)",
				},
			},
		},
	})

	return t
}

// Execute performs the trim transformation
func (t *TrimTransform) Execute(ctx context.Context, transformCtx transform.TransformContext) (transform.TransformResult, error) {
	startTime := time.Now()

	text := transformCtx.GetString("text")
	characters := transformCtx.GetConfigString("characters")

	var result string
	if characters != "" {
		result = strings.Trim(text, characters)
	} else {
		result = strings.TrimSpace(text)
	}

	return transform.TransformResult{
		Data: map[string]interface{}{
			"text": result,
		},
		Success:  true,
		Duration: time.Since(startTime),
	}, nil
}

// ReplaceTransform performs string replacement
type ReplaceTransform struct {
	transform.BaseTransform
}

// NewReplaceTransform creates a new replace transform
func NewReplaceTransform() *ReplaceTransform {
	t := &ReplaceTransform{}

	t.SetMetadata(transform.TransformMetadata{
		Name:        "replace",
		Version:     "1.0.0",
		Description: "Replaces occurrences of a substring or regex pattern in text",
		Category:    transform.CategoryString,
		Tags:        []string{"string", "replace", "regex", "substitute"},
		Author:      "CFGMS",
		Examples: []transform.TransformExample{
			{
				Name:        "Simple replace",
				Description: "Replace all occurrences of a substring",
				Input:       map[string]interface{}{"text": "hello world hello"},
				Config: map[string]interface{}{
					"old": "hello",
					"new": "hi",
				},
				Output: map[string]interface{}{"text": "hi world hi"},
			},
			{
				Name:        "Regex replace",
				Description: "Replace using regex pattern",
				Input:       map[string]interface{}{"text": "phone: 123-456-7890"},
				Config: map[string]interface{}{
					"pattern": "\\d{3}-\\d{3}-\\d{4}",
					"new":     "XXX-XXX-XXXX",
					"regex":   true,
				},
				Output: map[string]interface{}{"text": "phone: XXX-XXX-XXXX"},
			},
		},
		SupportsChaining: true,
	})

	t.SetSchema(transform.TransformSchema{
		InputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"text": {Type: "string", Description: "The text to perform replacement on"},
			},
			Required: []string{"text"},
		},
		OutputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"text": {Type: "string", Description: "The text with replacements applied"},
			},
		},
		ConfigSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"old": {
					Type:        "string",
					Description: "The substring to replace (used when regex=false)",
				},
				"pattern": {
					Type:        "string",
					Description: "The regex pattern to replace (used when regex=true)",
				},
				"new": {
					Type:        "string",
					Description: "The replacement text",
				},
				"regex": {
					Type:        "boolean",
					Description: "Whether to use regex matching (default: false)",
				},
				"max_replacements": {
					Type:        "number",
					Description: "Maximum number of replacements to make (-1 for all, default: -1)",
				},
			},
			Required: []string{"new"},
		},
	})

	return t
}

// Execute performs the replace transformation
func (t *ReplaceTransform) Execute(ctx context.Context, transformCtx transform.TransformContext) (transform.TransformResult, error) {
	startTime := time.Now()

	text := transformCtx.GetString("text")
	newText := transformCtx.GetConfigString("new")
	useRegex := transformCtx.GetConfigBool("regex")
	maxReplacements := transformCtx.GetConfigInt("max_replacements")

	if maxReplacements == 0 {
		maxReplacements = -1 // Default to replace all
	}

	var result string

	if useRegex {
		pattern := transformCtx.GetConfigString("pattern")
		if pattern == "" {
			return transform.TransformResult{
				Success: false,
				Error:   "pattern is required when regex=true",
			}, nil
		}

		regex, err := regexp.Compile(pattern)
		if err != nil {
			return transform.TransformResult{
				Success: false,
				Error:   fmt.Sprintf("invalid regex pattern: %v", err),
			}, nil
		}

		if maxReplacements == -1 {
			result = regex.ReplaceAllString(text, newText)
		} else {
			// For limited replacements with regex, we need to do it manually
			matches := regex.FindAllStringIndex(text, maxReplacements)
			result = text
			offset := 0
			for _, match := range matches {
				start := match[0] + offset
				end := match[1] + offset
				original := result[start:end]
				replacement := regex.ReplaceAllString(original, newText)
				result = result[:start] + replacement + result[end:]
				offset += len(replacement) - len(original)
			}
		}
	} else {
		old := transformCtx.GetConfigString("old")
		if old == "" {
			return transform.TransformResult{
				Success: false,
				Error:   "old is required when regex=false",
			}, nil
		}

		if maxReplacements == -1 {
			result = strings.ReplaceAll(text, old, newText)
		} else {
			result = strings.Replace(text, old, newText, maxReplacements)
		}
	}

	return transform.TransformResult{
		Data: map[string]interface{}{
			"text": result,
		},
		Success:  true,
		Duration: time.Since(startTime),
	}, nil
}

// Validate validates the replace transform configuration
func (t *ReplaceTransform) Validate(config map[string]interface{}) error {
	if config == nil {
		return fmt.Errorf("configuration is required")
	}

	// Check required fields
	if _, exists := config["new"]; !exists {
		return fmt.Errorf("'new' field is required")
	}

	useRegex := false
	if regexVal, exists := config["regex"]; exists {
		if regexBool, ok := regexVal.(bool); ok {
			useRegex = regexBool
		}
	}

	if useRegex {
		if _, exists := config["pattern"]; !exists {
			return fmt.Errorf("'pattern' field is required when regex=true")
		}
		// Test the regex pattern
		if pattern, ok := config["pattern"].(string); ok {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("invalid regex pattern: %v", err)
			}
		}
	} else {
		if _, exists := config["old"]; !exists {
			return fmt.Errorf("'old' field is required when regex=false")
		}
	}

	return nil
}

// FormatTransform performs string formatting with variables
type FormatTransform struct {
	transform.BaseTransform
}

// NewFormatTransform creates a new format transform
func NewFormatTransform() *FormatTransform {
	t := &FormatTransform{}

	t.SetMetadata(transform.TransformMetadata{
		Name:        "format",
		Version:     "1.0.0",
		Description: "Formats strings using template variables from workflow context",
		Category:    transform.CategoryString,
		Tags:        []string{"string", "format", "template", "variables"},
		Author:      "CFGMS",
		Examples: []transform.TransformExample{
			{
				Name:        "Simple formatting",
				Description: "Format a string with variables",
				Input: map[string]interface{}{
					"template": "Hello, {name}! You have {count} messages.",
					"name":     "Alice",
					"count":    5,
				},
				Config: map[string]interface{}{},
				Output: map[string]interface{}{"text": "Hello, Alice! You have 5 messages."},
			},
		},
		SupportsChaining: true,
	})

	t.SetSchema(transform.TransformSchema{
		InputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"template": {Type: "string", Description: "The template string with {variable} placeholders"},
			},
			Required: []string{"template"},
		},
		OutputSchema: transform.SchemaDefinition{
			Type: "object",
			Properties: map[string]transform.SchemaDefinition{
				"text": {Type: "string", Description: "The formatted text"},
			},
		},
	})

	return t
}

// Execute performs the format transformation
func (t *FormatTransform) Execute(ctx context.Context, transformCtx transform.TransformContext) (transform.TransformResult, error) {
	startTime := time.Now()

	template := transformCtx.GetString("template")
	if template == "" {
		return transform.TransformResult{
			Success: false,
			Error:   "template is required",
		}, nil
	}

	// Get all available data for variable substitution
	data := transformCtx.GetData()
	variables := transformCtx.GetVariables()

	// Combine data and variables for substitution
	allVars := make(map[string]interface{})
	for k, v := range variables {
		allVars[k] = v
	}
	for k, v := range data {
		allVars[k] = v
	}

	// Simple variable substitution
	result := template
	for key, value := range allVars {
		placeholder := fmt.Sprintf("{%s}", key)
		valueStr := fmt.Sprintf("%v", value)
		result = strings.ReplaceAll(result, placeholder, valueStr)
	}

	return transform.TransformResult{
		Data: map[string]interface{}{
			"text": result,
		},
		Success:  true,
		Duration: time.Since(startTime),
	}, nil
}
