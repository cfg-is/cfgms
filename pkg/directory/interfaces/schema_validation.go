// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces - Directory Schema Validation and Conflict Resolution
//
// This file implements object/field validation and conflict resolution methods
// for the DefaultDirectorySchemaMapper. Validation enforces normalized schema
// constraints (required fields, types, formats, patterns, enums, custom rules).
// Conflict resolution merges differing values from multiple directory providers.

package interfaces

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// ValidateNormalizedObject validates a normalized object against the schema
func (m *DefaultDirectorySchemaMapper) ValidateNormalizedObject(objectType DirectoryObjectType, data map[string]interface{}) error {
	var schema *NormalizedObjectSchema

	switch objectType {
	case DirectoryObjectTypeUser:
		schema = m.normalizedSchema.UserSchema
	case DirectoryObjectTypeGroup:
		schema = m.normalizedSchema.GroupSchema
	case DirectoryObjectTypeOU:
		schema = m.normalizedSchema.OUSchema
	default:
		return fmt.Errorf("unsupported object type: %s", objectType)
	}

	if schema == nil {
		return fmt.Errorf("schema not found for object type: %s", objectType)
	}

	// Check required fields
	allFields := make(map[string]*NormalizedField)
	for name, field := range schema.CoreFields {
		allFields[name] = field
	}
	for name, field := range schema.OptionalFields {
		allFields[name] = field
	}

	for name, field := range allFields {
		value, exists := data[name]

		if field.Required && !exists {
			return fmt.Errorf("required field missing: %s", name)
		}

		if exists && value != nil {
			if err := m.validateField(field, value); err != nil {
				return fmt.Errorf("validation failed for field %s: %w", name, err)
			}
		}
	}

	return nil
}

// validateField validates a single field value
func (m *DefaultDirectorySchemaMapper) validateField(field *NormalizedField, value interface{}) error {
	// Type validation
	if err := m.validateFieldType(field.Type, value); err != nil {
		return err
	}

	// Format validation
	if field.Format != "" {
		if err := m.validateFieldFormat(field.Format, value); err != nil {
			return err
		}
	}

	// Pattern validation
	if field.Pattern != "" {
		if str, ok := value.(string); ok {
			matched, err := regexp.MatchString(field.Pattern, str)
			if err != nil {
				return fmt.Errorf("invalid pattern: %w", err)
			}
			if !matched {
				return fmt.Errorf("value does not match pattern %s", field.Pattern)
			}
		}
	}

	// Length validation
	if field.MaxLength > 0 || field.MinLength > 0 {
		if str, ok := value.(string); ok {
			length := len(str)
			if field.MaxLength > 0 && length > field.MaxLength {
				return fmt.Errorf("value exceeds maximum length %d", field.MaxLength)
			}
			if field.MinLength > 0 && length < field.MinLength {
				return fmt.Errorf("value below minimum length %d", field.MinLength)
			}
		}
	}

	// Enum validation
	if len(field.EnumValues) > 0 {
		found := false
		for _, enumValue := range field.EnumValues {
			if reflect.DeepEqual(value, enumValue) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("value not in allowed enum values: %v", field.EnumValues)
		}
	}

	// Custom validation
	if field.Validation != nil && len(field.Validation.CustomRules) > 0 {
		for _, ruleName := range field.Validation.CustomRules {
			if validator, exists := m.validators[ruleName]; exists {
				if err := validator.Validate(field, value); err != nil {
					return fmt.Errorf("custom validation failed (%s): %w", ruleName, err)
				}
			}
		}
	}

	return nil
}

// validateFieldType validates the data type of a field value
func (m *DefaultDirectorySchemaMapper) validateFieldType(fieldType FieldType, value interface{}) error {
	switch fieldType {
	case FieldTypeString:
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string, got %T", value)
		}
	case FieldTypeInteger:
		switch value.(type) {
		case int, int32, int64, uint, uint32, uint64:
			// Valid integer types
		default:
			return fmt.Errorf("expected integer, got %T", value)
		}
	case FieldTypeBoolean:
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected boolean, got %T", value)
		}
	case FieldTypeDateTime:
		if _, ok := value.(time.Time); !ok {
			return fmt.Errorf("expected datetime, got %T", value)
		}
	case FieldTypeArray:
		if reflect.TypeOf(value).Kind() != reflect.Slice {
			return fmt.Errorf("expected array, got %T", value)
		}
	case FieldTypeObject:
		if reflect.TypeOf(value).Kind() != reflect.Map {
			return fmt.Errorf("expected object, got %T", value)
		}
	}

	return nil
}

// validateFieldFormat validates field format constraints
func (m *DefaultDirectorySchemaMapper) validateFieldFormat(format string, value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("format validation requires string value")
	}

	switch format {
	case "email":
		pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return fmt.Errorf("invalid email pattern: %w", err)
		}
		if !matched {
			return fmt.Errorf("invalid email format")
		}
	case "phone":
		// Basic phone number validation (can be enhanced)
		pattern := `^\+?[\d\s\-\(\)]+$`
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return fmt.Errorf("invalid phone pattern: %w", err)
		}
		if !matched {
			return fmt.Errorf("invalid phone format")
		}
	}

	return nil
}

// ValidateProviderObject validates a provider object against its schema
func (m *DefaultDirectorySchemaMapper) ValidateProviderObject(providerName string, objectType DirectoryObjectType, data map[string]interface{}) error {
	schema, exists := m.providerSchemas[providerName]
	if !exists {
		return fmt.Errorf("provider schema not found: %s", providerName)
	}

	var objectSchema *ProviderObjectSchema
	switch objectType {
	case DirectoryObjectTypeUser:
		objectSchema = schema.UserSchema
	case DirectoryObjectTypeGroup:
		objectSchema = schema.GroupSchema
	case DirectoryObjectTypeOU:
		objectSchema = schema.OUSchema
	default:
		return fmt.Errorf("unsupported object type: %s", objectType)
	}

	if objectSchema == nil {
		return fmt.Errorf("object schema not found for type: %s", objectType)
	}

	// Check required fields
	for _, fieldName := range objectSchema.RequiredFields {
		if _, exists := data[fieldName]; !exists {
			return fmt.Errorf("required field missing: %s", fieldName)
		}
	}

	// Validate field types (basic validation)
	for fieldName, value := range data {
		if field, exists := objectSchema.Fields[fieldName]; exists {
			if value != nil && field.ProviderType != "" {
				// TODO: Implement provider-specific type validation
				// Each provider (AD, Azure, etc.) has different data types and constraints
				// that should be validated based on field.ProviderType
				_ = field.ProviderType // Acknowledge need for future validation implementation
			}
		}
	}

	return nil
}

// ResolveConflicts resolves conflicts between different provider representations
func (m *DefaultDirectorySchemaMapper) ResolveConflicts(conflicts []FieldConflict) (map[string]interface{}, error) {
	resolved := make(map[string]interface{})

	for _, conflict := range conflicts {
		switch conflict.Resolution.Strategy {
		case "prefer_provider":
			if conflict.Resolution.PreferredProvider != "" {
				if value, exists := conflict.Conflicts[conflict.Resolution.PreferredProvider]; exists {
					resolved[conflict.NormalizedName] = value
				}
			}
		case "custom_value":
			if conflict.Resolution.CustomValue != nil {
				resolved[conflict.NormalizedName] = conflict.Resolution.CustomValue
			}
		case "merge":
			// Implement merge strategy (e.g., concatenate strings, merge arrays)
			merged := m.mergeConflictValues(conflict.Conflicts)
			resolved[conflict.NormalizedName] = merged
		case "newest":
			// Choose the value from the provider with the most recent timestamp
			// This would require timestamp metadata in the conflicts
		default:
			return nil, fmt.Errorf("unsupported conflict resolution strategy: %s", conflict.Resolution.Strategy)
		}
	}

	return resolved, nil
}

// mergeConflictValues merges conflicting values
func (m *DefaultDirectorySchemaMapper) mergeConflictValues(conflicts map[string]interface{}) interface{} {
	// Simple merge strategy - concatenate strings or return first non-nil value
	var result interface{}
	var stringValues []string

	for provider, value := range conflicts {
		if result == nil {
			result = value
		}

		if str, ok := value.(string); ok && str != "" {
			stringValues = append(stringValues, fmt.Sprintf("%s: %s", provider, str))
		}
	}

	// If we have multiple string values, concatenate them
	if len(stringValues) > 1 {
		return strings.Join(stringValues, "; ")
	}

	return result
}
