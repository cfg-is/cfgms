// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces - Directory Schema Built-in Validators
//
// This file contains built-in FieldValidator implementations for the schema
// normalization layer. Each validator enforces a specific constraint on field
// values during normalized object validation.

package interfaces

import (
	"fmt"
	"regexp"
	"strings"
)

// registerBuiltinValidators registers built-in field validators
func (m *DefaultDirectorySchemaMapper) registerBuiltinValidators() {
	m.validators["non_empty"] = &NonEmptyValidator{}
	m.validators["email_format"] = &EmailFormatValidator{}
	m.validators["phone_format"] = &PhoneFormatValidator{}
	m.validators["alphanumeric"] = &AlphanumericValidator{}
}

// Built-in validator implementations

type NonEmptyValidator struct{}

func (v *NonEmptyValidator) Validate(field *NormalizedField, value interface{}) error {
	if str, ok := value.(string); ok {
		if strings.TrimSpace(str) == "" {
			return fmt.Errorf("field cannot be empty")
		}
	}
	return nil
}

func (v *NonEmptyValidator) GetDescription() string {
	return "Validates that string fields are not empty"
}

type EmailFormatValidator struct{}

func (v *EmailFormatValidator) Validate(field *NormalizedField, value interface{}) error {
	if str, ok := value.(string); ok {
		pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return fmt.Errorf("email validation error: %w", err)
		}
		if !matched {
			return fmt.Errorf("invalid email format")
		}
	}
	return nil
}

func (v *EmailFormatValidator) GetDescription() string {
	return "Validates email address format"
}

type PhoneFormatValidator struct{}

func (v *PhoneFormatValidator) Validate(field *NormalizedField, value interface{}) error {
	if str, ok := value.(string); ok {
		pattern := `^\+?[\d\s\-\(\)\.]+$`
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return fmt.Errorf("phone validation error: %w", err)
		}
		if !matched {
			return fmt.Errorf("invalid phone format")
		}
	}
	return nil
}

func (v *PhoneFormatValidator) GetDescription() string {
	return "Validates phone number format"
}

type AlphanumericValidator struct{}

func (v *AlphanumericValidator) Validate(field *NormalizedField, value interface{}) error {
	if str, ok := value.(string); ok {
		pattern := `^[a-zA-Z0-9]+$`
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return fmt.Errorf("alphanumeric validation error: %w", err)
		}
		if !matched {
			return fmt.Errorf("field must contain only alphanumeric characters")
		}
	}
	return nil
}

func (v *AlphanumericValidator) GetDescription() string {
	return "Validates that field contains only alphanumeric characters"
}
