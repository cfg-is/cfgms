// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces - Directory Schema Built-in Transformers
//
// This file contains built-in DataTransformer implementations for the schema
// normalization layer. Each transformer handles a specific data conversion
// between provider and normalized formats.

package interfaces

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// registerBuiltinTransformers registers built-in data transformers
func (m *DefaultDirectorySchemaMapper) registerBuiltinTransformers() {
	m.transformers["to_lowercase"] = &ToLowercaseTransformer{}
	m.transformers["to_uppercase"] = &ToUppercaseTransformer{}
	m.transformers["trim_spaces"] = &TrimSpacesTransformer{}
	m.transformers["parse_boolean"] = &ParseBooleanTransformer{}
	m.transformers["format_phone"] = &FormatPhoneTransformer{}
	m.transformers["normalize_email"] = &NormalizeEmailTransformer{}
	m.transformers["parse_timestamp"] = &ParseTimestampTransformer{}
}

// Built-in transformer implementations

type ToLowercaseTransformer struct{}

func (t *ToLowercaseTransformer) Transform(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		return strings.ToLower(str), nil
	}
	return input, nil
}

func (t *ToLowercaseTransformer) Reverse(input interface{}) (interface{}, error) {
	return input, nil // Lowercasing is not reversible
}

func (t *ToLowercaseTransformer) GetDescription() string {
	return "Converts string to lowercase"
}

type ToUppercaseTransformer struct{}

func (t *ToUppercaseTransformer) Transform(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		return strings.ToUpper(str), nil
	}
	return input, nil
}

func (t *ToUppercaseTransformer) Reverse(input interface{}) (interface{}, error) {
	return input, nil // Uppercasing is not reversible
}

func (t *ToUppercaseTransformer) GetDescription() string {
	return "Converts string to uppercase"
}

type TrimSpacesTransformer struct{}

func (t *TrimSpacesTransformer) Transform(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		return strings.TrimSpace(str), nil
	}
	return input, nil
}

func (t *TrimSpacesTransformer) Reverse(input interface{}) (interface{}, error) {
	return input, nil // Trimming is not reversible
}

func (t *TrimSpacesTransformer) GetDescription() string {
	return "Trims whitespace from string"
}

type ParseBooleanTransformer struct{}

func (t *ParseBooleanTransformer) Transform(input interface{}) (interface{}, error) {
	switch v := input.(type) {
	case string:
		return strconv.ParseBool(strings.ToLower(v))
	case bool:
		return v, nil
	case int:
		return v != 0, nil
	default:
		return false, fmt.Errorf("cannot convert %T to boolean", input)
	}
}

func (t *ParseBooleanTransformer) Reverse(input interface{}) (interface{}, error) {
	if b, ok := input.(bool); ok {
		if b {
			return "true", nil
		}
		return "false", nil
	}
	return input, nil
}

func (t *ParseBooleanTransformer) GetDescription() string {
	return "Converts various formats to boolean"
}

type FormatPhoneTransformer struct{}

func (t *FormatPhoneTransformer) Transform(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		// Simple phone formatting - remove non-digits and add standard formatting
		digits := regexp.MustCompile(`\D`).ReplaceAllString(str, "")
		if len(digits) == 10 {
			return fmt.Sprintf("(%s) %s-%s", digits[0:3], digits[3:6], digits[6:10]), nil
		} else if len(digits) == 11 && digits[0] == '1' {
			return fmt.Sprintf("+1 (%s) %s-%s", digits[1:4], digits[4:7], digits[7:11]), nil
		}
		return str, nil // Return original if can't format
	}
	return input, nil
}

func (t *FormatPhoneTransformer) Reverse(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		// Extract digits only
		return regexp.MustCompile(`\D`).ReplaceAllString(str, ""), nil
	}
	return input, nil
}

func (t *FormatPhoneTransformer) GetDescription() string {
	return "Formats phone numbers to standard format"
}

type NormalizeEmailTransformer struct{}

func (t *NormalizeEmailTransformer) Transform(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		return strings.ToLower(strings.TrimSpace(str)), nil
	}
	return input, nil
}

func (t *NormalizeEmailTransformer) Reverse(input interface{}) (interface{}, error) {
	return input, nil // Email normalization is not reversible
}

func (t *NormalizeEmailTransformer) GetDescription() string {
	return "Normalizes email addresses (lowercase, trim)"
}

type ParseTimestampTransformer struct{}

func (t *ParseTimestampTransformer) Transform(input interface{}) (interface{}, error) {
	switch v := input.(type) {
	case string:
		// Try common timestamp formats
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
			"01/02/2006 15:04:05",
		}

		for _, format := range formats {
			if t, err := time.Parse(format, v); err == nil {
				return t, nil
			}
		}
		return nil, fmt.Errorf("unable to parse timestamp: %s", v)
	case time.Time:
		return v, nil
	case int64:
		// Assume Unix timestamp
		return time.Unix(v, 0), nil
	default:
		return nil, fmt.Errorf("unsupported timestamp type: %T", input)
	}
}

func (t *ParseTimestampTransformer) Reverse(input interface{}) (interface{}, error) {
	if ts, ok := input.(time.Time); ok {
		return ts.Format(time.RFC3339), nil
	}
	return input, nil
}

func (t *ParseTimestampTransformer) GetDescription() string {
	return "Parses timestamps from various formats"
}
