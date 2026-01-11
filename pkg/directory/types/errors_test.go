// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package types

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ValidationError
		expected string
	}{
		{
			name: "error with value",
			err: &ValidationError{
				Field:   "user_principal_name",
				Value:   "invalid-upn",
				Message: "format is invalid",
			},
			expected: "validation error for field 'user_principal_name' (value: 'invalid-upn'): format is invalid",
		},
		{
			name: "error without value",
			err: &ValidationError{
				Field:   "display_name",
				Message: "cannot be empty",
			},
			expected: "validation error for field 'display_name': cannot be empty",
		},
		{
			name: "error with empty value",
			err: &ValidationError{
				Field:   "mail",
				Value:   "",
				Message: "is required",
			},
			expected: "validation error for field 'mail': is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidationErrors_Error(t *testing.T) {
	tests := []struct {
		name     string
		errs     ValidationErrors
		expected string
	}{
		{
			name:     "no errors",
			errs:     ValidationErrors{},
			expected: "no validation errors",
		},
		{
			name: "single error",
			errs: ValidationErrors{
				{Field: "display_name", Message: "cannot be empty"},
			},
			expected: "validation error for field 'display_name': cannot be empty",
		},
		{
			name: "multiple errors",
			errs: ValidationErrors{
				{Field: "display_name", Message: "cannot be empty"},
				{Field: "user_principal_name", Value: "invalid", Message: "format is invalid"},
			},
			expected: "multiple validation errors: validation error for field 'display_name': cannot be empty; validation error for field 'user_principal_name' (value: 'invalid'): format is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.errs.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidationErrors_HasField(t *testing.T) {
	errs := ValidationErrors{
		{Field: "display_name", Message: "cannot be empty"},
		{Field: "user_principal_name", Message: "format is invalid"},
		{Field: "mail", Message: "is required"},
	}

	tests := []struct {
		name     string
		field    string
		expected bool
	}{
		{
			name:     "field exists",
			field:    "display_name",
			expected: true,
		},
		{
			name:     "field exists - different case",
			field:    "user_principal_name",
			expected: true,
		},
		{
			name:     "field does not exist",
			field:    "nonexistent_field",
			expected: false,
		},
		{
			name:     "empty field",
			field:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := errs.HasField(tt.field)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidationErrors_GetField(t *testing.T) {
	errs := ValidationErrors{
		{Field: "display_name", Message: "cannot be empty"},
		{Field: "user_principal_name", Value: "invalid", Message: "format is invalid"},
		{Field: "mail", Message: "is required"},
	}

	tests := []struct {
		name     string
		field    string
		expected *ValidationError
	}{
		{
			name:  "field exists",
			field: "display_name",
			expected: &ValidationError{
				Field:   "display_name",
				Message: "cannot be empty",
			},
		},
		{
			name:  "field exists with value",
			field: "user_principal_name",
			expected: &ValidationError{
				Field:   "user_principal_name",
				Value:   "invalid",
				Message: "format is invalid",
			},
		},
		{
			name:     "field does not exist",
			field:    "nonexistent_field",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := errs.GetField(tt.field)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidUPN(t *testing.T) {
	tests := []struct {
		name     string
		upn      string
		expected bool
	}{
		{
			name:     "valid UPN - simple",
			upn:      "user@domain.com",
			expected: true,
		},
		{
			name:     "valid UPN - with dots",
			upn:      "john.doe@example.org",
			expected: true,
		},
		{
			name:     "valid UPN - with numbers and plus",
			upn:      "user123+test@domain123.co.uk",
			expected: true,
		},
		{
			name:     "valid UPN - with hyphen and underscore",
			upn:      "test_user-1@sub-domain.example.com",
			expected: true,
		},
		{
			name:     "invalid UPN - empty",
			upn:      "",
			expected: false,
		},
		{
			name:     "invalid UPN - no @ symbol",
			upn:      "userdomain.com",
			expected: false,
		},
		{
			name:     "invalid UPN - no domain",
			upn:      "user@",
			expected: false,
		},
		{
			name:     "invalid UPN - no username",
			upn:      "@domain.com",
			expected: false,
		},
		{
			name:     "invalid UPN - no TLD",
			upn:      "user@domain",
			expected: false,
		},
		{
			name:     "invalid UPN - spaces",
			upn:      "user name@domain.com",
			expected: false,
		},
		{
			name:     "invalid UPN - multiple @",
			upn:      "user@domain@com",
			expected: false,
		},
		{
			name:     "invalid UPN - TLD too short",
			upn:      "user@domain.c",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidUPN(tt.upn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConversionError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ConversionError
		expected string
	}{
		{
			name: "conversion error with field",
			err: &ConversionError{
				SourceType: "GraphUser",
				TargetType: "DirectoryUser",
				Field:      "created_date_time",
				Message:    "invalid date format",
			},
			expected: "conversion error from GraphUser to DirectoryUser (field: created_date_time): invalid date format",
		},
		{
			name: "conversion error without field",
			err: &ConversionError{
				SourceType: "EntraGroupConfig",
				TargetType: "DirectoryGroup",
				Message:    "missing required properties",
			},
			expected: "conversion error from EntraGroupConfig to DirectoryGroup: missing required properties",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConversionError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &ConversionError{
		SourceType: "Type1",
		TargetType: "Type2",
		Message:    "conversion failed",
		Cause:      cause,
	}

	result := err.Unwrap()
	assert.Equal(t, cause, result)
}

func TestNewConversionError(t *testing.T) {
	cause := errors.New("underlying error")
	err := NewConversionError("GraphUser", "DirectoryUser", "created_date_time", "invalid format", cause)

	assert.Equal(t, "GraphUser", err.SourceType)
	assert.Equal(t, "DirectoryUser", err.TargetType)
	assert.Equal(t, "created_date_time", err.Field)
	assert.Equal(t, "invalid format", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestProviderError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ProviderError
		expected string
	}{
		{
			name: "error with object ID",
			err: &ProviderError{
				ProviderName: "entraid",
				Operation:    "get_user",
				ObjectType:   "user",
				ObjectID:     "12345",
				Message:      "user not found",
			},
			expected: "entraid provider error during get_user on user '12345': user not found",
		},
		{
			name: "error with object type but no ID",
			err: &ProviderError{
				ProviderName: "activedirectory",
				Operation:    "create_group",
				ObjectType:   "group",
				Message:      "insufficient permissions",
			},
			expected: "activedirectory provider error during create_group on group: insufficient permissions",
		},
		{
			name: "error without object type or ID",
			err: &ProviderError{
				ProviderName: "entraid",
				Operation:    "authenticate",
				Message:      "invalid credentials",
			},
			expected: "entraid provider error during authenticate: invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProviderError_Unwrap(t *testing.T) {
	cause := errors.New("network timeout")
	err := &ProviderError{
		ProviderName: "entraid",
		Operation:    "get_user",
		Message:      "request failed",
		Cause:        cause,
	}

	result := err.Unwrap()
	assert.Equal(t, cause, result)
}

func TestNewProviderError(t *testing.T) {
	cause := errors.New("network error")
	err := NewProviderError("entraid", "get_user", "user", "12345", "request failed", 500, cause)

	assert.Equal(t, "entraid", err.ProviderName)
	assert.Equal(t, "get_user", err.Operation)
	assert.Equal(t, "user", err.ObjectType)
	assert.Equal(t, "12345", err.ObjectID)
	assert.Equal(t, "request failed", err.Message)
	assert.Equal(t, 500, err.StatusCode)
	assert.Equal(t, cause, err.Cause)
}

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name: "provider error with 404 status",
			err: &ProviderError{
				ProviderName: "entraid",
				Operation:    "get_user",
				Message:      "user not found",
				StatusCode:   404,
			},
			expected: true,
		},
		{
			name: "provider error with different status",
			err: &ProviderError{
				ProviderName: "entraid",
				Operation:    "get_user",
				Message:      "server error",
				StatusCode:   500,
			},
			expected: false,
		},
		{
			name:     "different error type",
			err:      errors.New("generic error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNotFoundError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsConflictError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name: "provider error with 409 status",
			err: &ProviderError{
				ProviderName: "entraid",
				Operation:    "create_user",
				Message:      "user already exists",
				StatusCode:   409,
			},
			expected: true,
		},
		{
			name: "provider error with different status",
			err: &ProviderError{
				ProviderName: "entraid",
				Operation:    "create_user",
				Message:      "server error",
				StatusCode:   500,
			},
			expected: false,
		},
		{
			name:     "different error type",
			err:      errors.New("generic error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsConflictError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name: "single validation error",
			err: &ValidationError{
				Field:   "display_name",
				Message: "cannot be empty",
			},
			expected: true,
		},
		{
			name: "multiple validation errors",
			err: ValidationErrors{
				{Field: "display_name", Message: "cannot be empty"},
				{Field: "upn", Message: "invalid format"},
			},
			expected: true,
		},
		{
			name:     "different error type",
			err:      errors.New("generic error"),
			expected: false,
		},
		{
			name: "provider error",
			err: &ProviderError{
				ProviderName: "entraid",
				Operation:    "get_user",
				Message:      "not found",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidationError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsConversionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name: "conversion error",
			err: &ConversionError{
				SourceType: "GraphUser",
				TargetType: "DirectoryUser",
				Message:    "conversion failed",
			},
			expected: true,
		},
		{
			name:     "different error type",
			err:      errors.New("generic error"),
			expected: false,
		},
		{
			name: "validation error",
			err: &ValidationError{
				Field:   "display_name",
				Message: "cannot be empty",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsConversionError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPredefinedErrors(t *testing.T) {
	// Test that predefined error variables exist and have expected messages
	assert.Equal(t, "user principal name cannot be empty", ErrInvalidUserPrincipalName.Error())
	assert.Equal(t, "user principal name format is invalid", ErrInvalidUserPrincipalNameFormat.Error())
	assert.Equal(t, "display name cannot be empty", ErrInvalidDisplayName.Error())
	assert.Equal(t, "mail nickname is required for mail-enabled objects", ErrInvalidMailNickname.Error())
	assert.Equal(t, "group display name cannot be empty", ErrInvalidGroupDisplayName.Error())
	assert.Equal(t, "invalid group type", ErrInvalidGroupType.Error())
	assert.Equal(t, "email address format is invalid", ErrInvalidEmailAddress.Error())
}

func TestErrorWrapping(t *testing.T) {
	// Test error wrapping behavior with errors.Is and errors.As
	originalErr := errors.New("original error")

	conversionErr := &ConversionError{
		SourceType: "Type1",
		TargetType: "Type2",
		Message:    "conversion failed",
		Cause:      originalErr,
	}

	providerErr := &ProviderError{
		ProviderName: "test",
		Operation:    "test_op",
		Message:      "provider failed",
		Cause:        conversionErr,
	}

	// Test errors.Is
	assert.True(t, errors.Is(conversionErr, originalErr))
	assert.True(t, errors.Is(providerErr, conversionErr))
	assert.True(t, errors.Is(providerErr, originalErr))

	// Test errors.As
	var ce *ConversionError
	assert.True(t, errors.As(providerErr, &ce))
	assert.Equal(t, conversionErr, ce)

	var pe *ProviderError
	assert.True(t, errors.As(providerErr, &pe))
	assert.Equal(t, providerErr, pe)
}
