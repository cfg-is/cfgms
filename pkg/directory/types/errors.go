package types

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Common validation errors for directory objects
var (
	// User validation errors
	ErrInvalidUserPrincipalName       = errors.New("user principal name cannot be empty")
	ErrInvalidUserPrincipalNameFormat = errors.New("user principal name format is invalid")
	ErrInvalidDisplayName             = errors.New("display name cannot be empty")
	ErrInvalidMailNickname            = errors.New("mail nickname is required for mail-enabled objects")

	// Group validation errors
	ErrInvalidGroupDisplayName = errors.New("group display name cannot be empty")
	ErrInvalidGroupType        = errors.New("invalid group type")

	// Common validation errors
	ErrInvalidEmailAddress = errors.New("email address format is invalid")
)

// ValidationError represents a validation error with field-specific details
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value,omitempty"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("validation error for field '%s' (value: '%s'): %s", e.Field, e.Value, e.Message)
	}
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	if len(e) == 1 {
		return e[0].Error()
	}

	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return fmt.Sprintf("multiple validation errors: %s", strings.Join(messages, "; "))
}

// HasField checks if there's a validation error for a specific field
func (e ValidationErrors) HasField(field string) bool {
	for _, err := range e {
		if err.Field == field {
			return true
		}
	}
	return false
}

// GetField returns the validation error for a specific field, if any
func (e ValidationErrors) GetField(field string) *ValidationError {
	for _, err := range e {
		if err.Field == field {
			return &err
		}
	}
	return nil
}

// Validation helper functions

// isValidUPN validates User Principal Name format (basic validation)
func isValidUPN(upn string) bool {
	if upn == "" {
		return false
	}

	// Basic UPN format: username@domain
	// More comprehensive regex could be added here
	upnRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return upnRegex.MatchString(upn)
}

// TODO: Add validation functions when needed
// - isValidEmail: validates email address format
// - isValidMailNickname: validates mail nickname format for Microsoft 365

// Conversion error types

// ConversionError represents an error during object conversion
type ConversionError struct {
	SourceType string `json:"source_type"`
	TargetType string `json:"target_type"`
	Field      string `json:"field,omitempty"`
	Message    string `json:"message"`
	Cause      error  `json:"cause,omitempty"`
}

func (e *ConversionError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("conversion error from %s to %s (field: %s): %s", e.SourceType, e.TargetType, e.Field, e.Message)
	}
	return fmt.Sprintf("conversion error from %s to %s: %s", e.SourceType, e.TargetType, e.Message)
}

func (e *ConversionError) Unwrap() error {
	return e.Cause
}

// NewConversionError creates a new conversion error
func NewConversionError(sourceType, targetType, field, message string, cause error) *ConversionError {
	return &ConversionError{
		SourceType: sourceType,
		TargetType: targetType,
		Field:      field,
		Message:    message,
		Cause:      cause,
	}
}

// Provider error types

// ProviderError represents an error from a directory provider
type ProviderError struct {
	ProviderName string `json:"provider_name"`
	Operation    string `json:"operation"`
	ObjectType   string `json:"object_type,omitempty"`
	ObjectID     string `json:"object_id,omitempty"`
	Message      string `json:"message"`
	StatusCode   int    `json:"status_code,omitempty"`
	Cause        error  `json:"cause,omitempty"`
}

func (e *ProviderError) Error() string {
	if e.ObjectID != "" {
		return fmt.Sprintf("%s provider error during %s on %s '%s': %s", e.ProviderName, e.Operation, e.ObjectType, e.ObjectID, e.Message)
	}
	if e.ObjectType != "" {
		return fmt.Sprintf("%s provider error during %s on %s: %s", e.ProviderName, e.Operation, e.ObjectType, e.Message)
	}
	return fmt.Sprintf("%s provider error during %s: %s", e.ProviderName, e.Operation, e.Message)
}

func (e *ProviderError) Unwrap() error {
	return e.Cause
}

// NewProviderError creates a new provider error
func NewProviderError(providerName, operation, objectType, objectID, message string, statusCode int, cause error) *ProviderError {
	return &ProviderError{
		ProviderName: providerName,
		Operation:    operation,
		ObjectType:   objectType,
		ObjectID:     objectID,
		Message:      message,
		StatusCode:   statusCode,
		Cause:        cause,
	}
}

// IsNotFoundError checks if the error represents a "not found" condition
func IsNotFoundError(err error) bool {
	if providerErr, ok := err.(*ProviderError); ok {
		return providerErr.StatusCode == 404
	}
	return false
}

// IsConflictError checks if the error represents a conflict (already exists)
func IsConflictError(err error) bool {
	if providerErr, ok := err.(*ProviderError); ok {
		return providerErr.StatusCode == 409
	}
	return false
}

// IsValidationError checks if the error is a validation error
func IsValidationError(err error) bool {
	_, ok := err.(*ValidationError)
	if ok {
		return true
	}
	_, ok = err.(ValidationErrors)
	return ok
}

// IsConversionError checks if the error is a conversion error
func IsConversionError(err error) bool {
	_, ok := err.(*ConversionError)
	return ok
}